"""Experimental bounded symbolic argument tracing, never a proof of exploitability.

Only submitted source is inspected. No imports, source execution or filesystem I/O.
Unknown dispatch/control flow stays unknown; facts never suppress scanner findings.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace


@dataclass
class Value:
    origins: list[str] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)
    literal: object = None
    known: bool = False
    ref: str = ''
    guards: list[dict] = field(default_factory=list)
    uncertain: bool = False
    mapping: dict | None = None


def trace_commands(blocks, max_paths=40, max_depth=3):
    """Return bounded evidence records for simple named calls and assignments."""
    modules, functions, paths, limits, restrictions = {}, {}, [], set(), []
    sources = {}
    for block in blocks:
        lines = sources.setdefault(block.file_id, {})
        lines.update(enumerate(block.lines, block.start))
    for filename, numbered in sources.items():
        if not numbered:
            continue
        # Do not reconstruct missing source as if omitted branches did not exist.
        if set(numbered) != set(range(1, max(numbered) + 1)):
            limits.add(f'{filename}: noncontiguous source omitted from path tracing')
            continue
        try:
            tree = ast.parse('\n'.join(numbered[i] for i in range(1, max(numbered) + 1)))
        except (SyntaxError, ValueError, RecursionError):
            limits.add(f'{filename}: source could not be parsed')
            continue
        modules[filename] = tree
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[f'{filename}:{node.name}'] = (filename, node)

    def location(filename, node, kind):
        return dict(file=filename, line=node.lineno, kind=kind)

    def combine(values):
        return Value(origins=sorted({o for v in values for o in v.origins}),
                     steps=[s for v in values for s in v.steps][-12:],
                     guards=[s for v in values for s in v.guards][-8:],
                     uncertain=any(v.uncertain for v in values))

    globals_by_file = {}
    active = set()
    budget = [5000]

    def expr(node, env, filename, depth):
        budget[0] -= 1
        if budget[0] < 0:
            limits.add('expression budget exhausted')
            return Value(uncertain=True)
        if isinstance(node, ast.Constant):
            return Value(literal=node.value, known=True)
        if isinstance(node, ast.Name):
            return env.get(node.id, Value(uncertain=True))
        if isinstance(node, ast.Attribute):
            base = expr(node.value, env, filename, depth)
            if base.ref.startswith('module:'):
                return Value(ref=base.ref[7:] + ':' + node.attr, uncertain=base.uncertain)
            return Value(uncertain=True)
        if isinstance(node, ast.Dict):
            mapping = {}
            for key, value in zip(node.keys, node.values):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    return Value(uncertain=True)
                mapping[key.value] = expr(value, env, filename, depth)
            return Value(mapping=mapping)
        if isinstance(node, ast.Subscript):
            container = expr(node.value, env, filename, depth)
            key = expr(node.slice, env, filename, depth)
            if container.mapping is not None:
                fact = {**location(filename, node, 'literal-mapping-selection'),
                        'keys': list(container.mapping)[:20],
                        'truncated': len(container.mapping) > 20,
                        'note': 'Visible mapping declaration; later mutation and external rebinding are not proven absent.'}
                if fact not in restrictions and len(restrictions) < 40:
                    restrictions.append(fact)
                # Never assume a mutable table is a proven sanitizer.
                return replace(key, guards=key.guards + [fact], uncertain=True)
            return Value(uncertain=True)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            values = [expr(n, env, filename, depth) for n in node.elts]
            result = combine(values)
            if all(v.known for v in values):
                result.known, result.literal = True, [v.literal for v in values]
            return result
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            a, b = expr(node.left, env, filename, depth), expr(node.right, env, filename, depth)
            result = combine([a, b])
            if a.known and b.known and isinstance(a.literal, str) and isinstance(b.literal, str):
                result.literal, result.known = (a.literal + b.literal)[:2000], True
            return result
        if isinstance(node, ast.JoinedStr):
            values = [expr(n.value if isinstance(n, ast.FormattedValue) else n, env, filename, depth)
                      for n in node.values]
            result = combine(values)
            # Formatting/conversions are not evaluated.
            if all(v.known and isinstance(v.literal, str) for v in values):
                result.known, result.literal = True, ''.join(v.literal for v in values)[:2000]
            return result
        if isinstance(node, ast.Call):
            callee = expr(node.func, env, filename, depth)
            args = [expr(n, env, filename, depth) for n in node.args]
            kwargs = {k.arg: expr(k.value, env, filename, depth) for k in node.keywords}
            value = args[0] if args else kwargs.get('args', kwargs.get('command', Value(uncertain=True)))
            shell = kwargs.get('shell', Value(literal=False, known=True))
            ref = callee.ref
            if ref == 'os:system' or ref in {'subprocess:run', 'subprocess:Popen', 'subprocess:call',
                                          'subprocess:check_call', 'subprocess:check_output'}:
                uncertain = callee.uncertain or value.uncertain or None in kwargs or any(isinstance(n, ast.Starred) for n in node.args)
                if ref != 'os:system' and len(args) > 1:
                    uncertain = True  # positional signatures differ; no guessing shell position
                if ref == 'os:system':
                    shell = Value(literal=True, known=True)
                mode = ('enabled' if shell.known and shell.literal is True else
                        'disabled' if shell.known and shell.literal is False else 'unknown')
                status = ('unresolved' if uncertain or mode == 'unknown' else
                          'no-shell' if mode == 'disabled' else
                          'constant-shell-command' if value.known else
                          'parameter-to-shell' if value.origins else 'unresolved')
                record = {**location(filename, node, 'process-call'), 'callee': ref.replace(':', '.'),
                          'shell': mode, 'status': status, 'origins': value.origins,
                          'steps': value.steps[-12:], 'observed_guards': value.guards[-8:],
                          'attacker_control': 'not-established',
                          'note': 'No-shell is not a general safety verdict; explicit interpreters and argument injection need review.'}
                if record not in paths:
                    if len(paths) < max_paths:
                        paths.append(record)
                    else:
                        limits.add('path budget exhausted')
                return Value(uncertain=True)
            if ref in functions and not callee.uncertain and depth < max_depth and ref not in active and None not in kwargs:
                target_file, function = functions[ref]
                params = function.args.posonlyargs + function.args.args
                if function.decorator_list or function.args.vararg or function.args.kwarg or function.args.kwonlyargs:
                    limits.add(f'{ref}: unsupported function signature/decorators')
                    return Value(uncertain=True)
                if len(args) > len(params) or any(isinstance(n, ast.Starred) for n in node.args):
                    return Value(uncertain=True)
                if (set(kwargs) - {p.arg for p in params}
                        or set(kwargs) & {p.arg for p in params[:len(args)]}
                        or set(kwargs) & {p.arg for p in function.args.posonlyargs}):
                    limits.add(f'{filename}:{node.lineno}: unresolved argument binding')
                    return Value(uncertain=True)
                local = dict(globals_by_file.get(target_file, {}))
                for i, param in enumerate(params):
                    supplied = args[i] if i < len(args) else kwargs.get(param.arg, Value(uncertain=True))
                    local[param.arg] = replace(supplied, steps=(supplied.steps + [
                        location(filename, node, f'argument -> {ref}.{param.arg}')])[-12:])
                active.add(ref)
                result = statements(function.body, local, target_file, depth + 1)
                active.remove(ref)
                return result
            limits.add(f'{filename}:{node.lineno}: unresolved call or depth limit')
            # Unknown callees may mutate globals or bindings; do not carry a
            # previously observed binding forward as certain after such a call.
            env.update({k: replace(v, uncertain=True) for k, v in env.items()})
            result = combine(args + list(kwargs.values()))
            result.uncertain = True
            return result
        return Value(uncertain=True)

    def import_ref(module, filename, level=0):
        parts = filename.split('/')[:-1] if level else []
        if level > 1:
            parts = parts[:max(0, len(parts) - level + 1)]
        candidate = '/'.join(parts + module.split('.')) + '.py'
        return candidate if candidate in modules else module

    def statements(nodes, env, filename, depth):
        for node in nodes:
            if budget[0] < 0:
                return Value(uncertain=True)
            if isinstance(node, ast.Import):
                for name in node.names:
                    env[name.asname or name.name.split('.')[0]] = Value(ref='module:' + import_ref(name.name, filename))
            elif isinstance(node, ast.ImportFrom) and node.module:
                module = import_ref(node.module, filename, node.level)
                for name in node.names:
                    env[name.asname or name.name] = Value(ref=module + ':' + name.name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                env[node.name] = Value(ref=f'{filename}:{node.name}')
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = expr(node.value, env, filename, depth) if node.value else Value(uncertain=True)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = replace(value, steps=(value.steps + [location(filename, node, 'assignment')])[-12:])
                    else:
                        # Mutation/unpacking: invalidate all bound values conservatively.
                        limits.add(f'{filename}:{node.lineno}: mutation or unpacking unresolved')
                        env.update({k: Value(uncertain=True) for k in env})
            elif isinstance(node, ast.Expr):
                expr(node.value, env, filename, depth)
            elif isinstance(node, ast.Return):
                return expr(node.value, env, filename, depth) if node.value else Value(known=True)
            elif isinstance(node, ast.Raise):
                if node.exc:
                    expr(node.exc, env, filename, depth)
                return Value(uncertain=True)
            elif isinstance(node, ast.If):
                test = node.test
                guard = (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
                         and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotIn)
                         and len(node.body) == 1 and isinstance(node.body[0], (ast.Raise, ast.Return))
                         and not node.orelse and isinstance(test.comparators[0], (ast.Tuple, ast.List, ast.Set, ast.Name)))
                choices = expr(test.comparators[0], env, filename, depth) if guard else Value()
                if guard:
                    exit_node = node.body[0]
                    if isinstance(exit_node, ast.Return):
                        guard = exit_node.value is None or isinstance(exit_node.value, ast.Constant)
                    else:
                        guard = (isinstance(exit_node.exc, ast.Call) and isinstance(exit_node.exc.func, ast.Name)
                                 and exit_node.exc.func.id in {'ValueError', 'TypeError', 'PermissionError'}
                                 and all(isinstance(a, ast.Constant) for a in exit_node.exc.args)
                                 and not exit_node.exc.keywords)
                if choices.mapping is not None:
                    choices = Value(literal=list(choices.mapping), known=True)
                if guard and choices.known and isinstance(choices.literal, list) and all(isinstance(v, str) for v in choices.literal):
                    value = env.get(test.left.id, Value(uncertain=True))
                    fact = {**location(filename, node, 'reject-unless-member'), 'values': choices.literal[:20],
                            'truncated': len(choices.literal) > 20,
                            'note': 'Membership restriction only; allowed strings may themselves be dangerous.'}
                    env[test.left.id] = replace(value, guards=value.guards + [fact])
                    if fact not in restrictions and len(restrictions) < 40:
                        restrictions.append(fact)
                else:
                    limits.add(f'{filename}:{node.lineno}: control flow unresolved')
                    uncertain_env = {k: replace(v, uncertain=True) for k, v in env.items()}
                    statements(node.body, dict(uncertain_env), filename, depth)
                    statements(node.orelse, dict(uncertain_env), filename, depth)
                    env.update({k: Value(uncertain=True) for k in env})
            else:
                limits.add(f'{filename}:{getattr(node, "lineno", 1)}: unsupported statement')
                env.update({k: Value(uncertain=True) for k in env})
        return Value(uncertain=True)

    for filename, tree in modules.items():
        env = {}
        globals_by_file[filename] = env
        # Module initialization gives bindings, not knowledge of later mutation.
        statements(tree.body, env, filename, 0)
    for ref, (filename, function) in functions.items():
        if function.decorator_list:
            limits.add(f'{ref}: decorated function not traced independently')
            continue
        env = dict(globals_by_file[filename])
        for param in function.args.posonlyargs + function.args.args + function.args.kwonlyargs:
            env[param.arg] = Value(origins=[f'{ref}.{param.arg}'],
                                   steps=[location(filename, function, 'parameter; trust unknown')])
        active.add(ref)
        statements(function.body, env, filename, 0)
        active.remove(ref)
    return {'paths': paths, 'restrictions': restrictions, 'limitations': sorted(limits)[:40],
            'scope': 'Bounded syntactic paths; no reachability, caller trust, mutation or exploitability proof.'}

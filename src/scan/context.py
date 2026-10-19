"""Bounded, syntactic review context. Never imports or executes scanned code."""
from __future__ import annotations

import ast
import json
import tokenize
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SourceBlock:
    path: Path
    file_id: str
    start: int
    lines: list[str]

    def payload(self):
        return {"file": self.file_id, "start_line": self.start,
                "source": "\n".join(f"{i}: {s}" for i, s in enumerate(self.lines, self.start))}


@dataclass
class ReviewContext:
    blocks: list[SourceBlock]
    leads: list[dict] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    @property
    def file_ids(self):
        return list(dict.fromkeys(block.file_id for block in self.blocks))

    def render(self):
        return json.dumps({"primary_file": self.blocks[0].file_id,
                           "sources": [b.payload() for b in self.blocks],
                           "static_leads": self.leads, "context_limits": self.limitations},
                          ensure_ascii=True)


def build_context(target: Path, path: Path, lines: list[str], start: int,
                  chunk_lines: list[str], findings=(), max_chars: int = 12000) -> ReviewContext:
    """Add enclosing functions and one-hop local imports within a source budget.

    For a file target, only its parent directory is eligible. Imports are candidate
    context, not resolved runtime bindings or proof of a data-flow edge. Whole
    helper modules preserve guards and globals; oversized helpers are omitted.
    """
    display_root = target if target.is_dir() else target.parent
    root = display_root.resolve()
    primary = path.resolve()
    file_id = primary.relative_to(root).as_posix()
    result = ReviewContext([SourceBlock(path, file_id, start, chunk_lines)])
    end = start + len(chunk_lines) - 1
    result.leads = [{"file": file_id, "line": f.line, "end_line": f.end_line,
                     "rule_id": f.rule_id, "category": f.category}
                    for f in findings if Path(f.file).resolve() == primary
                    and f.line <= end and (f.end_line or f.line) >= start]
    remaining = max_chars

    def add(block):
        nonlocal remaining
        cost = len(json.dumps(block.payload(), ensure_ascii=True))
        if cost > remaining:
            result.limitations.append(f"Context budget omitted {block.file_id}:{block.start}.")
            return False
        result.blocks.append(block)
        remaining -= cost
        return True

    try:
        tree = ast.parse("\n".join(lines))
    except (SyntaxError, ValueError, RecursionError):
        result.limitations.append("Primary source could not be parsed; only the primary chunk is available.")
        return result
    # Add complete enclosing functions when the primary chunk cuts them, including
    # decorators. Do not silently truncate a function and hide its checks.
    functions = sorted((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
                       key=lambda n: n.lineno)
    spans = []
    for node in functions:
        first = min([node.lineno] + [d.lineno for d in node.decorator_list])
        last = node.end_lineno
        if first <= end and last >= start and not (start <= first and last <= end):
            if not any(a <= first and last <= b for a, b in spans):
                if add(SourceBlock(path, file_id, first, lines[first - 1:last])):
                    spans.append((first, last))
    visible = [(start, end)] + spans
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
            and any(a <= n.lineno <= b for a, b in visible)}
    candidates = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if (alias.asname or alias.name.split('.')[0]) in used:
                    candidates.append((root, alias.name.split('.')))
        elif isinstance(node, ast.ImportFrom):
            if not any((a.asname or a.name) in used for a in node.names):
                continue
            base = primary.parent if node.level else root
            for _ in range(max(0, node.level - 1)):
                base = base.parent
            parts = node.module.split('.') if node.module else []
            candidates.append((base, parts))
            # `from . import worker` and `from package import worker`.
            for alias in node.names:
                if (alias.asname or alias.name) in used:
                    candidates.append((base, parts + [alias.name]))
    seen = {primary}
    for base, parts in candidates:
        module = base.joinpath(*parts)
        for candidate in (module.with_suffix('.py'), module / '__init__.py'):
            resolved = candidate.resolve()
            if not resolved.is_relative_to(root) or resolved in seen:
                continue
            # Reject symlinked components even when their destination is in root.
            if any(p.is_symlink() for p in (candidate, *candidate.parents)):
                continue
            if not candidate.is_file():
                continue
            seen.add(resolved)
            name = resolved.relative_to(root).as_posix()
            try:
                if candidate.stat().st_size > max_chars * 4:
                    result.limitations.append(f"Oversized helper omitted: {name}.")
                    break
                with tokenize.open(candidate) as source:
                    text = source.read(max_chars + 1)
                if len(text) > max_chars:
                    result.limitations.append(f"Oversized helper omitted: {name}.")
                    break
                add(SourceBlock(display_root / name, name, 1, text.splitlines()))
            except (OSError, UnicodeError, SyntaxError):
                result.limitations.append(f"Unreadable helper omitted: {name}.")
            break
    result.limitations.append("Only one-hop local imports are included; runtime bindings, external modules, "
                              "dynamic imports and the complete call graph are not resolved.")
    # Also expose leads in helper/enclosing blocks, without duplicating leads
    # where a complete function overlaps the primary chunk.
    for block in result.blocks[1:]:
        for finding in findings:
            if (Path(finding.file).resolve() == block.path.resolve()
                    and finding.line <= block.start + len(block.lines) - 1
                    and (finding.end_line or finding.line) >= block.start):
                lead = {"file": block.file_id, "line": finding.line, "end_line": finding.end_line,
                        "rule_id": finding.rule_id, "category": finding.category}
                if lead not in result.leads:
                    result.leads.append(lead)
    return result

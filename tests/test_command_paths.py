import ast
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner
from scan.cli import main
from scan.command_paths import trace_commands
from scan.context import SourceBlock, ReviewContext
from scan.llm import Chunk, ReviewClient
from benchmarks.command_cases import CASES
from benchmarks.cases import expected_line


def trace(source, **options):
    files = {'app.py': source} if isinstance(source, str) else source
    return trace_commands([SourceBlock(Path(name), name, 1, text.splitlines())
                           for name, text in files.items()], **options)


class CommandPathTests(unittest.TestCase):
    def test_assignment_overwrite(self):
        case = next(c for c in CASES if c['id'] == 'assignment')
        before, after = (trace(case[v]) for v in ('before', 'after'))
        self.assertEqual(before['paths'][0]['status'], 'parameter-to-shell')
        self.assertEqual(before['paths'][0]['attacker_control'], 'not-established')
        self.assertEqual(after['paths'][0]['status'], 'constant-shell-command')
        self.assertEqual(after['paths'][0]['origins'], [])

    def test_guard_reassignment(self):
        case = next(c for c in CASES if c['id'] == 'guard_then_overwrite')
        before, after = (trace(case[v]) for v in ('before', 'after'))
        self.assertEqual(before['paths'][0]['observed_guards'], [])
        self.assertEqual(len(after['paths'][0]['observed_guards']), 1)
        self.assertIn('replacement', before['paths'][0]['origins'][0])

    def test_cross_file_argument_flow(self):
        result = trace(CASES[-1]['before'])
        paths = [p for p in result['paths'] if any('app.py:run.value' in o for o in p['origins'])]
        self.assertTrue(paths)
        self.assertEqual(paths[0]['file'], 'worker.py')
        self.assertEqual(paths[0]['line'], expected_line(CASES[-1]))
        self.assertTrue(any('argument ->' in step['kind'] for step in paths[0]['steps']))

    def test_return_flow_and_constants(self):
        case = next(c for c in CASES if c['id'] == 'helper_return')
        self.assertEqual(trace(case['before'])['paths'][0]['status'], 'parameter-to-shell')
        self.assertEqual(trace(case['after'])['paths'][0]['status'], 'constant-shell-command')

    def test_shell_modes_and_shadowed_import(self):
        source = 'import subprocess as p\ndef run(x):\n    p.run(["echo", x], shell=False)\n'
        self.assertEqual(trace(source)['paths'][0]['status'], 'no-shell')
        unknown = source.replace('shell=False', 'shell=x')
        self.assertEqual(trace(unknown)['paths'][0]['status'], 'unresolved')
        shadowed = source.replace('def run(x):', 'def run(x, p):')
        self.assertEqual(trace(shadowed)['paths'], [])
        self.assertTrue(trace(shadowed)['limitations'])

    def test_mapping_is_observation_not_proof(self):
        result = trace(CASES[-1]['after'])
        self.assertEqual(result['paths'], [])
        self.assertTrue(any(r['kind'] == 'literal-mapping-selection' for r in result['restrictions']))
        self.assertTrue(result['limitations'])

    def test_unknown_call_invalidates_certainty(self):
        source = 'import os\ndef run(x):\n    unknown()\n    os.system(x)\n'
        self.assertEqual(trace(source)['paths'][0]['status'], 'unresolved')

    def test_branch_and_recursion_are_not_proven_safe(self):
        source = 'import os\ndef run(x):\n    if x:\n        x = "pwd"\n    os.system(x)\n'
        self.assertTrue(trace(source)['limitations'])
        recursive = 'def recurse(x):\n    return recurse(x)\n'
        self.assertTrue(trace(recursive)['limitations'])

    def test_partial_source_and_budgets(self):
        block = SourceBlock(Path('app.py'), 'app.py', 5, ['import os', 'os.system(value)'])
        result = trace_commands([block])
        self.assertEqual(result['paths'], [])
        self.assertTrue(result['limitations'])
        source = 'import os\nos.system("pwd")\nos.system("whoami")\n'
        self.assertEqual(len(trace(source, max_paths=1)['paths']), 1)
        self.assertIn('path budget exhausted', trace(source, max_paths=1)['limitations'])

    def test_return_call_is_not_a_rejecting_guard(self):
        source = 'import os\ndef run(x):\n    if x not in ("pwd",):\n        return os.system(x)\n    return os.system(x)\n'
        result = trace(source)
        self.assertEqual(result['restrictions'], [])
        self.assertTrue(result['limitations'])

    def test_all_eight_pairs_parse_and_trace_vulnerable_sink(self):
        self.assertEqual(len(CASES), 8)
        for case in CASES:
            with self.subTest(case=case['id']):
                for variant in ('before', 'after'):
                    for code in case[variant].values():
                        ast.parse(code)
                result = trace(case['before'])
                self.assertTrue(any(p['file'] == case['expected_file'] and p['line'] == expected_line(case)
                                    and p['status'] == 'parameter-to-shell' for p in result['paths']), result)

    def test_opt_in_prompt_and_cli(self):
        block = SourceBlock(Path('app.py'), 'app.py', 1, ['import os', 'os.system("pwd")'])
        context = ReviewContext([block])
        self.assertNotIn('command_paths', json.loads(context.render()))
        context.command_paths = trace_commands([block])
        client = ReviewClient('http://localhost:11434/v1', 'test')
        self.addCleanup(client.close)
        response = Mock(choices=[Mock(finish_reason='stop', message=Mock(content='{"findings": []}', refusal=None))])
        with patch.object(client.client.chat.completions, 'create', return_value=response) as create:
            client.review(Chunk(1, block.lines, context))
        self.assertIn('not vulnerability verdicts', create.call_args.kwargs['messages'][0]['content'])
        self.assertIn('command_paths', create.call_args.kwargs['messages'][1]['content'])
        for mode in ('--llm-only', '--static-only'):
            result = CliRunner().invoke(main, ['scan', 'app.py', mode, '--command-paths'])
            self.assertEqual(result.exit_code, 2)

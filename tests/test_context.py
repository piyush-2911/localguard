import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner
from scan.cli import main
from scan.context import build_context
from scan.llm import Chunk, ReviewClient, parse_review, scan_llm
from scan.models import Finding, Severity
from scan.merge import merge_findings
from scan.report import render_text, render_markdown
from scan.structured import response_format, validate_response


def issue(**changes):
    return dict({"file": "worker.py", "line": 3, "end_line": None,
                 "severity": "high", "category": "command-injection",
                 "description": "Attacker-controlled value reaches a shell.",
                 "recommendation": "Use a fixed executable and argument list with shell=False.",
                 "evidence": "    return os.system(value)"}, **changes)


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / 'app.py'
        self.app.write_text('from worker import perform\ndef handle(value):\n    return perform(value)\n')
        (self.root / 'worker.py').write_text('import os\ndef perform(value):\n    return os.system(value)\n')

    def context(self, **kwargs):
        lines = self.app.read_text().splitlines()
        return build_context(self.root, self.app, lines, 1, lines, **kwargs)

    def test_local_helper_and_grounding(self):
        context = self.context()
        self.assertEqual(context.file_ids, ['app.py', 'worker.py'])
        result = parse_review(json.dumps([issue(line=99)]), self.app, Chunk(1, [], context))
        self.assertEqual((result[0].file, result[0].line), (str(self.root / 'worker.py'), 3))
        for name in ('app.py', '../worker.py', str(self.root / 'worker.py'), None):
            self.assertEqual(parse_review(json.dumps([issue(file=name)]), self.app, Chunk(1, [], context)), [])

    def test_unknown_and_outside_shown_evidence(self):
        context = self.context(max_chars=0)
        self.assertEqual(context.file_ids, ['app.py'])
        self.assertEqual(parse_review(json.dumps([issue()]), self.app, Chunk(1, [], context)), [])
        self.assertTrue(context.limitations)

    def test_enclosing_function_keeps_guard(self):
        lines = ['def handle(value):', '    if value not in {"cwd"}:',
                 '        raise ValueError(value)', '    return perform(value)']
        context = build_context(self.root, self.app, lines, 4, lines[3:])
        self.assertEqual(context.blocks[1].lines, lines)
        context = build_context(self.root, self.app, lines, 4, lines[3:], max_chars=10)
        self.assertEqual(len(context.blocks), 1)
        self.assertIn('budget', context.limitations[0])

    def test_relative_alias_and_one_hop(self):
        self.app.write_text('from . import worker as w\nw.perform(value)\n')
        (self.root / 'worker.py').write_text('import deep\ndef perform(value):\n    return deep.run(value)\n')
        (self.root / 'deep.py').write_text('DO_NOT_INCLUDE = True\n')
        context = self.context()
        self.assertEqual(context.file_ids, ['app.py', 'worker.py'])
        self.assertNotIn('DO_NOT_INCLUDE', context.render())

    def test_escape_is_not_read(self):
        self.app.write_text('from .. import outside\noutside.run(value)\n')
        with patch('scan.context.tokenize.open', side_effect=AssertionError('unexpected read')):
            self.assertEqual(self.context().file_ids, ['app.py'])

    def test_symlink_is_not_read(self):
        link = self.root / 'linked.py'
        try:
            link.symlink_to(self.root / 'worker.py')
        except OSError:
            self.skipTest('Symlink privilege unavailable')
        self.app.write_text('import linked\nlinked.perform(value)\n')
        self.assertEqual(self.context().file_ids, ['app.py'])

    def test_syntax_error_still_reviews_primary(self):
        self.app.write_text('def broken(:\n')
        self.assertEqual(self.context().file_ids, ['app.py'])

    def test_unused_import_and_budget(self):
        self.app.write_text('import worker\nx = 1\n')
        self.assertEqual(self.context().file_ids, ['app.py'])
        self.app.write_text('import worker\nworker.perform(value)\n')
        context = self.context(max_chars=200)
        self.assertLessEqual(sum(len(json.dumps(b.payload(), ensure_ascii=True))
                                 for b in context.blocks[1:]), 200)

    def test_helper_lead_and_merge(self):
        finding = Finding(str(self.root / 'worker.py'), 3, Severity.HIGH,
                          'command-injection', 'Static issue', 'Static fix', 'B605')
        context = self.context(findings=[finding])
        self.assertEqual(context.leads[0]['file'], 'worker.py')
        parsed = parse_review(json.dumps([issue()]), self.app, Chunk(1, [], context))
        merged = merge_findings([finding], parsed)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].source, 'static+llm')

    def test_context_limits_reported_in_text_and_markdown(self):
        client = Mock(model='test')
        client.review.return_value = '[]'
        coverage = {}
        scan_llm(self.app, client, static_findings=[], context_chars=0, coverage=coverage)
        for render in (render_text, render_markdown):
            result = render([], 1, str(self.app), metadata={'llm_coverage': coverage})
            self.assertIn('Context limitation:', result)
            self.assertIn('Static leads', result)

    def test_schema_files_and_legacy_unchanged(self):
        schema = response_format(['app.py', 'worker.py'])
        fields = schema['json_schema']['schema']['properties']['findings']['items']
        self.assertIn('file', fields['required'])
        self.assertNotIn('file', response_format()['json_schema']['schema']['properties']['findings']['items']['required'])
        validate_response(json.dumps({'findings': [issue()]}), 5, ['worker.py'])
        for bad in (issue(file='../worker.py'), {k: v for k, v in issue().items() if k != 'file'}):
            with self.assertRaises(ValueError):
                validate_response(json.dumps({'findings': [bad]}), 5, ['worker.py'])

    def test_client_transmits_context_and_validates_file(self):
        client = ReviewClient('http://localhost:11434/v1', 'test')
        self.addCleanup(client.close)
        response = Mock()
        response.choices = [Mock(finish_reason='stop', message=Mock(content=json.dumps({'findings': [issue()]}), refusal=None))]
        with patch.object(client.client.chat.completions, 'create', return_value=response) as create:
            client.review(Chunk(1, self.app.read_text().splitlines(), self.context()))
        payload = create.call_args.kwargs
        self.assertIn('worker.py', payload['messages'][1]['content'])
        self.assertIn('not proof', payload['messages'][0]['content'])
        self.assertIn('file', payload['response_format']['json_schema']['schema']['properties']['findings']['items']['required'])

    def test_scanner_single_call_and_legacy_mode(self):
        client = Mock(model='test')
        client.review.return_value = json.dumps({'findings': [issue()]})
        coverage = {}
        results, count = scan_llm(self.app, client, static_findings=[], coverage=coverage)
        self.assertEqual((len(results), count, client.review.call_count), (1, 1, 1))
        self.assertEqual(results[0].file, str(self.root / 'worker.py'))
        self.assertIn('context', coverage)
        client.reset_mock()
        client.review.return_value = '[]'
        scan_llm(self.app, client)
        self.assertIsNone(client.review.call_args.args[0].context)

    def test_bandit_leads_passed_and_never_removed(self):
        finding = Finding(str(self.app), 3, Severity.HIGH, 'command-injection',
                          'Static issue', 'Static fix', 'B602')
        context = self.context(findings=[finding])
        self.assertEqual(context.leads[0]['rule_id'], 'B602')
        with patch('scan.cli.scan', return_value=([finding], 1)), patch('scan.llm.ReviewClient'), \
                patch('scan.llm.scan_llm', return_value=([], 1)) as review:
            result = CliRunner().invoke(main, ['scan', str(self.app), '--format', 'json'])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(review.call_args.kwargs['static_findings'], [finding])
        self.assertEqual(json.loads(result.stdout)['findings'][0]['source'], 'static')


if __name__ == '__main__':
    unittest.main()

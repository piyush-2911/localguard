import ast
import json
import unittest
from unittest.mock import Mock, patch

from benchmarks.cases import CASES, expected_line
from benchmarks.run import evaluate, score, summarize
from scan.models import Finding, Severity


class BenchmarkTests(unittest.TestCase):
    def test_corpus_is_paired_and_parseable(self):
        self.assertEqual(len(CASES), 12)
        self.assertEqual(len({c['id'] for c in CASES}), 12)
        for case in CASES:
            self.assertGreater(expected_line(case), 0)
            self.assertNotEqual(case['before'], case['after'])
            self.assertEqual(set(case['before']), set(case['after']))
            for variant in ('before', 'after'):
                for source in case[variant].values():
                    ast.parse(source)
                    self.assertNotIn('#', source)

    def test_incomplete_empty_is_not_clean(self):
        result = score(CASES[0], 'after', [], False)
        self.assertFalse(result['clean_fixed_case'])
        records = [dict(case='sql', variant='after', repeat=0, model='test',
                        llm_score=result, elapsed_seconds=1)]
        metrics = summarize(records)['test']['llm_score']
        self.assertEqual(metrics['incomplete_runs'], 1)
        self.assertEqual(metrics['clean_fixed_runs'], 0)

    def test_matching_requires_file_category_and_location(self):
        case = CASES[-1]
        good = dict(file='worker.py', line=expected_line(case), category=case['category'])
        self.assertTrue(score(case, 'before', [good], True)['expected_issue_exact'])
        for bad in (dict(good, file='app.py'), dict(good, category='other'), dict(good, line=99)):
            self.assertFalse(score(case, 'before', [bad], True)['expected_issue_within_3'])

    def test_pair_requires_successful_detection_and_clean_fixed(self):
        case = CASES[0]
        finding = dict(file='app.py', line=expected_line(case), category=case['category'])
        records = [dict(case=case['id'], variant=v, repeat=0, model='test', elapsed_seconds=1,
                        llm_score=score(case, v, [finding] if v == 'before' else [], True))
                   for v in ('before', 'after')]
        self.assertEqual(summarize(records)['test']['llm_score']['successful_pairs'], 1)
        records[1]['llm_score']['clean_fixed_case'] = False
        self.assertEqual(summarize(records)['test']['llm_score']['successful_pairs'], 0)

    def test_static_hit_cannot_hide_llm_miss(self):
        case = CASES[0]

        def static(target):
            return [Finding(str(target / 'app.py'), expected_line(case), Severity.HIGH,
                            case['category'], 'Static explanation', 'Bind parameters', 'B608')], 1

        with patch('benchmarks.run.scan', side_effect=static), \
                patch('benchmarks.run.ReviewClient', return_value=Mock()), \
                patch('benchmarks.run.scan_llm', return_value=([], 1)):
            result = evaluate(case, 'before', 'test', {}, 'secret-test-key')
        self.assertIsNone(result['error'])
        self.assertTrue(result['combined_score']['expected_issue_exact'])
        self.assertFalse(result['llm_score']['expected_issue_exact'])
        self.assertNotIn('secret-test-key', json.dumps(result))

    def test_llm_failure_cannot_be_scored_as_clean(self):
        with patch('benchmarks.run.scan', return_value=([], 1)), \
                patch('benchmarks.run.ReviewClient', side_effect=RuntimeError('offline')):
            result = evaluate(CASES[0], 'after', 'test', {}, 'unused')
        self.assertFalse(result['llm_score']['clean_fixed_case'])
        self.assertFalse(result['combined_score']['complete'])

    def test_capture_contains_source_but_not_answers_or_key(self):
        response = Mock()
        response.choices = [Mock(finish_reason='stop', message=Mock(content='{"findings": []}', refusal=None))]
        response.model_dump.return_value = {'choices': [{'message': {'content': '{"findings": []}'}}]}
        sdk = Mock()
        sdk.chat.completions.create.return_value = response
        settings = dict(base_url='http://localhost:11434/v1', model='test')
        case = CASES[-1]
        with patch('benchmarks.run.scan', return_value=([], 2)), patch('scan.llm.OpenAI', return_value=sdk):
            result = evaluate(case, 'after', 'test', settings, 'private-test-key')
        self.assertIsNone(result['error'])
        self.assertEqual(len(result['raw_calls']), 2)
        for call in result['raw_calls']:
            payload = json.dumps(call['request'])
            self.assertNotIn(case['review_note'], payload)
            self.assertNotIn('helper_dispatch', payload)
            self.assertNotIn('private-test-key', payload)
            self.assertEqual(call['request']['temperature'], 0)
            self.assertIn('response', call)


if __name__ == '__main__':
    unittest.main()

"""Run from the repository root: python -m benchmarks.run --help."""
import argparse
import hashlib
import io
import json
import logging
import os
import tempfile
import time
from pathlib import Path

from .cases import CASES, expected_line
from scan.hybrid import run_hybrid
from scan.llm import ReviewClient, scan_llm
from scan.scanner import scan

ROOT = Path(__file__).resolve().parents[1]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def score(case, variant, findings, complete):
    expected = expected_line(case)
    matches = [f for f in findings if f['category'] == case['category']
               and f['file'] == case['expected_file']]
    exact = any(f['line'] <= expected <= (f.get('end_line') or f['line']) for f in matches)
    nearby = any(abs(f['line'] - expected) <= 3 or
                 f['line'] <= expected <= (f.get('end_line') or f['line']) for f in matches)
    return {'complete': complete, 'findings': len(findings),
            'expected_issue_exact': exact if variant == 'before' else None,
            'expected_issue_within_3': nearby if variant == 'before' else None,
            'fixed_case_alarms': len(findings) if variant == 'after' else None,
            'clean_fixed_case': complete and not findings if variant == 'after' else None}


def evaluate(case, variant, model, settings, api_key, command_paths=False):
    coverage, static, raw_llm, captures, warnings = {}, [], [], [], []
    log = io.StringIO()
    handler = logging.StreamHandler(log)
    logger = logging.getLogger('scan.llm')
    logger.addHandler(handler)
    started = time.perf_counter()
    record = {'case': case['id'], 'variant': variant, 'model': model,
              'findings': [], 'llm_findings': [], 'raw_calls': captures, 'error': None}
    try:
        # Both variants use identical anonymous paths; no labels enter requests.
        with tempfile.TemporaryDirectory(prefix='scan-benchmark-') as directory:
            target = Path(directory)
            for filename, source in case[variant].items():
                (target / filename).write_text(source, encoding='utf-8')

            def static_scan():
                result, count = scan(target)
                static.extend(result)
                return result, count

            def llm_scan():
                client = ReviewClient(api_key=api_key, **settings)
                create = client.client.chat.completions.create

                def capture(**payload):
                    payload['temperature'] = 0
                    call = {'request': payload}
                    captures.append(call)
                    response = create(**payload)
                    call['response'] = response.model_dump(mode='json')
                    return response

                client.client.chat.completions.create = capture
                try:
                    findings, count = scan_llm(target, client, static_findings=static, coverage=coverage,
                                               command_paths=command_paths)
                    raw_llm.extend(findings)
                    return findings, count
                finally:
                    client.close()

            if model is None:
                findings, _ = static_scan()
                metadata = {'analyzers': {'static': 'available'}}
            else:
                findings, _, metadata = run_hybrid(static_scan, llm_scan, warning=warnings.append)
            record['metadata'] = metadata
            for finding in findings:
                value = finding.to_dict()
                value['file'] = Path(value['file']).relative_to(target).as_posix()
                record['findings'].append(value)
            for finding in raw_llm:
                value = finding.to_dict()
                value['file'] = Path(value['file']).relative_to(target).as_posix()
                record['llm_findings'].append(value)
    except Exception as exc:
        # Failed runs are retained, never scored as successful clean reviews.
        record['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        logger.removeHandler(handler)
        handler.close()
    record.update(elapsed_seconds=round(time.perf_counter() - started, 3), coverage=coverage,
                  warnings=warnings, log=log.getvalue())
    available = record.get('metadata', {}).get('analyzers', {})
    complete = not record['error'] and not coverage.get('issues') and all(
        state == 'available' for state in available.values())
    record['combined_score'] = score(case, variant, record['findings'], complete)
    if model:
        record['llm_score'] = score(case, variant, record['llm_findings'],
                                  complete and available.get('llm') == 'available')
    record['manual_review'] = [dict(finding_index=i, diagnosis_correct=None,
                                    recommendation_correct=None, notes='')
                               for i, f in enumerate(record['llm_findings'])]
    return record


def summarize(records):
    summary = {}
    for model in dict.fromkeys(r['model'] or 'static-only' for r in records):
        runs = [r for r in records if (r['model'] or 'static-only') == model]
        groups = {}
        for key in ('combined_score', 'llm_score'):
            selected = [r for r in runs if key in r]
            if not selected:
                continue
            before = [r for r in selected if r['variant'] == 'before']
            after = [r for r in selected if r['variant'] == 'after']
            pairs = {(r['case'], r['repeat']): r for r in after}
            groups[key] = {
                'runs': len(selected), 'incomplete_runs': sum(not r[key]['complete'] for r in selected),
                'vulnerable_runs': len(before),
                'exact_hits': sum(r[key]['expected_issue_exact'] for r in before),
                'nearby_hits': sum(r[key]['expected_issue_within_3'] for r in before),
                'fixed_runs': len(after),
                'fixed_runs_with_alarms': sum(r[key]['fixed_case_alarms'] > 0 for r in after),
                'clean_fixed_runs': sum(r[key]['clean_fixed_case'] for r in after),
                'successful_pairs': sum(r[key]['complete'] and r[key]['expected_issue_within_3']
                                        and pairs.get((r['case'], r['repeat']), {}).get(key, {}).get('clean_fixed_case', False)
                                        for r in before)}
        summary[model] = {**groups, 'elapsed_seconds': round(sum(r['elapsed_seconds'] for r in runs), 2),
                          'semantic_review': 'Manual diagnosis and recommendation assessment required; location hits are proxies.'}
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--static-only', action='store_true')
    mode.add_argument('--model', action='append', help='Repeat to compare models served at the same URL.')
    parser.add_argument('--base-url', default=os.environ.get('SCAN_BASE_URL', 'http://localhost:11434/v1'))
    parser.add_argument('--timeout', type=float, default=600)
    parser.add_argument('--max-tokens', type=int, default=1024)
    parser.add_argument('--max-findings', type=int, default=3)
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--suite', choices=['general', 'commands'], default='general')
    parser.add_argument('--command-paths', action='store_true')
    parser.add_argument('--case', action='append')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.suite == 'commands':
        from .command_cases import CASES as cases_available
    else:
        cases_available = CASES
    if args.case and set(args.case) - {c['id'] for c in cases_available}:
        parser.error('Unknown case for the selected suite')
    if args.repeat < 1:
        parser.error('--repeat must be positive')
    args.output.mkdir(parents=True, exist_ok=True)
    code = {str(p.relative_to(ROOT)): p.read_text(encoding='utf-8')
            for folder in ('benchmarks', 'src/scan') for p in (ROOT / folder).glob('*.py')}
    records = []
    for repeat in range(args.repeat):
        cases = [c for c in cases_available if not args.case or c['id'] in args.case]
        for case in (cases if repeat % 2 == 0 else list(reversed(cases))):
            for model in args.model or [None]:
                settings = dict(base_url=args.base_url, model=model, timeout=args.timeout,
                                max_tokens=args.max_tokens, max_findings=args.max_findings,
                                structured_output='required')
                for variant in ('before', 'after') if repeat % 2 == 0 else ('after', 'before'):
                    fingerprint = digest(dict(case=case, variant=variant, settings=settings, code=code,
                                              temperature=0, repeat=repeat, command_paths=args.command_paths))
                    path = args.output / f"{case['id']}-{variant}-{digest(model)[:12]}-{repeat}.json"
                    if path.exists():
                        record = json.loads(path.read_text(encoding='utf-8'))
                        if record['fingerprint'] != fingerprint:
                            raise SystemExit(f'Inputs changed: use a new output directory ({path}).')
                    else:
                        print(f"Running {case['id']} {variant}: {model or 'Bandit'}", flush=True)
                        record = evaluate(case, variant, model, settings, os.environ.get('SCAN_API_KEY', 'not-needed'),
                                          command_paths=args.command_paths)
                        record.update(fingerprint=fingerprint, repeat=repeat, settings=settings,
                                      command_paths=args.command_paths, suite=args.suite)
                        path.write_text(json.dumps(record, indent=2), encoding='utf-8')
                    records.append(record)
                    (args.output / 'summary.json').write_text(json.dumps(summarize(records), indent=2), encoding='utf-8')
    print(json.dumps(summarize(records), indent=2))


if __name__ == '__main__':
    main()

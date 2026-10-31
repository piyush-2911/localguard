# Initial Bandit baseline

Run on 2026-10-19 using the workspace virtual environment and the 12 paired
fixtures in `cases.py`. Command from the repository root:

```powershell
python -m benchmarks.run --static-only --output benchmark-results/bandit
```

| Metric | Result |
|---|---:|
| Programs reviewed | 24 |
| Incomplete runs | 0 |
| Vulnerable cases with expected category/file/line hit | 10 / 12 |
| Fixed cases with no alarms | 11 / 12 |
| Successful vulnerable/fixed pairs | 9 / 12 |
| Total elapsed time | 13.24 seconds |

Bandit missed the ownership-check and path-traversal examples. It raised B404
(subprocess import) and B603 (review subprocess inputs) on the repaired shell
example, even though the input is parsed as an IP address and passed as an
argument with `shell=False`. These are conservative static warnings, not evidence
that the repair still has shell injection.

This is a development baseline on small synthetic fixtures, not a general
precision/recall claim. A location hit does not establish that a diagnosis or fix
is correct. No model comparison has been run on the full new corpus yet.
Machine-readable per-case output and fingerprints remain in the local ignored
`benchmark-results/bandit/` directory.

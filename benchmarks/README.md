# Paired regression benchmark

Twelve handwritten vulnerable/fixed pairs (24 programs) cover SQL, shell and code
injection, pickle/YAML deserialization, password hashing, TLS, embedded secrets,
path traversal, ownership checks, temporary-file races and cross-file dispatch.
Fixtures have no explanatory comments and are parsed/scanned, never executed.
This is a small development regression set, not evidence of production accuracy.

Run from the repository root in the installed scanner environment:

```powershell
python -m benchmarks.run --static-only --output benchmark-results/bandit
python -m benchmarks.run --model llama3.1:latest --output benchmark-results/llama31
```

Start with a small subset before spending time on CPU inference:

```powershell
python -m benchmarks.run --model llama3.1:latest --case sql --case helper_dispatch --output benchmark-results/smoke
```

Compare two already installed models at the same OpenAI-compatible endpoint:

```powershell
python -m benchmarks.run --model llama3.1:latest --model YOUR_SECOND_MODEL --repeat 2 --output benchmark-results/comparison
```

Use `--base-url`, `--timeout`, `--max-tokens`, and `--max-findings` to configure
requests. API keys come only from `SCAN_API_KEY`; this harness reads process
environment variables, not `.env`. Defaults: local Ollama, 600s, 1024 output
tokens, three findings per chunk, required schema, temperature 0. Scanner chunk
and context defaults are unchanged. Every model receives the same source,
Bandit leads, prompt and limits. There is no extra verification pass. Providers
can still produce nondeterministic results at temperature 0. Runs are sequential;
repeat 2 reverses case and before/after order. Model ordering is not randomized.

Answers, case IDs, before/after labels, anchor locations and `review_note` never
enter model requests. Both variants are materialized into anonymous temporary
directories with matching file names. The notes document ground-truth assumptions
for human assessors; findings should acknowledge conditions not established by
the source (e.g. attacker control or document privacy). Flag disputable labels
instead of silently treating a matched category as a correct diagnosis.

Each result preserves raw request/response bodies (without SDK authorization
headers), validated LLM findings **before merging**, combined findings, warnings,
coverage, runtime and a fingerprint of code, fixtures and settings. Results resume
only when fingerprints match. Failed runs remain failures; use a fresh directory
for a rerun. `summary.json` describes the runs selected by the current invocation.
Use a fresh output directory for each comparison and retain model version/digest,
server version and hardware alongside it; a model tag alone is not immutable.

## Reading results

- `exact_hits` / `nearby_hits`: expected file/category and exact line or within
  three lines, respectively. These are location proxies, **not semantic accuracy**.
- `fixed_runs_with_alarms`: repaired cases with findings. Inspect them: static
  rules sometimes intentionally flag risk patterns in protected code.
- `clean_fixed_runs`: completed repaired reviews with zero findings. Errors,
  rejected candidates and unavailable analyzers never count as clean.
- `successful_pairs`: complete vulnerable review with a nearby hit and complete
  repaired review with no findings, paired within the same model and repeat.
- Separate `llm_score` prevents a Bandit hit from concealing an LLM miss or
  borrowing Bandit's source location after merging.
- `elapsed_seconds` includes scanning/setup, not only model generation. Raw
  provider usage/timing fields are retained when the provider supplies them.

For each `llm_findings` entry, fill the corresponding `manual_review` row with
`diagnosis_correct`, `recommendation_correct`, and notes. Check actual attack
conditions, existing guards, API validity and whether the proposed fix closes
the attack path. For example, `os.system(..., shell=False)` is invalid, and
plain SHA-256 is not a suitable password-storage fix. The summary deliberately
does not pretend that keyword matching can grade recommendations. Review all
findings on fixed cases and expected-issue misses too, not just location hits.

Benchmark artifacts may contain the fixture source and model output. Keep them
local; the default `benchmark-results/` directory is Git-ignored.

## Command-path experiment

Eight additional pairs cover direct shell input, assignment and overwrite,
concatenation with a literal allowlist, import aliases, local helper arguments,
helper return values, guard placement around reassignment, and cross-file closed
operation dispatch. Some fixed cases deliberately retain constant or tightly
restricted shell commands: Bandit's conservative warnings should remain visible.
Review `llm_score` separately from combined results when assessing improvement.

Run the same model and limits with only path evidence toggled:

```powershell
python -m benchmarks.run --suite commands --model llama3.1:latest --max-findings 2 --max-tokens 800 --output benchmark-results/commands-baseline
python -m benchmarks.run --suite commands --command-paths --model llama3.1:latest --max-findings 2 --max-tokens 800 --output benchmark-results/commands-paths
```

For a short pilot, add `--case assignment --case concatenation` to both commands.
Use `--repeat 2` for a repeated comparison. Baseline and evidence-enabled runs
must use separate directories. Full evaluation requires manual diagnosis and
recommendation grading; lower alarm counts alone may reflect missed findings.

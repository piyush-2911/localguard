# Command-path pilot — 2026-10-20

Implemented an opt-in `--command-paths` prototype with eight automated paired
fixtures. Final unit suite: 92 tests run, 91 passed, one Windows symlink privilege
skip. Tests verify assignment overwrite, guard placement, local arguments and
returns, cross-file calls, aliases, shell modes, unresolved control flow and bounds.

The live pilot used two of those pairs: `assignment` and `concatenation`. Both
variants ran through hybrid scanning with `llama3.1:latest` at local Ollama,
temperature 0, required structured output, max findings 2, max tokens 800, timeout
240 seconds. Baseline ran first, then path-evidence mode. Both modes used the same
source, model, settings and implementation revision. The enabled mode adds path
observations and their interpretation instructions; it makes no additional calls.
There was one run per program per mode (eight reviews total).

| LLM-only metric, before merging with Bandit | Baseline | With path evidence |
|---|---:|---:|
| Reviews completed without rejected output | 1 / 4 | 1 / 4 |
| Vulnerable cases with expected category/location hit | 1 / 2 | 1 / 2 |
| Completed repaired reviews with no alarms | 0 / 2 | 0 / 2 |
| Successful vulnerable/fixed pairs | 0 / 2 | 0 / 2 |
| Repaired cases with retained LLM false alarms | 0 / 2 | 1 / 2 |
| Total elapsed time | 458.30s | 374.49s |

Zero retained baseline false alarms does **not** mean repaired cases were handled
correctly: both repaired reviews were incomplete. Raw responses made false claims
but failed validation. Time differences are not a speed improvement claim; the
sample is small and sequential ordering/warm-up were not controlled.

## Manual inspection

- Baseline, vulnerable assignment: recognized shell injection but quoted invented
  or rearranged evidence. All candidates rejected.
- Baseline, repaired assignment: ignored the overwrite to `"pwd"`, invented many
  source lines, and exhausted the output limit. Incomplete response.
- Baseline, vulnerable concatenation: valid location and relevant diagnosis,
  but recommended `os.popen(..., shell=False)`, an invalid API usage.
- Baseline, repaired concatenation: ignored the literal allowlist and invented an
  authorization bypass. Both quotes failed source validation.
- Path mode, vulnerable assignment: retained a generic input-assignment warning
  in the wrong category and rejected another finding. Not an expected-issue hit.
- Path mode, repaired assignment: the tracer reported a constant command, but the
  model still claimed unsafe input assignment. One false alarm retained; another
  quote rejected. Generic input validation advice does not address an actual flaw.
- Path mode, vulnerable concatenation: detected command injection but reported
  the same flow twice (assignment and call). Fix advice described argument lists
  and `shell=False` but did not name a concrete replacement API.
- Path mode, repaired concatenation: ignored the recorded `alpha`/`beta` allowlist,
  claimed the allowed strings might be dangerous, and suggested adding a whitelist
  already present. Both evidence quotes failed validation.

## Decision

Keep the feature experimental and off by default. The prototype can supply the
intended bounded observations, but this pilot shows **no detection improvement**
with the current model/prompt combination. It does not prove that path analysis
cannot help other models or larger, better-controlled evaluations. Bandit findings
were preserved in both modes; do not treat combined hits as LLM successes.

Raw requests, responses, coverage and machine-readable summaries remain locally in
`benchmark-results/command-pilot-baseline/` and
`benchmark-results/command-pilot-paths/`. The complete eight-pair live comparison
has not been run. No fixture source was executed.

# Qwen comparison — 2026-10-20

Ran `qwen2.5-coder:7b` on the assignment and concatenation vulnerable/fixed pairs,
first with baseline hybrid context, then with command-path evidence. Eight local
reviews completed. Model digest:
`dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`.

Settings matched the llama3.1 pilot: temperature 0, required schema, 800 output
tokens, maximum 2 findings, 240-second timeout, identical source and context.
Comparison of all eight saved request payloads confirmed exact equality with the
corresponding llama3.1 request after removing only the `model` field. The scanner
and prompts were not modified during this run.

| LLM result before merging | Llama baseline | Llama + paths | Qwen baseline | Qwen + paths |
|---|---:|---:|---:|---:|
| Complete reviews | 1/4 | 1/4 | 4/4 | 3/4 |
| Expected vulnerable category/location hits | 1/2 | 1/2 | 2/2 | 2/2 |
| Complete repaired reviews without alarms | 0/2 | 0/2 | 0/2 | 0/2 |
| Successful vulnerable/fixed pairs | 0/2 | 0/2 | 0/2 | 0/2 |
| Repaired cases with retained LLM alarms | 0/2 | 1/2 | 2/2 | 1/2 |
| Total elapsed seconds | 458.30 | 374.49 | 236.27 | 231.08 |

Incomplete repaired reviews never count as clean. Llama's lower retained alarm
count largely reflects rejected output, not superior false-positive performance.
Timing is observational: model loading, cache state and sequential ordering were
not controlled, and each case/mode had only one run.

## Manual findings

- Qwen baseline identified both vulnerable flows with matching source quotes.
  Descriptions were terse and assumed user control rather than clearly stating it
  as a prerequisite. Recommendations described argument lists and `shell=False`;
  one explicitly named `subprocess.run`.
- Qwen baseline falsely flagged both repaired examples: assignment overwritten
  with the constant `"pwd"`, and concatenation restricted to `"alpha"`/`"beta"`.
- With paths, Qwen still found both vulnerable cases. Recommendations named
  `subprocess.run(..., shell=False)` but omitted argument-list detail in these two
  responses, so they remain incomplete guidance rather than validated fixes.
- With paths, the repaired assignment was still called a dynamic command-injection
  vulnerability. Invented/reordered evidence caused validation to reject it; the
  result is incomplete, not safe.
- With paths, the repaired allowlist example still received a false command-
  injection finding, with valid evidence. The model did not account for the guard.

## Decision

Qwen is a better candidate for further experiments on output reliability and
vulnerable-case detection in this tiny pilot. It is **not a validated security
reviewer**: it did not distinguish either vulnerable/fixed pair successfully.
Command-path mode did not demonstrate an advantage and remains off by default.
No default model/configuration was changed; no additional model was downloaded.

Artifacts: `benchmark-results/qwen-command-pilot-baseline/` and
`benchmark-results/qwen-command-pilot-paths/` contain raw requests/responses,
coverage, findings and summaries. The full 8-pair command suite and 12-pair general
suite have not been run on Qwen. No fixture code was executed.

# Full Qwen general benchmark — reviewed November 1, 2026

All 24 records from the previously launched run were present when work resumed;
no model requests were rerun. The experiment used qwen2.5-coder:7b, baseline hybrid
context (Bandit leads supplied), command paths off, temperature 0, required schema,
800 output tokens, at most 2 findings per chunk and a 240-second timeout. One run
per variant, 12 handwritten pairs. Fixture code was never executed.

## Results

| Metric | LLM before merging | Hybrid combined |
|---|---:|---:|
| Completed reviews without rejected output | 10/24 | 10/24 fully complete |
| Expected vulnerable category/location hits | 4/12 | 11/12 |
| Completed repaired reviews with no alarms | 3/12 | 3/12 |
| Repaired cases with retained alarms | 3/12 | 3/12 |
| Successful vulnerable/fixed pairs | 2/12 | 2/12 |

Fourteen reviews were incomplete. On repaired examples specifically, three were
clean, three retained alarms, and six had no retained LLM findings but were
incomplete. The repaired shell case is both incomplete and has a retained alarm.
These classifications must not be interpreted as 9/12 safe cases.

Elapsed scan time totaled 2343.24 seconds (39.1 minutes). There were 25 model
responses: 16 finished normally and 9 hit the 800-token output limit. Five further
reviews failed entirely on evidence validation, and the repaired shell review
retained one finding while rejecting another. In the vulnerable helper case,
a grounded finding from the caller review was discarded after the helper review
hit its output limit, following the existing hybrid failure policy.

## Pair assessment

| Pair | Vulnerable version, LLM | Repaired version, LLM |
|---|---|---|
| SQL | Correct detection; parameter binding recommended | Clean |
| Shell | Output truncated | False unused-import warning; another finding rejected |
| eval | Evidence rejected | Two false code-execution claims about JSON parsing |
| Pickle | Output truncated | Output truncated; raw response confuses JSON with pickle |
| YAML | Evidence rejected | Evidence rejected; raw response still flags safe_load |
| Password hashing | Correct MD5 finding; password KDF recommended | Output truncated; falsely calls explicitly salted scrypt unsalted |
| TLS | Correct verify=False finding and fix | Clean |
| Embedded secret | Output truncated | Output truncated; raw response calls environment lookup hardcoding |
| Path traversal | Correct conditional detection; generic fix | False traversal and secret claims about closed path mapping |
| Ownership | Missed expected owner check | Clean |
| Temporary file | Evidence rejected | Output truncated; invents unrelated pickle code |
| Helper dispatch | Partial detection discarded on later failure | Output truncated |

SQL and TLS are the only successful pairs. A clean repaired ownership case does
not constitute success because the vulnerable version was missed. Ownership
ground truth assumes private per-owner documents; the absent storage implementation
means that assumption is not fully established by the supplied code. Likewise,
parameter-based findings depend on external attacker control. These are small
synthetic cases, not representative production precision/recall measurements.

## Added value and recommendation quality

The earlier Bandit baseline detected 10/12 expected vulnerable cases and missed
ownership and traversal. Qwen added a grounded traversal finding, lifting the
combined location/category hit count to 11/12, but also falsely flagged its closed-
mapping repair. It did not add the expected ownership detection.

Manual assessment of all nine retained LLM findings found four relevant diagnoses
under the fixture assumptions and five false claims. Three recommendations were
appropriate and actionable (parameter binding, password KDF, enable TLS
verification). The traversal recommendation, "validate and sanitize input", was
too vague to count as an actionable containment fix. Advice accompanying the five
false diagnoses was unnecessary or harmful. For example, removing the actively
used subprocess import would break the repaired program.

The raw responses show the output-budget failures often involved fabricated code
or fix suggestions inside the evidence string, not simply a legitimate report
needing more tokens. Increasing the cap alone is therefore not a demonstrated fix.
Evidence matching prevented many invented quotations from becoming report entries,
but cannot establish that a correctly quoted line supports the security claim.

## Conclusion and next experiment

The broader evaluation does not justify switching Qwen on as a trusted reviewer.
Keep Bandit as the baseline and LLM reports subject to human review. No default
model, prompt, output limit, or validation rule was changed for this evaluation.

A focused next experiment can withhold Bandit leads from the model while keeping
source context, model, prompt and limits otherwise fixed, and still run Bandit for
the final report. This tests whether leads bias the review; it does not assume
that they caused the observed errors. Include cases with false warnings despite
no Bandit leads too, since bias cannot explain all failures. Do not weaken evidence
validation to turn incomplete responses into apparent successes.

Local artifacts: `benchmark-results/qwen-general-baseline/` contains the 24 raw
records, `summary.json`, and a separate `manual-assessment.json`. The latter grades
each retained finding without changing raw records. The workspace helper
`evaluation/review_qwen_general.py` reproduces the saved manual-assessment artifact.

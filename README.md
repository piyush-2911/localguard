# scan

A security scanner CLI for Python code.

**Stage 3: hybrid static and LLM review.** `scan` wraps
[Bandit](https://bandit.readthedocs.io/) — Python's standard security
linter — and turns its output into a clean, colored terminal report, JSON,
or Markdown, with sensible exit codes for CI use. Hybrid scanning is the default.
Use `--static-only` for Bandit alone or `--llm-only` for your configured model alone.

## How hybrid mode works

```powershell
scan scan ./myproject --model llama3.1 --format json
scan scan ./myproject --static-only
scan scan ./myproject --llm-only --model llama3.1
scan scan ./myproject --merge-tolerance 3 --min-confidence likely --severity-threshold high
```

Both analyzers run once. Findings share a fixed category taxonomy. The merger
pairs same-file, same-category findings whose line ranges overlap or are separated
by at most `--merge-tolerance` lines (default 3). Nearest pairs match first, one
static finding to one LLM finding, without chaining nearby issues together.
Repeated findings at overlapping locations within an analyzer are deduplicated;
different Bandit rules remain separate. Unknown categories become `other`.

| Confidence | Source | Meaning |
|---|---|---|
| `confirmed` | `static+llm` | Both analyzers flagged the issue |
| `likely` | `static` | Bandit reported a deterministic pattern match |
| `needs-review` | `llm` | Only the probabilistic model flagged it; human review is needed |

These labels describe analyzer agreement, not proof of exploitability. Merged
findings preserve Bandit's rule ID, source location and snippet, use the LLM's
explanation and recommendation, and take the higher severity. JSON preserves
`original_severities` and `explanations` keyed by `static` and `llm`, plus the
original `bandit_confidence`. Use `--verbose` to see both explanations in text
and Markdown. Reports sort by descending severity, then confidence.

`--min-confidence` defaults to `needs-review` (everything). Confidence filtering
runs before severity filtering; only remaining findings cause exit 1. Summary
confidence counts describe displayed findings; analyzer contributions count input
findings before merging and filtering, so these counts need not sum to the total.

If one analyzer fails, hybrid mode warns and reports the other analyzer's results,
including an `LLM analysis unavailable` or `Static analysis unavailable` status in
every report format. If the LLM fails partway through, its partial findings are
discarded. If both fail, exit 2. Single-analyzer modes retain their own failure
behavior. A missing LLM model configuration also permits static fallback.

## What it catches

Whatever Bandit's ruleset covers: hardcoded passwords/secrets, `eval()` and
other dangerous calls, `subprocess`/`os.system` with `shell=True`, insecure
deserialization (`pickle`), weak/broken crypto (MD5, DES, ECB, etc.),
SQL built via string formatting, disabled TLS verification, insecure temp
files, bare `except: pass`, and more. See Bandit's own
[list of checks](https://bandit.readthedocs.io/en/latest/plugins/index.html#complete-test-plugin-listing)
for the full set — `scan` doesn't add or remove checks, it wraps and
reports on them.

## Install

Requires Python 3.9+.

```bash
git clone <this-repo-url>
cd scan
pip install -e .
```

This installs `bandit`, `click`, `rich`, and `openai`, and puts a `scan`
command on your `PATH`.

Alternatively, if you just want the dependencies without an editable
install:

```bash
pip install -r requirements.txt
```

## Usage

```bash
scan scan <path> [OPTIONS]
```

`<path>` can be a single `.py` file or a directory (scanned recursively).

### Options

| Option                   | Values                                            | Default  | Description                                                 |
| ------------------------ | ------------------------------------------------- | -------- | ----------------------------------------------------------- |
| `--severity-threshold` | `low` \| `medium` \| `high` \| `critical` | `low`  | Only report findings at or above this severity.             |
| `--format`             | `text` \| `json` \| `markdown`              | `text` | Report output format.                                       |
| `--output <file>`      | any path                                          | stdout   | Write the report to a file instead of printing it.          |
| `--verbose`            | flag                                              | off      | Show the full code snippet context per finding (text/JSON). |

### Exit codes

- `0` — scan completed, no findings at or above `--severity-threshold`
- `1` — scan completed, one or more findings at or above the threshold
  (useful as a CI gate in a later stage)
- `2` — scan could not run at all (bad path, no `.py` files, Bandit
  missing, etc.) — no stack trace, just a clear message on stderr

### LLM-only review

```bash
scan scan ./myproject --llm-only --model llama3.1
```

The executable and subcommand are both named `scan`, matching Stage 1.
The client uses the [OpenAI Python SDK](https://developers.openai.com/api/docs/libraries)
with an explicit base URL and the common `/chat/completions` protocol. No
provider-specific client is required. Ollama, LM Studio, vLLM,
text-generation-webui and proxies exposing this protocol can be selected through
`--base-url` and their served model name. Native Anthropic endpoints require an
OpenAI-compatible proxy; the Anthropic Messages API is a different protocol.

| Option              | Default                               | Environment variable |
| ------------------- | ------------------------------------- | -------------------- |
| `--llm-only`      | off                                   | —                   |
| `--model`         | required for LLM review               | `SCAN_MODEL`       |
| `--base-url`      | `http://localhost:11434/v1`         | `SCAN_BASE_URL`    |
| `--api-key`       | `not-needed`                        | `SCAN_API_KEY`     |
| `--timeout`       | 120 seconds per request               | `SCAN_TIMEOUT`     |
| `--max-tokens`    | 1024 generated tokens per chunk       | `SCAN_MAX_TOKENS`  |
| `--max-findings`  | 10 highest-impact findings per chunk  | `SCAN_MAX_FINDINGS`|
| `--structured-output` | `auto` (`auto`, `required`, `off`) | `SCAN_STRUCTURED_OUTPUT` |
| `--chunk-lines`   | 250                                   | —                   |
| `--chunk-overlap` | 20 (must be smaller than chunk-lines) | —                   |
| `--chunk-chars`   | 12000 (additional source-size limit)  | —                   |

Flags override environment variables, which override defaults. The project uses
a plain `.env` file for saved local configuration. Copy the included template
and edit it once:

```bash
cp .env.example .env
```

On Windows PowerShell, use `Copy-Item .env.example .env`. The CLI automatically
loads `.env` from the directory where you run it. The real `.env` is ignored by
Git; `.env.example` is safe to commit because it contains no secret. Command-line
flags and variables already set in your shell take precedence over `.env`.

```dotenv
SCAN_BASE_URL=http://localhost:11434/v1
SCAN_MODEL=llama3.1
SCAN_API_KEY=not-needed
SCAN_TIMEOUT=120
SCAN_MAX_TOKENS=1024
SCAN_MAX_FINDINGS=10
SCAN_STRUCTURED_OUTPUT=auto
```

You can still configure values for one shell session in PowerShell:

```powershell
$env:SCAN_BASE_URL = "http://localhost:11434/v1"
$env:SCAN_MODEL = "llama3.1"
$env:SCAN_API_KEY = "not-needed"
$env:SCAN_TIMEOUT = "180"
scan scan ./myproject --llm-only
```

### Local model setup

**Ollama** — install Ollama, then start `ollama serve` in a separate terminal
if the desktop service is not already running. Download and warm up the model:

```bash
ollama pull llama3.1
ollama run llama3.1 "Reply with OK"
ollama ps
scan scan examples/vulnerable_sample.py --llm-only --model llama3.1 --base-url http://localhost:11434/v1 --format json
```

`ollama ps` checks models currently loaded in memory; `ollama list` lists downloaded
models. See the [Ollama CLI reference](https://docs.ollama.com/cli).

**LM Studio** — download a chat/instruct model through the app, then use its
`lms` CLI (replace `<model-key>` with a key from `lms ls`):

```bash
lms ls
lms load <model-key> --identifier security-reviewer
lms server start --port 1234
lms ps
scan scan examples/vulnerable_sample.py --llm-only --model security-reviewer --base-url http://localhost:1234/v1 --format json
```

[`lms load`](https://lmstudio.ai/docs/cli/local-models/load) sets the API model
identifier; [`lms ps`](https://lmstudio.ai/docs/cli/local-models/ps) verifies it is
loaded. You can also load a model and start the server in the app's Developer tab.

For either server, check the API is reachable with `curl http://localhost:11434/v1/models`
or `curl http://localhost:1234/v1/models` (use `curl.exe` in Windows PowerShell).
Use your server's configured port if different. For a vLLM server on port 8000:

```bash
scan scan ./myproject --llm-only --model your-served-model --base-url http://localhost:8000/v1
```

### LLM findings and failure behavior

By default, the client requests [schema-constrained structured output](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=chat)
using the standard chat-completions `response_format`. The response is an object
containing a `findings` array. Every finding must include `line`, `end_line` (null
for a single line), `severity`, a canonical `category`, `description`,
`recommendation`, and `evidence`. Local validation checks these fields even if
the server ignores the schema. Invalid or truncated structured responses fail
LLM analysis: LLM-only exits 2 and hybrid falls back to Bandit. Schema constraints
prevent missing fields and malformed output; they do not prove a vulnerability
exists or that the evidence points to the right operation.

`--structured-output auto` retries without the schema only after an explicit
HTTP 400/422 error stating that the format is unsupported. A warning announces
the downgrade, which applies to subsequent chunks in that scan. Authentication,
timeout, rate-limit, server errors, and invalid responses do not trigger this
fallback. Use `required` to prohibit downgrading, or `off` for legacy endpoints:

```powershell
scan scan examples/vulnerable_sample.py --llm-only --model llama3.1:latest --structured-output required --max-findings 5 --max-tokens 1600 --timeout 600
```

In legacy mode, the prompt requests a JSON array with `line`, optional `end_line`, `severity`,
`category`, `description`, `recommendation`, and `evidence` (verbatim affected code).
Evidence is checked against the chunk, ignoring outer whitespace. If the reported
line is wrong but the quoted code has one exact match, the scanner corrects it.
Single-line expression excerpts are also matched by exact Python tokens, excluding
comments and preserving identifier and string-literal contents.
If evidence has no match, the scanner also tries removing the displayed `35: `
style prefix from every quoted line. This fallback requires complete source lines
to match exactly (apart from outer whitespace); it does not repair altered code or
use the prefix numbers to resolve ambiguous matches. Original evidence is checked
first to preserve numeric keys and literal text.
Missing, invented, comment-only, or ambiguously located evidence is skipped with
a warning. A quote matching the reported location is accepted; use a multiline
quote to distinguish repeated code. End lines are derived from multiline evidence,
not trusted from the model. This verifies the quoted location, not whether the
model's security interpretation is correct. No second model call is needed.
If every returned finding fails validation, LLM-only mode exits 2 rather than
presenting a clean result; hybrid mode falls back to static analysis. If some
findings survive, warnings identify skipped entries and coverage is partial.
Both line fields use absolute
source line numbers, including in later chunks. Findings use the existing model
with `source: "llm"`, `rule_id: "LLM"`, and optional `end_line`. All report formats
show the source. Existing severity filters, output files, verbose snippets and
exit codes apply.

In legacy mode (`off` or an announced compatibility fallback),
malformed/partial JSON or incomplete completions produce a warning on stderr,
skip that chunk, and continue. Markdown fences are tolerated. Invalid individual
findings are warned about and skipped while valid siblings are retained.
The parser also accepts explanatory text around a complete JSON array and the
common `{ "findings": [...] }` wrapper produced by some local models.
If the model truncates the array after emitting one or more complete finding
objects, those complete findings are recovered and a warning notes partial coverage.
Warnings never include raw model output or API keys. HTTP, connection and timeout
errors stop LLM-only scans with a clear message and exit 2; hybrid mode falls back
to Bandit. Successful processing exits
1 when reported findings exist, otherwise 0, **even if malformed chunks were
skipped**; inspect stderr for incomplete coverage before treating a scan as clean.

Directory scans skip common environment/build/cache directories and nested
symlinks. Python encoding declarations are respected. Empty files count as scanned
without making a request. Chunks overlap and retain absolute line numbers; exact
LLM duplicates from overlap are removed. Hybrid mode also reconciles Bandit results.
An individual line exceeding the character cap requires increasing `--chunk-chars`.

Source is sent only to the configured endpoint, localhost by default; a remote URL
sends source remotely. Apart from the explicit format-capability fallback above,
no cloud fallback, automatic retries, proxy environment
routing, or redirects are used. Bandit is not run in LLM-only mode, though it remains
an installation dependency. Models can miss issues or produce false positives;
review findings. Each request sees one file chunk, so distant or cross-file flows
may be missed. Tune chunk sizes for your model's token context window.

LLM requests show their file, line range, model, and elapsed time on stderr; JSON
reports remain clean on stdout. `--max-tokens` bounds generation time. Reducing it
can make reviews faster, but values that are too small can truncate the JSON. Model
loading and inference still depend on local hardware. With Ollama, run `ollama ps`
while scanning and inspect the `PROCESSOR` column; a CPU-only model is usually much
slower than one that fits on the GPU. A smaller quantized instruct/code model can
also substantially reduce latency.

For a faster, intentionally narrower CPU-only review, limit both output size and
finding count while leaving enough tokens to finish valid JSON:

```bash
scan scan ./myproject --llm-only --max-findings 5 --max-tokens 600
```

### Examples

Scan a project directory, default text report to the terminal:

```bash
scan scan ./myproject
```

Only show high-and-above findings, as Markdown, saved to a file (handy for
pasting into a PR description or CI comment):

```bash
scan scan ./myproject --severity-threshold high --format markdown --output security-report.md
```

Machine-readable output for piping into another tool:

```bash
scan scan ./myproject --format json | jq '.findings[] | select(.severity == "high")'
```

Full detail, including the exact source line for every finding:

```bash
scan scan ./myproject --verbose
```

### Try it on the bundled example

`examples/vulnerable_sample.py` contains a handful of intentionally
insecure patterns (`eval()`, a hardcoded password, `subprocess` with
`shell=True`, MD5 for hashing, `pickle.loads` on untrusted data, SQL string
concatenation, and more) so you can see the tool in action immediately
after install:

```bash
scan scan examples/vulnerable_sample.py
```

You should see a colored report with entries grouped by severity
(HIGH/MEDIUM/LOW), and the command should exit with status `1` since real
findings are present.

## How it works

1. `scan` validates the target path exists and contains at least one
   `.py` file.
2. It shells out to `bandit -f json [-r] <path>` and parses the resulting
   JSON.
3. Each Bandit result is normalized into a `Finding` (file, line, severity,
   category, description, a short fix recommendation, Bandit's rule ID,
   and a code snippet).
4. Findings are filtered by `--severity-threshold` and rendered in the
   requested `--format`.

## Project layout

```
scan/
├── pyproject.toml
├── requirements.txt
├── README.md
├── src/
│   └── scan/
│       ├── __init__.py
│       ├── cli.py        # click CLI (scan command, options, exit codes)
│       ├── scanner.py     # bandit subprocess wrapper + JSON parsing
│       ├── report.py      # text/json/markdown renderers
│       └── models.py      # Finding / Severity data model
└── examples/
    └── vulnerable_sample.py
```

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests use a local HTTP fixture; no model or remote service is needed.

## What's next (later stages, not in this release)

Later stages may add richer configuration, CI integration, and reviewed fix suggestions.

# scan

A security scanner CLI for Python code.

**Stage 2: static scanning and independent LLM review.** `scan` wraps
[Bandit](https://bandit.readthedocs.io/) — Python's standard security
linter — and turns its output into a clean, colored terminal report, JSON,
or Markdown, with sensible exit codes for CI use. Static scanning remains
the default. Use `--llm-only` to review code through a local or explicitly
configured OpenAI-compatible endpoint. Hybrid scanning is a later stage.

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
provider-specific JSON mode is required. Ollama, LM Studio, vLLM,
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

The prompt requests a JSON array with `line`, optional `end_line`, `severity`,
`category`, `description`, and `recommendation`. Both line fields use absolute
source line numbers, including in later chunks. Findings use the existing model
with `source: "llm"`, `rule_id: "LLM"`, and optional `end_line`. All report formats
show the source. Existing severity filters, output files, verbose snippets and
exit codes apply.

Malformed/partial JSON or incomplete completions produce a warning on stderr,
skip that chunk, and continue. Markdown fences are tolerated. Invalid individual
findings are warned about and skipped while valid siblings are retained.
The parser also accepts explanatory text around a complete JSON array and the
common `{ "findings": [...] }` wrapper produced by some local models.
If the model truncates the array after emitting one or more complete finding
objects, those complete findings are recovered and a warning notes partial coverage.
Warnings never include raw model output or API keys. HTTP, connection and timeout
errors stop the scan with a clear message and exit 2. Successful processing exits
1 when reported findings exist, otherwise 0, **even if malformed chunks were
skipped**; inspect stderr for incomplete coverage before treating a scan as clean.

Directory scans skip common environment/build/cache directories and nested
symlinks. Python encoding declarations are respected. Empty files count as scanned
without making a request. Chunks overlap and retain absolute line numbers; exact
LLM duplicates from overlap are removed. No Bandit results are merged or deduplicated.
An individual line exceeding the character cap requires increasing `--chunk-chars`.

Source is sent only to the configured endpoint, localhost by default; a remote URL
sends source remotely. No cloud fallback, automatic retries, proxy environment
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

Planned next: a hybrid engine that merges and confidence-scores both sources,
a config file system, CI-friendly output/exit-code polish, and auto-fix suggestions.

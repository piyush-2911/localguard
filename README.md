# scan

A security scanner CLI for Python code.

**Stage 1 (this release): static-analysis only.** `scan` wraps
[Bandit](https://bandit.readthedocs.io/) — Python's standard security
linter — and turns its output into a clean, colored terminal report, JSON,
or Markdown, with sensible exit codes for CI use. No AI/LLM is involved at
this stage; that's planned for a later release (`--llm-only` / hybrid
mode).

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

This installs `bandit`, `click`, and `rich`, and puts a `scan`
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

## What's next (later stages, not in this release)

This is Stage 1 of a larger tool. Planned next: an LLM-based reviewer for
context-dependent logic flaws that pattern-based linting misses, a hybrid
engine that merges and confidence-scores both sources, a config file
system, CI-friendly output/exit-code polish, and auto-fix suggestions.
Stage 1 deliberately has none of that — it's self-contained, works fully
offline (beyond installing Bandit), and is testable purely against local
files.

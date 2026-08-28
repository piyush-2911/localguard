"""Wraps Bandit (run as a subprocess, JSON output) and normalizes its
results into scan's own `Finding` data model.
"""

from __future__ import annotations

import json
import importlib.util
import subprocess
import sys
from pathlib import Path

from .models import Finding, Severity


class ScanError(Exception):
    """Raised for any expected, user-facing scan failure.

    The CLI layer catches this and prints a clean message instead of a
    traceback.
    """


# Bandit's severity strings are already close to ours; just lowercase them.
_BANDIT_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}

# Short, actionable one-line fix hints keyed by Bandit test id. Falls back
# to a generic message (built from the bandit-provided text) if a test id
# isn't in this table.
_FIX_HINTS = {
    "B101": "Remove assert statements from production code paths; asserts are stripped with `python -O`.",
    "B102": "Avoid exec(); use a safe alternative such as a lookup table or ast.literal_eval().",
    "B103": "Avoid overly permissive file permissions (e.g. chmod 0o777); grant the minimum needed.",
    "B104": "Avoid binding to 0.0.0.0; bind to a specific interface/localhost unless public exposure is intended.",
    "B105": "Do not hardcode secrets/passwords; load them from environment variables or a secrets manager.",
    "B106": "Do not hardcode secrets/passwords in function arguments; use env vars or a secrets manager.",
    "B107": "Avoid hardcoded default passwords in function signatures.",
    "B108": "Avoid predictable/hardcoded temp file paths; use tempfile.mkstemp()/NamedTemporaryFile().",
    "B110": "Avoid bare `except: pass`; handle or at least log the specific exception.",
    "B112": "Avoid `except: continue` that silently swallows errors; log or handle explicitly.",
    "B201": "Never run Flask in debug mode in production; disable debug=True.",
    "B301": "Avoid pickle for untrusted data; use json or another safe serialization format.",
    "B302": "Avoid marshal for untrusted data; prefer json.",
    "B303": "Avoid weak hashes (MD5/SHA1) for security purposes; use SHA-256+ or hashlib with usedforsecurity=False if non-crypto.",
    "B304": "Avoid weak/broken ciphers (e.g. DES, RC4); use a modern authenticated cipher (AES-GCM).",
    "B305": "Avoid weak cipher modes (e.g. ECB); use an authenticated mode like GCM.",
    "B306": "Avoid mktemp(); use mkstemp() to prevent race conditions.",
    "B307": "Avoid eval(); parse input safely (e.g. ast.literal_eval) or use a dedicated parser.",
    "B308": "Avoid mark_safe()/similar on unescaped input; ensure content is sanitized first.",
    "B310": "Validate/allowlist URLs before urllib requests to prevent SSRF.",
    "B311": "Use `secrets` instead of `random` for anything security-sensitive (tokens, passwords).",
    "B312": "Review use of telnetlib; unencrypted protocol, prefer SSH.",
    "B313": "Use defusedxml instead of standard XML libs to avoid XML entity expansion attacks.",
    "B314": "Use defusedxml for XML parsing to prevent XXE/entity-expansion attacks.",
    "B318": "Use defusedxml.minidom to avoid XML vulnerabilities.",
    "B320": "Use defusedxml.lxml to avoid XML vulnerabilities.",
    "B321": "Avoid FTP; prefer SFTP/FTPS for credential and data confidentiality.",
    "B324": "Avoid weak hash functions for security purposes; use hashlib.sha256 or stronger.",
    "B401": "Review use of the telnet module; prefer encrypted alternatives.",
    "B402": "Review use of ftplib; prefer SFTP/FTPS.",
    "B403": "Avoid pickle-family modules for untrusted data.",
    "B404": "Review subprocess usage; ensure inputs are not attacker-controlled.",
    "B405": "Use defusedxml instead of xml.etree for untrusted input.",
    "B406": "Use defusedxml instead of xml.sax for untrusted input.",
    "B407": "Use defusedxml instead of xml.dom.expatbuilder for untrusted input.",
    "B408": "Use defusedxml instead of xml.dom.minidom for untrusted input.",
    "B409": "Use defusedxml instead of xml.dom.pulldom for untrusted input.",
    "B410": "Use defusedxml.lxml for untrusted XML input.",
    "B411": "Use defusedxml instead of xmlrpclib for untrusted input.",
    "B412": "Review httpoxy vulnerability exposure from HTTP_PROXY env var handling.",
    "B413": "Review use of pycrypto; it's unmaintained, migrate to pyca/cryptography.",
    "B415": "Review cryptography key size; ensure it meets current recommended minimums.",
    "B501": "Do not disable certificate/hostname verification (verify=False) on requests.",
    "B502": "Avoid weak SSL/TLS protocol versions; require TLS 1.2+.",
    "B503": "Do not disable SSL certificate verification.",
    "B504": "Explicitly set an ssl_version/context with strong protocol requirements.",
    "B505": "Use a sufficiently large key size for the cryptographic algorithm in use.",
    "B506": "Avoid yaml.load() on untrusted input; use yaml.safe_load().",
    "B507": "Do not disable SSH host key verification (AutoAddPolicy); use a known_hosts policy.",
    "B508": "Review snmp configuration for insecure/weak settings.",
    "B509": "Avoid SNMPv1/v2 with weak community strings; use SNMPv3.",
    "B601": "Avoid shell=True with paramiko/fabric-style command execution; pass args as a list.",
    "B602": "Avoid subprocess with shell=True on dynamic input; pass args as a list, shell=False.",
    "B603": "Ensure subprocess calls without shell=True still validate/sanitize all inputs.",
    "B604": "Review function calls that may invoke a shell with untrusted input.",
    "B605": "Avoid os.system() with dynamic/untrusted input; use subprocess with an argument list.",
    "B606": "Review process spawning without shell for untrusted/unsanitized arguments.",
    "B607": "Avoid partial executable paths; use a fully-qualified path to avoid PATH-hijacking.",
    "B608": "Use parameterized queries/ORM instead of building SQL via string formatting.",
    "B609": "Avoid wildcard injection in shell command construction.",
    "B610": "Review Django extra() usage for SQL injection risk; prefer the ORM.",
    "B611": "Review Django RawSQL usage for SQL injection risk; prefer the ORM or parameterized queries.",
    "B701": "Enable Jinja2 autoescaping to prevent XSS.",
    "B702": "Review use of mako templates for autoescaping/XSS risk.",
    "B703": "Avoid Django mark_safe() on unsanitized input; risk of XSS.",
}

_DEFAULT_HINT = "Review this finding against secure coding best practices for this pattern."


def _severity_from_bandit(value: str) -> Severity:
    return _BANDIT_SEVERITY_MAP.get(value.upper(), Severity.LOW)


def _check_bandit_available() -> None:
    if importlib.util.find_spec("bandit") is None:
        raise ScanError(
            "Bandit is not installed in the active Python environment.\n"
            "Install it with:  python -m pip install bandit\n"
            "(or reinstall this package's dependencies: pip install -e .)"
        )


def _validate_target(path: Path) -> None:
    if not path.exists():
        raise ScanError(f"Path does not exist: {path}")

    if path.is_file():
        if path.suffix != ".py":
            raise ScanError(f"Not a Python file: {path}")
        return

    # Directory: make sure there's at least one .py file somewhere in it.
    has_py = any(path.rglob("*.py"))
    if not has_py:
        raise ScanError(f"No .py files found under: {path}")


def run_bandit(target: Path) -> dict:
    """Run bandit -f json against `target` and return the parsed JSON.

    Raises ScanError on any expected failure (bandit missing, bad target,
    unparsable output, unexpected non-finding error from bandit itself).
    """
    _check_bandit_available()
    _validate_target(target)

    cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q"]
    if target.is_dir():
        cmd.append("-r")
    cmd.append(str(target))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Bandit timed out after 300 seconds.") from exc
    except OSError as exc:
        raise ScanError(f"Failed to run bandit: {exc}") from exc

    # Bandit exits 1 when findings exist, 0 when clean, >=2 on real errors.
    # In all of these cases it still writes JSON to stdout, EXCEPT hard
    # errors (e.g. syntax errors bandit can't parse at all end up inside
    # the JSON's "errors" list, not a nonzero-only failure) - so always
    # try to parse stdout first.
    stdout = proc.stdout.strip()
    if not stdout:
        raise ScanError(
            "Bandit produced no output.\n"
            f"stderr: {proc.stderr.strip() or '(empty)'}"
        )

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ScanError(
            "Could not parse bandit's JSON output.\n"
            f"stderr: {proc.stderr.strip() or '(empty)'}"
        ) from exc

    return data


def parse_findings(bandit_json: dict, verbose: bool = False) -> list[Finding]:
    """Convert bandit's raw JSON dict into a list of `Finding` objects."""
    findings: list[Finding] = []

    for result in bandit_json.get("results", []):
        rule_id = result.get("test_id", "")
        hint = _FIX_HINTS.get(rule_id, _DEFAULT_HINT)
        raw_code = result.get("code", "")
        line_no = int(result.get("line_number", 0))
        snippet = raw_code.strip() if verbose else _line_at(raw_code, line_no)

        findings.append(
            Finding(
                file=result.get("filename", ""),
                line=int(result.get("line_number", 0)),
                severity=_severity_from_bandit(result.get("issue_severity", "LOW")),
                category=result.get("test_name", "unknown"),
                description=result.get("issue_text", "").strip(),
                recommendation=hint,
                rule_id=rule_id,
                code_snippet=snippet,
                confidence=result.get("issue_confidence", ""),
            )
        )

    return findings


def _line_at(code: str, line_number: int) -> str:
    """Extract just the offending line's source text from bandit's
    multi-line, number-prefixed `code` context block (e.g. "14 DB_PASSWORD
    = ...").
    """
    target_prefix = f"{line_number} "
    for line in code.splitlines():
        if line.startswith(target_prefix):
            return line[len(target_prefix):].strip()

    # Fallback: bandit's numbering didn't match up (shouldn't normally
    # happen) - just return the first non-blank context line.
    for line in code.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def scan(target: Path, verbose: bool = False) -> tuple[list[Finding], int]:
    """Run a full scan of `target` and return (findings, files_scanned)."""
    bandit_json = run_bandit(target)
    findings = parse_findings(bandit_json, verbose=verbose)

    metrics = bandit_json.get("metrics", {})
    files_scanned = max(len(metrics) - 1, 0) if metrics else 0  # metrics has a "_totals" key

    return findings, files_scanned

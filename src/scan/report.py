"""Renders a list of Findings as text (rich/colored), JSON, or Markdown."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .models import Finding, Severity

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
}


def _counts_by_severity(findings: list[Finding]) -> dict:
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_text(
    findings: list[Finding],
    files_scanned: int,
    target: str,
    verbose: bool = False,
) -> str:
    """Render a colored terminal report, grouped by severity."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, color_system="standard", width=100)

    counts = _counts_by_severity(findings)
    total = len(findings)

    summary_bits = []
    for sev in _SEVERITY_ORDER:
        c = counts[sev]
        if c:
            summary_bits.append(f"[{_SEVERITY_STYLE[sev]}]{sev.value.upper()}: {c}[/]")
    summary_line = "  ".join(summary_bits) if summary_bits else "[bold green]No findings[/]"

    header = Text.from_markup(
        f"[bold]scan[/] — scanned [bold]{target}[/] "
        f"({files_scanned} file{'s' if files_scanned != 1 else ''})\n"
        f"Total findings: [bold]{total}[/]   {summary_line}"
    )
    console.print(Panel(header, expand=False, border_style="blue"))

    if not findings:
        console.print("[bold green]✔ No issues found.[/]")
        return buf.getvalue()

    grouped: dict[Severity, list[Finding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        grouped[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        items = grouped[sev]
        if not items:
            continue

        style = _SEVERITY_STYLE[sev]
        console.print()
        console.print(f"[{style}]{'─' * 4} {sev.value.upper()} ({len(items)}) {'─' * 4}[/]")

        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("Location", style="dim", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Category", no_wrap=True)
        table.add_column("Description")

        for f in sorted(items, key=lambda x: (x.file, x.line)):
            table.add_row(
                f"{f.file}:{f.line}",
                f.rule_id,
                f.category,
                f.description,
            )
        console.print(table)

        for f in sorted(items, key=lambda x: (x.file, x.line)):
            console.print(f"  [dim]→ fix:[/] {f.recommendation}")
            if verbose and f.code_snippet:
                console.print(f"    [dim]{f.file}:{f.line}[/]  [italic]{f.code_snippet}[/]")

    return buf.getvalue()


def render_json(findings: list[Finding], files_scanned: int, target: str) -> str:
    payload = {
        "target": target,
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "counts_by_severity": {
            sev.value: c for sev, c in _counts_by_severity(findings).items()
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def render_markdown(findings: list[Finding], files_scanned: int, target: str) -> str:
    counts = _counts_by_severity(findings)
    total = len(findings)

    lines = []
    lines.append("# scan Security Report")
    lines.append("")
    lines.append(f"**Target:** `{target}`  ")
    lines.append(f"**Files scanned:** {files_scanned}  ")
    lines.append(f"**Total findings:** {total}")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in _SEVERITY_ORDER:
        if counts[sev]:
            lines.append(f"| {sev.value.upper()} | {counts[sev]} |")
    lines.append("")

    if not findings:
        lines.append("✅ No issues found.")
        return "\n".join(lines)

    grouped: dict[Severity, list[Finding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        grouped[f.severity].append(f)

    for sev in _SEVERITY_ORDER:
        items = grouped[sev]
        if not items:
            continue
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}[sev.value]
        lines.append(f"## {emoji} {sev.value.upper()} ({len(items)})")
        lines.append("")
        for f in sorted(items, key=lambda x: (x.file, x.line)):
            lines.append(f"### `{f.file}:{f.line}` — {f.category} ({f.rule_id})")
            lines.append("")
            lines.append(f"{f.description}")
            lines.append("")
            lines.append(f"**Fix:** {f.recommendation}")
            if f.code_snippet:
                lines.append("")
                lines.append("```python")
                lines.append(f.code_snippet)
                lines.append("```")
            lines.append("")

    return "\n".join(lines)

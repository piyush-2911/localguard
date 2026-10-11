"""Command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console

from .models import CONFIDENCE_RANK, finding_sort_key
from .hybrid import run_hybrid
from .scanner import ScanError, scan
from . import report as report_mod

_SEVERITY_CHOICES = ["low", "medium", "high", "critical"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_CHOICES)}

_err_console = Console(stderr=True)


@click.group()
@click.version_option(package_name="scan")
def main() -> None:
    """Load project-local configuration before parsing the scan command."""
    load_dotenv(Path.cwd() / ".env", override=False)


@main.command(name="scan")
@click.argument("path", type=click.Path(path_type=Path))
@click.option(
    "--severity-threshold",
    type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
    default="low",
    show_default=True,
    help="Only report findings at or above this severity.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "markdown"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Report output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(path_type=Path),
    default=None,
    help="Write the report to a file instead of stdout.",
)
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Show extra detail (full code snippet per finding).",
)
@click.option("--llm-only", is_flag=True, help="Review with an LLM instead of running Bandit.")
@click.option("--structured-output", envvar="SCAN_STRUCTURED_OUTPUT",
              type=click.Choice(["auto", "required", "off"]), default="auto", show_default=True,
              help="Request JSON schema; auto falls back only on explicit unsupported-format errors.")
@click.option("--static-only", is_flag=True, help="Run Bandit without LLM review.")
@click.option("--merge-tolerance", type=click.IntRange(min=0), default=3, show_default=True)
@click.option("--min-confidence", type=click.Choice(list(CONFIDENCE_RANK)), default="needs-review", show_default=True)
@click.option("--model", envvar="SCAN_MODEL", help="Model identifier served by your endpoint (SCAN_MODEL).")
@click.option("--base-url", envvar="SCAN_BASE_URL", default="http://localhost:11434/v1",
              show_default=True, help="OpenAI-compatible API base URL (SCAN_BASE_URL).")
@click.option("--api-key", envvar="SCAN_API_KEY", default="not-needed", help="Endpoint API key; prefer SCAN_API_KEY.")
@click.option("--timeout", envvar="SCAN_TIMEOUT", type=click.FloatRange(min=0.1), default=120, show_default=True,
              help="LLM request timeout in seconds.")
@click.option("--max-tokens", envvar="SCAN_MAX_TOKENS", type=click.IntRange(min=64), default=1024,
              show_default=True, help="Maximum tokens the model may generate per chunk.")
@click.option("--max-findings", envvar="SCAN_MAX_FINDINGS", type=click.IntRange(min=1), default=10,
              show_default=True, help="Maximum highest-impact findings requested per chunk.")
@click.option("--chunk-chars", type=click.IntRange(min=256), default=12000, show_default=True,
              help="Maximum numbered source characters per LLM request.")
@click.option("--chunk-lines", type=click.IntRange(min=1), default=250, show_default=True,
              help="Maximum lines per LLM chunk.")
@click.option("--chunk-overlap", type=click.IntRange(min=0), default=20, show_default=True,
              help="Context lines repeated between chunks; must be smaller than --chunk-lines.")
def scan_cmd(path: Path, severity_threshold: str, output_format: str, output_file: Path,
             verbose: bool, llm_only: bool, model: str, base_url: str, api_key: str,
             timeout: float, max_tokens: int, max_findings: int, chunk_chars: int,
             chunk_lines: int, chunk_overlap: int, static_only: bool,
             merge_tolerance: int, min_confidence: str, structured_output: str) -> None:
    """Scan PATH (a file or directory) for security issues."""
    if llm_only and static_only:
        raise click.UsageError("--static-only and --llm-only are mutually exclusive.")

    def review_llm():
        from .llm import ReviewClient, scan_llm
        if chunk_overlap >= chunk_lines:
            raise ScanError("--chunk-overlap must be smaller than --chunk-lines.")
        client = ReviewClient(base_url, model or "", api_key, timeout, max_tokens, max_findings,
                              structured_output=structured_output)
        try:
            return scan_llm(
                path, client, chunk_chars, verbose, chunk_lines, chunk_overlap,
                progress=lambda message: _err_console.print(message, markup=False),
            )
        finally:
            client.close()

    try:
        if llm_only:
            findings, files_scanned = review_llm()
            metadata = {"analyzers": {"static": "not-requested", "llm": "available"},
                        "analyzer_contributions": {"static": 0, "llm": len(findings)}}
        elif static_only:
            findings, files_scanned = scan(path, verbose=verbose)
            metadata = {"analyzers": {"static": "available", "llm": "not-requested"},
                        "analyzer_contributions": {"static": len(findings), "llm": 0}}
        else:
            findings, files_scanned, metadata = run_hybrid(
                lambda: scan(path, verbose=verbose), review_llm, merge_tolerance,
                warning=lambda message: click.echo(f"Warning: {message}", err=True))
    except ScanError as exc:
        _err_console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001 - last-resort guard against stack traces
        _err_console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(2)

    threshold_rank = _SEVERITY_RANK[severity_threshold.lower()]
    confident = [f for f in findings if CONFIDENCE_RANK[f.confidence] >= CONFIDENCE_RANK[min_confidence]]
    filtered = sorted((f for f in confident if _SEVERITY_RANK[f.severity.value] >= threshold_rank),
                      key=finding_sort_key)

    target_str = str(path)

    if output_format == "json":
        rendered = report_mod.render_json(filtered, files_scanned, target_str, metadata=metadata)
    elif output_format == "markdown":
        rendered = report_mod.render_markdown(filtered, files_scanned, target_str, verbose=verbose, metadata=metadata)
    else:
        rendered = report_mod.render_text(filtered, files_scanned, target_str, verbose=verbose, metadata=metadata)

    if output_file:
        try:
            output_file.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            _err_console.print(f"[bold red]Error writing output file:[/bold red] {exc}")
            sys.exit(2)
        _err_console.print(f"[green]Report written to {output_file}[/green]")
    else:
        # For text format, print raw (already has ANSI codes from rich).
        # For json/markdown, print plainly.
        click.echo(rendered)

    sys.exit(1 if filtered else 0)


main.add_command(scan_cmd, name="scan")


if __name__ == "__main__":
    main()

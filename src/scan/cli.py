"""Command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from .models import Severity
from .scanner import ScanError, scan
from . import report as report_mod

_SEVERITY_CHOICES = ["low", "medium", "high", "critical"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_CHOICES)}

_err_console = Console(stderr=True)


@click.group()
@click.version_option(package_name="scan")
def main() -> None:
    pass


@main.command()
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
def scan_cmd(path: Path, severity_threshold: str, output_format: str, output_file: Path, verbose: bool) -> None:
    """Scan PATH (a file or directory) for security issues."""
    try:
        findings, files_scanned = scan(path, verbose=verbose)
    except ScanError as exc:
        _err_console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001 - last-resort guard against stack traces
        _err_console.print(f"[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(2)

    threshold_rank = _SEVERITY_RANK[severity_threshold.lower()]
    filtered = [f for f in findings if _SEVERITY_RANK[f.severity.value] >= threshold_rank]

    target_str = str(path)

    if output_format == "json":
        rendered = report_mod.render_json(filtered, files_scanned, target_str)
    elif output_format == "markdown":
        rendered = report_mod.render_markdown(filtered, files_scanned, target_str)
    else:
        rendered = report_mod.render_text(filtered, files_scanned, target_str, verbose=verbose)

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

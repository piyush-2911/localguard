"""Analyzer orchestration and graceful fallback."""
from .merge import merge_findings
from .scanner import ScanError


def run_hybrid(static_scan, llm_scan, tolerance=3, warning=None):
    results, counts, status = {}, {}, {}
    for name, analyze in (("static", static_scan), ("llm", llm_scan)):
        try:
            findings, files = analyze()
            results[name], counts[name] = findings, files
            status[name] = "available"
        except Exception as exc:
            results[name], counts[name] = [], 0
            label = "LLM" if name == "llm" else "Static"
            status[name] = f"{label} analysis unavailable"
            if warning:
                # Only expected scan errors have safe, user-facing details.
                detail = str(exc) if isinstance(exc, ScanError) else type(exc).__name__
                warning(f"{status[name]}: {detail}")
    if all(value != "available" for value in status.values()):
        raise ScanError("Both analyzers failed: Static analysis unavailable; LLM analysis unavailable.")
    return (merge_findings(results["static"], results["llm"], tolerance),
            max(counts.values()),
            {"analyzers": status, "analyzer_contributions": {k: len(v) for k, v in results.items()}})

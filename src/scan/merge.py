"""Pure, deterministic finding normalization, deduplication and reconciliation."""
from dataclasses import replace
import posixpath

from .categories import BANDIT_CATEGORIES, normalize_category
from .models import Finding, finding_sort_key


def file_key(file: str) -> str:
    return posixpath.normpath(file.replace("\\", "/"))


def line_gap(a: Finding, b: Finding) -> int:
    return max(0, a.line - (b.end_line or b.line), b.line - (a.end_line or a.line))


def normalize(f: Finding) -> Finding:
    source = "static" if f.source in ("bandit", "static") else "llm"
    category = (BANDIT_CATEGORIES.get(f.rule_id, "other") if source == "static"
                else normalize_category(f.category))
    return replace(f, category=category, source=source,
                   confidence="likely" if source == "static" else "needs-review",
                   original_severities={source: f.severity.value},
                   explanations={source: f.description})


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse repeated reports at overlapping ranges; retain distinct static rules.

    Proximity alone is only used across analyzers, to avoid collapsing nearby
    independent issues from a single analyzer.
    """
    result = []
    for item in sorted(findings, key=finding_sort_key):
        duplicate = next((f for f in result if file_key(f.file) == file_key(item.file)
                          and f.category == item.category and f.source == item.source
                          and f.rule_id == item.rule_id and line_gap(f, item) == 0
                          and (f.category != "other" or f.description == item.description)), None)
        if duplicate is None:
            result.append(item)
    return result


def merge_findings(static: list[Finding], llm: list[Finding], tolerance: int = 3) -> list[Finding]:
    if tolerance < 0:
        raise ValueError("Merge tolerance must be non-negative")
    left = deduplicate([normalize(f) for f in static])
    right = deduplicate([normalize(f) for f in llm])
    # Nearest matches first, one-to-one. No transitive chains across nearby issues.
    candidates = sorted((line_gap(a, b), i, j) for i, a in enumerate(left)
                        for j, b in enumerate(right)
                        if file_key(a.file) == file_key(b.file) and a.category == b.category
                        and line_gap(a, b) <= tolerance)
    used_left, used_right, result = set(), set(), []
    for _, i, j in candidates:
        if i in used_left or j in used_right:
            continue
        a, b = left[i], right[j]
        result.append(replace(a, severity=max(a.severity, b.severity, key=lambda s: s.rank),
                              description=b.description, recommendation=b.recommendation,
                              source="static+llm", confidence="confirmed",
                              original_severities={"static": a.severity.value, "llm": b.severity.value},
                              explanations={"static": a.description, "llm": b.description}))
        used_left.add(i)
        used_right.add(j)
    result.extend(f for i, f in enumerate(left) if i not in used_left)
    result.extend(f for j, f in enumerate(right) if j not in used_right)
    return sorted(result, key=finding_sort_key)

"""Data models shared across the scanner and report layers."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum


class Severity(str, Enum):
    """Normalized severity levels, ordered from lowest to highest."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass
class Finding:
    """A single normalized security finding.

    `category` uses the shared canonical taxonomy. `rule_id` retains Bandit's
    test ID on static/merged findings. Original evidence is keyed by analyzer.
    """

    file: str
    line: int
    severity: Severity
    category: str
    description: str
    recommendation: str
    rule_id: str
    code_snippet: str = ""
    confidence: str = "likely"
    source: str = "static"
    end_line: int | None = None
    original_severities: dict = field(default_factory=dict)
    explanations: dict = field(default_factory=dict)
    bandit_confidence: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanSummary:
    """Aggregate counts for a scan, used in report headers."""

    total: int = 0
    counts_by_severity: dict = field(default_factory=dict)
    files_scanned: int = 0


CONFIDENCE_RANK = {"needs-review": 0, "likely": 1, "confirmed": 2}


def finding_sort_key(finding: Finding) -> tuple:
    return (-finding.severity.rank, -CONFIDENCE_RANK.get(finding.confidence, 0),
            finding.file, finding.line, finding.category, finding.rule_id)

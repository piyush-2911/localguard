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

    `category` is Bandit's test name (e.g. "hardcoded_password_string"),
    `rule_id` is Bandit's short test id (e.g. "B105").
    """

    file: str
    line: int
    severity: Severity
    category: str
    description: str
    recommendation: str
    rule_id: str
    code_snippet: str = ""
    confidence: str = ""
    source: str = "bandit"

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

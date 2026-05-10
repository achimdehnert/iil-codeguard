"""Core domain types for iil-codeguard.

Per ADR-191 v1.1 §Output Schema: all checkers emit `Finding` objects which
reporters render as SARIF 2.1.0, JSON, or text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    """SARIF 2.1.0 severity levels (mapped from internal severity)."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    def sarif_level(self) -> str:
        """Map to SARIF level field. SARIF only has 4 levels."""
        return {
            Severity.CRITICAL: "error",
            Severity.ERROR: "error",
            Severity.WARNING: "warning",
            Severity.INFO: "note",
        }[self]

    def order(self) -> int:
        """For sorting and severity_threshold filtering."""
        return {
            Severity.INFO: 0,
            Severity.WARNING: 1,
            Severity.ERROR: 2,
            Severity.CRITICAL: 3,
        }[self]


@dataclass(frozen=True)
class Location:
    """Source code location of a finding."""

    file_path: str
    start_line: int
    start_column: int = 1
    end_line: int | None = None
    end_column: int | None = None

    def relative_to(self, root: Path) -> Location:
        """Return a copy with file_path made relative to root."""
        try:
            rel = Path(self.file_path).resolve().relative_to(root.resolve())
            return Location(
                file_path=str(rel),
                start_line=self.start_line,
                start_column=self.start_column,
                end_line=self.end_line,
                end_column=self.end_column,
            )
        except ValueError:
            return self


@dataclass(frozen=True)
class Finding:
    """A single rule violation reported by a checker.

    Stable across versions: rule_id, severity, message.
    """

    rule_id: str
    """Stable identifier like 'SL-001', 'HX-009', 'DC-001'."""

    severity: Severity

    message: str
    """Human-readable, one sentence, no trailing period."""

    location: Location

    fix_hint: str | None = None
    """Optional suggestion for how to fix this finding."""

    context: dict[str, str] = field(default_factory=dict)
    """Optional structured context (e.g. model_name, attribute_name)."""


@dataclass
class AuditResult:
    """Result of an audit run over one or more files."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_ms: int = 0

    def filter_by_severity(self, threshold: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity.order() >= threshold.order()]

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def counts_by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
        return counts


# Rule registry — central source for rule metadata
@dataclass(frozen=True)
class RuleMeta:
    """Metadata for a rule. Used by `codeguard list-rules` and reporters."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    category: str  # SL, HX, DC, DF, NX
    adr_refs: tuple[str, ...]  # e.g. ("ADR-009", "ADR-192")


RULE_REGISTRY: dict[str, RuleMeta] = {}


def register_rule(meta: RuleMeta) -> None:
    """Register a rule. Idempotent."""
    RULE_REGISTRY[meta.rule_id] = meta


def get_rule(rule_id: str) -> RuleMeta | None:
    return RULE_REGISTRY.get(rule_id)

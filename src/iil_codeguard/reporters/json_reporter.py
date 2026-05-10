"""Flat JSON reporter — for MCP / programmatic consumption."""

from __future__ import annotations

import json
from dataclasses import asdict

from iil_codeguard.domain import AuditResult


def render(result: AuditResult, summary_only: bool = False) -> str:
    """Render an AuditResult as a flat JSON string.

    summary_only: if True, omits individual findings — only counts.
    Used by MCP `codeguard_audit` to stay within token budget.
    """
    payload = {
        "version": "1",
        "files_scanned": result.files_scanned,
        "duration_ms": result.duration_ms,
        "counts_by_severity": result.counts_by_severity(),
        "counts_by_rule": result.counts_by_rule(),
    }
    if not summary_only:
        payload["findings"] = [_finding_dict(f) for f in result.findings]
    return json.dumps(payload, indent=2)


def _finding_dict(finding) -> dict:
    d = {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "message": finding.message,
        "location": asdict(finding.location),
    }
    if finding.fix_hint:
        d["fix_hint"] = finding.fix_hint
    if finding.context:
        d["context"] = finding.context
    return d

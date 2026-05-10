"""SARIF 2.1.0 reporter for GitHub Code Scanning native integration.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
Schema: https://json.schemastore.org/sarif-2.1.0.json
"""

from __future__ import annotations

import json

from iil_codeguard import __version__
from iil_codeguard.domain import RULE_REGISTRY, AuditResult


def render(result: AuditResult) -> str:
    """Render an AuditResult as SARIF 2.1.0 JSON string."""
    return json.dumps(_to_sarif(result), indent=2)


def _to_sarif(result: AuditResult) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "iil-codeguard",
                    "version": __version__,
                    "informationUri": "https://github.com/achimdehnert/iil-codeguard",
                    "rules": _rules_for_findings(result),
                },
            },
            "results": [_finding_to_result(f) for f in result.findings],
            "columnKind": "utf16CodeUnits",
        }],
    }


def _rules_for_findings(result: AuditResult) -> list[dict]:
    """Return SARIF rule definitions for all rule_ids present in findings."""
    seen = set()
    rules = []
    for f in result.findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        meta = RULE_REGISTRY.get(f.rule_id)
        if meta is None:
            rules.append({
                "id": f.rule_id,
                "shortDescription": {"text": f.rule_id},
                "fullDescription": {"text": f.rule_id},
            })
            continue
        rules.append({
            "id": meta.rule_id,
            "name": meta.name,
            "shortDescription": {"text": meta.description},
            "fullDescription": {"text": meta.description},
            "defaultConfiguration": {"level": meta.severity.sarif_level()},
            "properties": {
                "category": meta.category,
                "adr_refs": list(meta.adr_refs),
            },
        })
    return rules


def _finding_to_result(finding) -> dict:
    region = {
        "startLine": finding.location.start_line,
        "startColumn": finding.location.start_column,
    }
    if finding.location.end_line:
        region["endLine"] = finding.location.end_line
    if finding.location.end_column:
        region["endColumn"] = finding.location.end_column

    result = {
        "ruleId": finding.rule_id,
        "level": finding.severity.sarif_level(),
        "message": {"text": finding.message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": finding.location.file_path},
                "region": region,
            },
        }],
    }
    if finding.fix_hint:
        result["fixes"] = [{
            "description": {"text": finding.fix_hint},
        }]
    if finding.context:
        result["properties"] = dict(finding.context)
    return result

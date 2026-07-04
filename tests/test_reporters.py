"""Tests for SARIF, JSON, and text reporters."""

from __future__ import annotations

import json

from iil_codeguard.domain import AuditResult, Finding, Location, Severity
from iil_codeguard.reporters import json_reporter, sarif, text


def _result_with_finding() -> AuditResult:
    return AuditResult(
        findings=[
            Finding(
                rule_id="SL-001",
                severity=Severity.ERROR,
                message="Direct ORM access via Trip.objects",
                location=Location("apps/trips/views.py", 12, 8),
                fix_hint="Move to services",
            )
        ],
        files_scanned=1,
        duration_ms=42,
    )


def test_should_emit_valid_sarif_2_1_0_structure():
    result = _result_with_finding()
    output = sarif.render(result)
    doc = json.loads(output)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert doc["runs"][0]["tool"]["driver"]["name"] == "iil-codeguard"
    res = doc["runs"][0]["results"][0]
    assert res["ruleId"] == "SL-001"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 12


def test_should_register_rule_definitions_in_sarif():
    result = _result_with_finding()
    doc = json.loads(sarif.render(result))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert any(r["id"] == "SL-001" for r in rules)


def test_should_emit_json_with_summary_only():
    result = _result_with_finding()
    output = json_reporter.render(result, summary_only=True)
    doc = json.loads(output)
    assert doc["counts_by_severity"]["error"] == 1
    assert "findings" not in doc


def test_should_emit_json_with_findings():
    result = _result_with_finding()
    doc = json.loads(json_reporter.render(result, summary_only=False))
    assert len(doc["findings"]) == 1
    assert doc["findings"][0]["rule_id"] == "SL-001"


def test_should_emit_text_with_no_findings():
    out = text.render(AuditResult(files_scanned=3, duration_ms=10), use_color=False)
    assert "No findings" in out


def test_should_emit_text_with_findings():
    out = text.render(_result_with_finding(), use_color=False)
    assert "SL-001" in out
    assert "Direct ORM access" in out
    assert "Summary" in out

"""Smoke tests for the MCP server.

Calls the underlying tool functions directly (without spinning up the server).
"""

from __future__ import annotations

import importlib.util

import pytest

mcp_available = importlib.util.find_spec("fastmcp") is not None

pytestmark = pytest.mark.skipif(
    not mcp_available, reason="fastmcp not installed (use pip install iil-codeguard[mcp])"
)


def test_should_audit_via_mcp_tool_summary_only(tmp_path):
    from iil_codeguard.mcp_server.server import AuditRequest, codeguard_audit

    (tmp_path / "views.py").write_text(
        "def x(r):\n    return Trip.objects.all()\n",
        encoding="utf-8",
    )
    result = codeguard_audit(
        AuditRequest(
            repo_path=str(tmp_path),
            severity_threshold="info",
            summary_only=True,
        )
    )
    assert result["files_scanned"] >= 1
    assert result["counts_by_rule"].get("SL-001", 0) == 1
    assert "findings" not in result  # summary mode


def test_should_audit_with_findings(tmp_path):
    from iil_codeguard.mcp_server.server import AuditRequest, codeguard_audit

    (tmp_path / "views.py").write_text(
        "def x(r):\n    return Trip.objects.all()\n",
        encoding="utf-8",
    )
    result = codeguard_audit(
        AuditRequest(
            repo_path=str(tmp_path),
            summary_only=False,
            max_findings=10,
        )
    )
    assert "findings" in result
    assert any(f["rule_id"] == "SL-001" for f in result["findings"])


def test_should_check_single_file_via_mcp(tmp_path):
    from iil_codeguard.mcp_server.server import CheckFileRequest, codeguard_check_file

    f = tmp_path / "views.py"
    f.write_text("def x(r):\n    Trip.objects.all()\n", encoding="utf-8")
    result = codeguard_check_file(CheckFileRequest(file_path=str(f)))
    assert result["counts_by_rule"].get("SL-001", 0) == 1
    assert any(x["rule_id"] == "SL-001" for x in result["findings"])


def test_should_list_rules_via_mcp():
    from iil_codeguard.mcp_server.server import codeguard_list_rules

    result = codeguard_list_rules()
    assert result["rule_count"] >= 24  # SL+HX+DC+DF
    rule_ids = {r["rule_id"] for r in result["rules"]}
    assert "SL-001" in rule_ids
    assert "DC-001" in rule_ids
    assert "DF-001" in rule_ids


def test_should_filter_rules_by_category():
    from iil_codeguard.mcp_server.server import codeguard_list_rules

    result = codeguard_list_rules(category="DC")
    assert all(r["category"] == "DC" for r in result["rules"])
    assert result["rule_count"] >= 8


def test_should_handle_missing_path_gracefully(tmp_path):
    from iil_codeguard.mcp_server.server import AuditRequest, codeguard_audit

    result = codeguard_audit(
        AuditRequest(
            repo_path=str(tmp_path / "nonexistent"),
        )
    )
    assert "error" in result

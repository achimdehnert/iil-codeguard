"""Smoke tests for the codeguard CLI."""

from __future__ import annotations

import json

import pytest

from iil_codeguard.cli import main


def test_should_print_version(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0


def test_should_list_rules(capsys):
    rc = main(["list-rules"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SL-001" in out
    assert "HX-001" in out
    assert "HX-009" in out


def test_should_filter_rules_by_category(capsys):
    rc = main(["list-rules", "--category", "HX"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "HX-001" in out
    assert "SL-001" not in out


def test_should_audit_clean_repo(tmp_path, capsys):
    # Empty repo — no findings expected
    rc = main(["audit", str(tmp_path), "--format", "text"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No findings" in out


def test_should_emit_sarif_for_violations(tmp_path, capsys):
    views = tmp_path / "apps" / "trips"
    views.mkdir(parents=True)
    (views / "views.py").write_text(
        "def x(request):\n    return Trip.objects.all()\n",
        encoding="utf-8",
    )
    rc = main(["audit", str(tmp_path), "--format", "sarif"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert any(r["ruleId"] == "SL-001" for r in doc["runs"][0]["results"])


def test_should_exit_nonzero_with_exit_code_flag(tmp_path, capsys):
    (tmp_path / "views.py").write_text(
        "def x(r):\n    Trip.objects.all()\n",
        encoding="utf-8",
    )
    rc = main([
        "audit", str(tmp_path), "--format", "text",
        "--severity-threshold", "error", "--exit-code",
    ])
    assert rc == 1


def test_should_check_single_file(tmp_path, capsys):
    f = tmp_path / "views.py"
    f.write_text("def x(r):\n    Trip.objects.all()\n", encoding="utf-8")
    rc = main(["check-file", str(f), "--format", "text"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SL-001" in out

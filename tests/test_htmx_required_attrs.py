"""Tests for HX-001..009 HTMX template scanning."""

from __future__ import annotations

from pathlib import Path

from iil_codeguard.checkers import htmx_required_attrs


def _write(tmp: Path, name: str, source: str) -> Path:
    f = tmp / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(source, encoding="utf-8")
    return f


# HX-001 / HX-002 ------------------------------------------------------------


def test_should_detect_missing_hx_target_and_swap(tmp_path):
    f = _write(
        tmp_path,
        "page.html",
        """
<button hx-get="/api/trips/">Click</button>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-001" in rule_ids
    assert "HX-002" in rule_ids


def test_should_pass_complete_htmx_element(tmp_path):
    f = _write(
        tmp_path,
        "page.html",
        """
<button hx-get="/api/trips/" hx-target="#main" hx-swap="innerHTML"
        hx-indicator="#spinner" data-testid="trips-btn">Click</button>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    err_ids = {x.rule_id for x in findings if x.severity.order() >= 2}
    assert err_ids == set()


# HX-003 / HX-004 ------------------------------------------------------------


def test_should_warn_on_missing_indicator_and_testid(tmp_path):
    f = _write(
        tmp_path,
        "page.html",
        """
<button hx-post="/api/x/" hx-target="#out" hx-swap="innerHTML">Submit</button>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-003" in rule_ids
    assert "HX-004" in rule_ids


# HX-005 ----------------------------------------------------------------------


def test_should_detect_hx_boost(tmp_path):
    f = _write(tmp_path, "page.html", '<a href="/x" hx-boost="true">link</a>\n')
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-005" in rule_ids


# HX-006 ----------------------------------------------------------------------


def test_should_detect_onclick_with_htmx(tmp_path):
    f = _write(
        tmp_path,
        "page.html",
        """
<button hx-get="/x" hx-target="#out" hx-swap="innerHTML"
        hx-indicator="#sp" data-testid="b" onclick="alert(1)">X</button>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-006" in rule_ids


# HX-007 ----------------------------------------------------------------------


def test_should_detect_hx_post_form_without_csrf(tmp_path):
    f = _write(
        tmp_path,
        "page.html",
        """
<form hx-post="/x/" hx-target="#out" hx-swap="innerHTML"
      hx-indicator="#sp" data-testid="f">
  <input name="x">
</form>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-007" in rule_ids


def test_should_pass_hx_post_form_with_csrf(tmp_path):
    f = _write(
        tmp_path,
        "page.html",
        """
<form hx-post="/x/" hx-target="#out" hx-swap="innerHTML"
      hx-indicator="#sp" data-testid="f">
  {% csrf_token %}
  <input name="x">
</form>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-007" not in rule_ids


# HX-008 ----------------------------------------------------------------------


def test_should_detect_extends_in_partial(tmp_path):
    f = _write(
        tmp_path,
        "_partial.html",
        """
{% extends "base.html" %}
<div>partial</div>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-008" in rule_ids


def test_should_pass_clean_partial(tmp_path):
    f = _write(tmp_path, "_partial.html", "<div>partial fragment</div>\n")
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-008" not in rule_ids


# HX-009 — Trip-Wire ---------------------------------------------------------


def test_should_detect_django_tag_between_htmx_attrs(tmp_path):
    """Pathological case: {% if %} between HTMX attributes (ADR-192 §HX-009)."""
    f = _write(
        tmp_path,
        "page.html",
        """
<div hx-get="/x"
     {% if user.is_authenticated %}hx-target="#main"{% endif %}
     hx-swap="innerHTML">
</div>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-009" in rule_ids


def test_should_not_flag_django_tag_inside_attribute_value(tmp_path):
    """Common case: {% url %} inside an attribute value — must NOT trigger HX-009."""
    f = _write(
        tmp_path,
        "page.html",
        """
<button hx-get="{% url 'trips:detail' trip.id %}"
        hx-target="#main" hx-swap="innerHTML"
        hx-indicator="#spinner" data-testid="x">View</button>
""",
    )
    findings = htmx_required_attrs.check_file(f)
    rule_ids = {x.rule_id for x in findings}
    assert "HX-009" not in rule_ids


# Non-template files ---------------------------------------------------------


def test_should_skip_non_html_files(tmp_path):
    f = _write(tmp_path, "page.txt", "<button hx-get='x'>x</button>\n")
    findings = htmx_required_attrs.check_file(f)
    assert findings == []

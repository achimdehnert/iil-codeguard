"""HX-001..009: Validate HTMX templates against ADR-048.

Per ADR-192 v1.1 §2: Empirical validation showed `html.parser` is sufficient
for the realistic patterns in our codebase (940 HTMX elements, 0 pathological
`{% if %}` between attributes). HX-009 trip-wire detects the pathological
case via regex pre-scan.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

from iil_codeguard.domain import (
    Finding,
    Location,
    RuleMeta,
    Severity,
    register_rule,
)

# Rule registration ----------------------------------------------------------

register_rule(
    RuleMeta(
        rule_id="HX-001",
        name="missing-hx-target",
        description="HTMX element missing required hx-target",
        severity=Severity.ERROR,
        category="HX",
        adr_refs=("ADR-048", "ADR-192"),
    )
)
register_rule(
    RuleMeta(
        rule_id="HX-002",
        name="missing-hx-swap",
        description="HTMX element missing required hx-swap",
        severity=Severity.ERROR,
        category="HX",
        adr_refs=("ADR-048", "ADR-192"),
    )
)
register_rule(
    RuleMeta(
        rule_id="HX-003",
        name="missing-hx-indicator",
        description="HTMX element missing hx-indicator",
        severity=Severity.WARNING,
        category="HX",
        adr_refs=("ADR-048", "ADR-192"),
    )
)
register_rule(
    RuleMeta(
        rule_id="HX-004",
        name="missing-data-testid",
        description="HTMX element missing data-testid for testability",
        severity=Severity.WARNING,
        category="HX",
        adr_refs=("ADR-048", "ADR-192"),
    )
)
register_rule(
    RuleMeta(
        rule_id="HX-005",
        name="hx-boost-banned",
        description="hx-boost banned by ADR-048 (multi-tenant performance issue)",
        severity=Severity.ERROR,
        category="HX",
        adr_refs=("ADR-048",),
    )
)
register_rule(
    RuleMeta(
        rule_id="HX-006",
        name="onclick-with-htmx",
        description="onclick= mixed with hx-* attributes",
        severity=Severity.ERROR,
        category="HX",
        adr_refs=("ADR-048",),
    )
)
register_rule(
    RuleMeta(
        rule_id="HX-007",
        name="hx-post-no-csrf",
        description="hx-post form without {% csrf_token %} in same template",
        severity=Severity.INFO,
        category="HX",
        adr_refs=("ADR-048",),
    )
)
register_rule(
    RuleMeta(
        rule_id="HX-008",
        name="partial-extends",
        description="Partial template (_*.html) contains {% extends %} — should be a fragment",
        severity=Severity.ERROR,
        category="HX",
        adr_refs=("ADR-041", "ADR-048"),
    )
)
register_rule(
    RuleMeta(
        rule_id="HX-009",
        name="django-tag-between-htmx-attrs",
        description=(
            "Django template tag ({% %}) between HTMX attributes — html.parser cannot "
            "reliably parse this; move {% if %} to wrap the entire element"
        ),
        severity=Severity.ERROR,
        category="HX",
        adr_refs=("ADR-048", "ADR-192"),
    )
)


# HX-009 Pre-Scan -----------------------------------------------------------

# Matches: hx-attr=... followed by {% something %} followed by another attribute
# (the pathological case from ADR-192 §HX-009).
_HX_BETWEEN_ATTRS_RE = re.compile(
    # Whitespace, then Django tag, then immediately an identifier char.
    # The "immediate identifier" check excludes:
    #   hx-get="{% url 'foo' %}"   — { is preceded by `"` (no match)
    #   hx-get="x {% url 'foo' %}" — { is inside quotes (no match)
    # And matches:
    #   <div hx-get="/x" {% if u %}hx-target="..."{% endif %}>
    #   <div {% if u %}hx-target="x"{% endif %} hx-swap="...">
    r"""\s                # whitespace before {%
        \{%[^%]+?%\}      # Django template tag (non-greedy)
        [A-Za-z_][\w-]*=  # immediately followed by attribute name + =
    """,
    re.VERBOSE,
)


def _is_inside_quoted_attr(source: str, pos: int) -> bool:
    """Check whether `pos` lies inside a quoted attribute value.

    Walks backwards from pos counting unescaped quote characters on the same
    line. Returns True if the position is inside an open quoted string.
    """
    line_start = source.rfind("\n", 0, pos) + 1
    segment = source[line_start:pos]
    quotes = sum(1 for c in segment if c == '"') + sum(1 for c in segment if c == "'")
    return quotes % 2 == 1


def _scan_hx_009(source: str, file_path: Path) -> list[Finding]:
    """Pre-scan source for HX-009 (Django tag between HTMX attributes).

    Phase 1: regex-based; this is intentionally conservative — false positives
    are preferable to silent false negatives.
    """
    findings: list[Finding] = []
    for match in _HX_BETWEEN_ATTRS_RE.finditer(source):
        # Skip matches inside quoted attribute values
        if _is_inside_quoted_attr(source, match.start()):
            continue
        # Skip if the surrounding element has no hx-* attribute
        # (rough heuristic: look for "hx-" within 200 chars before the match)
        window_start = max(0, match.start() - 200)
        window = source[window_start : match.start()]
        if "hx-" not in window:
            continue
        line = source.count("\n", 0, match.start()) + 1
        col = match.start() - source.rfind("\n", 0, match.start())
        findings.append(
            Finding(
                rule_id="HX-009",
                severity=Severity.ERROR,
                message=(
                    "Django template tag between HTMX attributes — html.parser "
                    "cannot parse this reliably"
                ),
                location=Location(
                    file_path=str(file_path),
                    start_line=line,
                    start_column=max(col, 1),
                ),
                fix_hint=(
                    "Move {% if %} to wrap the entire element instead of between "
                    "attributes (split into two element variants if needed)"
                ),
            )
        )
    return findings


# HTML parser ----------------------------------------------------------------


class HTMXLinter(HTMLParser):
    """Walk an HTML/Django template and emit HX-* findings."""

    def __init__(self, file_path: Path, is_partial: bool, has_csrf_token: bool):
        super().__init__(convert_charrefs=False)
        self.file_path = str(file_path)
        self.is_partial = is_partial
        self.has_csrf_token = has_csrf_token
        self.findings: list[Finding] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {k: (v or "") for k, v in attrs}

        # HX-005: hx-boost
        if "hx-boost" in attrs_dict:
            self._add(
                "HX-005",
                Severity.ERROR,
                f"<{tag}> uses hx-boost (banned by ADR-048)",
                fix_hint="Replace with explicit hx-get / hx-post on individual links",
            )
            # Continue to also report missing required attrs

        hx_attrs = {k: v for k, v in attrs_dict.items() if k.startswith("hx-")}
        if not hx_attrs:
            return

        # HX-006: onclick + hx-*
        if "onclick" in attrs_dict:
            self._add(
                "HX-006",
                Severity.ERROR,
                f"<{tag}> mixes onclick= with hx-* attributes",
                fix_hint="Use hx-trigger or remove onclick handler",
            )

        # HX-001/002: required triggers (hx-target, hx-swap)
        # Only require if the element has an action attr (hx-get/post/put/delete/patch).
        action_attrs = {"hx-get", "hx-post", "hx-put", "hx-patch", "hx-delete"}
        if any(a in hx_attrs for a in action_attrs):
            if "hx-target" not in hx_attrs:
                self._add(
                    "HX-001",
                    Severity.ERROR,
                    f"<{tag}> with hx-{_first_action(hx_attrs)} is missing hx-target",
                )
            if "hx-swap" not in hx_attrs:
                self._add(
                    "HX-002",
                    Severity.ERROR,
                    f"<{tag}> with hx-{_first_action(hx_attrs)} is missing hx-swap",
                )
            if "hx-indicator" not in hx_attrs:
                self._add(
                    "HX-003",
                    Severity.WARNING,
                    f"<{tag}> with hx-{_first_action(hx_attrs)} is missing hx-indicator",
                )
            if "data-testid" not in attrs_dict:
                self._add(
                    "HX-004",
                    Severity.WARNING,
                    f"<{tag}> HTMX element is missing data-testid for testability",
                )

        # HX-007: hx-post on form without csrf_token
        if tag == "form" and "hx-post" in hx_attrs and not self.has_csrf_token:
            self._add(
                "HX-007",
                Severity.INFO,
                "<form hx-post> without {% csrf_token %} in the same template",
                fix_hint="Add {% csrf_token %} as the first child of the form",
            )

    def _add(
        self,
        rule_id: str,
        severity: Severity,
        message: str,
        fix_hint: str | None = None,
    ) -> None:
        line, col = self.getpos()
        self.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                location=Location(
                    file_path=self.file_path,
                    start_line=line,
                    start_column=max(col, 1),
                ),
                fix_hint=fix_hint,
            )
        )


def _first_action(hx_attrs: dict[str, str]) -> str:
    for a in ("hx-get", "hx-post", "hx-put", "hx-patch", "hx-delete"):
        if a in hx_attrs:
            return a.replace("hx-", "")
    return "?"


# Public API -----------------------------------------------------------------


def check_file(file_path: Path) -> list[Finding]:
    """Check a single .html template for HTMX compliance."""
    if file_path.suffix != ".html":
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []

    # HX-009 pre-scan (regex)
    findings.extend(_scan_hx_009(source, file_path))

    # HX-008: partial templates with {% extends %}
    if file_path.name.startswith("_") and "{% extends" in source:
        findings.append(
            Finding(
                rule_id="HX-008",
                severity=Severity.ERROR,
                message=(
                    f"Partial template '{file_path.name}' contains "
                    "{% extends %} — should be a fragment"
                ),
                location=Location(file_path=str(file_path), start_line=1),
                fix_hint="Remove {% extends %} from partial templates",
            )
        )

    has_csrf = "{% csrf_token %}" in source
    is_partial = file_path.name.startswith("_")
    linter = HTMXLinter(file_path, is_partial=is_partial, has_csrf_token=has_csrf)
    try:
        linter.feed(source)
    except Exception:
        # html.parser raised on malformed input — skip rather than crash
        return findings
    findings.extend(linter.findings)
    return findings


_EXCLUDE_DIRS = frozenset(
    {
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".git",
        ".tox",
        "node_modules",
        "site-packages",
        "dist",
        "build",
        ".pytest_cache",
    }
)


def check_repo(repo_root: Path) -> list[Finding]:
    """Scan all .html templates in a repo recursively."""
    findings: list[Finding] = []
    for html_file in repo_root.rglob("*.html"):
        if any(part in _EXCLUDE_DIRS for part in html_file.parts):
            continue
        findings.extend(check_file(html_file))
    return findings

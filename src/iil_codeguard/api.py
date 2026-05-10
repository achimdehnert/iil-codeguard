"""Public Python API for iil-codeguard.

Used by CLI, MCP server, and any embedding application.
"""

from __future__ import annotations

import time
from pathlib import Path

from iil_codeguard.checkers import htmx_required_attrs, orm_in_view
from iil_codeguard.domain import AuditResult, Finding


def audit_repo(repo_root: Path) -> AuditResult:
    """Run all checkers over a repo root.

    Returns an AuditResult with all findings (no severity filtering).
    """
    started = time.monotonic()
    findings: list[Finding] = []
    files_scanned = 0

    # SL-* checks
    view_files = orm_in_view._find_view_files_recursive(repo_root)
    for vf in view_files:
        findings.extend(orm_in_view.check_file(vf))
        files_scanned += 1

    # HX-* checks (every .html file)
    for html in repo_root.rglob("*.html"):
        if any(part in orm_in_view._EXCLUDE_DIRS for part in html.parts):
            continue
        findings.extend(htmx_required_attrs.check_file(html))
        files_scanned += 1

    duration_ms = int((time.monotonic() - started) * 1000)
    return AuditResult(
        findings=findings,
        files_scanned=files_scanned,
        duration_ms=duration_ms,
    )


def check_file(file_path: Path) -> AuditResult:
    """Check a single file. Dispatches based on extension."""
    started = time.monotonic()
    findings: list[Finding] = []
    if file_path.suffix == ".py":
        findings.extend(orm_in_view.check_file(file_path))
    elif file_path.suffix == ".html":
        findings.extend(htmx_required_attrs.check_file(file_path))
    duration_ms = int((time.monotonic() - started) * 1000)
    return AuditResult(
        findings=findings,
        files_scanned=1,
        duration_ms=duration_ms,
    )

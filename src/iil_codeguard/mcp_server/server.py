"""FastMCP server for iil-codeguard.

Exposes 2 read-only tools per ADR-191 v1.1 §MCP Tools:
  - codeguard_audit:       audit an entire repo
  - codeguard_check_file:  audit a single file

Both tools default to summary_only=True to stay within MCP token budget.
Set summary_only=False to retrieve full findings (paginated).

Per ADR-010 (MCP Tool Governance) + ADR-075 (Read-Only MCP).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from iil_codeguard import __version__, api
from iil_codeguard.domain import RULE_REGISTRY, Severity

mcp = FastMCP(
    name="iil-codeguard",
    instructions=(
        "Library-first code compliance auditing for the IIL Platform. "
        "Detects ORM-in-views, HTMX violations, docker-compose drift, and Dockerfile issues. "
        "All tools are read-only."
    ),
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AuditRequest(BaseModel):
    """Request schema for codeguard_audit."""

    repo_path: str = Field(
        ...,
        description="Absolute or relative path to the repo root to audit",
    )
    severity_threshold: str = Field(
        default="info",
        description="Minimum severity to report: critical, error, warning, info",
    )
    summary_only: bool = Field(
        default=True,
        description=(
            "If True (default), only return counts per severity and rule. "
            "Set to False to get individual findings (may be large)."
        ),
    )
    max_findings: int = Field(
        default=100,
        description="Cap on individual findings returned when summary_only=False",
    )


class CheckFileRequest(BaseModel):
    """Request schema for codeguard_check_file."""

    file_path: str = Field(
        ...,
        description="Path to the file to check (.py, .html, Dockerfile, docker-compose.yml)",
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="codeguard_audit",
    description=(
        "Audit a repo for compliance violations across SL- (service layer), "
        "HX- (HTMX), DC- (docker-compose), and DF- (Dockerfile) rule categories. "
        "Read-only. Defaults to summary mode for token efficiency."
    ),
)
def codeguard_audit(req: AuditRequest) -> dict[str, Any]:
    """Run all checkers over a repo, return SARIF-friendly summary."""
    repo = Path(req.repo_path).expanduser().resolve()
    if not repo.is_dir():
        return {"error": f"path not found or not a directory: {repo}"}

    result = api.audit_repo(repo)
    threshold = _parse_severity(req.severity_threshold)
    if threshold:
        result.findings = result.filter_by_severity(threshold)

    payload: dict[str, Any] = {
        "version": __version__,
        "repo_path": str(repo),
        "files_scanned": result.files_scanned,
        "duration_ms": result.duration_ms,
        "counts_by_severity": result.counts_by_severity(),
        "counts_by_rule": result.counts_by_rule(),
        "summary_only": req.summary_only,
    }

    if not req.summary_only:
        capped = result.findings[: req.max_findings]
        payload["findings"] = [_finding_dict(f) for f in capped]
        payload["truncated"] = len(result.findings) > req.max_findings
        payload["total_findings"] = len(result.findings)

    return payload


@mcp.tool(
    name="codeguard_check_file",
    description=(
        "Check a single file for compliance violations. Dispatches based on filename "
        "(.py = service-layer; .html = HTMX; Dockerfile / docker-compose*.yml = deployment). "
        "Read-only. Always returns full findings (no pagination needed for one file)."
    ),
)
def codeguard_check_file(req: CheckFileRequest) -> dict[str, Any]:
    """Check a single file for compliance violations."""
    f = Path(req.file_path).expanduser().resolve()
    if not f.is_file():
        return {"error": f"file not found: {f}"}

    result = api.check_file(f)
    return {
        "version": __version__,
        "file_path": str(f),
        "duration_ms": result.duration_ms,
        "counts_by_severity": result.counts_by_severity(),
        "counts_by_rule": result.counts_by_rule(),
        "findings": [_finding_dict(x) for x in result.findings],
    }


@mcp.tool(
    name="codeguard_list_rules",
    description=(
        "List all registered rules with their ID, severity, category (SL/HX/DC/DF), "
        "ADR references, and description. Read-only."
    ),
)
def codeguard_list_rules(category: str | None = None) -> dict[str, Any]:
    """List all rules optionally filtered by category."""
    rules = sorted(RULE_REGISTRY.values(), key=lambda r: r.rule_id)
    if category:
        rules = [r for r in rules if r.category == category.upper()]
    return {
        "version": __version__,
        "category_filter": category,
        "rule_count": len(rules),
        "rules": [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "category": r.category,
                "severity": r.severity.value,
                "description": r.description,
                "adr_refs": list(r.adr_refs),
            }
            for r in rules
        ],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_severity(value: str) -> Severity | None:
    try:
        return Severity(value.lower())
    except ValueError:
        return None


def _finding_dict(finding) -> dict[str, Any]:
    d = {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "message": finding.message,
        "file_path": finding.location.file_path,
        "line": finding.location.start_line,
        "column": finding.location.start_column,
    }
    if finding.fix_hint:
        d["fix_hint"] = finding.fix_hint
    if finding.context:
        d["context"] = finding.context
    return d


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for `iil-codeguard-mcp` console script."""
    mcp.run()


if __name__ == "__main__":
    main()

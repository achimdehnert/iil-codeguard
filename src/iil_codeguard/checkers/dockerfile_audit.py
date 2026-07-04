"""DF-001..009: Audit Dockerfile against platform standards.

Per ADR-193 v1.1 §check_dockerfile Rules. Line-by-line analysis (no full parser
needed for our rule set). Critical inversion in DF-001: HEALTHCHECK in
Dockerfile is now an *error* (Coach-hub Incident, ADR-021 §2.4).
"""

from __future__ import annotations

import re
from pathlib import Path

from iil_codeguard.domain import (
    Finding,
    Location,
    RuleMeta,
    Severity,
    register_rule,
)

# Rule registration ---------------------------------------------------------

register_rule(
    RuleMeta(
        rule_id="DF-001",
        name="healthcheck-in-dockerfile",
        description=(
            "HEALTHCHECK in Dockerfile applies to all containers (web+worker+beat) "
            "— move to per-service block in compose (ADR-021 §2.4)"
        ),
        severity=Severity.ERROR,
        category="DF",
        adr_refs=("ADR-021", "ADR-193"),
    )
)
register_rule(
    RuleMeta(
        rule_id="DF-003",
        name="missing-non-root-user",
        description="Dockerfile has no USER instruction — runs as root by default",
        severity=Severity.WARNING,
        category="DF",
        adr_refs=("ADR-056", "ADR-193"),
    )
)
register_rule(
    RuleMeta(
        rule_id="DF-004",
        name="missing-oci-labels",
        description="Dockerfile missing OCI labels (LABEL org.opencontainers.image.*)",
        severity=Severity.INFO,
        category="DF",
        adr_refs=("ADR-056", "ADR-193"),
    )
)
register_rule(
    RuleMeta(
        rule_id="DF-005",
        name="single-stage-build",
        description="Dockerfile uses single-stage build — multi-stage recommended",
        severity=Severity.WARNING,
        category="DF",
        adr_refs=("ADR-056", "ADR-193"),
    )
)
register_rule(
    RuleMeta(
        rule_id="DF-006",
        name="strict-host-key-checking-no",
        description="Dockerfile contains `StrictHostKeyChecking=no` — security violation",
        severity=Severity.CRITICAL,
        category="DF",
        adr_refs=("ADR-193",),
    )
)
register_rule(
    RuleMeta(
        rule_id="DF-007",
        name="hardcoded-server-ip",
        description="Dockerfile contains hardcoded server IP `88.198.191.108`",
        severity=Severity.CRITICAL,
        category="DF",
        adr_refs=("ADR-193",),
    )
)
register_rule(
    RuleMeta(
        rule_id="DF-008",
        name="hardcoded-secret",
        description="Dockerfile contains hardcoded secret (SECRET_KEY=, password=, API_KEY=)",
        severity=Severity.CRITICAL,
        category="DF",
        adr_refs=("ADR-193",),
    )
)
register_rule(
    RuleMeta(
        rule_id="DF-009",
        name="non-standard-base-image",
        description="Base image is not python:3.12-slim (platform standard)",
        severity=Severity.WARNING,
        category="DF",
        adr_refs=("ADR-193",),
    )
)


# Detection patterns --------------------------------------------------------

_FROM_RE = re.compile(r"^\s*FROM\s+([^\s]+)(?:\s+AS\s+([^\s]+))?", re.IGNORECASE)
_HEALTHCHECK_RE = re.compile(r"^\s*HEALTHCHECK\s+", re.IGNORECASE)
_USER_RE = re.compile(r"^\s*USER\s+", re.IGNORECASE)
_LABEL_OCI_RE = re.compile(r"LABEL\s+.*org\.opencontainers\.image\.", re.IGNORECASE)
_HARDCODED_SECRET_RE = re.compile(
    r"""(?ix)
    (?:
        SECRET_KEY \s* [=]
        | password \s* [=:] \s* (?!\$\{|\$\() [^\s\n]+
        | API_KEY \s* [=]
        | DJANGO_SECRET_KEY \s* [=]
    )
    """,
)


# Public API ----------------------------------------------------------------


def check_file(file_path: Path) -> list[Finding]:
    """Audit a single Dockerfile."""
    if not _is_dockerfile(file_path):
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    lines = source.splitlines()
    findings: list[Finding] = []

    has_user = False
    has_oci_labels = False
    from_lines: list[tuple[int, str, str | None]] = []

    for idx, line in enumerate(lines, 1):
        if line.lstrip().startswith("#"):
            continue

        # DF-001: HEALTHCHECK present
        if _HEALTHCHECK_RE.match(line):
            findings.append(
                _f(
                    "DF-001",
                    Severity.ERROR,
                    "HEALTHCHECK in Dockerfile applies to all derived containers — move to compose",
                    file_path,
                    idx,
                    fix_hint=(
                        "Remove HEALTHCHECK here; add per-service `healthcheck:` block to "
                        "docker-compose.prod.yml"
                    ),
                )
            )

        # DF-003 marker
        if _USER_RE.match(line):
            has_user = True

        # DF-004 marker
        if _LABEL_OCI_RE.search(line):
            has_oci_labels = True

        # DF-005: collect FROM lines
        m = _FROM_RE.match(line)
        if m:
            from_lines.append((idx, m.group(1), m.group(2)))

        # DF-006
        if "StrictHostKeyChecking=no" in line:
            findings.append(
                _f(
                    "DF-006",
                    Severity.CRITICAL,
                    "StrictHostKeyChecking=no is a security violation",
                    file_path,
                    idx,
                    fix_hint="Use ssh-keyscan to add the host key to known_hosts beforehand",
                )
            )

        # DF-007
        if "88.198.191.108" in line:
            findings.append(
                _f(
                    "DF-007",
                    Severity.CRITICAL,
                    "Hardcoded production server IP 88.198.191.108",
                    file_path,
                    idx,
                    fix_hint="Use a build ARG or environment variable for the host",
                )
            )

        # DF-008
        if _HARDCODED_SECRET_RE.search(line):
            findings.append(
                _f(
                    "DF-008",
                    Severity.CRITICAL,
                    f"Hardcoded secret in Dockerfile: {line.strip()[:60]}",
                    file_path,
                    idx,
                    fix_hint="Use ARG / ENV with build-time injection, never hardcode",
                )
            )

    # DF-005: single-stage build
    if from_lines and len(from_lines) == 1 and from_lines[0][2] is None:
        findings.append(
            _f(
                "DF-005",
                Severity.WARNING,
                "Single-stage Dockerfile — consider multi-stage build for smaller images",
                file_path,
                from_lines[0][0],
                fix_hint="Add a builder stage: FROM python:3.12-slim AS builder",
            )
        )

    # DF-009: non-standard base image (only check the *final* stage)
    if from_lines:
        final = from_lines[-1]
        base = final[1].split(":", 1)[0]
        # Skip if it's a build stage reference (FROM builder)
        if base != "scratch" and not base.endswith("/builder"):
            named_stages = {n[2] for n in from_lines if n[2]}
            if final[1] not in named_stages and base != "python":
                findings.append(
                    _f(
                        "DF-009",
                        Severity.WARNING,
                        f"Non-standard base image '{final[1]}' — "
                        "platform default is python:3.12-slim",
                        file_path,
                        final[0],
                    )
                )
            elif base == "python" and "3.12-slim" not in final[1]:
                findings.append(
                    _f(
                        "DF-009",
                        Severity.WARNING,
                        f"Base image '{final[1]}' deviates from python:3.12-slim",
                        file_path,
                        final[0],
                    )
                )

    # DF-003: no USER directive
    if from_lines and not has_user:
        findings.append(
            _f(
                "DF-003",
                Severity.WARNING,
                "Dockerfile has no USER directive — runs as root by default",
                file_path,
                1,
                fix_hint="Add: RUN useradd -u 1000 app && USER app",
            )
        )

    # DF-004: missing OCI labels
    if from_lines and not has_oci_labels:
        findings.append(
            _f(
                "DF-004",
                Severity.INFO,
                "Dockerfile missing OCI labels (org.opencontainers.image.*)",
                file_path,
                1,
                fix_hint="Add LABEL org.opencontainers.image.source=https://github.com/...",
            )
        )

    return findings


def check_repo(repo_root: Path) -> list[Finding]:
    """Find and audit all Dockerfiles in a repo."""
    findings: list[Finding] = []
    candidates: list[Path] = []
    for name in ("Dockerfile", "Dockerfile.prod", "Dockerfile.production"):
        candidates.extend(repo_root.rglob(name))
    candidates.extend(repo_root.rglob("docker/*/Dockerfile"))

    seen = set()
    for f in candidates:
        if any(part in {".venv", "venv", "node_modules", ".git"} for part in f.parts):
            continue
        if f in seen:
            continue
        seen.add(f)
        findings.extend(check_file(f))
    return findings


# Helpers -------------------------------------------------------------------


def _is_dockerfile(path: Path) -> bool:
    if path.name in {"Dockerfile", "Dockerfile.prod", "Dockerfile.production"}:
        return True
    return path.name.startswith("Dockerfile.")


def _f(
    rule_id: str,
    severity: Severity,
    message: str,
    file_path: Path,
    line: int,
    fix_hint: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        location=Location(file_path=str(file_path), start_line=line),
        fix_hint=fix_hint,
    )

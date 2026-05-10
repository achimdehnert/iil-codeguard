"""DC-001..009: Audit docker-compose.prod.yml against platform standards.

Per ADR-193 v1.1 §check_compose Rules. YAML parsing via PyYAML — structural
not regex, so handles v2/v3 syntax variations correctly.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from iil_codeguard.domain import (
    Finding,
    Location,
    RuleMeta,
    Severity,
    register_rule,
)

# Rule registration ----------------------------------------------------------

register_rule(RuleMeta(
    rule_id="DC-001", name="env-var-interpolation",
    description="Compose `environment:` block uses ${VAR} interpolation — use env_file instead",
    severity=Severity.CRITICAL, category="DC", adr_refs=("ADR-022", "ADR-193"),
))
register_rule(RuleMeta(
    rule_id="DC-002", name="missing-env-file",
    description="Web service missing `env_file: .env.prod`",
    severity=Severity.ERROR, category="DC", adr_refs=("ADR-022", "ADR-193"),
))
register_rule(RuleMeta(
    rule_id="DC-003", name="missing-healthcheck",
    description="Web service missing `healthcheck:` block",
    severity=Severity.ERROR, category="DC", adr_refs=("ADR-056", "ADR-193"),
))
register_rule(RuleMeta(
    rule_id="DC-004", name="missing-memory-limit",
    description="Service missing `mem_limit` or `deploy.resources.limits.memory`",
    severity=Severity.WARNING, category="DC", adr_refs=("ADR-021", "ADR-193"),
))
register_rule(RuleMeta(
    rule_id="DC-005", name="image-not-from-ghcr",
    description="Image not from `ghcr.io/achimdehnert/` registry",
    severity=Severity.WARNING, category="DC", adr_refs=("ADR-021", "ADR-193"),
))
register_rule(RuleMeta(
    rule_id="DC-006", name="missing-restart-policy",
    description="Service missing `restart: unless-stopped`",
    severity=Severity.ERROR, category="DC", adr_refs=("ADR-021", "ADR-193"),
))
register_rule(RuleMeta(
    rule_id="DC-007", name="public-port-binding",
    description="Service binds port on 0.0.0.0 instead of 127.0.0.1",
    severity=Severity.INFO, category="DC", adr_refs=("ADR-193",),
))
register_rule(RuleMeta(
    rule_id="DC-008", name="missing-migrate-service",
    description="No separate `migrate` service in compose — risk of unsafe migrations",
    severity=Severity.WARNING, category="DC", adr_refs=("ADR-094", "ADR-193"),
))
register_rule(RuleMeta(
    rule_id="DC-009", name="celery-inspect-healthcheck",
    description="Worker/Beat uses `celery inspect ping` — slim images need `pidof python3.12`",
    severity=Severity.ERROR, category="DC", adr_refs=("ADR-021",),
))


# Patterns ------------------------------------------------------------------

# Detect ${VAR} interpolation in environment values.
_ENV_INTERP_RE = re.compile(r"\$\{[A-Z_][A-Z0-9_]*(:-[^}]*)?\}")

# Service names that count as "web" — match common conventions.
_WEB_SERVICE_NAMES = frozenset({"web", "app", "django", "gunicorn", "api", "backend"})

_WORKER_BEAT_NAMES = frozenset({"worker", "beat", "celery", "celery-beat", "celery_beat"})

_PROD_COMPOSE_NAMES = frozenset({"docker-compose.prod.yml", "docker-compose.production.yml"})


# Public API ----------------------------------------------------------------

def check_file(file_path: Path) -> list[Finding]:
    """Audit a single docker-compose YAML file."""
    if file_path.suffix not in {".yml", ".yaml"}:
        return []
    if not file_path.name.startswith("docker-compose"):
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        data = yaml.safe_load(source)
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    is_prod = file_path.name in _PROD_COMPOSE_NAMES
    findings: list[Finding] = []
    services = data.get("services", {}) or {}
    if not isinstance(services, dict):
        return findings

    # DC-008: missing migrate service (only for prod compose with web service)
    has_web = any(_is_web_service(n) for n in services)
    has_migrate = "migrate" in services or any(
        n.startswith("migrate") for n in services
    )
    if is_prod and has_web and not has_migrate:
        findings.append(_finding(
            "DC-008", Severity.WARNING,
            f"{file_path.name}: no separate `migrate` service found",
            file_path, line=1,
            fix_hint="Add a one-shot `migrate` service that runs python manage.py migrate",
        ))

    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        findings.extend(_check_service(name, svc, file_path, source, is_prod))

    return findings


def check_repo(repo_root: Path) -> list[Finding]:
    """Find and audit all docker-compose*.yml files in a repo."""
    findings: list[Finding] = []
    for pattern in ("docker-compose*.yml", "docker-compose*.yaml"):
        for f in repo_root.glob(pattern):
            findings.extend(check_file(f))
    return findings


# Per-service checks --------------------------------------------------------

def _check_service(
    name: str,
    svc: dict[str, Any],
    file_path: Path,
    source: str,
    is_prod: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    line = _find_service_line(source, name)

    is_web = _is_web_service(name)
    is_worker_beat = name in _WORKER_BEAT_NAMES or any(
        token in name for token in ("worker", "beat")
    )

    # DC-001: ${VAR} interpolation in environment block
    env = svc.get("environment")
    if env:
        env_strs: list[str] = []
        if isinstance(env, dict):
            env_strs = [f"{k}={v}" for k, v in env.items()]
        elif isinstance(env, list):
            env_strs = [str(item) for item in env]
        for entry in env_strs:
            if _ENV_INTERP_RE.search(entry):
                findings.append(_finding(
                    "DC-001", Severity.CRITICAL,
                    f"Service '{name}' uses ${{VAR}} interpolation in environment: {entry}",
                    file_path, line=line,
                    fix_hint=f"Move to env_file: .env.prod (current: {entry.split('=')[0]})",
                ))

    # DC-002: web service missing env_file
    if is_prod and is_web and not svc.get("env_file"):
        findings.append(_finding(
            "DC-002", Severity.ERROR,
            f"Web service '{name}' is missing env_file",
            file_path, line=line,
            fix_hint="Add: env_file: .env.prod",
        ))

    # DC-003: web service missing healthcheck
    if is_prod and is_web and not svc.get("healthcheck"):
        findings.append(_finding(
            "DC-003", Severity.ERROR,
            f"Web service '{name}' is missing healthcheck",
            file_path, line=line,
            fix_hint=(
                'Add healthcheck.test: ["CMD-SHELL", "python -c \\"import urllib.request; '
                'urllib.request.urlopen(\\"http://localhost:8000/livez/\\")\\""]'
            ),
        ))

    # DC-004: missing memory limit
    has_mem_limit = svc.get("mem_limit") or _has_deploy_memory_limit(svc)
    if is_prod and not has_mem_limit:
        findings.append(_finding(
            "DC-004", Severity.WARNING,
            f"Service '{name}' has no mem_limit",
            file_path, line=line,
            fix_hint="Add: mem_limit: 512m  (or deploy.resources.limits.memory)",
        ))

    # DC-005: image not from ghcr.io/achimdehnert/
    image = svc.get("image")
    if (
        isinstance(image, str)
        and image
        and not image.startswith("ghcr.io/achimdehnert/")
        and not _is_third_party_image(image)
    ):
        findings.append(_finding(
                "DC-005", Severity.WARNING,
                f"Service '{name}' uses non-platform registry: {image}",
                file_path, line=line,
            ))

    # DC-006: missing restart policy (only for prod, and only for long-running services)
    if is_prod and not svc.get("restart") and not _is_one_shot(svc):
        findings.append(_finding(
            "DC-006", Severity.ERROR,
            f"Service '{name}' is missing restart policy",
            file_path, line=line,
            fix_hint="Add: restart: unless-stopped",
        ))

    # DC-007: public port binding
    ports = svc.get("ports") or []
    for port in ports:
        port_str = str(port)
        if port_str.startswith("0.0.0.0:") or (
            ":" in port_str and not port_str.startswith("127.0.0.1:")
            and not port_str.startswith("[::1]:")
            and port_str.count(":") == ":" and len(port_str.split(":")) == 2
        ):
            # The "host:container" pattern without explicit IP binds to 0.0.0.0
            findings.append(_finding(
                "DC-007", Severity.INFO,
                f"Service '{name}' binds port publicly: {port_str}",
                file_path, line=line,
                fix_hint=f"Bind to localhost: 127.0.0.1:{port_str}",
            ))

    # DC-009: worker/beat with celery-inspect healthcheck
    if is_worker_beat:
        hc = svc.get("healthcheck")
        if isinstance(hc, dict):
            test = hc.get("test")
            test_str = " ".join(test) if isinstance(test, list) else str(test or "")
            if "celery" in test_str and "inspect" in test_str:
                findings.append(_finding(
                    "DC-009", Severity.ERROR,
                    f"Worker/Beat '{name}' uses celery inspect ping healthcheck",
                    file_path, line=line,
                    fix_hint='Use ["CMD-SHELL", "pidof python3.12"] (slim images, ADR-021 §3.10)',
                ))

    return findings


# Helpers -------------------------------------------------------------------

def _is_web_service(name: str) -> bool:
    return name in _WEB_SERVICE_NAMES or any(
        name.startswith(prefix) or name.endswith(prefix) for prefix in ("web", "_web")
    )


def _has_deploy_memory_limit(svc: dict) -> bool:
    deploy = svc.get("deploy") or {}
    if not isinstance(deploy, dict):
        return False
    resources = deploy.get("resources") or {}
    limits = resources.get("limits") or {}
    return "memory" in limits


_THIRD_PARTY_IMAGES = (
    "postgres", "postgis/postgres", "pgvector/pgvector", "redis", "rabbitmq",
    "nginx", "traefik", "prom/prometheus", "grafana/grafana", "minio/minio",
    "elasticsearch", "mongo", "mysql", "mariadb", "memcached", "ollama/ollama",
    "alpine", "ubuntu", "debian",
)


def _is_third_party_image(image: str) -> bool:
    base = image.split(":", 1)[0]
    return any(base == name or base.startswith(name + "/") for name in _THIRD_PARTY_IMAGES)


def _is_one_shot(svc: dict) -> bool:
    """Heuristic: services with `command: ... migrate` or similar are one-shot."""
    cmd = svc.get("command")
    if not cmd:
        return False
    cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
    return any(token in cmd_str.lower() for token in ("migrate", "collectstatic", "loaddata"))


def _find_service_line(source: str, service_name: str) -> int:
    """Return the 1-indexed line where `<service_name>:` is defined under `services:`."""
    in_services = False
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.lstrip()
        if line.startswith("services:"):
            in_services = True
            continue
        if in_services and not line[:1].isspace() and stripped:
            # Left services block (top-level key)
            in_services = False
        if in_services and stripped.startswith(f"{service_name}:"):
            return i
    return 1


def _finding(
    rule_id: str,
    severity: Severity,
    message: str,
    file_path: Path,
    line: int = 1,
    fix_hint: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        location=Location(file_path=str(file_path), start_line=line),
        fix_hint=fix_hint,
    )

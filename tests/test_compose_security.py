"""Tests for DC-001..009 docker-compose audit."""

from __future__ import annotations

from pathlib import Path

from iil_codeguard.checkers import compose_security


def _write(tmp: Path, name: str, content: str) -> Path:
    f = tmp / name
    f.write_text(content, encoding="utf-8")
    return f


# DC-001 ---------------------------------------------------------------------


def test_should_detect_env_var_interpolation(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  web:
    image: ghcr.io/achimdehnert/dev-hub-web:latest
    environment:
      DATABASE_URL: ${DATABASE_URL}
      SECRET_KEY: ${SECRET_KEY}
    env_file: .env.prod
    healthcheck: {test: ["CMD", "true"]}
    restart: unless-stopped
    mem_limit: 512m
""",
    )
    findings = compose_security.check_file(f)
    dc001 = [x for x in findings if x.rule_id == "DC-001"]
    assert len(dc001) == 2


def test_should_pass_clean_environment_block(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  web:
    image: ghcr.io/achimdehnert/x-web:latest
    env_file: .env.prod
    environment:
      DJANGO_SETTINGS_MODULE: config.settings.production
    healthcheck: {test: ["CMD", "true"]}
    restart: unless-stopped
    mem_limit: 512m
""",
    )
    findings = compose_security.check_file(f)
    assert not [x for x in findings if x.rule_id == "DC-001"]


# DC-002 ---------------------------------------------------------------------


def test_should_detect_missing_env_file_on_web(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  web:
    image: ghcr.io/achimdehnert/x-web:latest
    healthcheck: {test: ["CMD", "true"]}
    restart: unless-stopped
    mem_limit: 512m
""",
    )
    findings = compose_security.check_file(f)
    assert any(x.rule_id == "DC-002" for x in findings)


# DC-003 ---------------------------------------------------------------------


def test_should_detect_missing_healthcheck_on_web(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  web:
    image: ghcr.io/achimdehnert/x-web:latest
    env_file: .env.prod
    restart: unless-stopped
    mem_limit: 512m
""",
    )
    findings = compose_security.check_file(f)
    assert any(x.rule_id == "DC-003" for x in findings)


# DC-004 ---------------------------------------------------------------------


def test_should_warn_on_missing_memory_limit(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  worker:
    image: ghcr.io/achimdehnert/x-web:latest
    restart: unless-stopped
""",
    )
    findings = compose_security.check_file(f)
    assert any(x.rule_id == "DC-004" and "worker" in x.message for x in findings)


def test_should_pass_with_deploy_resources_memory(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  worker:
    image: ghcr.io/achimdehnert/x-web:latest
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 256m
""",
    )
    findings = compose_security.check_file(f)
    dc004 = [x for x in findings if x.rule_id == "DC-004"]
    assert dc004 == []


# DC-005 ---------------------------------------------------------------------


def test_should_warn_on_non_platform_image(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  web:
    image: docker.io/myorg/x:latest
    env_file: .env.prod
    healthcheck: {test: ["CMD", "true"]}
    restart: unless-stopped
    mem_limit: 512m
""",
    )
    findings = compose_security.check_file(f)
    assert any(x.rule_id == "DC-005" for x in findings)


def test_should_skip_third_party_images(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  db:
    image: postgres:16
    restart: unless-stopped
    mem_limit: 256m
""",
    )
    findings = compose_security.check_file(f)
    dc005 = [x for x in findings if x.rule_id == "DC-005"]
    assert dc005 == []


# DC-006 ---------------------------------------------------------------------


def test_should_detect_missing_restart(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  web:
    image: ghcr.io/achimdehnert/x-web:latest
    env_file: .env.prod
    healthcheck: {test: ["CMD", "true"]}
    mem_limit: 512m
""",
    )
    findings = compose_security.check_file(f)
    assert any(x.rule_id == "DC-006" for x in findings)


# DC-008 ---------------------------------------------------------------------


def test_should_detect_missing_migrate_service(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  web:
    image: ghcr.io/achimdehnert/x-web:latest
    env_file: .env.prod
    healthcheck: {test: ["CMD", "true"]}
    restart: unless-stopped
    mem_limit: 512m
""",
    )
    findings = compose_security.check_file(f)
    assert any(x.rule_id == "DC-008" for x in findings)


def test_should_pass_with_migrate_service(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  migrate:
    image: ghcr.io/achimdehnert/x-web:latest
    command: python manage.py migrate
  web:
    image: ghcr.io/achimdehnert/x-web:latest
    env_file: .env.prod
    healthcheck: {test: ["CMD", "true"]}
    restart: unless-stopped
    mem_limit: 512m
""",
    )
    findings = compose_security.check_file(f)
    dc008 = [x for x in findings if x.rule_id == "DC-008"]
    assert dc008 == []


# DC-009 ---------------------------------------------------------------------


def test_should_detect_celery_inspect_healthcheck(tmp_path):
    f = _write(
        tmp_path,
        "docker-compose.prod.yml",
        """
services:
  worker:
    image: ghcr.io/achimdehnert/x-web:latest
    env_file: .env.prod
    restart: unless-stopped
    mem_limit: 256m
    healthcheck:
      test: ["CMD-SHELL", "celery -A app inspect ping"]
""",
    )
    findings = compose_security.check_file(f)
    assert any(x.rule_id == "DC-009" for x in findings)


# Non-compose files ---------------------------------------------------------


def test_should_skip_non_compose_files(tmp_path):
    f = _write(tmp_path, "regular.yml", "key: value\n")
    assert compose_security.check_file(f) == []


def test_should_handle_invalid_yaml_gracefully(tmp_path):
    f = _write(tmp_path, "docker-compose.prod.yml", "{[}\n")
    assert compose_security.check_file(f) == []

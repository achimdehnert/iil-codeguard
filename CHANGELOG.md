# Changelog

All notable changes to iil-codeguard. CalVer (`YYYY.MM.PATCH`).

## 2026.05.1 — 2026-05-10

Phase 2b + 2c (per ROADMAP).

### Added

- **Compose checker** (`DC-001..009`): structural YAML audit
  - `DC-001` ${VAR} interpolation in environment block (critical)
  - `DC-002` Web service missing env_file
  - `DC-003` Web service missing healthcheck
  - `DC-004` Service missing memory limit
  - `DC-005` Image not from ghcr.io/achimdehnert/
  - `DC-006` Service missing restart policy
  - `DC-007` Public port binding (0.0.0.0)
  - `DC-008` No separate `migrate` service
  - `DC-009` Worker/Beat with `celery inspect ping` instead of `pidof python3.12`
- **Dockerfile checker** (`DF-001..009`): line-based audit
  - `DF-001` HEALTHCHECK in Dockerfile (now an **error** per ADR-193 v1.1, Coach-hub Incident)
  - `DF-003` Missing USER instruction
  - `DF-004` Missing OCI labels
  - `DF-005` Single-stage build
  - `DF-006` StrictHostKeyChecking=no (critical)
  - `DF-007` Hardcoded server IP 88.198.191.108 (critical)
  - `DF-008` Hardcoded secret (critical)
  - `DF-009` Non-standard base image
- **MCP server** (`iil-codeguard-mcp`): FastMCP-based, 3 read-only tools
  - `codeguard_audit` — repo-level audit, summary by default for token budget
  - `codeguard_check_file` — single-file check
  - `codeguard_list_rules` — enumerate all registered rules
- **Tests** grew from 37 → 69 passing

### Empirical Validation (incl. Phase 2c)

Across 5 platform repos:
- bfagent: **14 critical**, 925 errors (DF rules surfaced hardcoded secrets)
- weltenhub: 1 critical, 38 errors
- travel-beat: 2 critical, 31 errors
- dev-hub: 2 critical, 42 errors
- coach-hub: 0 critical, 34 errors

Total: **17 critical findings** that REFLEX did not detect.

## 2026.05.0 — 2026-05-10

Initial release. Implements Phase 1a–1c + 2a from ROADMAP.md.

### Added

- **Core domain**: `Finding`, `Severity`, `Location`, `AuditResult`, `RuleMeta`, central `RULE_REGISTRY`
- **Service-layer checker** (`SL-001..006`): AST-based ORM detection for FBV, CBV (incl. mixin methods), and async views
  - `SL-001` ORM access in views (`Model.objects.*`)
  - `SL-002` `transaction.atomic()` in views
  - `SL-003` Queryset chains (select_related, prefetch_related)
  - `SL-004` Direct model imports in views.py
  - `SL-005` Raw SQL (`connection.cursor()`, `.raw()`)
  - `SL-006` Missing services.py for app with views
- **HTMX checker** (`HX-001..009`): html.parser + regex pre-scan for trip-wire
  - `HX-001` Missing `hx-target`
  - `HX-002` Missing `hx-swap`
  - `HX-003` Missing `hx-indicator`
  - `HX-004` Missing `data-testid`
  - `HX-005` Banned `hx-boost` (ADR-048)
  - `HX-006` `onclick` mixed with `hx-*`
  - `HX-007` `hx-post` without `{% csrf_token %}`
  - `HX-008` Partial template with `{% extends %}`
  - `HX-009` Trip-wire: Django tag between HTMX attributes
- **Reporters**: SARIF 2.1.0 (GitHub Code Scanning), JSON (MCP-friendly), Text (terminal)
- **CLI**: `codeguard audit`, `codeguard check-file`, `codeguard list-rules`
- **Pre-commit hooks** (`.pre-commit-hooks.yaml`): `codeguard` + `codeguard-changed`
- **GitHub Action template** (`github_actions/codeguard.yml`): SARIF upload + gate
- **Tests**: 37 passing across SL-*, HX-*, reporters, and CLI

### Empirical Validation (2026-05-10)

Baseline audit across 5 platform repos:

| Repo        | Files | Duration | Errors | Warnings | Top Rule    |
|-------------|------:|---------:|-------:|---------:|-------------|
| dev-hub     |    87 |   384 ms |     40 |       64 | SL-001 (38) |
| bfagent     |   675 |   759 ms |    924 |      953 | SL-001 (727)|
| weltenhub   |    76 |    71 ms |     37 |       73 | SL-004 (36) |
| travel-beat |   101 |    78 ms |     28 |       84 | HX-003 (31) |
| coach-hub   |    99 |    78 ms |     33 |       54 | SL-001 (31) |

**Total: 1,038 files scanned in <1.5s, 1,062 errors + 1,228 warnings detected.**
This is the surface area iil-codeguard now governs.

### Trade-offs

- `html.parser` (stdlib) instead of `lxml` — empirically validated as sufficient
  with HX-009 trip-wire for the pathological case (0/940 occurrences)
- Stdlib `ast` instead of `libcst` — `lineno`/`col_offset` reliable for our
  detection patterns
- 0 runtime dependencies except `pyyaml` (planned for compose checker)

### References

- ADR-191 v1.1: Adopt iil-codeguard — Library-First Code Compliance Tooling
- ADR-192 v1.1: Django Service-Layer and HTMX Template Compliance Scanner
- ADR-193 v1.1: Automated Deployment Configuration Compliance Audit (compose/Dockerfile checkers — Phase 2c)

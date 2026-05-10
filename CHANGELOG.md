# Changelog

All notable changes to iil-codeguard. CalVer (`YYYY.MM.PATCH`).

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

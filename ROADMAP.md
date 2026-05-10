# iil-codeguard Roadmap

> Per ADR-191 v1.1. Total: ~8.5 Tage.

## Phase 0 — Repo Setup (1 Tag)

- [x] Create `achimdehnert/iil-codeguard` repo
- [x] `pyproject.toml` with hatchling, CalVer
- [x] `README.md`, `ROADMAP.md`, `LICENSE` (MIT)
- [ ] CI workflow (`.github/workflows/ci.yml`): lint + test + build
- [ ] Publish workflow (`.github/workflows/publish.yml`): trigger via `workflow_dispatch`, secret `PYPI_API_TOKEN` from platform org-secrets
- [ ] Pre-commit hooks config (self-applied)

## Phase 1a — ORM Detector (1.5 Tage)

- [ ] `checkers/orm_in_view.py` — Python `ast` walk, detects `Model.objects.*`
- [ ] Support FBV, CBV (`form_valid`, `dispatch`, `get_queryset`), async views
- [ ] Detect `transaction.atomic` (SL-002), `select_related` (SL-003)
- [ ] Tests: 30+ cases incl. CBV mixin patterns

## Phase 1b — HTMX Scanner (1 Tag)

- [ ] `checkers/htmx_required_attrs.py` — `html.parser` + Pre-Scan-Regex for HX-009
- [ ] Rules HX-001..009
- [ ] Tests with real templates from bfagent/dev-hub/weltenhub

## Phase 1c — SARIF + JSON + Text Reporters (1 Tag)

- [ ] `reporters/sarif.py` — SARIF 2.1.0 with `tool.driver`, `results[].locations`, `fixes`
- [ ] `reporters/json.py` — flat JSON for MCP
- [ ] `reporters/text.py` — colored terminal output
- [ ] Validation against `https://json.schemastore.org/sarif-2.1.0.json`

## Phase 2a — CLI + GitHub Action + pre-commit (1 Tag)

- [ ] `cli.py` — `codeguard audit`, `codeguard check-file`, `codeguard list-rules`
- [ ] `github_actions/codeguard.yml` — uploads SARIF to GitHub Code Scanning
- [ ] `.pre-commit-hooks.yaml` for downstream consumption

## Phase 2b — MCP Server (1 Tag)

- [ ] `mcp_server/server.py` — FastMCP, 2 tools: `codeguard_audit`, `codeguard_check_file`
- [ ] Token budget: `summary_only=True` default, pagination via `max_results`
- [ ] Read-only markers per ADR-010

## Phase 2c — Compose + Dockerfile Checkers (1 Tag)

- [ ] `checkers/compose_security.py` — pyyaml-based, rules DC-001..009
- [ ] `checkers/dockerfile_audit.py` — line-based, rules DF-001..009 (incl. HEALTHCHECK inversion)

## Phase 3 — Integration (1 Tag)

- [ ] Pre-Commit Hook in 7 consumer repos
- [ ] GitHub Action in 7 consumer repos
- [ ] Update `mcp_config.json` to register `iil-codeguard-mcp`
- [ ] Knowledge capture in Outline (Konzepte: "iil-codeguard architecture")

## Future (Phase 4+)

- [ ] Suppression mechanism (inline `# codeguard: disable=SL-001`)
- [ ] Auto-fix for trivial rules (`codeguard fix --safe`)
- [ ] Performance: incremental `git diff` mode, content-hash caching
- [ ] i18n of violation messages
- [ ] Nginx checks (decision deferred to ADR-194)

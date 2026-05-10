# iil-codeguard

Library-first code compliance tooling for the IIL Platform.

> **Status**: Skeleton (2026-05-10) — implementation per ADR-191 v1.1, ADR-192 v1.1, ADR-193 v1.1
> **Versioning**: CalVer (`YYYY.MM.PATCH`)
> **Python**: 3.12+

## What it checks

| Category | Rules | Source |
|----------|-------|--------|
| **Service Layer** | `SL-001..006` | ADR-009 + ADR-192 |
| **HTMX Templates** | `HX-001..009` | ADR-048 + ADR-192 |
| **Docker Compose** | `DC-001..009` | ADR-021/022 + ADR-193 |
| **Dockerfile** | `DF-001..009` | ADR-056 + ADR-193 |
| **Nginx** (optional) | `NX-001..005` | ADR-060 + ADR-193 |

All rules emit findings in **SARIF 2.1.0** (GitHub Code Scanning native).

## Architecture

```
Core Library (stdlib-first: ast, html.parser, pyyaml)
    │
    ├── CLI: codeguard audit . --format sarif
    ├── Pre-commit Hook
    ├── GitHub Action: codeguard.yml
    └── MCP Server (2 tools: codeguard_audit, codeguard_check_file)
```

## Quick Start (planned)

```bash
pip install iil-codeguard

# CLI
codeguard audit .                    # human-readable text
codeguard audit . --format sarif     # SARIF 2.1.0 for GitHub
codeguard check-file apps/views.py   # single file

# Pre-commit
echo '
- repo: https://github.com/achimdehnert/iil-codeguard
  rev: v2026.05.0
  hooks:
    - id: codeguard
' >> .pre-commit-config.yaml

# GitHub Action
# Copy .github/workflows/codeguard.yml from this repo

# MCP (in mcp_config.json)
"iil-codeguard": {
  "command": "iil-codeguard-mcp",
  "args": []
}
```

## Why a separate package?

ADR-191 v1.1 explains the trade-offs vs. extending `platform-context`:
- CLI ab Tag 1 → erfasst Dependabot, Web-UI-Edits, External Contributors
- 2 MCP-Tools statt 4 → kein "god server"
- Eigenes Repo = unabhängiger Release-Zyklus
- Pattern wie `iil-adrfw` (ADR-190)

## Empirical Foundation

The rule design is grounded in a 2026-05-10 stakeholder validation across 7 consumer repos:
- 388 Views (110 CBV, 6 async, 272 FBV)
- 940 HTMX elements (399 with Django tags inside attribute values)
- 0 pathological cases (`{% %}` between HTMX attributes) — covered by HX-009 trip-wire

## Status & Roadmap

See [ROADMAP.md](ROADMAP.md) for the 8.5-day implementation plan.

## License

MIT (consistent with other `iil-*` packages).

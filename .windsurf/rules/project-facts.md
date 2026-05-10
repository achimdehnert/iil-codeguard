---
trigger: always_on
---

# Project Facts: iil-codeguard

## Meta

- **Type**: `unknown`
- **GitHub**: `https://github.com/achimdehnert/iil-codeguard`
- **Branch**: `main` — push: `git push` (SSH-Key konfiguriert)
- **PyPI**: `iil-codeguard`
- **Venv**: `.venv/` — test: `.venv/bin/python -m pytest`

## System (Hetzner Server)

- devuser hat **KEIN sudo-Passwort** → System-Pakete immer via SSH als root:
  ```bash
  ssh root@localhost "apt-get install -y <package>"
  ```

## Secrets / Config

- **Secrets**: `.env` (nicht in Git) — Template: `.env.example`

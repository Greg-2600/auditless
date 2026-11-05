# Naming: Auditless vs Linux Health

Canonical product name: **Auditless** (agentless Linux security scanner).
**Linux Health** is the former product name, retained only where noted.
Full backlog: `ROADMAP.md` items 1–20. Decision record:
`.github/ARCHITECTURE.md` → "Product Naming".

## Alias table

| Layer | Write this (new) | Still valid (legacy) | Notes |
|---|---|---|---|
| Product, UI, docs titles | **Auditless** | "Linux Health" only in historical docs and the README subtitle alias | Historical analyses (`ANALYSIS_*`, `LYNIS_*`, `FEATURES_ADDED`, `RELEASE_NOTES_v2.0.0`) keep era-accurate names |
| Distribution (`pip`, Docker, CLI) | `auditless` | `linux-health` console script, deprecated through v3.x | Both entry points ship today |
| Import package | `linux_health` (through v3.x) | `import auditless` shim resolves to the same objects | See `auditless.py`; full rename slated v4.0 |
| `python -m` | `python -m linux_health` | `python -m auditless` (same CLI) | Module path unchanged in Docker |
| Env namespace | `AUDITLESS_*` | — | Never `LINUX_HEALTH_*` |
| Config files | `auditless.yaml`, `~/.config/auditless/`, `/etc/auditless/` | `linux_health.yaml`, `~/.config/linux_health/`, `/etc/linux_health/` (warn once) | See `get_config_dirs()` |
| Data dir | `$AUDITLESS_DATA_DIR` (`./data`, `/app/data` in containers) | — | See `store.data_dir()` |
| Artifacts | `auditless-*` (reports, backups, tempfiles) | — | Locked by `tests/test_artifact_names.py` |
| Repo URLs | `Greg-2600/auditless` | `yourusername/linux_health` was a template placeholder, now fixed | — |
| JSON `scan_info.scanner` | `Auditless` | fixture-only `"test"`/`"selenium-test"` values | Pinned by tests |
| `/api/version` `scanner` | `Auditless` | — | Pinned by `test_version_endpoint` |

## When writing docs

- New docs say **Auditless**; mention `linux_health` only for the import
  package, module paths (`linux_health/foo.py`), and legacy config paths.
- Never invent new `Linux Health`-branded titles, badges, or URLs.
- Point-in-time analyses keep the name they were written under; link here
  instead of rewriting them.

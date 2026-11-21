# Naming: Auditless

Canonical product name: **Auditless** (agentless Linux security scanner).
The rename completed in 4.0: there is one distribution, one import package,
one module path, one console script and one config namespace.

## Canonical surface

| Layer | Value |
|---|---|
| Product, UI, docs titles | **Auditless** |
| Distribution (`pip`, Docker) | `auditless` |
| Console script | `auditless` |
| Import package | `auditless` |
| `python -m` | `python -m auditless` |
| Env namespace | `AUDITLESS_*` |
| Config files | `auditless.yaml`, `~/.config/auditless/`, `/etc/auditless/` |
| Data dir | `$AUDITLESS_DATA_DIR` (`./data`, `/app/data` in containers) |
| Artifacts | `auditless-*` (reports, backups, tempfiles) |
| Repo URLs | `Greg-2600/auditless` |
| JSON `scan_info.scanner` | `Auditless` |
| `/api/version` `scanner` | `Auditless` |

## Historical documents

`docs/ANALYSIS_*`, `docs/LYNIS_*`, `docs/FEATURES_ADDED.md` and
`docs/RELEASE_NOTES_v2.0.0.md` preserve their original content; identifiers
were normalized to **Auditless** during the 4.0 rename. The only page that
still spells out the pre-4.0 package name is `docs/MIGRATION_v4.md`,
because upgrade instructions need to say what to replace.

Users upgrading from 3.x should follow `docs/MIGRATION_v4.md`; the old
import path, console script and config locations are no longer supported.

## When writing docs

- Always write **Auditless** for the product, the package and the command.
- Module paths are `auditless/...`; examples use `python -m auditless`.
- Never invent new branded titles, badges, or URLs.

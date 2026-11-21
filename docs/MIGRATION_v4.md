# Migrating to Auditless 4.0

Auditless 4.0 completes the package rename that 3.x only aliased. The
product, distribution and code now use one name everywhere. This is a
breaking change: the old import package, console script, module path and
config fallbacks were removed.

## What changed

| Layer | Before 4.0 | 4.0 |
|---|---|---|
| Distribution | `auditless` (unchanged) | `auditless` |
| Import package | `linux_health` | `auditless` |
| Module entry point | `python -m linux_health` | `python -m auditless` |
| Console script | `linux-health` (deprecated) | `auditless` |
| Config files | `linux_health.yaml`, `~/.config/linux_health/`, `/etc/linux_health/` | `auditless.yaml`, `~/.config/auditless/`, `/etc/auditless/` |
| Docker volume | `linux_health_auditless-data` | `auditless-data` |
| Docker network | `linux_health_default` | `auditless_default` |
| Import shim | `auditless.py` module alias | removed |

Environment variables were already `AUDITLESS_*` and do not change.

## Codemod

Replace imports and module invocations in your own code and automation:

```sh
# macOS (BSD sed)
grep -rl 'linux_health' . | xargs sed -i '' 's/linux_health/auditless/g'

# GNU sed
grep -rl 'linux_health' . | xargs sed -i 's/linux_health/auditless/g'
```

Then replace script invocations:

```sh
# before
linux-health 10.0.0.5 admin --format json
python -m linux_health 10.0.0.5 admin --format json

# after
auditless 10.0.0.5 admin --format json
python -m auditless 10.0.0.5 admin --format json
```

## Config and data

Move profile files to the canonical locations; the legacy fallback and its
deprecation warning were removed, so profiles left behind are no longer
discovered:

```sh
mkdir -p ~/.config/auditless
mv ~/.config/linux_health/profile.yaml ~/.config/auditless/profile.yaml
```

For a running container, stop the stack, create the new volume and copy
the old data into it before starting again:

```sh
docker compose down
docker volume create auditless-data
docker run --rm -v linux_health_auditless-data:/from:ro \
  -v auditless-data:/to alpine cp -a /from/. /to/
docker compose up -d
docker volume rm linux_health_auditless-data
```

## Packaging notes

- `pip install auditless` is unchanged.
- The editable install must be refreshed (`pip install -e .`) because the
  package directory moved from `linux_health/` to `auditless/`.
- The Docker image tag remains `auditless:<version>`.

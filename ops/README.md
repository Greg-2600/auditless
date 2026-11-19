# Fleet operations helpers

Small, dependency-free helpers for onboarding a set of SSH hosts into a
running Auditless dashboard. They use only the documented public API via
`linux_health.client.ApiClient`; nothing here reaches into the database or
the scan internals.

| File | Purpose |
| --- | --- |
| `onboard_fleet.py` | Register hosts from an inventory and/or run one baseline scan each |
| `serve.sh` / `stop.sh` | Start/stop the dashboard on loopback with a pidfile |
| `README.md` | This runbook |
| `../docs/FLEET_PLAYBOOK.md` | How to sequence onboarding, hardening and automation work |

## Start the dashboard

```bash
cd <repo-root>
ops/serve.sh          # http://127.0.0.1:8080/ by default
ops/stop.sh
```

Override the bind address/port with `AUDITLESS_HOST` / `AUDITLESS_PORT`.
Keep it on loopback unless an authenticating reverse proxy is in front of
it. The scripts write `data/serve.pid` and `data/serve.log` (gitignored).

## Inventory format

`onboard_fleet.py` accepts TSV (default) or CSV, detected from the header:

```tsv
name	hostname	port	username	password	notes
web-01	192.0.2.10	22	operator		web tier
db-01	192.0.2.20	22	operator		database
```

Only `name` and `hostname` are required; `port` defaults to `22`. A row
with no `username` is skipped. Passwords can come from (in order): the row,
`--password`, `--password-file`, or `AUDITLESS_FLEET_PASSWORD`.

**Never commit a populated inventory.** Add your local path to
`.git/info/exclude` (for example `ops/inventory.tsv`) or use
`--password-file` with a 0600 file outside the repo. Baseline summaries
written to `ops/baseline-*.json` are local-only too.

## Common workflows

```bash
# 1. Register every row without scanning
.venv/bin/python ops/onboard_fleet.py --inventory inventory.tsv --register-only

# 2. Run one baseline scan per host (writes ops/baseline-<timestamp>.json)
.venv/bin/python ops/onboard_fleet.py --inventory inventory.tsv \
  --password-file ~/.auditless-fleet-password

# 3. Re-scan a subset, e.g. after a config change
.venv/bin/python ops/onboard_fleet.py --inventory inventory.tsv \
  --scan-only --name web-01 --name db-01

# 4. Point at a different server / token
AUDITLESS_API=http://127.0.0.1:9000 AUDITLESS_TOKEN=... \
  .venv/bin/python ops/onboard_fleet.py --inventory inventory.tsv --register-only
```

Registration is idempotent: an existing host is matched by `hostname` +
`username` and is not duplicated. Passwords are held only for the request
and are never written to the inventory, the summary JSON, or the server
store. Use a dedicated SSH key (stored in the dashboard) for unattended
scans rather than a password.

Check results via the API:

```bash
curl -s http://127.0.0.1:8080/api/fleet | python3 -m json.tool
curl -s 'http://127.0.0.1:8080/api/fleet/heatmap?mode=issue' | python3 -m json.tool
```

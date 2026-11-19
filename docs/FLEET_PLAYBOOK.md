# Fleet playbook

A derived execution plan for taking a set of hosts from "discovered" to
"measured, trusted and automated". **`ROADMAP.md` is the single source of
truth** for numbered work items; this document only sequences them and
adds operational steps that are not upstream code.

Check the live backlog before starting anything:

```bash
.venv/bin/python scripts/roadmap.py next
```

All upstream changes follow the normal loop: one item per iteration, branch
`roadmap/<NNN>-<slug>`, run ruff / black / pylint 10.00 / mypy / bandit
(high only) / full pytest / Selenium e2e, open a PR, and squash-merge only
on green.

## Guiding order

1. **See the fleet** — inventory, credentials, baseline scans.
2. **Trust the platform** — auth, encrypted secrets, backups before any
   unattended schedule or webhook.
3. **Deepen the checks** — fix what the baseline actually shows, not what
   a guess suggests.
4. **Automate** — schedules, drift alerts, trends.
5. **Prove compliance** — map the frameworks that are really in scope.

## Track 0 — Onboarding (operations, no upstream code)

| # | Task | Done when |
| --- | --- | --- |
| 0.1 | Fill an inventory (`ops/onboard_fleet.py` format) with usernames, then choose password or key auth | Every in-scope host has a usable credential |
| 0.2 | `onboard_fleet.py --register-only` | Hosts visible in `GET /api/hosts` |
| 0.3 | Baseline scan via `--scan-only` | One report and hardening index per host |
| 0.4 | Set `AUDITLESS_TOKEN` + `AUDITLESS_MASTER_KEY`, restart | Mutations require a token; stored keys encrypted |
| 0.5 | Triage failures by category | Top fixes ranked by number of affected hosts |
| 0.6 | Nightly schedules + `regression` webhook | Schedule fires and alert payload arrives |
| 0.7 | Weekly backup and a restore drill | Backup restored into a scratch data dir |

The operational work maps to upstream items such as bulk host import, SSH
reachability pre-checks, host groups/tags and rate limiting. Land Track 0
first; those items then automate what was done by hand.

## Track 1 — Next backlog, in canonical order

Once baseline reports exist, work the next items from `scripts/roadmap.py
next`. Early candidates are logging/audit depth (logrotate, journald),
service hardening (PHP, caches, TLS expiry), noise reduction
(world-writable/SUID triage with allowlists), and exposure checks
(container sockets, kubelet). Defer any item whose technology is absent
from the fleet — decide from report data, not guesses.

## Track 2 — Trust the platform

Complete this **before** exposing the dashboard beyond loopback or
enabling schedules that store webhook URLs:

1. Token auth by default when `AUDITLESS_TOKEN` is set; timing-safe
   comparison; prove secrets never reach logs.
2. RBAC-lite (`viewer` vs `operator`) before sharing access.
3. Security headers, CSP and an XSS review of host-controlled rendering.
4. Rate limiting on scan-start and auth endpoints.
5. API client parity so operational helpers only use supported endpoints.
6. Pagination/filtering as report history grows.
7. Streaming scan progress (SSE/WebSocket) to replace polling.
8. Per-host timeline and first-class report comparison in the UI.

Bulk import and host groups should land early: they productise
`ops/onboard_fleet.py` and let hosts be modelled as
`core / infrastructure / edge / workstations`.

## Track 3 — Fleet automation

Sequence after Track 2: timezone-aware schedules (DST-safe), webhook
delivery log with dead-letter replay and SSRF guard, webhook HMAC signing,
daily digests instead of per-run alerts, SSH reachability pre-checks with
last-seen, encrypted backups with tested restore, retention policy, and
scheduler observability. Add offline bundle ingest if a segment is
air-gapped; consider Postgres only when SQLite is genuinely outgrown.

## Track 4 — Compliance

Order by actual fleet composition:

1. CIS baseline for the dominant OS family first.
2. PCI-DSS only if card data is in scope; Rocky/Alma CIS only if RHEL-family
   hosts appear.
3. Per-control evidence export (high leverage for auditors) and compliance
   trend per host.
4. STIG / NIST / SOC 2 / ISO 27001 / HIPAA: finish one framework before
   starting another. Avoid five thin overlays.

## Phase plan

| Phase | Focus | Exit criteria |
| --- | --- | --- |
| A — Baseline | Track 0 and the next logging items | Every in-scope host has a report and index |
| B — Trust | Auth, RBAC, client parity, headers, rate limit | Green gates; no unauthenticated mutations |
| C — Fleet ops | Import, groups, schedules, alerts, backups | Schedules fire, alerts arrive, restore verified |
| D — Depth | Items justified by baseline data | Noise reduction measured; deferrals documented |
| E — Compliance | One in-scope framework end to end | Evidence export works |

Milestone reviews every 10 completed items (`/roadmap-review`) write
`ROADMAP-REVIEW-<NNN>.md`.

## Risks and guardrails

- Treat DNS/DHCP or other infrastructure hosts as keystones: scan them
  off-peak and never as a brute-force experiment target.
- Older distributions produce `UNKNOWN` results for missing tooling.
  Unknown is excluded from scoring by design — do not optimise it away.
- Confirm ownership of unidentified hosts before credentialed access.
- Prefer key auth for unattended schedules; passwords should be a
  transitional path only.
- Keep the dashboard on loopback until token auth and encrypted secrets
  are enabled.
- Keep real inventories, credentials, baseline JSON and private network
  notes out of git (`.git/info/exclude` or a 0600 file outside the repo).

## Definition of done

- Baseline: every in-scope SSH host has a report and hardening index.
- Trust: no `/api/*` mutation without auth; secrets encrypted at rest.
- Automation: schedules run, regressions alert, backups are verified.
- Depth: the loudest fleet-wide failures are fixed or explicitly accepted.
- Compliance: one framework scored end to end with exportable evidence.

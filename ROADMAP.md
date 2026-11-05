# Auditless Roadmap — 200 Items, Prioritized

> Canonical repo: `Greg-2600/auditless`. Status as of v2.5.3 (2026-11-05).
> Test suite: **499 passed / 16 skipped**. Gates: ruff / black / mypy / pylint 10.00 / bandit HIGH-only — all green.
> This file is the single prioritized backlog. Check a box only when the work is merged to `main`.
> Priority: **P0 = tech debt / correctness blocking**, **P1 = high-value next**, **P2 = important**, **P3 = nice-to-have**, **P4 = backlog / polish**.

How to read: `— [P0] description \`area\` (effort: S/M/L)`. Effort S ≤ 1 day, M = 2–5 days, L ≥ 1 week.

---

## Naming decision (read first — frames items 1–20)

Today three names coexist:

| Layer | Current | Proposed canonical |
|---|---|---|
| Product / UI / docs title | `Linux Health Security Scanner` + `Auditless` mixed | **Auditless** (subtitle: "agentless Linux security scanner") |
| Distribution (`pip install`, Docker, CLI) | `auditless` (pyproject/setup), image `auditless`, CLIs `auditless` + `linux-health` | **auditless** (keep `linux-health` as deprecated alias for 2 minor versions) |
| Import package (`import x`, `python -m x`) | `linux_health` (228 refs) | **keep `linux_health` as the import package** through v3.x for backward compat; add `auditless` import alias shim; full package rename deferred to v4.0 major |
| Env / config namespace | `AUDITLESS_*` (46 refs) + paths `~/.config/linux_health`, `/etc/linux_health` | **AUDITLESS_* stays**; config paths gain `auditless` variants with automatic migration from `linux_health` paths |
| Repo URLs | stale `yourusername/linux_health` in pyproject/CHANGELOG/CONTRIBUTING | **`Greg-2600/auditless`** everywhere |

Rule for all renames below: **never break existing installs silently** — add the new name, shim/migrate the old, warn once, remove after deprecation window. Each rename item must update code + tests + docs together.

---

## P0 — Naming / branding / packaging tech debt (1–20)

Do these first. They are cheap, blocking, and every later doc/feature assumes them.

- [x] 1 — [P0] Record the naming decision above in `docs/ARCHITECTURE.md` + `README.md` header so contributors stop guessing. `docs` (effort: S)
- [x] 2 — [P0] Fix `pyproject.toml [project.urls]` (`yourusername/linux_health` → `Greg-2600/auditless` ×4). `packaging` (effort: S)
- [x] 3 — [P0] Fix stale `yourusername/linux_health` links in `CHANGELOG.md` (releases section), `.github/CONTRIBUTING.md`, `.github/*.md`. `docs` (effort: S)
- [x] 4 — [P0] Retitle `README.md` H1 to `Auditless` with subtitle `Agentless Linux security scanner (formerly Linux Health)`; keep one `Linux Health` alias mention for searchability. `docs` (effort: S)
- [x] 5 — [P0] Fix `README.md` badges: version `2.0.0` → `2.5.3` (or dynamic), tests `334/334` → `499`, coverage `76%` → actual. `docs` (effort: S)
- [x] 6 — [P0] Unify `linux_health/dashboard.py` strings: module docstring + FastAPI `title/description` + `<title>`/`<h1>` currently mix `Linux Health Security Scanner` and `Auditless`. Canonical: `Auditless`. `dashboard` (effort: S)
- [x] 7 — [P0] Unify `linux_health/report.py` + JSON `scan_info.scanner` (`Linux Health Security Scanner` → `Auditless`, keep `scanner_version`). Add test asserting the string. `report` (effort: S)
- [x] 8 — [P0] Unify CLI help/epilog (`cli.py`, `--help` output, Docker `HEALTHCHECK`) on `auditless` as primary, `linux-health` noted as alias. `cli` (effort: S)
- [x] 9 — [P0] Add `auditless` import alias for the `linux_health` package (shim module + `sys.modules` fallback) so `import auditless` and `python -m auditless` work; keep `linux_health` working. `packaging` (effort: M)
- [x] 10 — [P0] Dual config-path discovery: check `~/.config/auditless/`, `/etc/auditless/`, `auditless.yaml` **first**, fall back to existing `linux_health` paths with a one-time deprecation warning (no silent break). `config` (effort: M)
- [x] 11 — [P0] Migrate `dashboard.py` profile search path (`~/.config/linux_health/profiles`) to the same dual-path helper as item 10; extract one shared `get_config_dirs()` used by both. `config` (effort: S)
- [x] 12 — [P0] Decide and document `AUDITLESS_DATA_DIR` default (`./data` vs `/app/data` in container) in one place; remove contradictory comments in `store.py`/`cli.py`/`compose`. `store` (effort: S)
- [x] 13 — [P0] Regenerate or gitignore `linux_health.egg-info/` (currently stale: `Name: linux-health`, `Version: 2.0.0`, stale URLs). Add egg-info hygiene to release checklist. `packaging` (effort: S)
- [x] 14 — [P0] Align `setup.py` shim metadata with `pyproject.toml` (author, URLs already point at `Greg-2600/auditless` — lock them with a test so they can't drift again). `packaging` (effort: S)
- [x] 15 — [P0] Add a `test_packaging_names.py` test that asserts dist-name `auditless`, both console scripts exist, import alias works, and no `yourusername` string survives in packaged metadata. `tests` (effort: S)
- [x] 16 — [P0] Rename `tests/test_linux_health.py` → `tests/test_auditless.py` with a backward-compat re-export (or keep filename + document why); update `conftest.py` imports accordingly. `tests` (effort: S)
- [x] 17 — [P0] Standardize report/artifact prefix on `auditless-*` (reports dir already does; verify JSON/MD exporters + scheduler snapshots + backup filenames all match). `reports` (effort: S)
- [x] 18 — [P0] Audit `docs/*.md` + `scripts/` for `linux_health` vs `auditless` references; add a `docs/NAMING.md` alias table and fix titles (keep `IMPLEMENTATION_ROADMAP_V3.md` as historical, superseded-by pointer to this file). `docs` (effort: M)
- [x] 19 — [P0] Deprecation policy for the `linux-health` console script: emit `DeprecationWarning`/stderr note, keep through v3.x, removal slated v4.0; document in `CHANGELOG.md` + `README.md`. `cli` (effort: S)
- [x] 20 — [P0] Docker/GHCR naming pass: `Dockerfile`, `docker-compose.yml`, `SECURITY.md` verify-example (`2.5.2` → parameterized `VERSION`), service/container names all `auditless`; no `linux_health` image tag remains. `docker` (effort: S)

---

## P1 — Core scan engine & detection accuracy (21–40)

- [x] 21 — [P1] Parallelize per-host SSH checks with bounded worker pool (configurable `--jobs`); measure wall-time on 100-check host, target ≥2× speedup. `engine` (effort: M)
- [x] 22 — [P1] SSH multiplexing / persistent connection reuse across checks (no connect-per-check); fall back cleanly. `ssh` (effort: M)
- [x] 23 — [P1] Per-check timeouts + global scan deadline with partial-report output (never lose completed checks on one hang). `engine` (effort: M)
- [x] 24 — [P1] Retry with backoff for transient SSH failures (auth vs network distinguished); `--retries` flag. `ssh` (effort: S)
- [x] 25 — [P1] Make `--strict-host-key-checking` default-on with `known_hosts` management docs; fail closed with actionable error. `ssh` (effort: S)
- [x] 26 — [P1] IPv6 target support (bracket parsing, port scanner dual-stack). `scanner` (effort: S)
- [x] 27 — [P1] Port scanner: service banner grabbing + version inference for top 20 ports. `scanner` (effort: M)
- [x] 28 — [P1] Command-output cache keyed on (host, command) with TTL + `--no-cache` escape hatch; document invalidation rules. `engine` (effort: S)
- [x] 29 — [P1] Distro detection hardening (`/etc/os-release` + fallbacks) shared by all checks; one `get_distro()` helper, tested on Ubuntu/Debian/RHEL/Alpine. `checks` (effort: S)
- [x] 30 — [P1] Privilege model: declare per-check needs-root table; warn (not crash) when unprivileged, mark result `unknown` with reason. `checks` (effort: M)
- [x] 31 — [P1] Replace remaining `XXXX` fallback test IDs (`ACCT-XXXX`, `FS-XXXX`, `DBS-XXXX`, `PKGS-XXXX` in checks_*_*.py) with real registry IDs. `test-ids` (effort: S)
- [x] 32 — [P1] False-positive harness: canary hosts (hardened vs weakened fixtures) asserting expected index delta; gate regressions in CI. `tests` (effort: M)
- [x] 33 — [P1] Check severity re-grade pass (FAIL vs WARN audit against CIS impact); document rationale per change. `checks` (effort: M)
- [x] 34 — [P1] `sudo -n` non-interactive discipline: no password prompts mid-scan; preflight auth check with clear error. `ssh` (effort: S)
- [x] 35 — [P1] Large-fleet memory discipline: stream checks, cap stored output bytes per check (`--max-output-bytes`). `engine` (effort: S)
- [x] 36 — [P1] Scan profiles: `--profile` + `--only-tests`/`--skip-tests` CLI flags mirroring profile YAML (today YAML-only for some paths). `cli` (effort: S)
- [x] 37 — [P1] Profile validation (`auditless profile lint`) with JSON-schema + unknown-ID suggestions. `config` (effort: M)
- [x] 38 — [P1] Deterministic check ordering + stable JSON key order (diff-friendly reports). `report` (effort: S)
- [x] 39 — [P1] Structured `unknown`/`skipped` status distinct from `warn` (tool missing ≠ vulnerable); update hardening-index math + docs. `report` (effort: M)
- [x] 40 — [P1] Benchmark script (`scripts/bench_fleet.py`) promoted to CI perf gate (fail on >10% scan-time regression). `perf` (effort: M)

---

## P1 — New security checks, Lynis parity gaps (41–60)

Each item = check + test IDs + fixtures + docs. Proposed IDs are suggestions; registry (`test_ids.py`) is authoritative.

- [x] 41 — [P1] Sudoers.d auditing (`/etc/sudoers.d/*`, `!authenticate`, `NOPASSWD` scope) — `AUTH-9341` (`AUTH-9340` was already taken by recent-accounts). `checks` (effort: S)
- [ ] 42 — [P1] PAM faillock / pwquality completeness (deny, unlock_time, minlen, retry) — `AUTH-9350`. `checks` (effort: S)
- [ ] 43 — [P1] SSH `AllowUsers/AllowGroups`, `MaxAuthTries`, `LoginGraceTime`, `ClientAlive*` hardening — extend `AUTH-9328` family. `checks` (effort: S)
- [ ] 44 — [P1] Kernel Secure Boot + module signature enforcement (`mokutil --sb-state`, `module.sig_enforce`). `checks` (effort: S)
- [ ] 45 — [P1] Kernel livepatch status (canonical/ubuntu-advantage, kpatch) informational. `checks` (effort: S)
- [ ] 46 — [P1] Sysctl extended pass (`kernel.kptr_restrict`, `kernel.dmesg_restrict`, `kernel.unprivileged_bpf_disabled`, `net.*` forwarding). `checks` (effort: M)
- [ ] 47 — [P1] AIDE / Samhain / OSSEC presence **and** DB freshness (not just installed). `checks` (effort: S)
- [ ] 48 — [P1] USBGuard / USB authorization (`usbcore.authorized_default`, UDISKS rules) — extend `USB-1000`. `checks` (effort: S)
- [ ] 49 — [P1] Firewall rich rules audit (default-deny, loopback, established, logging) for ufw/firewalld/nftables. `checks` (effort: M)
- [ ] 50 — [P1] Listening-socket → process → package attribution (`ss -ltnp` × `dpkg -S`/`rpm -qf`). `checks` (effort: M)
- [ ] 51 — [P1] Cron/at/systemd-timer allow/deny files (`cron.allow`, `cron.deny`, `at.allow`) + world-writable job detection. `checks` (effort: S)
- [ ] 52 — [P1] Logrotate presence + auth/syslog rotation config. `checks` (effort: S)
- [ ] 53 — [P1] Journald persistence (`Storage=persistent`, `SystemMaxUse`, forwarding). `checks` (effort: S)
- [ ] 54 — [P1] PHP-FPM / opcache / `disable_functions` audit (where PHP present). `checks` (effort: S)
- [ ] 55 — [P1] Redis/Memcached/Elasticsearch bind + auth checks (no open `0.0.0.0` without password). `checks` (effort: M)
- [ ] 56 — [P1] TLS certificate expiry scan for local services (not just web: mail, DB). `checks` (effort: M)
- [ ] 57 — [P1] World-writable + SUID/SGID combined triage with package-owned allowlist to cut noise. `checks` (effort: M)
- [ ] 58 — [P1] Container runtime socket exposure (`/var/run/docker.sock` perms, Podman socket, containerd). `checks` (effort: S)
- [ ] 59 — [P1] Kubernetes kubelet/node CIS-lite (anonymous-auth, read-only-port, event qps) when kubelet detected. `checks` (effort: M)
- [ ] 60 — [P1] Time sync extended (chrony `nts`, NTS sources, `timedatectl` NTP active, max skew). `checks` (effort: S)

---

## P1 — Dashboard & API (61–80)

- [ ] 61 — [P1] Token auth on by default when `AUDITLESS_TOKEN` set — audit remaining unauthenticated `/api/*` routes; add test matrix. `api` (effort: M)
- [ ] 62 — [P1] RBAC-lite: `viewer` vs `operator` tokens (view vs scan/remediate/rotate). `api` (effort: M)
- [ ] 63 — [P1] Pagination + filtering on `/api/reports`, `/api/hosts`, `/api/scans` (limit/offset, status, host, date range). `api` (effort: M)
- [ ] 64 — [P1] Live scan progress via WebSocket/SSE (`/api/scans/{id}/events`) instead of poll-only. `api` (effort: M)
- [ ] 65 — [P1] Bulk host import (CSV/JSON) + export; validation errors reported per-row. `dashboard` (effort: M)
- [ ] 66 — [P1] Global search (hosts, reports, check IDs, CVE strings) with keyboard shortcut. `ui` (effort: M)
- [ ] 67 — [P1] Saved report views (filters as shareable query strings). `ui` (effort: S)
- [ ] 68 — [P1] Per-host scan history timeline with index sparkline drill-down (click point → report). `ui` (effort: M)
- [ ] 69 — [P1] Compare any two reports from UI (today API-only `/api/diff` + one button path — make it first-class). `ui` (effort: S)
- [ ] 70 — [P1] Host groups / tags (prod/staging, team) with group-level fleet rollups. `api` (effort: M)
- [ ] 71 — [P1] API client (`client.py`) parity audit: every new endpoint gets a client method + test on day one. `api` (effort: S)
- [ ] 72 — [P1] OpenAPI examples + error schema consistency (`application/problem+json` for all 4xx/5xx). `api` (effort: S)
- [ ] 73 — [P1] Audit-trail UI viewer (hash chain, verify button mirrors `GET /api/audit/verify`). `ui` (effort: S)
- [ ] 74 — [P1] Token management UI (mint/revoke/last-used) — today API-only. `ui` (effort: M)
- [ ] 75 — [P1] Secrets migration/rotation UI affordances (today curl-only `POST /api/maintenance/*`). `ui` (effort: S)
- [ ] 76 — [P1] Dashboard accessibility pass (keyboard nav, ARIA, contrast) + mobile layout. `ui` (effort: M)
- [ ] 77 — [P1] Dark mode + print stylesheet for reports. `ui` (effort: S)
- [ ] 78 — [P1] CSRF + session hardening review for cookie paths (if any added); document bearer-only rationale. `security` (effort: S)
- [ ] 79 — [P1] Rate limiting on scan-start + auth endpoints (per-IP token bucket). `api` (effort: S)
- [x] 80 — [P1] UI e2e tests, Selenium harness (DONE: `tests/test_ui_selenium.py` — headless Chrome, skip-guarded, seeded via public API with stubbed `run_scan`; asserts index empty-state + zero SEVERE console errors, history → report render, fleet table; `selenium` in requirements-dev; runs in CI and in the `/roadmap` e2e gate). Follow-ups: login/token-bar flow, add-host form submit, diff-view click path. `tests` (effort: L)

---

## P2 — Compliance frameworks (81–100)

- [ ] 81 — [P2] CIS Rocky Linux 9 + AlmaLinux 9 mappings (RHEL-family reuse audit). `compliance` (effort: M)
- [ ] 82 — [P2] CIS Ubuntu 24.04 LTS mapping (delta from 22.04). `compliance` (effort: M)
- [ ] 83 — [P2] CIS Debian 13 mapping (delta from 12). `compliance` (effort: S)
- [ ] 84 — [P2] DISA STIG (RHEL 9) overlay, partial/best-effort with explicit gaps. `compliance` (effort: L)
- [ ] 85 — [P2] NIST 800-53 rev5 overlay (control → test-ID traceability matrix). `compliance` (effort: L)
- [ ] 86 — [P2] SOC 2 CC7 overlay (change/logging/availability evidence mapping). `compliance` (effort: M)
- [ ] 87 — [P2] ISO 27001:2022 Annex A overlay. `compliance` (effort: M)
- [ ] 88 — [P2] HIPAA technical-safeguards overlay. `compliance` (effort: M)
- [ ] 89 — [P2] PCI-DSS 4.0 overlay expansion (today focused subset → full Req 1,2,5,10,11 coverage statement). `compliance` (effort: M)
- [ ] 90 — [P2] Custom-framework authoring (`docs/COMPLIANCE_AUTHORING.md` + YAML schema + `auditless compliance lint`). `compliance` (effort: M)
- [ ] 91 — [P2] Per-control evidence export (which command output proved each verdict; redaction-safe). `compliance` (effort: M)
- [ ] 92 — [P2] Compliance trend per host (score over time, §-level deltas). `dashboard` (effort: M)
- [ ] 93 — [P2] Framework version pinning + deprecation (CIS v2.0.0 vs v3.0.0 side-by-side). `compliance` (effort: S)
- [ ] 94 — [P2] `auto` distro detection: test + document fallback chain; explicit `unknown-distro` verdict path. `compliance` (effort: S)
- [ ] 95 — [P2] Unmapped-checks transparency report per framework (never silent — already policy; add UI surface). `ui` (effort: S)
- [ ] 96 — [P2] Compliance PDF attestation pack (auditor-ready: scope, method, versions, hashes). `reports` (effort: M)
- [ ] 97 — [P2] Waivers/exceptions workflow (risk-accepted control with expiry + approver in audit trail). `compliance` (effort: M)
- [ ] 98 — [P2] Control → remediation linkage (every failed control links to a propose/approve fix). `remediation` (effort: M)
- [ ] 99 — [P2] Multi-framework diff (same host scored against CIS+STIG+NIST side-by-side). `ui` (effort: M)
- [ ] 100 — [P2] Compliance API versioning (`/api/compliance/v1/...`, framework catalog endpoint tests). `api` (effort: S)

---

## P2 — Remediation engine (101–120)

- [ ] 101 — [P2] 20 additional `Remediation` entries (sshd, sysctl, pwquality, firewall, cron perms, logrotate, journald, PHP, DB anon-users). `remediation` (effort: L)
- [ ] 102 — [P2] Risk-badge taxonomy expansion (`safe`/`service` today → + `reboot`, `data-loss-risk`, `irreversible`) with per-badge approval policy. `remediation` (effort: M)
- [ ] 103 — [P2] Dry-run diff preview (unified diff of files the fix would change, fetched first). `remediation` (effort: M)
- [ ] 104 — [P2] Automatic rollback snapshot (backup touched files, one-click revert, revert verified by rescan). `remediation` (effort: M)
- [ ] 105 — [P2] Least-privilege sudo scoping docs + scoped sudoers example (exact commands remediator needs, nothing more). `docs` (effort: S)
- [ ] 106 — [P2] Approval workflow: propose → second-operator approve → apply (4-eyes for `service`+ risk). `api` (effort: M)
- [ ] 107 — [P2] Scheduled remediation windows (apply only in maintenance window, auto-verify after). `scheduler` (effort: M)
- [ ] 108 — [P2] Remediation history per host (what ran, when, by whom, before/after index). `dashboard` (effort: M)
- [ ] 109 — [P2] `REMEDIATION_AUTHORING.md` conformance test (every entry has risk, idempotence proof, verify-check mapping). `tests` (effort: S)
- [ ] 110 — [P2] Idempotence guarantee: re-applying a fix is a no-op (tested per remediation). `remediation` (effort: M)
- [ ] 111 — [P2] Fix-plan bundles (one approval applies N related fixes as a transaction with per-step results). `api` (effort: M)
- [ ] 112 — [P2] Pre-flight safety checks (disk space, config syntax `sshd -t`/`visudo -c`, service existence) before apply. `remediation` (effort: M)
- [ ] 113 — [P2] Post-apply service reload discipline (only touched services, `systemctl reload` preferred over restart). `remediation` (effort: S)
- [ ] 114 — [P2] Remediation audit-trail linkage (proposal/approval/apply/verify all hash-chained). `trust` (effort: S)
- [ ] 115 — [P2] Ansible/Puppet/Chef export of approved fixes (take the verified fix to config management). `integrations` (effort: M)
- [ ] 116 — [P2] Shell-script export (`auditless fix export --format sh`) for air-gapped hosts. `cli` (effort: S)
- [ ] 117 — [P2] Remediation coverage matrix in docs (check → fix → risk → verify). `docs` (effort: S)
- [ ] 118 — [P2] Dangerous-fix guardrails (blocklist patterns like `rm -rf`, require typed confirmation). `remediation` (effort: S)
- [ ] 119 — [P2] Fix testing against weakened-target fixtures (prove each fix flips its check in e2e). `tests` (effort: M)
- [ ] 120 — [P2] Remediation metrics (MTTR per check, fix success rate) on fleet view. `dashboard` (effort: M)

---

## P2 — Fleet, scheduler & automation (121–140)

- [ ] 121 — [P2] Timezone-aware cron schedules (store TZ per schedule; DST-safe next-run). `scheduler` (effort: M)
- [ ] 122 — [P2] Schedule jitter + overlap guard audit (already partial — prove with contention tests). `scheduler` (effort: S)
- [ ] 123 — [P2] Webhook delivery log + dead-letter replay UI (today retry-only). `scheduler` (effort: M)
- [ ] 124 — [P2] Webhook signing (HMAC) + receiver verification docs. `security` (effort: S)
- [ ] 125 — [P2] Threshold policies per group (not just per host) + hysteresis (no flapping alerts). `scheduler` (effort: M)
- [ ] 126 — [P2] Drift-alert digest mode (daily summary instead of per-run spam). `scheduler` (effort: S)
- [ ] 127 — [P2] Fleet concurrency auto-tuning (bounded pool already — add load-adaptive sizing + `--fleet-jobs`). `engine` (effort: M)
- [ ] 128 — [P2] Fleet scan queue with priorities + cancellation. `api` (effort: M)
- [ ] 129 — [P2] Host health (SSH reachability) pre-check with cached status + last-seen. `dashboard` (effort: S)
- [ ] 130 — [P2] Bastion 3-hop chains + per-hop key types audit; document `AllowTcpForwarding` requirement per hop. `ssh` (effort: M)
- [ ] 131 — [P2] SSH certificate auth support (in addition to keys/passwords). `ssh` (effort: M)
- [ ] 132 — [P2] Kerberos/GSSAPI auth path (enterprise AD-joined fleets). `ssh` (effort: L)
- [ ] 133 — [P2] Offline/air-gap bundle (`auditless bundle` → run elsewhere → `auditless ingest`). `cli` (effort: M)
- [ ] 134 — [P2] `cron.py` ↔ `scheduler.py` consolidation (one scheduler; today two modules overlap). `scheduler` (effort: M)
- [ ] 135 — [P2] Backup encryption + restore drill (`POST /api/maintenance/restore` tested in CI). `store` (effort: M)
- [ ] 136 — [P2] SQLite → Postgres optional backend (fleet-scale deployments). `store` (effort: L)
- [ ] 137 — [P2] Data retention policies (auto-prune old reports/snapshots/logs per policy). `store` (effort: M)
- [ ] 138 — [P2] Fleet tagging + dynamic inventory sync (AWS/GCP/Azure/NetBox importers). `integrations` (effort: L)
- [ ] 139 — [P2] Maintenance windows (suppress alerts during windows, still record). `scheduler` (effort: M)
- [ ] 140 — [P2] Scheduler observability (`/api/scheduler/status`: next runs, lag, failures, worker saturation). `api` (effort: S)

---

## P3 — Reporting, UX & integrations (141–160)

- [ ] 141 — [P3] HTML standalone report (single-file, offline, print-ready). `reports` (effort: M)
- [ ] 142 — [P3] PDF report export (via HTML → print pipeline, no new runtime dep if possible). `reports` (effort: M)
- [ ] 143 — [P3] SARIF output (`--format sarif`) for GitHub code-scanning ingestion. `reports` (effort: M)
- [ ] 144 — [P3] CycloneDX + SPDX report artifacts alongside existing SBOM attestation. `reports` (effort: S)
- [ ] 145 — [P3] JUnit XML output for CI test-tab ingestion. `reports` (effort: S)
- [ ] 146 — [P3] Prometheus metrics endpoint (`/metrics`: scans, scores, durations). `api` (effort: S)
- [ ] 147 — [P3] Grafana dashboard JSON + ELK/Splunk field mapping docs. `integrations` (effort: M)
- [ ] 148 — [P3] Slack/Teams/PagerDuty notifiers in addition to generic webhook. `integrations` (effort: M)
- [ ] 149 — [P3] Jira/ServiceNow auto-ticketing for failed criticals (dedupe by test-ID + host). `integrations` (effort: M)
- [ ] 150 — [P3] GitHub Action wrapper (`auditless-scan@v1`) + GitLab component. `integrations` (effort: M)
- [ ] 151 — [P3] Jenkins shared-library step + Azure DevOps task. `integrations` (effort: M)
- [ ] 152 — [P3] OPA/Rego policy gate example (fail pipeline on FAIL in category X). `integrations` (effort: S)
- [ ] 153 — [P3] Report redaction mode (`--redact ips,users`) for sharing/pasting. `reports` (effort: S)
- [ ] 154 — [P3] Executive-summary template (one-page: index, delta, top-5 risks, trend). `reports` (effort: S)
- [ ] 155 — [P3] i18n scaffolding for UI strings (en first, community locales later). `ui` (effort: M)
- [ ] 156 — [P3] CLI interactive TUI (`auditless interactive`: pick host → scan → browse results). `cli` (effort: L)
- [ ] 157 — [P3] Shell completions (bash/zsh/fish) for CLI flags + test IDs. `cli` (effort: S)
- [ ] 158 — [P3] `--watch` mode (rescan on interval with terminal dashboard). `cli` (effort: M)
- [ ] 159 — [P3] Public status/health page for the dashboard service (`/healthz` extended: version, uptime, queue depth). `api` (effort: S)
- [ ] 160 — [P3] MCP server (Model Context Protocol) exposing scans/reports to AI assistants, reusing bearer auth. `integrations` (effort: M)

---

## P3 — Supply chain, release & ops (161–180)

- [ ] 161 — [P3] Publish to PyPI (`auditless` sdist+wheels) with Trusted Publishing (OIDC); needs `PYPI_API_TOKEN` decision recorded. `release` (effort: M)
- [ ] 162 — [P3] Sign git tags (`git tag -s`) + verify in release workflow. `release` (effort: S)
- [ ] 163 — [P3] Attach SBOM + provenance to GitHub Release assets (not just image attestations). `release` (effort: S)
- [ ] 164 — [P3] SLSA Build Level 3 provenance for Python artifacts (not just container). `release` (effort: M)
- [ ] 165 — [P3] Reproducible-builds check (two builds → identical digests, CI gate). `release` (effort: M)
- [ ] 166 — [P3] Container minimalism: distroless/slim variant, non-root verified, `no-new-privileges`. `docker` (effort: M)
- [ ] 167 — [P3] Image vulnerability SLO (Trivy HIGH/CRITICAL → block release; document exceptions). `security` (effort: S)
- [ ] 168 — [P3] Dependency-floor policy (already raised for 10 OSVs — add monthly `pip-audit` CI job). `security` (effort: S)
- [ ] 169 — [P3] Pinned-action freshness SLO (Dependabot weekly, semver-grouped, auto-merge patch). `ci` (effort: S)
- [ ] 170 — [P3] Release-drafter / auto-notes curated from `CHANGELOG.md` (single source of truth). `release` (effort: S)
- [ ] 171 — [P3] Version-bump automation (`bumpver` config: one command bumps `__init__`+`pyproject`+changelog stub). `ci` (effort: S)
- [ ] 172 — [P3] Docker multi-registry (GHCR + Docker Hub mirrors) with cosign signing on both. `release` (effort: M)
- [ ] 173 — [P3] Helm chart + Kubernetes CronJob example for fleet scans. `ops` (effort: M)
- [ ] 174 — [P3] Systemd unit + logrotate example for `--serve` on bare metal. `ops` (effort: S)
- [ ] 175 — [P3] Backup/restore runbook tested quarterly in CI (restore into scratch volume, verify). `ops` (effort: M)
- [ ] 176 — [P3] Incident-response runbook (`docs/IR_RUNBOOK.md`: compromised-host scan profile + evidence capture). `docs` (effort: M)
- [ ] 177 — [P3] `SECURITY.md` verify-example parameterized by release (no hardcoded `2.5.2` on next bump). `docs` (effort: S)
- [ ] 178 — [P3] Scorecard remediation inbox-zero (keep score high; track deltas per release). `security` (effort: S)
- [ ] 179 — [P3] Fuzz `verify-release` failure paths (bad digest, expired cert) with negative tests. `tests` (effort: M)
- [ ] 180 — [P3] Release smoke matrix (amd64+arm64 boot test already — add `--serve` boot + one API call). `release` (effort: S)

---

## P4 — Testing, quality, docs & community (181–200)

- [ ] 181 — [P4] Coverage 76% → 90% (exclude `dashboard.py` HTML template strings honestly; cover logic). `tests` (effort: L)
- [ ] 182 — [P4] Mutation testing baseline (mutmut/cosmic-ray on `checks.py` pure parsers). `tests` (effort: M)
- [ ] 183 — [P4] Property-based tests (Hypothesis) for parsers (sysctl, fstab, sshd_config, resolv.conf). `tests` (effort: M)
- [ ] 184 — [P4] Windows/macOS CI parity audit (today matrix exists — fix/flake-hunt slow tests, e.g. generous client timeout follow-ups). `ci` (effort: M)
- [ ] 185 — [P4] E2E live-fire range expansion (more distros in `tests/test_e2e.py`, weakened-target matrix). `tests` (effort: L)
- [ ] 186 — [P4] Performance regression suite (per-check timings published as artifact). `perf` (effort: M)
- [ ] 187 — [P4] Type-strictness ratchet (mypy `disallow_untyped_defs` on new modules, grandfather old). `quality` (effort: M)
- [ ] 188 — [P4] Pylint custom checker for check-authoring rules (every check has test ID, category, remediation link). `quality` (effort: M)
- [ ] 189 — [P4] Docs site (MkDocs + `docs/` as source, versioned per release, hosted on GH Pages). `docs` (effort: M)
- [ ] 190 — [P4] Check-authoring cookbook (`docs/CHECK_AUTHORING.md` mirroring `REMEDIATION_AUTHORING.md`) + template generator (`auditless new-check`). `docs` (effort: M)
- [ ] 191 — [P4] Architecture Decision Records (`docs/adr/`: naming, scheduler, store backend, auth model). `docs` (effort: S)
- [ ] 192 — [P4] `PROJECT_STRUCTURE.md` + `FEATURES_ADDED.md` refresh (both stale vs v2.5.x reality). `docs` (effort: M)
- [ ] 193 — [P4] Demo environment (`docker compose --profile demo`: scanner + vulnerable target + seeded data). `docs` (effort: M)
- [ ] 194 — [P4] Video/GIF quickstart in README (60-second scan-to-report). `docs` (effort: S)
- [ ] 195 — [P4] Community health: `CODE_OF_CONDUCT` enforcement contact, issue/PR templates triage, `good-first-issue` label pass. `community` (effort: S)
- [ ] 196 — [P4] Telemetry (opt-in, anonymous): check runtimes + error rates to prioritize work; privacy policy. `product` (effort: M)
- [ ] 197 — [P4] Plugin system (entry-point `auditless.checks` third-party checks, sandboxed, profile-filterable) — Lynis parity item. `product` (effort: L)
- [ ] 198 — [P4] Multi-system central reporting (fleet rollup dashboard already partial → hardened, exportable). `product` (effort: L)
- [ ] 199 — [P4] CIS-CAT/Lynis report import (migrate existing audit history into Auditless store). `integrations` (effort: M)
- [ ] 200 — [P4] v4.0 major: complete package rename (`linux_health` → `auditless`) with codemod + migration guide, dropping deprecated aliases. `product` (effort: L)

---

## Suggested build order (next 4 milestones)

- **v2.5.4 (hygiene):** 1–8, 12–17, 31, 171, 177, 192 — naming surface + packaging tests, no behavior change.
- **v2.6.0 (engine + checks):** 9–11, 21–30, 41–60 (subset), 37, 109–110 — dual paths, parallelism, 10 highest-signal new checks.
- **v2.7.0 (platform):** 61–79 (subset), 121–140 (subset), 141–145 — dashboard/API hardening, scheduler observability, SARIF/JUnit.
- **v3.0.0 (compliance + remediation):** 81–120 — framework expansion, remediation bundles/approvals, attestation packs.

## Supersedes

`docs/IMPLEMENTATION_ROADMAP_V3.md` (v3.0 Lynis-parity plan, largely delivered: DB/audit/filesystem/packages/container/web/DNS modules exist) remains as historical reference. This file is authoritative going forward.

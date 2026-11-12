# Auditless Roadmap — v2 (Rebuilt 2026-11-12)

> Canonical repo: `Greg-2600/auditless`. Rebuilt from the 200-item v1
> (53 shipped, carried below as checked theme boxes; all 147 pending
> intents preserved, plus review candidates C-01…C-05 folded in).
> Status: **53 shipped**. Suite: **756 passed / 16 deselected** (e2e in CI).
> Gates: ruff / black / mypy / pylint 10.00 / bandit HIGH-only — all green.
> This file is the single prioritized backlog. Check a box only when the
> work is merged to `main`.
> Priority: **P1 = v2.6.0 (next)**, **P2 = v3.0.0 (following)**,
> **P3 = release/ops/integrations**, **P4 = backlog / polish**.
> Every 10 completed items the loop runs `/roadmap-review` (quality,
> stability, security, wow factor) and writes `ROADMAP-REVIEW-<NNN>.md`;
> numbering is sequential 1–N and locked by test — future candidates
> live in reviews until the next backlog is cut.

How to read: `— [P1] description \`area\` (effort: S/M/L)`. Effort S ≤ 1 day, M = 2–5 days, L ≥ 1 week.

---

## Shipped (do not reopen — condensed from v1 items 1–51, 80, 177)

- [x] 1 — [P0] Naming/branding/packaging block: `Auditless` canonical, dual config paths, `auditless` import shim, `linux-health` deprecation policy, Docker/GHCR naming, egg-info + metadata hygiene. `docs` (effort: L)
- [x] 2 — [P1] Engine core: parallel checks (`--jobs`, ≥2× perf gate), SSH pool + retry/backoff, strict host keys by default, timeouts + deadline + partial reports, output cache, `--max-output-bytes`. `engine` (effort: L)
- [x] 3 — [P1] Scanner depth: IPv6, banner grabbing, distro helper, privilege model (`unknown` results), real test-ID registry, profiles + lint, deterministic reports. `checks` (effort: L)
- [x] 4 — [P1] Quality gates: false-positive harness, severity re-grade, `sudo -n` discipline, unknown/skipped status + scoring math, Selenium UI e2e. `tests` (effort: L)
- [x] 5 — [P1] Auth checks: sudoers.d auditing (`AUTH-9341`), PAM faillock/pwquality (`AUTH-9350`), sshd hardening directives (`SSH-7408`). `checks` (effort: M)
- [x] 6 — [P1] Boot/kernel checks: Secure Boot + `module.sig_enforce` (`BOOT-5124`), report-only livepatch (`KRNL-5790`), extended sysctl (`KERN-5822`). `checks` (effort: M)
- [x] 7 — [P1] Integrity checks: FIM database freshness (`FINT-4316`), USB device authorization (`USB-1000`). `checks` (effort: M)
- [x] 8 — [P1] Network checks: firewall rich rules (`FIRE-4512`), socket→process→package attribution (`NETW-3030`). `checks` (effort: M)
- [x] 9 — [P1] Scheduler presence: cron/at allow-deny + world-writable job detection (`SCHD-7230`). `checks` (effort: S)
- [x] 10 — [P1] `SECURITY.md` release-verification parameterized by `VERSION` (was v1 item 177, duplicate of naming pass). `docs` (effort: S)
- [x] 11 — [P4] Process: milestone reviews every 10 items, roadmap-worker skill, roadmap quality passes. `process` (effort: S)

History: v1 items, per-item merges, and review `ROADMAP-REVIEW-050.md` remain in git. Naming rationale lives in `docs/NAMING.md`.

---

## v2.6.0 — Checks wave 2 (12–22)

Each item = check + test IDs + fixtures + docs. Registry (`test_ids.py`) is authoritative.

- [ ] 12 — [P1] Logrotate presence + auth/syslog rotation config. `checks` (effort: S)
- [ ] 13 — [P1] Journald persistence (`Storage=persistent`, `SystemMaxUse`, forwarding). `checks` (effort: S)
- [ ] 14 — [P1] PHP-FPM / opcache / `disable_functions` audit (where PHP present). `checks` (effort: S)
- [ ] 15 — [P1] Redis/Memcached/Elasticsearch bind + auth checks (no open `0.0.0.0` without password). `checks` (effort: M)
- [ ] 16 — [P1] TLS certificate expiry scan for local services (not just web: mail, DB). `checks` (effort: M)
- [ ] 17 — [P1] World-writable + SUID/SGID combined triage with package-owned allowlist to cut noise. `checks` (effort: M)
- [ ] 18 — [P1] Container runtime socket exposure (`/var/run/docker.sock` perms, Podman socket, containerd). `checks` (effort: S)
- [ ] 19 — [P1] Kubernetes kubelet/node CIS-lite (anonymous-auth, read-only-port, event qps) when kubelet detected. `checks` (effort: M)
- [ ] 20 — [P1] Time sync extended (chrony `nts`, NTS sources, `timedatectl` NTP active, max skew). `checks` (effort: S)
- [ ] 21 — [P1] Livepatch × reboot-required correlation: a livepatched host pending reboot (`KERN-5830`) scores softer than one without. `checks` (effort: S)
- [ ] 22 — [P1] FIM database-age threshold (`90d` today) profile-configurable instead of hardcoded. `checks` (effort: S)

---

## v2.6.0 — Platform: API, dashboard, UI (23–41)

- [ ] 23 — [P1] Token auth on by default when `AUDITLESS_TOKEN` set — audit remaining unauthenticated `/api/*` routes; add test matrix; lock timing-safe compare (`hmac.compare_digest`) with a test; assert tokens/secrets never hit logs. `api` (effort: M)
- [ ] 24 — [P1] RBAC-lite: `viewer` vs `operator` tokens (view vs scan/remediate/rotate). `api` (effort: M)
- [ ] 25 — [P1] Pagination + filtering on `/api/reports`, `/api/hosts`, `/api/scans` (limit/offset, status, host, date range). `api` (effort: M)
- [ ] 26 — [P1] Live scan progress via WebSocket/SSE (`/api/scans/{id}/events`) instead of poll-only. `api` (effort: M)
- [ ] 27 — [P1] Bulk host import (CSV/JSON) + export; validation errors reported per-row. `dashboard` (effort: M)
- [ ] 28 — [P1] Global search (hosts, reports, check IDs, CVE strings) with keyboard shortcut. `ui` (effort: M)
- [ ] 29 — [P1] Saved report views (filters as shareable query strings). `ui` (effort: S)
- [ ] 30 — [P1] Per-host scan history timeline with index sparkline drill-down (click point → report). `ui` (effort: M)
- [ ] 31 — [P1] Compare any two reports from UI (today API-only `/api/diff` + one button path — make it first-class). `ui` (effort: S)
- [ ] 32 — [P1] Host groups / tags (prod/staging, team) with group-level fleet rollups. `api` (effort: M)
- [ ] 33 — [P1] API client (`client.py`) parity audit: every new endpoint gets a client method + test on day one. `api` (effort: S)
- [ ] 34 — [P1] OpenAPI examples + error schema consistency (`application/problem+json` for all 4xx/5xx). `api` (effort: S)
- [ ] 35 — [P1] Audit-trail UI viewer (hash chain, verify button mirrors `GET /api/audit/verify`). `ui` (effort: S)
- [ ] 36 — [P1] Token management UI (mint/revoke/last-used) — today API-only. `ui` (effort: M)
- [ ] 37 — [P1] Secrets migration/rotation UI affordances (today curl-only `POST /api/maintenance/*`). `ui` (effort: S)
- [ ] 38 — [P1] Dashboard accessibility pass (keyboard nav, ARIA, contrast) + mobile layout. `ui` (effort: M)
- [ ] 39 — [P1] Dark mode + print stylesheet for reports. `ui` (effort: S)
- [ ] 40 — [P1] CSRF + session hardening review for cookie paths (if any added); document bearer-only rationale; add CSP / `X-Frame-Options` / `X-Content-Type-Options` headers + XSS review of host-controlled rendering (hostnames, check output). `security` (effort: S)
- [ ] 41 — [P1] Rate limiting on scan-start + auth endpoints (per-IP token bucket; `429` + `Retry-After`, covered by test). `api` (effort: S)

---

## v2.6.0 — Platform: fleet, SSH, store (42–60)

- [ ] 42 — [P2] Timezone-aware cron schedules (store TZ per schedule; DST-safe next-run; persisted `next_run` survives process restart — prove with restart test). `scheduler` (effort: M)
- [ ] 43 — [P2] Schedule jitter + overlap guard audit (already partial — prove with contention tests). `scheduler` (effort: S)
- [ ] 44 — [P2] Webhook delivery log + dead-letter replay UI (today retry-only) + SSRF guard (deny private-range URLs unless explicitly allowlisted). `scheduler` (effort: M)
- [ ] 45 — [P2] Webhook signing (HMAC) + receiver verification docs. `security` (effort: S)
- [ ] 46 — [P2] Threshold policies per group (not just per host) + hysteresis (no flapping alerts). `scheduler` (effort: M)
- [ ] 47 — [P2] Drift-alert digest mode (daily summary instead of per-run spam). `scheduler` (effort: S)
- [ ] 48 — [P2] Fleet concurrency auto-tuning (bounded pool already — add load-adaptive sizing + `--fleet-jobs`). `engine` (effort: M)
- [ ] 49 — [P2] Fleet scan queue with priorities + cancellation. `api` (effort: M)
- [ ] 50 — [P2] Host health (SSH reachability) pre-check with cached status + last-seen. `dashboard` (effort: S)
- [ ] 51 — [P2] Bastion 3-hop chains + per-hop key types audit; document `AllowTcpForwarding` requirement per hop. `ssh` (effort: M)
- [ ] 52 — [P2] SSH certificate auth support (in addition to keys/passwords). `ssh` (effort: M)
- [ ] 53 — [P2] SSH channel-open failure handling: investigate e2e "Unable to open channel" under load; cover channel exhaustion in retry/backoff or document server limits (do not change code without a repro). `ssh` (effort: S)
- [ ] 54 — [P2] Kerberos/GSSAPI auth path (enterprise AD-joined fleets). `ssh` (effort: L)
- [ ] 55 — [P2] Offline/air-gap bundle (`auditless bundle` → run elsewhere → `auditless ingest`). `cli` (effort: M)
- [ ] 56 — [P2] `cron.py` ↔ `scheduler.py` consolidation (one scheduler; today two modules overlap). `scheduler` (effort: M)
- [ ] 57 — [P2] Maintenance windows (suppress alerts during windows, still record). `scheduler` (effort: M)
- [ ] 58 — [P2] Backup encryption + restore drill (`POST /api/maintenance/restore` tested in CI). `store` (effort: M)
- [ ] 59 — [P2] SQLite → Postgres optional backend (fleet-scale deployments) with migration path + parity test (same scan → same score on both). `store` (effort: L)
- [ ] 60 — [P2] Data retention policies (auto-prune old reports/snapshots/logs per policy). `store` (effort: M)
- [ ] 61 — [P2] Fleet tagging + dynamic inventory sync (AWS/GCP/Azure/NetBox importers). `integrations` (effort: L)
- [ ] 62 — [P2] Scheduler observability (`/api/scheduler/status`: next runs, lag, failures, worker saturation). `api` (effort: S)

---

## v3.0.0 — Compliance frameworks (63–82)

- [ ] 63 — [P2] CIS Rocky Linux 9 + AlmaLinux 9 mappings (RHEL-family reuse audit). `compliance` (effort: M)
- [ ] 64 — [P2] CIS Ubuntu 24.04 LTS mapping (delta from 22.04). `compliance` (effort: M)
- [ ] 65 — [P2] CIS Debian 13 mapping (delta from 12). `compliance` (effort: S)
- [ ] 66 — [P2] DISA STIG (RHEL 9) overlay, partial/best-effort with explicit gaps. `compliance` (effort: L)
- [ ] 67 — [P2] NIST 800-53 rev5 overlay (control → test-ID traceability matrix). `compliance` (effort: L)
- [ ] 68 — [P2] SOC 2 CC7 overlay (change/logging/availability evidence mapping). `compliance` (effort: M)
- [ ] 69 — [P2] ISO 27001:2022 Annex A overlay. `compliance` (effort: M)
- [ ] 70 — [P2] HIPAA technical-safeguards overlay. `compliance` (effort: M)
- [ ] 71 — [P2] PCI-DSS 4.0 overlay expansion (today focused subset → full Req 1,2,5,10,11 coverage statement). `compliance` (effort: M)
- [ ] 72 — [P2] Custom-framework authoring (`docs/COMPLIANCE_AUTHORING.md` + YAML schema + `auditless compliance lint`). `compliance` (effort: M)
- [ ] 73 — [P2] Per-control evidence export (which command output proved each verdict; redaction-safe). `compliance` (effort: M)
- [ ] 74 — [P2] Compliance trend per host (score over time, §-level deltas). `dashboard` (effort: M)
- [ ] 75 — [P2] Framework version pinning + deprecation (CIS v2.0.0 vs v3.0.0 side-by-side). `compliance` (effort: S)
- [ ] 76 — [P2] `auto` distro detection: test + document fallback chain; explicit `unknown-distro` verdict path. `compliance` (effort: S)
- [ ] 77 — [P2] Unmapped-checks transparency report per framework (never silent — already policy; add UI surface). `ui` (effort: S)
- [ ] 78 — [P2] Compliance PDF attestation pack (auditor-ready: scope, method, versions, hashes). `reports` (effort: M)
- [ ] 79 — [P2] Waivers/exceptions workflow (risk-accepted control with expiry + approver in audit trail). `compliance` (effort: M)
- [ ] 80 — [P2] Control → remediation linkage (every failed control links to a propose/approve fix). `remediation` (effort: M)
- [ ] 81 — [P2] Multi-framework diff (same host scored against CIS+STIG+NIST side-by-side). `ui` (effort: M)
- [ ] 82 — [P2] Compliance API versioning (`/api/compliance/v1/...`, framework catalog endpoint tests). `api` (effort: S)

---

## v3.0.0 — Remediation engine (83–102)

- [ ] 83 — [P2] 20 additional `Remediation` entries (sshd, sysctl, pwquality, firewall, cron perms, logrotate, journald, PHP, DB anon-users) **plus** entries for shipped checks (udev `authorized_default=0`, `aideinit`/`tripwire --init` + schedule, USBGuard baseline). `remediation` (effort: L)
- [ ] 84 — [P2] Risk-badge taxonomy expansion (`safe`/`service` today → + `reboot`, `data-loss-risk`, `irreversible`) with per-badge approval policy. `remediation` (effort: M)
- [ ] 85 — [P2] Dry-run diff preview (unified diff of files the fix would change, fetched first). `remediation` (effort: M)
- [ ] 86 — [P2] Automatic rollback snapshot (backup touched files, one-click revert, revert verified by rescan). `remediation` (effort: M)
- [ ] 87 — [P2] Least-privilege sudo scoping docs + scoped sudoers example (exact commands remediator needs, nothing more). `docs` (effort: S)
- [ ] 88 — [P2] Approval workflow: propose → second-operator approve → apply (4-eyes for `service`+ risk). `api` (effort: M)
- [ ] 89 — [P2] Scheduled remediation windows (apply only in maintenance window, auto-verify after). `scheduler` (effort: M)
- [ ] 90 — [P2] Remediation history per host (what ran, when, by whom, before/after index). `dashboard` (effort: M)
- [ ] 91 — [P2] `REMEDIATION_AUTHORING.md` conformance test (every entry has risk, idempotence proof, verify-check mapping). `tests` (effort: S)
- [ ] 92 — [P2] Idempotence guarantee: re-applying a fix is a no-op (tested per remediation). `remediation` (effort: M)
- [ ] 93 — [P2] Fix-plan bundles (one approval applies N related fixes as a transaction with per-step results). `api` (effort: M)
- [ ] 94 — [P2] Pre-flight safety checks (disk space, config syntax `sshd -t`/`visudo -c`, service existence) before apply. `remediation` (effort: M)
- [ ] 95 — [P2] Post-apply service reload discipline (only touched services, `systemctl reload` preferred over restart). `remediation` (effort: S)
- [ ] 96 — [P2] Remediation audit-trail linkage (proposal/approval/apply/verify all hash-chained). `trust` (effort: S)
- [ ] 97 — [P2] Ansible/Puppet/Chef export of approved fixes (take the verified fix to config management). `integrations` (effort: M)
- [ ] 98 — [P2] Shell-script export (`auditless fix export --format sh`) for air-gapped hosts. `cli` (effort: S)
- [ ] 99 — [P2] Remediation coverage matrix in docs (check → fix → risk → verify). `docs` (effort: S)
- [ ] 100 — [P2] Dangerous-fix guardrails (blocklist patterns like `rm -rf`, require typed confirmation). `remediation` (effort: S)
- [ ] 101 — [P2] Fix testing against weakened-target fixtures (prove each fix flips its check in e2e). `tests` (effort: M)
- [ ] 102 — [P2] Remediation metrics (MTTR per check, fix success rate) on fleet view. `dashboard` (effort: M)

---

## P3 — Reports, integrations, CLI (103–120)

- [ ] 103 — [P3] HTML standalone report (single-file, offline, print-ready). `reports` (effort: M)
- [ ] 104 — [P3] PDF report export (via HTML → print pipeline, no new runtime dep if possible). `reports` (effort: M)
- [ ] 105 — [P3] CI machine-readable outputs: SARIF (`--format sarif`) for code-scanning ingestion + JUnit XML for test-tab ingestion. `reports` (effort: M)
- [ ] 106 — [P3] CycloneDX + SPDX report artifacts alongside existing SBOM attestation. `reports` (effort: S)
- [ ] 107 — [P3] Prometheus metrics endpoint (`/metrics`: scans, scores, durations). `api` (effort: S)
- [ ] 108 — [P3] Grafana dashboard JSON + ELK/Splunk field mapping docs. `integrations` (effort: M)
- [ ] 109 — [P3] Slack/Teams/PagerDuty notifiers in addition to generic webhook. `integrations` (effort: M)
- [ ] 110 — [P3] Jira/ServiceNow auto-ticketing for failed criticals (dedupe by test-ID + host). `integrations` (effort: M)
- [ ] 111 — [P3] CI components pack: GitHub Action (`auditless-scan@v1`) + GitLab component + Jenkins shared library + Azure DevOps task. `integrations` (effort: L)
- [ ] 112 — [P3] OPA/Rego policy gate example (fail pipeline on FAIL in category X). `integrations` (effort: S)
- [ ] 113 — [P3] Report redaction mode (`--redact ips,users`) for sharing/pasting. `reports` (effort: S)
- [ ] 114 — [P3] Executive-summary template (one-page: index, delta, top-5 risks ranked by severity × exposure, trend). `reports` (effort: S)
- [ ] 115 — [P3] i18n scaffolding for UI strings (en first, community locales later). `ui` (effort: M)
- [ ] 116 — [P3] CLI interactive TUI (`auditless interactive`: pick host → scan → browse results). `cli` (effort: L)
- [ ] 117 — [P3] Shell completions (bash/zsh/fish) for CLI flags + test IDs. `cli` (effort: S)
- [ ] 118 — [P3] `--watch` mode (rescan on interval with terminal dashboard). `cli` (effort: M)
- [ ] 119 — [P3] Public status/health page for the dashboard service (`/healthz` extended: version, uptime, queue depth). `api` (effort: S)
- [ ] 120 — [P3] MCP server (Model Context Protocol) exposing scans/reports to AI assistants, reusing bearer auth. `integrations` (effort: M)

---

## P3 — Supply chain, release & ops (121–139)

- [ ] 121 — [P3] Publish to PyPI (`auditless` sdist+wheels) with Trusted Publishing (OIDC); needs `PYPI_API_TOKEN` decision recorded. `release` (effort: M)
- [ ] 122 — [P3] Sign git tags (`git tag -s`) + verify in release workflow. `release` (effort: S)
- [ ] 123 — [P3] Attach SBOM + provenance to GitHub Release assets (not just image attestations). `release` (effort: S)
- [ ] 124 — [P3] SLSA Build Level 3 provenance for Python artifacts (not just container). `release` (effort: M)
- [ ] 125 — [P3] Reproducible-builds check (two builds → identical digests, CI gate). `release` (effort: M)
- [ ] 126 — [P3] Container minimalism: distroless/slim variant, non-root verified, `no-new-privileges`. `docker` (effort: M)
- [ ] 127 — [P3] Image vulnerability SLO (Trivy HIGH/CRITICAL → block release; document exceptions). `security` (effort: S)
- [ ] 128 — [P3] Dependency-floor policy (monthly `pip-audit` CI job; floors already raised for past OSVs). `security` (effort: S)
- [ ] 129 — [P3] Pinned-action freshness SLO (Dependabot weekly, semver-grouped, auto-merge patch). `ci` (effort: S)
- [ ] 130 — [P3] Release-drafter / auto-notes curated from `CHANGELOG.md` (single source of truth). `release` (effort: S)
- [ ] 131 — [P3] Version-bump automation (`bumpver` config: one command bumps `__init__`+`pyproject`+changelog stub). `ci` (effort: S)
- [ ] 132 — [P3] Docker multi-registry (GHCR + Docker Hub mirrors) with cosign signing on both. `release` (effort: M)
- [ ] 133 — [P3] Helm chart + Kubernetes CronJob example for fleet scans. `ops` (effort: M)
- [ ] 134 — [P3] Systemd unit + logrotate example for `--serve` on bare metal. `ops` (effort: S)
- [ ] 135 — [P3] Backup/restore runbook tested quarterly in CI (restore into scratch volume, verify). `ops` (effort: M)
- [ ] 136 — [P3] Incident-response runbook (`docs/IR_RUNBOOK.md`: compromised-host scan profile + evidence capture). `docs` (effort: M)
- [ ] 137 — [P3] Scorecard remediation inbox-zero (keep score high; track deltas per release). `security` (effort: S)
- [ ] 138 — [P3] Fuzz `verify-release` failure paths (bad digest, expired cert) with negative tests. `tests` (effort: M)
- [ ] 139 — [P3] Release smoke matrix (amd64+arm64 boot test already — add `--serve` boot + one API call). `release` (effort: S)

---

## P4 — Quality, docs & community (140–158)

- [ ] 140 — [P4] Coverage ratchet: hold the line from the current baseline, then push to 90%+ (exclude `dashboard.py` HTML template strings honestly; cover logic). `tests` (effort: S)
- [ ] 141 — [P4] Mutation testing baseline (mutmut/cosmic-ray on `checks.py` pure parsers). `tests` (effort: M)
- [ ] 142 — [P4] Property-based tests (Hypothesis) for parsers (sysctl, fstab, sshd_config, resolv.conf). `tests` (effort: M)
- [ ] 143 — [P4] Windows/macOS CI parity audit — fix/flake-hunt slow tests (known flake classes: registry pull failures, Windows loopback resets, e2e timing/channel pressure; rerun-once policy for proven infra flakes). `ci` (effort: M)
- [ ] 144 — [P4] E2E live-fire range expansion (more distros in `tests/test_e2e.py`, weakened-target matrix). `tests` (effort: L)
- [ ] 145 — [P4] Performance regression suite (per-check timings published as artifact). `perf` (effort: M)
- [ ] 146 — [P4] Type-strictness ratchet (mypy `disallow_untyped_defs` on new modules, grandfather old). `quality` (effort: M)
- [ ] 147 — [P4] Pylint custom checker for check-authoring rules (every check has test ID, category, remediation link). `quality` (effort: M)
- [ ] 148 — [P4] Docs site (MkDocs + `docs/` as source, versioned per release, hosted on GH Pages). `docs` (effort: M)
- [ ] 149 — [P4] Check-authoring cookbook (`docs/CHECK_AUTHORING.md` mirroring `REMEDIATION_AUTHORING.md`) + template generator (`auditless new-check`). `docs` (effort: M)
- [ ] 150 — [P4] Architecture Decision Records (`docs/adr/`: naming, scheduler, store backend, auth model). `docs` (effort: S)
- [ ] 151 — [P4] `PROJECT_STRUCTURE.md` + `FEATURES_ADDED.md` refresh + README badge-freshness guard (static shields drifted once already: test or automation) + remaining `Linux Health` stragglers in README body + fleet note that stock kernels report `authorized_default=-1` + `NAMING.md` upkeep. `docs` (effort: M)
- [ ] 152 — [P4] Demo environment (`docker compose --profile demo`: scanner + vulnerable target + seeded data). `docs` (effort: M)
- [ ] 153 — [P4] Video/GIF quickstart in README (60-second scan-to-report). `docs` (effort: S)
- [ ] 154 — [P4] Community health: `CODE_OF_CONDUCT` enforcement contact, issue/PR templates triage, `good-first-issue` label pass. `community` (effort: S)
- [ ] 155 — [P4] Telemetry (opt-in, anonymous): check runtimes + error rates to prioritize work; privacy policy. `product` (effort: M)
- [ ] 156 — [P4] Plugin system (entry-point `auditless.checks` third-party checks, sandboxed, profile-filterable) — Lynis parity item. `product` (effort: L)
- [ ] 157 — [P4] Multi-system central reporting (fleet rollup dashboard already partial → hardened, exportable). `product` (effort: L)
- [ ] 158 — [P4] CIS-CAT/Lynis report import (migrate existing audit history into Auditless store). `integrations` (effort: M)
- [ ] 159 — [P4] v4.0 major: complete package rename (`linux_health` → `auditless`) with codemod + migration guide, dropping deprecated aliases. `product` (effort: L)

---

## Release plan

- **v2.6.0 (platform):** sections Checks wave 2 + Platform API/UI + Platform fleet/SSH/store + Reports/CLI (items 12–62, 103–120) — dashboard/API hardening, scheduler observability, machine-readable outputs. Release decision is a maintainer call, not loop work.
- **v3.0.0 (compliance + remediation):** sections Compliance + Remediation (items 63–102) — framework expansion, bundles/approvals, attestation packs.
- **Continuous:** Supply chain/ops (121–139) and Quality/backlog (140–159) ride every release; next milestone review at 60.

## Supersedes

`docs/IMPLEMENTATION_ROADMAP_V3.md` (v3.0 Lynis-parity plan, largely delivered) remains as historical reference, as do `ROADMAP-REVIEW-*.md` (written against v1 numbering). This file is authoritative going forward.

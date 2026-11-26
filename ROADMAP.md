# Auditless Roadmap, November 2026

> Canonical repo: the auditless repository under the Greg 2600 account. This file replaces the v2 list rebuilt in PR #117. Items that are still valid are carried forward, and items shipped since then are checked after verification against git history. Item lines follow the `scripts/roadmap.py` format so the status and mark commands keep working. Numbering stays sequential 1 to N and is locked by `tests/test_roadmap.py`.

## Vision

Auditless is an agentless Linux security assessment platform that turns SSH reachable hosts into scored, reproducible evidence. It combines more than 100 checks, Lynis compatible test IDs, profiles, a hardening index, JSON reports, a local dashboard and API, fleet scheduling, compliance mappings, and remediation guidance, delivered through a signed container. The goal is to make hardening measurable and fixable at fleet scale without installing an agent, while keeping every verdict explainable and every fix reviewable.

## Current state

* Package version is 4.0.1 after the v4 rename, with a migration guide in `docs/MIGRATION_v4.md`. Release metadata was added in PR #132 and PR #133.
* The engine runs checks in parallel, pools SSH sessions, retries transient failures, enforces strict host keys, and caches command output. Reports are deterministic and carry test IDs and a hardening index.
* Checks cover 24 domains. Recent additions include logrotate in PR #121, journald persistence in PR #125, PHP FPM and opcache in PR #126, cron allow and deny files in PR #116, listener attribution in PR #115, firewall rich rules in PR #114, FIM database freshness in PR #104, and USB authorization in PR #112.
* The local dashboard and API support token auth, fleet hosts, a heatmap in PR #122, range scans in PR #124, onboarding helpers in PR #123, and verbose SSH output in PR #127.
* Delivery is a multi architecture GHCR image built on Python 3.15 in PR #120, with SLSA provenance, an SPDX SBOM, keyless cosign signing, verification in CI, and a Trivy scan uploaded to code scanning.
* Test gate: a local run of the full suite reported 812 passed, 16 skipped, and 1 failed. Coverage is 90 percent overall, with `checks.py` at 82 percent. The failing test, `test_scan_ports_opt_out_skips_banners`, assumes a service listening on local port 22. A backup naming test also failed once in an earlier run.
* CI: the latest Tests run on main for PR #133 had every job green except e2e. In e2e, 15 of 16 tests passed and `test_api_diff_and_report_formats` saw a scan finish in error state instead of done. The matrix covers Python 3.11 and 3.12 on Linux, macOS, and Windows. Ruff, Black, Pylint at 10.00, Mypy, Bandit HIGH only, a package build, coverage upload, and a parallel speedup gate run on each matrix leg.
* Open work: PR #134 proposes Python 3.13 and 3.15 on Linux plus cancellation of superseded runs. PR #135 adds CSP and isolation headers. PR #136 adds rate limiting on scan start and token mint. Dependabot PRs #128, #129, #130, and #131 update Selenium, Ruff, Pylint, and the Scorecard action. No open issues were found at the time of writing.

## Shipped, verified in git history

- [x] 1 — [Shipped] Engine core: parallel checks, SSH pool and retry, strict host keys, timeouts, output cache, max output bytes. Why: fleet scans finish fast without flaky sessions. Size: L.
- [x] 2 — [Shipped] Naming and packaging: v4 rename to `auditless`, console script, migration guide, artifact prefixes, CITATION.cff and Zenodo DOI in PR #132 and PR #133. Why: one canonical name across install, docs, and releases. Size: L.
- [x] 3 — [Shipped] Check registry, profiles, deterministic reports, Selenium UI e2e, and quality gates. Why: verdicts are reproducible and auditable. Size: L.
- [x] 4 — [Shipped] Auth and boot checks: sudoers.d, PAM faillock and pwquality, sshd directives, Secure Boot, livepatch, extended sysctl in PR #85, #86, #87, #99, #102, and #103. Why: closes high value hardening gaps. Size: L.
- [x] 5 — [Shipped] Integrity, network, and scheduler checks: FIM freshness, USB authorization, firewall rich rules, listener attribution, cron allow and deny in PR #104, #112, #114, #115, and #116. Why: installed tools are no longer treated as protection. Size: L.
- [x] 6 — [Shipped] Logging and application checks: logrotate retention in PR #121, journald persistence in PR #125, PHP FPM and opcache in PR #126. Why: closes the remaining wave two check items. Size: M.
- [x] 7 — [Shipped] Dashboard and ops: fleet heatmap in PR #122, fleet onboarding in PR #123, range scans in PR #124, verbose SSH output in PR #127, Python 3.15 container in PR #120. Why: the platform is usable for real fleets, not only single hosts. Size: M.
- [x] 8 — [Shipped] Roadmap process: v2 rebuild in PR #117 and milestone review 050 in PR #113. Why: the backlog stays machine readable and reviewed. Size: S.

## Now, next 2 to 4 weeks

- [ ] 9 — [Now] Land PR #135, CSP and isolation headers on the dashboard and API. Why: the local UI currently sets no response headers. Size: S.
- [ ] 10 — [Now] Land PR #136, per IP token bucket on scan start and token mint with 429 and Retry After. Why: expensive endpoints can be abused without a limit. Size: S.
- [ ] 11 — [Now] Land PR #134, Python 3.13 and 3.15 on Linux plus concurrency cancellation. Why: the shipped image runtime is untested and superseded runs waste CI minutes. Size: S.
- [ ] 12 — [Now] Merge Dependabot PRs #128, #129, #130, and #131 after green gates. Why: keeps dev tools and the Scorecard action current. Size: S.
- [ ] 13 — [Now] Fix the e2e flake where `test_api_diff_and_report_formats` sees a scan end in error state. Why: the latest main run is red and blocks a release. Size: M.
- [ ] 14 — [Now] Make `test_scan_ports_opt_out_skips_banners` independent of a listener on local port 22. Why: the local suite fails with connection refused. Size: S.
- [ ] 15 — [Now] Pin down the backup naming and prune order flake seen once in `test_backup_uses_auditless_prefix`. Why: an order dependent test weakens every gate. Size: S.
- [ ] 16 — [Now] Audit every `/api` route for token coverage and add a route matrix test. Why: bearer auth is optional today and an unauthenticated route leaks host data. Size: M.
- [ ] 17 — [Now] Add a container runtime socket exposure check for Docker, Podman, and containerd sockets. Why: a writable socket is equivalent to host root. Size: S.
- [ ] 18 — [Now] Make the FIM database age threshold configurable in profiles. Why: the hardcoded 90 days does not fit every policy. Size: S.
- [ ] 19 — [Now] Correlate livepatch active with reboot required in `KERN-5830`. Why: a livepatched host pending reboot is less urgent than one without. Size: S.
- [ ] 20 — [Now] Extend time sync checks to chrony NTS and timedatectl NTP active. Why: clock skew breaks auth and audit evidence. Size: S.
- [ ] 21 — [Now] Refresh stale README badges and test counts. Why: the README still claims 507 tests and 87 percent coverage against 812 passed and 90 percent. Size: S.
- [ ] 22 — [Now] Update the docs index version from 2.0.0 to 4.0.1 and link the v4 migration guide. Why: new users follow stale instructions. Size: S.

## Next, 1 to 3 months

This is a scope menu rather than a commitment. The maintainer picks a slice each cycle and reprioritizes when a release or a security finding demands it.

- [ ] 23 — [Next] Redis, Memcached, and Elasticsearch bind and auth checks. Why: open data stores without passwords are a common finding. Size: M.
- [ ] 24 — [Next] TLS certificate expiry scan for local mail and database services. Why: expiry outages are missed by web only checks. Size: M.
- [ ] 25 — [Next] World writable and SUID or SGID triage with a package owner allowlist. Why: reduces noise from expected binaries. Size: M.
- [ ] 26 — [Next] Kubernetes kubelet and node CIS lite when kubelet is detected. Why: node roles are part of the fleet. Size: M.
- [ ] 27 — [Next] Pagination and filtering on reports, hosts, and scans endpoints. Why: fleet data grows past a single page. Size: M.
- [ ] 28 — [Next] Bulk host import and export with per row validation errors. Why: onboarding a fleet by hand does not scale. Size: M.
- [ ] 29 — [Next] Host groups and tags with group level rollups. Why: production and staging need different views. Size: M.
- [ ] 30 — [Next] Per host scan history timeline with a score sparkline that opens a report. Why: makes drift visible. Size: M.
- [ ] 31 — [Next] First class comparison of any two reports in the UI. Why: the diff API exists but is exposed through one button only. Size: S.
- [ ] 32 — [Next] Saved report views as shareable query strings. Why: auditors need repeatable links. Size: S.
- [ ] 33 — [Next] API client parity audit with a client method and test per endpoint. Why: new routes must be usable from Python. Size: S.
- [ ] 34 — [Next] Token management UI for mint, revoke, and last used. Why: token handling is curl only today. Size: M.
- [ ] 35 — [Next] Audit trail viewer with a verify button that mirrors the verify endpoint. Why: trust evidence should be visible in the UI. Size: S.
- [ ] 36 — [Next] Timezone aware schedules with DST safe next run and restart persistence. Why: schedules drift after DST and process restarts. Size: M.
- [ ] 37 — [Next] Webhook delivery log, replay, and a guard against private network URLs. Why: failed notifications are silent and can be abused for SSRF. Size: M.
- [ ] 38 — [Next] HMAC signing for webhooks with receiver docs. Why: receivers cannot authenticate events today. Size: S.
- [ ] 39 — [Next] Threshold policies per group with hysteresis. Why: per host rules flap under load. Size: M.
- [ ] 40 — [Next] Adaptive fleet concurrency and a fleet jobs flag. Why: a fixed pool underuses large fleets and overloads small hosts. Size: M.
- [ ] 41 — [Next] SSH certificate authentication support. Why: enterprise fleets issue short lived certificates instead of keys. Size: M.
- [ ] 42 — [Next] Reproduce the channel open failures seen under e2e load before changing retry logic. Why: one failure is a hint, not evidence. Size: S.
- [ ] 43 — [Next] Scheduler status endpoint with next runs, lag, failures, and worker saturation. Why: operators cannot see queue health. Size: S.
- [ ] 44 — [Next] CIS mappings for Rocky Linux 9 and AlmaLinux 9. Why: RHEL family hosts are common. Size: M.
- [ ] 45 — [Next] CIS mapping for Ubuntu 24.04. Why: the current map targets 22.04. Size: M.
- [ ] 46 — [Next] CIS mapping for Debian 13. Why: stable releases move on. Size: S.
- [ ] 47 — [Next] Custom framework authoring with YAML schema and a lint command. Why: teams need their own controls. Size: M.
- [ ] 48 — [Next] Per control evidence export with redaction. Why: auditors need the command output behind each verdict. Size: M.
- [ ] 49 — [Next] Waivers and exceptions with expiry and approver in the audit trail. Why: accepted risk must be visible and time bounded. Size: M.
- [ ] 50 — [Next] Remediation entries for checks already shipped, including USBGuard baseline and FIM init. Why: a finding without a safe fix is half a product. Size: L.
- [ ] 51 — [Next] Dry run diff preview for fixes. Why: operators need to see file changes before apply. Size: M.
- [ ] 52 — [Next] Rollback snapshot with verified one click revert. Why: risky fixes need a way back. Size: M.
- [ ] 53 — [Next] Second operator approval for risky fixes. Why: service and data loss changes need four eyes. Size: M.
- [ ] 54 — [Next] Conformance test for remediation authoring rules. Why: every fix needs risk, idempotence, and a verify check. Size: S.
- [ ] 55 — [Next] Idempotence test per remediation. Why: repeated apply must be a no op. Size: M.
- [ ] 56 — [Next] Pre flight checks for disk space, config syntax, and service presence. Why: stops fixes from breaking a host. Size: M.
- [ ] 57 — [Next] Strong confirmation for dangerous fix patterns. Why: a blocked list alone is not enough. Size: S.
- [ ] 58 — [Next] Fix tests against weakened target fixtures. Why: proves each fix flips its own check. Size: M.

## Later

- [ ] 59 — [Later] Optional Postgres store backend with a score parity test. Why: SQLite has one writer at fleet scale. Size: L.
- [ ] 60 — [Later] Data retention policies for reports, snapshots, and logs. Why: long running fleets accumulate unbounded data. Size: M.
- [ ] 61 — [Later] Dynamic inventory importers for AWS, GCP, Azure, and NetBox. Why: static host lists go stale. Size: L.
- [ ] 62 — [Later] Bastion chains with more hops and per hop key audits. Why: deep networks need multi hop access. Size: M.
- [ ] 63 — [Later] Kerberos and GSSAPI authentication. Why: domain joined fleets use tickets. Size: L.
- [ ] 64 — [Later] Offline bundle commands to scan elsewhere and ingest later. Why: air gap sites cannot reach the controller. Size: M.
- [ ] 65 — [Later] Consolidation of the cron and scheduler modules. Why: two schedulers overlap today. Size: M.
- [ ] 66 — [Later] Maintenance windows that suppress alerts but keep records. Why: planned work should not page anyone. Size: M.
- [ ] 67 — [Later] DISA STIG overlay for RHEL 9 with explicit gaps. Why: regulated users need STIG evidence. Size: L.
- [ ] 68 — [Later] NIST 800-53 revision 5 control traceability. Why: maps test IDs to controls. Size: L.
- [ ] 69 — [Later] Compliance PDF attestation pack with scope and hashes. Why: auditors want a signed paper trail. Size: M.
- [ ] 70 — [Later] Side by side multi framework comparison. Why: one host often needs several mappings. Size: M.
- [ ] 71 — [Later] Ansible, Puppet, and Chef export of approved fixes. Why: verified fixes should reach config management. Size: M.
- [ ] 72 — [Later] Standalone HTML report and PDF export. Why: reports must travel without the dashboard. Size: M.
- [ ] 73 — [Later] CI component pack for GitHub Actions, GitLab, and Jenkins. Why: lowers adoption cost. Size: L.
- [ ] 74 — [Later] Slack, Teams, and PagerDuty notifiers. Why: generic webhooks are not enough for on call. Size: M.
- [ ] 75 — [Later] Jira and ServiceNow ticketing with dedupe by test ID and host. Why: closes the remediation loop. Size: M.
- [ ] 76 — [Later] MCP server exposing scans and reports with bearer auth. Why: assistants should query evidence safely. Size: M.
- [ ] 77 — [Later] Interactive terminal mode and a watch mode. Why: local operators want a fast feedback loop. Size: L.
- [ ] 78 — [Later] Plugin system for third party checks. Why: keeps parity with Lynis extensions. Size: L.
- [ ] 79 — [Later] Opt in anonymous telemetry with a privacy policy. Why: runtime data should drive priorities. Size: M.
- [ ] 80 — [Later] Versioned docs site built from the docs directory. Why: the current docs index is stale. Size: M.
- [ ] 81 — [Later] Architecture decision records for naming, scheduler, store, and auth. Why: decisions need context. Size: S.
- [ ] 82 — [Later] Import of CIS CAT and Lynis history. Why: protects prior audit investment. Size: M.

## Quality and DevOps

- [ ] 83 — [Quality] Coverage ratchet to 92 percent with `checks.py` above 88 percent. Why: 82 percent in the largest module hides regressions. Size: M.
- [ ] 84 — [Quality] Zero known flakes in unit and e2e suites, with reruns only for proven infrastructure flakes. Why: a red gate must mean a real defect. Size: S.
- [ ] 85 — [Quality] Property based tests for sysctl, fstab, sshd, and resolver parsers. Why: parsers see hostile input. Size: M.
- [ ] 86 — [Quality] Mutation baseline on pure check parsers. Why: measures whether tests actually catch changes. Size: M.
- [ ] 87 — [Quality] Windows and macOS parity on 3.13 and 3.15 once PR #134 lands. Why: release claims must match tested platforms. Size: M.
- [ ] 88 — [Quality] Per check timing artifact and a regression gate. Why: catches slow checks before users do. Size: M.
- [ ] 89 — [Quality] Monthly pip audit job with a dependency floor policy. Why: known advisories should fail fast. Size: S.
- [ ] 90 — [Quality] Block releases on Trivy HIGH and CRITICAL with a logged exception path. Why: Trivy currently reports but does not gate. Size: S.
- [ ] 91 — [Quality] Weekly Dependabot grouping for pinned actions with patch auto merge. Why: action pins are already required by tests. Size: S.
- [ ] 92 — [Quality] Slim or distroless image variant verified non root with no new privileges. Why: shrinks attack surface. Size: M.
- [ ] 93 — [Quality] Signed git tags verified in the release workflow. Why: source and image provenance should match. Size: S.
- [ ] 94 — [Quality] PyPI trusted publishing with OIDC after the distribution name decision. Why: GHCR alone limits adoption. Size: M.
- [ ] 95 — [Quality] Release notes generated from CHANGELOG.md. Why: one source of truth for changes. Size: S.
- [ ] 96 — [Quality] Reproducible build check across two builds. Why: proves the artifact matches the source. Size: M.
- [ ] 97 — [Quality] Backup and restore drill in CI against a scratch volume. Why: an untested backup is not a backup. Size: M.
- [ ] 98 — [Quality] Keep OpenSSF Scorecard findings at inbox zero. Why: supply chain posture is part of the product. Size: S.

## Known risks

* The latest main CI run is red because e2e saw a scan end in error state in `test_api_diff_and_report_formats`. Do not cut a release until a green run is confirmed.
* E2E channel open failures have been seen under load before. The milestone 050 review says one failure is not proof. Item 42 keeps this as investigation before code changes.
* `test_scan_ports_opt_out_skips_banners` depends on a local listener on port 22 and fails in a plain checkout. The backup naming test also failed once, so the suite still has order or timing sensitivity.
* README badges and the docs index advertise older numbers and versions. Until items 21 and 22 land, new users may trust stale figures.
* PR #135 relies on inline scripts in the Content Security Policy and allows a public CDN for API docs. HSTS is deferred to the operator reverse proxy.
* PR #136 ignores forwarded client headers, so behind a proxy all clients share one bucket and a single noisy client can throttle everyone.
* The container ships Python 3.15 while CI tests 3.11 and 3.12 until PR #134 merges. An untested runtime can regress silently.
* Coverage is 90 percent overall but `checks.py` is 82 percent, so parser and check regressions can hide.
* SQLite has a single writer and no Postgres backend yet. Fleet scale workloads may hit lock contention.
* PyPI publishing is not configured. Distribution depends on the GHCR image and the release workflow notes a pending token and name decision.
* Almost all work flows through one maintainer. Seven pull requests are open, four of them Dependabot updates, so review capacity is a bottleneck.

## Supersedes

`docs/IMPLEMENTATION_ROADMAP_V3.md` and the milestone 050 review remain as history. The v2 list is preserved in git at commit `39b18d7`. This file is authoritative for planning. Item numbers stay sequential because `tests/test_roadmap.py` locks them and `scripts/roadmap.py` depends on them.

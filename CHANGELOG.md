# Changelog

All notable changes to Auditless are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2026-11-21

### BREAKING

- Package rename completed: the import package, module path, console
  script and config locations now use the `auditless` name. The
  compatibility shim, legacy console alias and config fallbacks were
  removed. See `docs/MIGRATION_v4.md`.
- SSH strict host-key checking is now default-on (`--strict-host-key-
  checking` default `True`; `--no-strict-host-key-checking` opts out;
  API `strict_host_key_checking` defaults `True`). Scans against
  unknown hosts now fail closed with `ssh-keyscan` guidance. Populate
  `~/.ssh/known_hosts` before upgrading (see README “SSH Host Key
  Management”).

### Changed

- Unprivileged scans (non-root, no sudo, no password) now mark the
  four root-only checks (stale/recent accounts, sudo usage, privilege
  vectors) as `unknown` results under a Privilege category instead of
  reporting PASS on unreadable sources. Privileged scans unchanged.
- Severity re-grade (FAIL = active compromise / remotely exploitable /
  missing critical control; WARN = hardening gap). Upgraded to FAIL:
  DBS-1002 anonymous MySQL accounts (auth bypass, exploited in the
  wild), DBS-1004 PostgreSQL trust auth (passwordless DB access),
  AUTH-9234 extra UID 0 accounts (backdoor indicator). Downgraded to
  WARN: FS-3011 missing /tmp noexec, HTTP-6503 missing security
  headers, HTTP redirect missing, directory listing enabled (each
  needs a second vector to exploit), DBS-1007 no backup evidence
  (operational, not compromise), DNSSEC absent (integrity hardening).
- Wrong sudo passwords now fail fast: with a password given, the scan
  verifies `sudo -S true` up front and aborts with an actionable error
  instead of degrading all sudo-gated checks one by one.
- New `unknown` check status (❓): unprivileged-skipped, timed-out,
  and crashed checks no longer masquerade as WARN/FAIL — they are
  counted separately and excluded from hardening-index math (overall
  and per-category) and compliance verdicts/averages. Same for the
  scan-deadline truncation marker.
- ACCT-5006 log-retention stage 2: auth/syslog/audit configs are now
  audited for rotate/maxage directives, world-writable `create` modes,
  world-writable live log files, and stale logrotate status; a config
  file's presence alone no longer passes.
- ACCT-5007 journald persistence: new check verifies `Storage=persistent`
  (or `auto` with `/var/log/journal`), a configured journal size limit
  (`SystemMaxUse`/`SystemKeepFree` and friends) and off-host forwarding
  via journal-upload, rsyslog or syslog-ng. Commented-out directives are
  ignored, drop-in overrides win, and failed probes return `unknown`.
- PHP-2320 PHP hardening stage 2: effective `php -i` and PHP-FPM pool
  configs are audited for an exact dangerous `disable_functions` allowlist,
  URL inclusion, session-cookie and opcache API settings, and FPM pools
  running as root, listening on all interfaces or with world-writable
  sockets. A failed probe returns `unknown`.
- New checks: AUTH-9341 sudoers drop-in auditing, AUTH-9350 PAM
  faillock/pwquality completeness, SSH-7408 sshd hardening directives
  (AllowUsers/AllowGroups, MaxAuthTries, LoginGraceTime, ClientAlive),
  BOOT-5124 Secure Boot state plus module signature enforcement,
  KRNL-5790 kernel livepatch status (report-only: active passes,
  idle warns, absent tooling is unknown — never FAIL),
  KERN-5822 extended sysctl pass (unprivileged BPF, userns clone,
  forwarding, hardlink/symlink protection, SYN cookies, perf paranoia),
  FINT-4316 FIM database freshness (AIDE/Tripwire DB age + schedule,
  Samhain/OSSEC daemons — presence alone no longer passes),
  USB-1000 USB device authorization (usbcore.authorized_default,
  USBGuard policy, UDISKS rules; no-USB hosts pass as not applicable),
  FIRE-4512 firewall rich-rules audit (default-deny, loopback,
  established, logging across ufw/firewalld/nftables/iptables),
  NETW-3030 socket-to-package attribution (ss pid to dpkg/rpm owner;
  unpackaged /tmp or deleted-exe listeners warn as possible rogues),
  SCHD-7230 cron/at allow-deny audit (missing allow/deny files warn;
  world-writable job paths flagged as persistence vectors).

### Deprecated

- Deprecated console alias: emitted a notice pointing at `auditless`.
  Removed in 4.0.

### Added

- Fleet heatmap: a treemap card in the dashboard with a host/issue toggle.
  `GET /api/fleet/heatmap?mode=host|issue` groups tiles by subnet or check
  category, sizes them by finding weight or affected-host count, and
  colours them by hardening index or worst status. Raw check details and
  credentials are never included in the response.
- Range scanning: the New scan card accepts a network range (CIDR, hyphen
  range or single IP), probes it for open SSH, and launches one bounded
  scan per reachable host with per-host progress. New
  `POST /api/scans/range` and `ApiClient.range_scan()` return a discovery
  summary plus job ids. Ranges are capped (256 addresses by default) and
  no credentials are used during the port probe.

- Fleet operations helpers: `ops/onboard_fleet.py` registers hosts from a
  TSV/CSV inventory and/or runs one baseline scan each through the public
  API; `ops/serve.sh` / `ops/stop.sh` manage a loopback dashboard with a
  pidfile. Documented in `ops/README.md` with a generic sequencing guide in
  `docs/FLEET_PLAYBOOK.md`. Inventories, credentials and baseline summaries
  are intentionally local-only and are never written to git.

## [2.5.3] - 2026-11-05

### Fixed

- Release verify chain: cosign-native SPDX SBOM attestation
  (buildx attestations are not cosign-readable) and `slsa-verifier`
  for buildx SLSA provenance; first fully green signed release.

## [2.5.2] - 2026-11-05

### Fixed

- Release pipeline: GHCR login in sign-image job so cosign can push
  the signature (fixes UNAUTHENTICATED on v2.5.1); first fully
  signed + verified release.

## [2.5.1] - 2026-11-05

### Fixed

- Release pipeline signs with lowercase digest refs (registry rejects
  uppercase); first fully signed + verified release.

## [2.5.0] - 2026-11-05

### Added

**Supply chain (SLSA Level 3)**
- SBOM + SLSA provenance attestations on every image build
- Keyless cosign signatures with a verify gate (signature,
  attestation, SBOM download, boot smoke test) before releases count
- OpenSSF Scorecard workflow; 10 OSV vulnerabilities closed by
  raising dependency floors; all actions SHA-pinned with Dependabot

## [2.4.0] - 2026-11-05

### Added

**Operator trust**
- Fernet-encrypted secrets at rest (SSH keys, webhook URLs) with
  migration, rotation, and boot refusal on invalid keys
- Named API tokens with last-used tracking; hash-chained operator
  audit trail with verifier (API + UI)

**Fleet scale**
- Bastion jump hosts (direct-tcpip tunnels, per-type keys, 2-hop e2e)
- Parallel fleet scans over a bounded pool (3.0x measured), fleet
  benchmark script, CLI jump flags

**Compliance expansion**
- CIS Debian 12 + RHEL 9 mappings, PCI-DSS 4.0 overlay, distro
  auto-detection, per-framework API/UI/client support

## [2.3.0] - 2026-11-04

### Added

**Fleet automation**
- Unattended cron schedules per saved host with regression/threshold/
  always/never webhook policies, hardening trends, and fleet overview
  (API, UI charts, `--no-scheduler` opt-out)
- Scheduler production gaps closed: overlap guard, webhook retries,
  SQLite snapshots (daily auto + endpoint), log rotation

**Compliance & remediation**
- Runtime test-ID registry (50 checks locked by tests)
- CIS Ubuntu Linux 22.04 v2.0.0 scoring (API + UI, best effort with
  explicit unmapped list)
- Guided remediation: propose dry-runs, approve + apply over SSH,
  automatic verification rescan (5 fixes, authoring guide)

**Platform**
- Bearer-token API auth, env-driven bind (`AUDITLESS_HOST/_PORT`),
  persistent compose stack, containerized e2e suite (14 tests),
  multi-arch images, full lint gates (black/ruff/pylint/mypy/bandit)

## [2.0.0] - 2026-01-10

### Added

**Major Features (95% Lynis Parity Achievement)**
- ✨ **Test ID System** - Lynis-compatible test identifiers (e.g., STOR-6310, AUTH-9328) for all 53 checks
- 📊 **JSON Output Format** - Machine-readable structured output via `--format json`
- ⚙️ **Profile/Configuration System** - YAML-based scan profiles for test filtering and customization
- 🎯 **Test Skip Functionality** - Skip tests by ID or category via profile configuration
- 🔍 **Enhanced Check Coverage** - Expanded from 36 to 53+ security checks across 20+ categories

**New Security Checks**
- Boot/kernel hardening (GRUB password, sysctl parameters)
- File integrity monitoring tools (AIDE, Tripwire, OSSEC)
- Package manager security (GPG verification)
- Logging and auditing (syslog, rsyslog, auditd)
- MAC systems (SELinux, AppArmor enforcement)
- Security tools detection (fail2ban, ClamAV, IDS/IPS)
- File system security (mount options: noexec, nosuid, nodev)
- Shell security (umask, TMOUT, history configuration)
- Compiler presence warnings on production systems
- Legacy service detection (telnet, rsh, FTP)
- USB storage control auditing
- Web server security (Apache/Nginx configuration)
- Database security (MySQL/PostgreSQL hardening)
- Mail server security (Postfix/Exim/Sendmail)
- PHP security configuration
- DNS configuration validation

**API & Output Enhancements**
- `render_report_json()` function with comprehensive scan data structure
- Test ID field in `CheckResult` dataclass
- Profile auto-discovery from multiple default paths
- `--profile` CLI argument for YAML configuration files
- Graceful degradation when PyYAML not installed

**Testing**
- 20+ new unit tests for JSON output, profiles, and configuration
- All tests passing (127+ total tests)
- Test coverage for new features

**Documentation**
- Added FEATURES_ADDED.md with detailed feature documentation
- Updated README with JSON output examples
- Profile/configuration usage guide
- CI/CD integration examples
- PyYAML dependency documentation
- Updated Lynis comparison table (95% parity achieved)

### Changed
- CLI now supports `--format {text|md|json}` (was `{text|md}`)
- Enhanced CLI with `--profile` argument
- Updated requirements.txt to include pyyaml>=6.0

### Fixed
- Type hints improved for better IDE support
- Import organization cleanup
- Linting issues resolved in new modules

## [1.0.0] - 2026-01-09

### Added

**Core Features**
- ✨ 36+ comprehensive security assessments across 12 security domains
- 🔒 Agentless SSH-based scanning (no agent installation required)
- 🎯 Advanced threat detection (reverse shells, crypto miners, rootkits)
- 📊 Vulnerability assessment (privilege escalation, weak configurations)
- 💻 System health monitoring (disk, memory, CPU, processes)
- 📋 Professional reporting in text and Markdown formats
- 🐳 Full Docker and Kubernetes support
- ⚙️ Configurable timeouts for high-latency networks

**Security Checks**
- Malware/backdoor detection (reverse shells, miners, rootkits)
- Privilege escalation vector identification
- Weak password policy detection
- Container escape indicator scanning
- Network security analysis (ARP spoofing, DNS tampering)
- File integrity monitoring (SUID binaries, world-writable files)
- Log tampering detection
- Suspicious network connection tracking

**Testing & Quality**
- 107 comprehensive unit tests (100% pass rate)
- 66% code coverage (100% on critical modules)
- Zero linting errors (ruff + black)
- Production-ready code quality

**Documentation**
- Professional README with 15+ sections
- Quick start guide
- Complete security check reference
- Docker deployment guide
- Development guide with examples
- Integration examples (Ansible, Nagios, Kubernetes)

**Integration**
- Docker and Docker Compose support
- Kubernetes CronJob examples
- Ansible playbook examples
- Nagios/Icinga plugin examples

---

## Future Roadmap

### [1.1.0] (Planned)
- Configuration file support (`.linuxhealth.json`)
- Baseline comparison mode (detect changes)
- Results database export (JSON/CSV)
- Custom check plugin system
- Parallel check execution
- Multi-host orchestration script

### [1.2.0] (Planned)
- SSH key-based authentication (optional password-less auth)
- Results caching for repeated scans
- Detailed remediation guidance expansion
- Helm chart for Kubernetes deployment
- Integration with Prometheus metrics

### [2.0.0] (Future)
- Agent-based scanning mode (optional)
- Windows system support
- Cloud platform scanning (AWS, Azure, GCP)
- REST API for integrations
- Web-based dashboard

---

## How to Upgrade

### From v0.x to v1.0.0

No breaking changes! All v0.x commands work with v1.0.0:

```bash
pip install --upgrade auditless
```

Then use as normal:

```bash
python -m auditless host user password
```

---

## Security Advisory

### Version 1.0.0 Security Status
- ✅ All dependencies audited
- ✅ No known vulnerabilities
- ✅ Read-only operations only
- ✅ SSH over encrypted connections

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Contributors

Thanks to all contributors who made this release possible!

- **Greg B** - Lead Developer
- **Community Feedback** - Alpha testing and suggestions

---

## Support

- 📖 **Documentation:** See [README.md](README.md)
- 🐛 **Report Bugs:** [GitHub Issues](https://github.com/Greg-2600/auditless/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/Greg-2600/auditless/discussions)
- 🔒 **Security:** See [SECURITY.md](SECURITY.md)

---

[1.0.0]: https://github.com/Greg-2600/auditless/releases/tag/v1.0.0

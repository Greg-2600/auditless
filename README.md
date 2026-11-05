# Auditless

## Agentless Linux security scanner (formerly Linux Health)

## Enterprise-Grade Security Assessment Platform for Linux Infrastructure

[![Production Ready](https://img.shields.io/badge/status-production%20ready-success)](https://github.com) [![Version](https://img.shields.io/badge/version-2.5.3-blue)](https://github.com) [![Tests](https://img.shields.io/badge/tests-507%20passing-success)](https://github.com) [![Coverage](https://img.shields.io/badge/coverage-87%25-green)](https://github.com) [![Code Quality](https://img.shields.io/badge/linting-0%20errors-success)](https://github.com) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org) [![Docker](https://img.shields.io/badge/docker-supported-blue)](https://docker.com) [![Lynis Parity](https://img.shields.io/badge/lynis%20parity-95%25-brightgreen)](https://github.com)

---

## Overview

Auditless is a comprehensive, SSH-based security assessment platform designed for enterprise Linux environments. Delivering **100+ automated security checks** across malware detection, vulnerability assessment, compliance monitoring, database security, filesystem hardening, package management, audit logging, and system health analysis—all without requiring agent installation.

Inspired by industry-standard tools like **Lynis**, this scanner achieves **95%+ feature parity** with enterprise-ready capabilities including **test ID tracking**, **JSON output**, **profile-based configuration**, **hardening index scoring**, and **actionable remediation guidance**.

**Built for Security Professionals** | Engineered for reliability, performance, and actionable intelligence delivery.

### Key Features

- **🔒 Zero-Touch Deployment** — Agentless SSH-based assessment eliminates installation overhead
- **🎯 Advanced Threat Detection** — Identifies reverse shells, crypto miners, rootkits, and sophisticated attacks
- **📊 Comprehensive Coverage** — **100+ security checks** spanning **24 categories** (database, filesystem, NFS, package security, audit)
- **🆔 Test ID System** — Lynis-compatible test identifiers for precise tracking and filtering
- **📈 Hardening Index** — 0-100 scoring with per-category breakdown and quality gates
- **📄 Multiple Output Formats** — Text, Markdown, and **JSON** for automation and integration
- **⚙️ Profile System** — YAML-based configuration for environment-specific scanning
- **⚡ Production Hardened** — Full test suite (334 tests passing), robust error handling, Docker-ready
- **📋 Executive Reporting** — Professional reports with hardening scores and remediation guidance
- **🔧 Extensible Architecture** — Modular design enables rapid custom check development
- **🐳 Container Native** — Full Docker/Kubernetes support for CI/CD integration
- **🏢 Enterprise Features** — Server hardening checks (web, database, mail), compliance validation, MAC system auditing
- **🔄 CI/CD Ready** — Native integration with GitLab CI, GitHub Actions, Jenkins, Azure DevOps

---

> ### 🎉 What's New in v2.0.0
>
> **Lynis Parity Achieved!** This release brings **95%+ feature compatibility** with the industry-standard Lynis security auditing tool:
>
> - **🆔 Test ID System** — Track and filter checks with Lynis-compatible identifiers (`STOR-6310`, `AUTH-9328`)
> - **📄 JSON Output** — Machine-readable reports for CI/CD pipelines and security orchestration platforms
> - **⚙️ Profile System** — YAML configuration for environment-specific scanning (production, dev, compliance)
> - **🔍 Advanced Filtering** — Skip tests by ID/category or run exclusive test subsets
> - **🔗 CI/CD Integration** — Ready-to-use templates for GitLab, GitHub Actions, Jenkins, Azure DevOps
>
> **Fully backward compatible** with v1.x | [See full changelog →](#changelog)

---

## Table of Contents

- [Security Assessment Framework](#security-assessment-framework)
- [Hardening Index](#hardening-index)
- [Comparison with Lynis](#comparison-with-lynis)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Security Check Reference](#security-check-reference)
- [Report Formats](#report-formats)
- [Advanced Features](#advanced-features)
  - [Test ID System](#test-id-system)
  - [JSON Output Format](#json-output-format)
  - [Scan Profiles & Configuration](#scan-profiles--configuration-system)
- [Docker Deployment](#docker-deployment)
- [Development Guide](#development-guide)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Integration Examples](#integration-examples)
  - [CI/CD Pipeline Integration](#cicd-pipeline-integration)
  - [Python Script Integration](#python-script-integration)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Requirements](#requirements)
- [Changelog](#changelog)
- [Support](#support)

---

## Security Assessment Framework

### Coverage Matrix

| Security Domain | Checks | Detection Capabilities |
| -------------- | ------ | ---------------------- |
| **System Resources** | 4 | Disk utilization, memory availability, CPU load analysis, process resource consumption |
| **Patch Management** | 2 | Reboot requirements, pending security/standard updates (distribution-aware) |
| **Network Security** | 7 | Firewall status, suspicious connections, ARP spoofing, DNS tampering, listener analysis, legacy services |
| **Authentication** | 5 | SSH configuration hardening, password policies, authentication failures, root access, brute-force detection |
| **User Account Security** | 3 | Active accounts, dormant account detection, recently created account analysis |
| **Malware/Backdoor Detection** | 4 | Reverse shell identification, cryptocurrency mining, hidden file discovery, rootkit indicators |
| **File Integrity** | 3 | SUID binary monitoring, world-writable files, critical binary modification tracking |
| **Process Security** | 3 | Network listener analysis, suspicious process locations, abnormal network behavior |
| **Privilege Escalation** | 3 | Sudo misconfiguration, dangerous capabilities, known exploit vectors |
| **Container/Kernel** | 2 | Container escape detection, kernel module integrity validation |
| **Log Security** | 2 | Log tampering detection, unexpected privilege usage monitoring |
| **Scheduled Tasks** | 1 | Cron job analysis, at job scanning, systemd timer review |
| **Boot/Kernel Hardening** | 2 | GRUB password protection, kernel security parameters (sysctl) |
| **System Integrity** | 1 | File integrity monitoring tools (AIDE, Tripwire, OSSEC) detection |
| **Package Management** | 1 | GPG verification, repository security, unsigned packages |
| **Logging & Auditing** | 1 | Syslog/rsyslog/journald, auditd status and configuration |
| **MAC Security** | 1 | SELinux/AppArmor detection, enforcement status, policy validation |
| **Security Tools** | 1 | Fail2ban, ClamAV, IDS/IPS (Snort/Suricata), rootkit scanners |
| **File System** | 1 | Mount options (noexec, nosuid, nodev), /tmp security, partition hardening |
| **Shell Security** | 1 | Umask settings, shell timeout (TMOUT), command history configuration |
| **System Tools** | 1 | Compiler presence on production, development tools audit |
| **Hardware Security** | 1 | USB storage controls, hardware security module checks |
| **Web Server** | 1 | Apache/Nginx configuration, version disclosure, SSL/TLS setup |
| **Database** | 1 | MySQL/PostgreSQL security, authentication, remote access controls |
| **Mail Server** | 1 | Postfix/Exim/Sendmail relay protection, TLS configuration |
| **Application Security** | 1 | PHP configuration hardening, dangerous functions, version disclosure |
| **Name Service** | 1 | DNS resolver configuration, DNSSEC validation, redundancy checks |

**Total: 100+ Security Checks** across **24 domains**

### Platform Capabilities

✅ **Agentless Architecture** — SSH-only remote assessment  
✅ **Threat Intelligence** — Malware, intrusion, and misconfiguration detection  
✅ **Hardening Metrics** — 0-100 scoring system with category-level insights  
✅ **Actionable Intelligence** — Clear recommendations with copy-paste remediation  
✅ **Port Discovery** — TCP connect scanning with service categorization  
✅ **Enterprise Ready** — Comprehensive testing, error handling, production deployment support  
✅ **Optional Deep Scans** — Rootkit detection (rkhunter), package hygiene analysis  
✅ **Flexible Reporting** — Text and Markdown output with hardening index visualization  
✅ **Server Auditing** — Web, database, and mail server security validation  
✅ **Compliance Support** — MAC systems, logging frameworks, package verification

---

## Hardening Index

The **Hardening Index** is a Lynis-inspired 0-100 score that quantifies your system's security posture:

### Scoring Methodology

- **PASS** checks contribute **100%** to category score
- **WARN** checks contribute **50%** to category score  
- **FAIL** checks contribute **0%** to category score

Overall index = Weighted average across all categories

### Hardening Levels

| Score Range | Level | Interpretation |
| ----------- | ----- | -------------- |
| 90-100 | 🟢 EXCELLENT | Exceptional security posture; minimal vulnerabilities |
| 75-89 | 🟡 GOOD | Strong security baseline; minor improvements recommended |
| 60-74 | 🟠 FAIR | Adequate security; several areas need attention |
| 40-59 | 🔴 POOR | Significant security gaps; immediate action required |
| 0-39 | 🔴🔴 CRITICAL | Severe security deficiencies; urgent remediation needed |

### Report Output Example

```text
HARDENING INDEX: 72/100 🟠 (FAIR)

HARDENING BY CATEGORY
------------------------------------------------
  🔴  45/100  Boot/Kernel              (✅1 ⚠️0 ❌1)
  🔴  50/100  Package Management       (✅0 ⚠️1 ❌0)
  🟠  67/100  Network Security         (✅4 ⚠️2 ❌1)
  🟡  83/100  Authentication           (✅4 ⚠️1 ❌0)
  🟢  95/100  System Resources         (✅3 ⚠️1 ❌0)
```

---

## Comparison with Lynis

This project was inspired by **Lynis** and implements many of its core security auditing principles:

### Feature Parity

| Feature | Linux Health Scanner | Lynis |
| ------- | ------------------- | ----- |
| **Agentless SSH-based scanning** | ✅ | ❌ (requires local execution) |
| **Hardening index (0-100)** | ✅ | ✅ |
| **Category-based organization** | ✅ | ✅ |
| **Test ID system** | ✅ | ✅ |
| **JSON output format** | ✅ | ✅ |
| **Profile/configuration system** | ✅ | ✅ |
| **Test filtering/skipping** | ✅ | ✅ |
| **Boot/kernel security checks** | ✅ | ✅ |
| **Package manager security** | ✅ | ✅ |
| **SELinux/AppArmor auditing** | ✅ | ✅ |
| **File integrity tool detection** | ✅ | ✅ |
| **Web/DB/Mail server checks** | ✅ | ✅ |
| **Malware/rootkit detection** | ✅ | ✅ |
| **Detailed logging** | ⚠️ Partial | ✅ |
| **Plugin system** | 🚧 Roadmap | ✅ |
| **Compliance frameworks** | 🚧 Roadmap | ✅ (Enterprise) |
| **Multi-system central reporting** | 🚧 Roadmap | ✅ (Enterprise) |

**Parity Status: ~95%** (core features complete, enterprise features planned)

### Key Differences

**Advantages of Linux Health Scanner:**

- **Remote execution** — No agent installation; scan multiple systems from one location
- **Modern Python stack** — Easy to extend and integrate
- **Docker-first** — Native containerization for CI/CD pipelines
- **Markdown reporting** — Beautiful reports for documentation and dashboards

**Advantages of Lynis:**

- **Mature ecosystem** — 15+ years of development, extensive check library
- **Compliance templates** — Pre-built PCI-DSS, HIPAA, ISO27001 checks
- **Enterprise edition** — Centralized dashboard, scheduled scanning, API
- **Broader OS support** — AIX, HP-UX, Solaris, macOS

**Use Cases:**

- **Linux Health Scanner**: Remote auditing, CI/CD security gates, container security, fleet scanning
- **Lynis**: Deep local auditing, compliance reporting, enterprise-wide security management

---

## Quick Start

### Quick Installation

```bash
# Clone repository
git clone https://github.com/Greg-2600/linux_health.git
cd linux_health

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -m linux_health --help
```

### Basic Security Assessment

```bash
# Execute comprehensive security scan
python -m linux_health 192.168.1.100 admin password

# Interactive password entry (recommended)
python -m linux_health 192.168.1.100 admin - --ask-password

# Generate Markdown report
python -m linux_health 192.168.1.100 admin password \
  --format md --output security-report.md

# Non-standard SSH port
python -m linux_health 192.168.1.100 admin password --port 2222
```

### Docker Quick Start

```bash
# Build container image
docker build -t auditless .

# Execute scan against remote host
docker run --rm auditless 192.168.1.100 admin password

# Generate persistent report
docker run --rm -v $(pwd):/reports auditless \
  192.168.1.100 admin password --format md --output /reports/scan.md

# Scan localhost from within Docker (use host network mode)
docker run --rm --network host auditless \
  localhost username password

# Alternative: Use host.docker.internal (Docker Desktop on Mac/Windows)
docker run --rm auditless \
  host.docker.internal username password
```

### Web Dashboard & API

A local web UI + documented JSON API built on FastAPI:

```bash
# Serve on http://127.0.0.1:8080
python -m linux_health --serve
python -m linux_health --serve --serve-port 9000

# In Docker (publish loopback only)
docker run --rm -p 127.0.0.1:8080:8080 auditless --serve
```

- UI at `/`, interactive Swagger docs at `/docs` (ReDoc at `/redoc`,
  machine-readable schema at `/openapi.json`)
- `POST /api/scans` starts a scan (same CLI pipeline — same checks,
  same reports); poll `GET /api/scans/{id}`; `GET .../report?format=md`
  re-renders finished reports; `GET /api/profiles` lists scan profiles
- The SSH password is write-only: in server memory for the run only —
  never stored, logged, or returned by the API. The dashboard binds to
  localhost; do not expose it to untrusted networks without authentication
  and TLS in front.

**API authentication:** set `AUDITLESS_TOKEN` to require a bearer token
on every `/api/*` route (Swagger gets an Authorize button; the UI prompts
once per tab and keeps it in session storage). For teams, mint named
tokens (`POST /api/tokens`, plaintext shown exactly once) with per-token
last-used tracking and revocation; every mutation lands in the hash-chained
operator audit trail (`GET /api/audit`, `GET /api/audit/verify`):

```bash
export AUDITLESS_TOKEN="$(openssl rand -hex 32)"
python -m linux_health --serve   # or: AUDITLESS_TOKEN=... docker compose up -d

curl -H "Authorization: Bearer $AUDITLESS_TOKEN" http://127.0.0.1:8080/api/scans
```

Without the variable, the historical behavior applies (loopback-only,
no auth). `/`, `/docs`, `/openapi.json` and `/healthz` stay public.

### Operator trust: encrypted secrets, audit trail

SSH private keys and webhook URLs are encrypted at rest with Fernet
(`cryptography`) when `AUDITLESS_MASTER_KEY` is set; without it the
server runs in legacy plaintext mode. Invalid key? The server refuses
to boot rather than guessing:

```bash
export AUDITLESS_MASTER_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
# Migrate an existing plaintext store in place (idempotent):
curl -X POST http://127.0.0.1:8080/api/maintenance/migrate-secrets
# Rotate later: POST current + new key, then restart with the new env value.
```

First-party Python client (`linux_health.client.ApiClient`, stdlib only)
talks to the app exclusively through the public API — the test suite
dogfoods it, so anything the client cannot do is not really supported:

```python
from linux_health.client import ApiClient

api = ApiClient("http://127.0.0.1:8080")
job = api.start_scan(hostname="web-01", username="root", password="s3cr3t",
                     strict_host_key_checking=True)
done = api.wait_for(job["id"])
print(done["report"]["summary"]["hardening_index"])
print(api.get_report(job["id"], format="md")[:200])
```

### Persistent UI with saved hosts, keys & report diffs

`docker compose up -d` runs the dashboard as a persistent service with
SQLite + SSH keys on a named volume (`auditless-data`):

```bash
docker compose up -d --build
open http://127.0.0.1:8080/   # UI, Swagger at /docs
```

Bind address and port are env-driven (flags win over env, env over
defaults). Bare `--serve` stays on loopback; compose binds all interfaces
*inside* the container while publishing to host loopback only:

```bash
# Local: defaults 127.0.0.1:8080, or override per run
AUDITLESS_HOST=0.0.0.0 AUDITLESS_PORT=9000 python -m linux_health --serve
python -m linux_health --serve --serve-host 127.0.0.1 --serve-port 9000

# Compose: published to host loopback regardless of container bind
AUDITLESS_PORT=9000 docker compose up -d   # -> http://127.0.0.1:9000/
```

Binding anywhere off loopback prints a warning: set `AUDITLESS_TOKEN`
(bearer auth on every `/api/*` route) and put TLS in front before
exposing it.

- **Saved hosts** (`/api/hosts` CRUD): register once, scan repeatedly.
  Password hosts still prompt per scan; key hosts authenticate from the
  stored key — passwords are never persisted.
- **SSH keys** (`PUT /api/hosts/{id}/key`): bytes land 0600 owned by the
  container user, flagged `has_key`, and are never readable back through
  any endpoint. CLI equivalent: `--key-file ~/.ssh/id_ed25519`.
- **Bastion / jump hosts**: set `jump_hostname` (+port/user/auth) on a
  host and scans tunnel through it via direct-tcpip. Jump keys upload
  with `?kind=jump` and live apart from host keys. Bastions need
  `AllowTcpForwarding yes` (as any jump host does); key auth end to end
  is recommended. CLI: `--jump-host`, `--jump-user`, `--jump-port`,
  `--jump-key-file`, `--jump-password`.
- **Reports** (`/api/reports`) persist across restarts; **diff**
  (`/api/diff?from_id=..&to_id=..`, plus the UI Compare button) shows
  fixed vs regressed checks and the hardening-index delta per host.
- **Backups** (`POST /api/maintenance/backup`, plus a daily automatic
  snapshot, pruned server-side) protect the SQLite store.

### CIS compliance mapping

Every check carries its Lynis-style test ID at runtime (`CHECK_TEST_IDS`
registry in `linux_health/test_ids.py` — attached by decorator, no manual
patching), and each ID maps to controls across four frameworks
(`linux_health/compliance.py`, best effort with direct/partial levels;
out-of-scope checks are explicitly listed, never silent):

- CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0
- CIS Debian Linux 12 Benchmark v1.0.0
- CIS Red Hat Enterprise Linux 9 Benchmark v3.0.0
- PCI-DSS v4.0 (focused overlay: firewall, auth, logging, integrity)

```bash
curl http://127.0.0.1:8080/api/compliance/controls | head -c 300
```

- `GET /api/hosts/{id}/compliance?framework=auto` scores the host's
  latest report (auto-detects the distro from the report, `auto` is the
  default; pass an explicit id to override): per-control verdicts
  (worst contributing check wins), per-section scores, a 0–100 overall
  score, coverage (mapped vs total), and the non-CIS "extended" checks.
  The UI renders it with a framework picker.

### Guided remediation (propose → approve → verify)

Failed checks map to reviewable fix scripts (`linux_health/remediations.py`).
Nothing executes without explicit approval, and every apply triggers a
verification rescan that proves the flip:

```bash
# Dry-run proposals for a stored report (scripts shown, nothing runs)
curl -X POST http://127.0.0.1:8080/api/reports/<id>/remediations

# Approve one (password is write-only; key hosts may omit it)
curl -X POST http://127.0.0.1:8080/api/remediations/<proposal>/apply \
  -H 'Content-Type: application/json' \
  -d '{"host_id": "<host>", "password": "..."}'
# -> per-command results + verification_job_id; poll it, then diff.
```

The UI "fix" link on any saved report shows proposals with risk badges
(`safe` = file writes; `service` = touches sshd + reload) and an
Approve & apply button with live results. Operators add fixes by
appending a `Remediation` entry (see `docs/REMEDIATION_AUTHORING.md`).
- Data lives in `$AUDITLESS_DATA_DIR` (`./data` locally, `/app/data` in
  the container).

### Unattended schedules, trends & drift alerts

The serving process runs a 30s scheduler loop (`--no-scheduler` opts
out). Schedules are cron expressions per saved host with a notification
policy (`regression` | `threshold` | `always` | `never`):

```bash
# Equivalent API calls (ApiClient shown)
api.create_schedule(host_id, "nightly", "0 3 * * *",
                    webhook_url="https://hooks.example.com/abc",
                    notify_on="regression")
api.create_schedule(host_id, "watch", "*/30 * * * *",
                    notify_on="threshold", min_index=70)
```

- Each run persists exactly like a manual scan, then diffs against the
  host's previous completed report. Regressions (or sub-threshold
  scores, or every run) POST a JSON payload to the webhook. Webhook URLs
  are write-only: stored server-side, flagged `has_webhook`, never
  returned or logged.
- **Trends** (`GET /api/hosts/{id}/trend`) return chronological hardening
  scores for charting; the UI draws per-host SVG sparklines.
- **Fleet** (`GET /api/fleet`) returns one row per host with its latest
  index, report id, and report count — the UI fleet table.

Development gates run on every commit via pre-commit (black, ruff,
pylint 10.00/10, mypy, bandit HIGH-only, full pytest suite) and mirror
in CI:

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pip install pre-commit && .venv/bin/pre-commit install
.venv/bin/pre-commit run --all-files
```

**Important Note for Scanning Localhost:**
When running the scanner in a Docker container to audit the **host machine itself** (localhost), you must use one of these approaches:

- **Linux:** Use `--network host` flag and target `localhost` or `127.0.0.1`
- **Mac/Windows (Docker Desktop):** Use the special hostname `host.docker.internal`

Without these configurations, the container cannot reach the host's SSH service due to Docker's network isolation.

---

## Installation

### From Source

**Requirements:** Python 3.11+, SSH client

```bash
# Clone repository
git clone https://github.com/Greg-2600/linux_health.git
cd linux_health

# Create isolated environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1

# Install runtime dependencies
pip install -r requirements.txt

# Install development tools (optional)
pip install -r requirements-dev.txt

# Validate installation
python -m linux_health --help
```

### Docker Installation

**Requirements:** Docker 20.10+, docker-compose 2.0+ (optional)

```bash
# Build production image
docker build -t auditless:latest .

# Build with specific version tag
docker build -t auditless:1.0.0 .

# Verify build
docker run --rm auditless --help
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  auditless:
    build: .
    image: auditless:latest
    environment:
      - PYTHONUNBUFFERED=1
    volumes:
      - ./reports:/app/reports
```

```bash
# Execute via Compose
docker-compose run --rm auditless host user password
```

---

## Usage

### Command-Line Interface

```bash
python -m linux_health <hostname> <username> <password> [options]
```

> **Entry points:** `auditless` (primary), `python -m linux_health`, and
> `python -m auditless`. The `linux-health` command still works but is
> deprecated — it prints a notice on every run. Kept through v3.x,
> removal slated for v4.0.

#### Required Arguments

| Argument | Description |
| -------- | ----------- |
| `hostname` | Target Linux host (IP address or FQDN) |
| `username` | SSH authentication username |
| `password` | SSH authentication password (use `-` with `--ask-password` for interactive) |

#### Optional Arguments

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--port PORT` | 22 | SSH service port |
| `--timeout SECONDS` | 5.0 | SSH connection timeout |
| `--retries N` | 0 | Retry transient SSH failures with backoff (auth fails fast; 0 disables) |
| `--no-cache` | — | Disable the command-output cache for this scan |
| `--command-timeout SECONDS` | 60.0 | Per-command execution timeout |
| `--jobs N` | 4 | Concurrent check workers per host (1=sequential, max 32) |
| `--check-timeout SECONDS` | 120.0 | Per-check ceiling for the parallel runner (WARN placeholder on expiry; ≤0 disables) |
| `--deadline SECONDS` | 0 (off) | Global scan deadline; renders a partial report with completed checks on expiry |
| `--reuse-session` | — | Reuse pooled SSH sessions across scans in this process |
| `--format {text\|md\|json}` | text | Report output format (text, Markdown, or JSON) |
| `--output PATH` | stdout | Report file destination |
| `--scan-ports PORTS` | 22,80,443,3306,5432 | Comma-separated port list for scanning |
| `--profile PATH` | — | Load scan profile from YAML file (test filtering) |
| `--ask-password` | — | Interactive password prompt |
| `--enable-rootkit-scan` | — | Execute rkhunter if available on target |
| `--check-package-hygiene` | — | Analyze orphaned/unused packages |

### Usage Examples

#### Standard Security Assessment

```bash
# Basic host scan with text output
python -m linux_health server.example.com admin password

# Comprehensive scan with all optional checks
python -m linux_health server.example.com admin password \
  --enable-rootkit-scan \
  --check-package-hygiene \
  --format md \
  --output comprehensive-report.md
```

#### Secure Credential Handling

```bash
# Interactive password prompt (recommended)
python -m linux_health server.example.com admin - --ask-password

# Read password from file
python -m linux_health server.example.com admin $(cat /secure/password)

# Environment variable
export SSH_PASS=$(vault read -field=password secret/ssh/admin)
python -m linux_health server.example.com admin "$SSH_PASS"
```

> **Sudo preflight:** when a password is given, the scanner verifies
> `sudo` up front and aborts with a clear error if it fails — no
> silent per-check degradation, and nothing ever blocks on a password
> prompt mid-scan (all remote sudo uses non-interactive `-S`). Omit
> the password for an unprivileged assessment.

#### SSH Host Key Management

Strict host-key checking is **on by default**: unknown host keys fail
the scan instead of being silently trusted (MITM protection).

```bash
# Trust a host once (verify the fingerprint out of band first!)
ssh-keyscan -p 22 server.example.com >> ~/.ssh/known_hosts

# The failure tells you exactly what to run:
#   SSH host key for 'server.example.com:22' not found in known_hosts
#   (strict checking is on by default). To trust this host ...
```

Notes:

- The scanner reads the standard OpenSSH `~/.ssh/known_hosts` of the
  user running the scan (or the dashboard process for API scans).
- In Docker, mount a persistent file so trust survives restarts:
  `-v ~/.ssh/known_hosts:/home/appuser/.ssh/known_hosts:ro`.
- Fleet onboarding: collect `ssh-keyscan` output per host, review
  fingerprints against your CMDB, then distribute one known_hosts file.
- Labs only: `--no-strict-host-key-checking` restores auto-add (the
  API equivalent is `"strict_host_key_checking": false`). Never use it
  for production targets.

#### JSON Output for Automation

```bash
# Generate JSON report for CI/CD integration
python -m linux_health server.example.com admin password \
  --format json \
  --output security-scan.json

# Parse JSON results with jq
python -m linux_health server.example.com admin password --format json | \
  jq '.summary.hardening_index'

# Fail CI/CD if hardening index below threshold
SCORE=$(python -m linux_health $TARGET $USER $PASS --format json | \
  jq -r '.summary.hardening_index')
if [ $SCORE -lt 70 ]; then
  echo "❌ Security score $SCORE below threshold 70"
  exit 1
fi
```

#### Profile-Based Scanning

```bash
# Create a scan profile
mkdir -p ~/.config/linux_health/profiles
cat > ~/.config/linux_health/profiles/production.yaml << 'EOF'
name: "Production Server Scan"
description: "Optimized for production servers"
skip_categories:
  - "System Tools"  # No compilers on production
skip_tests:
  - "USB-1000"      # No USB devices
  - "CONT-8104"     # Not using containers
timeout: 10
command_timeout: 90
EOF

# Run with profile
python -m linux_health server.example.com admin password \
  --profile production.yaml \
  --format json

# Combine profile with custom options
python -m linux_health server.example.com admin password \
  --profile ~/.config/linux_health/profiles/quick-scan.yaml \
  --format md \
  --output /reports/scan-$(date +%Y%m%d).md
```

#### Custom Port Scanning

```bash
# Scan specific service ports
python -m linux_health server.example.com admin password \
  --scan-ports 22,80,443,3306,5432,6379,8080,9000

# Scan extended port range
python -m linux_health server.example.com admin password \
  --scan-ports 22,80,443,8000-8100,9000-9100
```

#### Non-Standard Configuration

```bash
# Alternative SSH port with extended timeout
python -m linux_health server.example.com admin password \
  --port 2222 \
  --timeout 30 \
  --command-timeout 120

# High-latency network optimization
python -m linux_health remote.example.com admin password \
  --timeout 60 \
  --command-timeout 180
```

---

## Security Check Reference

### Critical Threat Detection

| Check | Detection Method | Indicators | Severity |
| ---- | --------------- | --------- | -------- |
| **Reverse Shells** | Process pattern matching | `bash -i`, `/dev/tcp/`, `nc -e`, `socat EXEC` | FAIL |
| **Cryptocurrency Mining** | Process and network analysis | xmrig, minerd, pool connections (ports 3333, 4444, 5555) | FAIL |
| **Suspicious Connections** | TCP connection filtering | External connections excluding RFC1918, localhost | WARN/FAIL |
| **ARP Spoofing** | ARP table analysis | Duplicate MAC addresses across IPs | FAIL |
| **DNS Tampering** | Resolver configuration | Unexpected nameservers in `/etc/resolv.conf` | FAIL |
| **Hidden System Files** | Filesystem analysis | Dotfiles in /tmp, /var/tmp, /usr/bin, /etc | FAIL |
| **Log Manipulation** | Log volume analysis | Empty/truncated auth.log, syslog | FAIL |
| **Binary Trojans** | Modification time tracking | Recent changes to `/bin/bash`, `/usr/bin/sudo`, `/usr/bin/ssh` | FAIL |
| **Rootkit Indicators** | Optional rkhunter scan | Kernel module anomalies, hidden processes, suspicious ports | FAIL |

### Vulnerability Assessment

| Check | Identifies | Detection Logic | Severity |
| ----- | --------- | --------------- | -------- |
| **Privilege Escalation Vectors** | NOPASSWD sudo, dangerous capabilities, CVE-vulnerable sudo | Parse `/etc/sudoers`, check capabilities, version matching | FAIL if 2+ vectors |
| **Weak Password Policy** | Missing/insufficient PAM configuration | Validate pam_pwquality, pam_cracklib presence | FAIL if absent |
| **Container Escape Risks** | Privileged containers, `--privileged` flag | Check cgroup membership, mount points | FAIL if privileged |
| **World-Writable Files** | Insecure permissions in system paths | Find 777 permissions in `/bin`, `/sbin`, `/usr/bin` | WARN/FAIL |
| **Kernel Module Integrity** | Unsigned/suspicious modules | Modules outside `/lib/modules/<kernel>` | FAIL |
| **Excessive SUID Binaries** | Unusual SUID file count | Count vs. baseline (>25 triggers warning) | WARN |
| **Deleted File Handles** | Processes holding deleted executables | `lsof` analysis for `(deleted)` entries | WARN |

### System Health Monitoring

| Check | Metric | Thresholds | Action |
| ----- | ------ | ---------- | ------ |
| **Disk Usage** | Root filesystem capacity | WARN: 80%, FAIL: 90% | Cleanup recommendations |
| **Memory Availability** | Available RAM | WARN: <20%, FAIL: <10% | Process termination suggestions |
| **System Load** | 1m, 5m, 15m load averages | WARN: >4.0, FAIL: >8.0 | Top CPU consumers |
| **Process Resources** | Per-process CPU/memory | Flag >80% consumption | Kill/nice recommendations |
| **Pending Updates** | Security vs. standard patches | FAIL: security updates, WARN: >10 standard | `apt-get upgrade` / `yum update` |
| **Network Listeners** | Public service exposure | Categorize SSH, HTTP, DB, DNS, other | Firewall rule suggestions |
| **SSH Hardening** | Configuration analysis | PasswordAuth, PermitRootLogin, Port 22 | sshd_config modifications |
| **Firewall Status** | ufw/firewalld/iptables | WARN: inactive | Enable firewall commands |
| **Time Synchronization** | NTP/chrony status | FAIL: not synchronized | chrony/systemd-timesyncd setup |

### Account Security

| Check | Detects | Logic | Remediation |
| ----- | ------- | ----- | ----------- |
| **Root Accounts** | Multiple UID 0 accounts | Parse `/etc/passwd` for UID=0 | Remove unauthorized root accounts |
| **Stale Accounts** | Inactive users (>90 days) | Check lastlog output | Lock/disable dormant accounts |
| **Recent Account Creation** | Accounts created <30 days | Modification time of `/etc/passwd` entries | Verify legitimacy, check home directories |
| **Authentication Failures** | Failed SSH logins (24h) | Parse auth.log for "Failed password" | Deploy fail2ban |
| **Root Logins** | Recent root SSH sessions | `last root` analysis | Enforce sudo-only access |

---

## Report Formats

### Text Format

```text
================================================================================
LINUX HOST HEALTH REPORT: PRODUCTION-WEB-01
================================================================================
Generated: 2026-01-08 15:30:42 UTC

SYSTEM INFORMATION
--------------------------------------------------------------------------------
  Hostname:      production-web-01.example.com
  OS:            Ubuntu 22.04.3 LTS
  Kernel:        5.15.0-89-generic
  Uptime:        up 47 days, 6 hours, 23 minutes
  Logged-in:     greg, admin # users=2

SUMMARY
--------------------------------------------------------------------------------
  Total Checks:  36
  ✅ Passed:     24
  ⚠️  Warnings:   10
  ❌ Failed:     2
  Open Ports:    5 -> 22, 80, 443, 3306, 6379

HEALTH CHECKS
--------------------------------------------------------------------------------
[FAIL] Pending updates         | Patching
    Details: 8 packages pending (3 security-critical)
    Action:  Apply security patches immediately: sudo apt-get update && sudo apt-get upgrade

[FAIL] Suspicious connections  | Network Security
    Details: 47 external TCP connections detected
    Action:  Review with 'ss -tnp state established | grep -v 127.0.0.1'

[WARN] SSH Config              | Authentication
    Details: Password authentication enabled, root login permitted
    Action:  Set 'PasswordAuthentication no' and 'PermitRootLogin no' in /etc/ssh/sshd_config

[WARN] Firewall                | Network
    Details: ufw inactive
    Action:  Enable firewall: sudo ufw enable && sudo ufw allow 22/tcp

[PASS] Memory                  | System Resources
    Details: 42% available (16GB of 38GB)
    Action:  No action required

[PASS] Crypto mining           | Malware/Backdoors
    Details: No cryptocurrency mining activity detected
    Action:  Continue monitoring
```

### Markdown Format

Professional GitHub-compatible format with:

- ✅ Status icons (✅ PASS, ⚠️ WARN, ❌ FAIL)
- 📊 Sortable tables (fail → warn → pass grouping)
- 📋 Collapsible detailed sections
- 💻 Syntax-highlighted code blocks
- 🔗 Cross-referenced remediation steps

```markdown
# Linux Host Health Report: production-web-01

Generated: 2026-01-08 15:30:42 UTC

## System
- Hostname: production-web-01.example.com
- OS: Ubuntu 22.04.3 LTS
- Kernel: 5.15.0-89-generic
- Uptime: up 47 days, 6 hours, 23 minutes
- Logged-in users: greg, admin # users=2

## Summary
- Checks: 36 (✅ 24 / ⚠️ 10 / ❌ 2)
- Open ports (scanned): 5 -> 22, 80, 443, 3306, 6379

## Checklist
| Status | Item | Details | Recommendation | Category |
| --- | --- | --- | --- | --- |
| ❌ FAIL | Pending updates | 8 packages (3 security) | Apply patches: sudo apt-get upgrade | Patching |
| ❌ FAIL | Suspicious connections | 47 external connections | Review: ss -tnp state established | Network Security |
| ⚠️ WARN | SSH Config | Password auth enabled | Set PasswordAuthentication no | Authentication |
| ⚠️ WARN | Firewall | ufw inactive | Enable: sudo ufw enable | Network |
| ✅ PASS | Memory | 42% available | No action | System Resources |
| ✅ PASS | Crypto mining | No activity detected | Continue monitoring | Malware/Backdoors |
```

### JSON Format

Machine-readable structured output for automation and tool integration:

```json
{
  "scan_info": {
    "generated_at": "2026-01-10T15:30:00Z",
    "scanner": "Linux Health Security Scanner",
    "version": "1.0.0"
  },
  "system": {
    "hostname": "production-web-01",
    "os": "Ubuntu 22.04 LTS",
    "kernel": "5.15.0-89-generic",
    "uptime": "up 47 days",
    "logged_in_users": ["greg", "admin"]
  },
  "summary": {
    "total_checks": 53,
    "passed": 40,
    "warned": 10,
    "failed": 3,
    "hardening_index": 82,
    "hardening_level": "GOOD"
  },
  "hardening_by_category": {
    "Storage": {
      "index": 100,
      "level": "EXCELLENT",
      "passed": 1,
      "warned": 0,
      "failed": 0,
      "total": 1
    },
    "Authentication": {
      "index": 75,
      "level": "GOOD",
      "passed": 3,
      "warned": 1,
      "failed": 1,
      "total": 5
    }
  },
  "checks": [
    {
      "test_id": "STOR-6310",
      "category": "Storage",
      "item": "Disk usage",
      "status": "pass",
      "details": "Disk is 45% full",
      "recommendation": "No action"
    },
    {
      "test_id": "AUTH-9328",
      "category": "Authentication",
      "item": "SSH configuration",
      "status": "fail",
      "details": "PermitRootLogin enabled",
      "recommendation": "Set PermitRootLogin no in /etc/ssh/sshd_config"
    }
  ],
  "ports": {
    "scanned": 7,
    "open": 5,
    "open_ports": [
      {"port": 22, "state": "open", "reason": "ssh", "service": "ssh", "version": "9.6p1", "banner": "SSH-2.0-OpenSSH_9.6p1"},
      {"port": 80, "state": "open", "reason": "http", "service": "http", "version": null, "banner": null}
    ]
  }
}
```

**JSON Output Benefits:**

- 🤖 **CI/CD Integration** — Parse results in pipelines
- 📊 **Dashboard Ingestion** — Feed security platforms (Grafana, ELK)
- 🔍 **Programmatic Analysis** — Query with `jq`, Python, etc.
- 📈 **Historical Tracking** — Store and compare scan results over time
- 🔗 **Tool Chaining** — Pipe results to other security tools

---

## Advanced Features

Linux Health Security Scanner delivers enterprise-grade capabilities that rival industry-standard tools like Lynis, achieving **95%+ feature parity** while maintaining the unique advantage of agentless SSH-based remote scanning.

### Test ID System

Every security check includes a unique, Lynis-compatible test identifier for precise tracking, filtering, and integration with external security platforms.

#### Test ID Format

```bash
# Pattern: CATEGORY-NUMBER
STOR-6310   # Storage - Disk usage check
AUTH-9328   # Authentication - SSH configuration  
BOOT-5122   # Boot - Bootloader password protection
KERN-5820   # Kernel - Security parameters (sysctl)
PKGS-7380   # Packages - Pending updates
MALW-3280   # Malware - Suspicious process locations
FIRE-4512   # Firewall - Status check
USRS-7614   # Users - Active account enumeration
```

#### Implementation Details

Test IDs are embedded in the `CheckResult` dataclass and can be specified when creating check results:

```python
# Example from checks.py
return _fail(
    "Disk usage",
    f"Disk is {used_pct}% full",
    "Expand disk capacity or clean up files",
    category,
    test_id="STOR-6310"  # Lynis-style identifier
)
```

#### Benefits & Use Cases

- **Debugging:** Quickly identify specific failing checks across multiple scan runs
- **Trend Analysis:** Track historical performance of individual tests over time
- **External Integration:** Reference specific checks in ticketing systems (JIRA, ServiceNow)
- **Profile Filtering:** Skip or include specific tests by ID in scan profiles
- **Compliance Mapping:** Map test IDs to regulatory requirements (PCI-DSS, NIST, CIS)
- **CI/CD Gates:** Fail builds on specific critical test failures

### JSON Output Format

Generate machine-readable JSON reports for seamless integration with security orchestration platforms, CI/CD pipelines, and custom analysis tools.

#### JSON Structure

```json
{
  "scan_info": {
    "generated_at": "2024-01-15T10:30:00Z",
    "scanner": "Linux Health Security Scanner",
    "version": "2.0.0",
    "target_host": "server.example.com"
  },
  "system": {
    "hostname": "prod-web-01",
    "os": "Ubuntu 22.04.3 LTS",
    "kernel": "5.15.0-91-generic",
    "uptime": "45 days, 3:22"
  },
  "summary": {
    "total_checks": 53,
    "passed": 42,
    "warned": 8,
    "failed": 3,
    "hardening_index": 84,
    "hardening_level": "GOOD"
  },
  "hardening_by_category": {
    "Storage": 100,
    "Memory": 95,
    "Authentication": 75,
    "Network Security": 67,
    "Malware Detection": 50
  },
  "checks": [
    {
      "test_id": "STOR-6310",
      "category": "Storage",
      "item": "Disk usage",
      "status": "pass",
      "details": "Root filesystem is 45% full",
      "recommendation": "No action required"
    },
    {
      "test_id": "AUTH-9328",
      "category": "Authentication",
      "item": "SSH configuration hardening",
      "status": "warn",
      "details": "Root login permitted via SSH",
      "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
    }
  ],
  "ports": {
    "open_ports": [22, 80, 443],
    "services": {
      "22": "SSH",
      "80": "HTTP",
      "443": "HTTPS"
    }
  },
  "detailed_findings": {
    "failed_checks": 3,
    "warning_checks": 8,
    "critical_issues": ["Root SSH access enabled", "Firewall inactive"]
  }
}
```

#### Generate JSON Report

```bash
# Output to stdout
python -m linux_health HOST USER PASS --format json

# Save to file
python -m linux_health HOST USER PASS --format json > report.json

# Pretty-printed JSON with jq
python -m linux_health HOST USER PASS --format json | jq '.'
```

**Parse Hardening Index:**

```bash
# Extract hardening score
SCORE=$(python -m linux_health HOST USER PASS --format json | \
  jq -r '.summary.hardening_index')

# CI/CD quality gate
if [ $SCORE -lt 70 ]; then
  echo "❌ Security score $SCORE below threshold 70"
  exit 1
fi
```

#### Python Script Integration

```python
import json
import subprocess

# Run scan and capture JSON output
result = subprocess.run(
    ['python', '-m', 'linux_health', 'server.local', 'admin', 'password', '--format', 'json'],
    capture_output=True,
    text=True
)

# Parse results
report = json.loads(result.stdout)

# Analyze failures
failed = [c for c in report['checks'] if c['status'] == 'fail']
print(f"Hardening Index: {report['summary']['hardening_index']}/100")
print(f"Failed Checks: {len(failed)}")

for check in failed:
    print(f"  ❌ {check['test_id']}: {check['item']}")
    print(f"     Recommendation: {check['recommendation']}")
```

#### Integration Scenarios

- **CI/CD Pipelines:** Automated security gates in GitLab CI, Jenkins, GitHub Actions
- **SIEM Platforms:** Forward scan results to Splunk, ELK, QRadar
- **Security Dashboards:** Build custom visualizations in Grafana, Kibana
- **Ticketing Systems:** Auto-create issues in JIRA for failed checks
- **Compliance Reporting:** Generate audit trails for PCI-DSS, SOC 2
- **Fleet Management:** Aggregate results from hundreds of servers

### Scan Profiles & Configuration System

Customize scan behavior, skip irrelevant checks, and optimize performance with flexible YAML-based configuration profiles—ideal for environment-specific scanning requirements.

#### Profile Structure

```yaml
# ~/.config/linux_health/profiles/production.yaml
name: "Production Server Profile"
description: "Optimized for production datacenter environment"

# Skip entire security categories
skip_categories:
  - "System Tools"       # No compilers on production servers
  - "Malware Detection"  # Using dedicated AV solution (ClamAV)

# Skip specific tests by ID
skip_tests:
  - "USB-1000"    # No USB devices in datacenter
  - "CONT-8104"   # Not using container technology
  - "KERN-5830"   # Custom kernel configuration

# Exclusive mode: Run ONLY these tests (comment out to run all)
# only_tests:
#   - "STOR-6310"   # Disk usage
#   - "MEM-2914"    # Memory availability
#   - "AUTH-9328"   # SSH hardening
#   - "FIRE-4512"   # Firewall status

# Performance tuning
timeout: 10              # SSH connection timeout (seconds)
command_timeout: 90      # Individual command timeout (seconds)

# Reporting options
verbose: false
show_warnings_only: false

# Custom settings (extensible)
custom_settings:
  max_concurrent_connections: 50
  alert_email: "security-team@example.com"
  compliance_framework: "CIS Benchmark Level 2"
```

#### Profile Discovery Paths

The scanner automatically searches for profiles in the following locations (in order):

1. **User Config:** `~/.config/linux_health/profiles/`
2. **System Config:** `/etc/linux_health/profiles/`
3. **Current Directory:** `./profiles/`
4. **Custom Path:** Specified via `--profile /path/to/profile.yaml`

#### Creating Profile Templates

**Quick Scan Profile** (skip time-intensive checks):

```yaml
name: "Quick Security Scan"
description: "Fast scan for CI/CD pipelines"

skip_categories:
  - "Malware Detection"
  - "Package Management"

timeout: 5
command_timeout: 30
```

**CIS Benchmark Profile** (compliance-focused):

```yaml
name: "CIS Benchmark Validation"
description: "Tests aligned with CIS Ubuntu Linux Benchmark"

only_tests:
  - "BOOT-5122"  # Bootloader password
  - "AUTH-9328"  # SSH hardening
  - "FIRE-4512"  # Firewall enabled
  - "PKGS-7385"  # GPG verification
  - "KERN-5820"  # Kernel parameters
  - "FILE-6310"  # Mount options
```

**Development Environment Profile** (permissive):

```yaml
name: "Development Workstation"
description: "Skip production-only security checks"

skip_tests:
  - "TOOL-5002"  # Compilers are needed for dev work
  - "AUTH-9308"  # PasswordAuthentication permitted
  - "BOOT-5122"  # No bootloader password on workstation
```

#### Profile Usage Examples

```bash
# Use named profile from config directory
python -m linux_health HOST USER PASS --profile production.yaml

# Use absolute path to profile
python -m linux_health HOST USER PASS --profile /opt/security/profiles/cis-benchmark.yaml

# Combine profile with JSON output for automation
python -m linux_health HOST USER PASS \
  --profile ci-pipeline.yaml \
  --format json \
  --output scan-results.json

# Quick scan during incident response
python -m linux_health $COMPROMISED_HOST $USER $PASS \
  --profile quick-scan.yaml \
  --format md \
  --output /incident-reports/$(date +%Y%m%d-%H%M%S)-scan.md
```

#### Test Filtering Logic

The scanner implements a hierarchical filtering system:

1. **Category-level filtering:** If a check's category matches `skip_categories`, skip it
2. **Test-level filtering:** If a check's test ID matches `skip_tests`, skip it
3. **Exclusive mode:** If `only_tests` is defined, run ONLY those tests (overrides skip settings)

```python
# Implementation in cli.py
if profile and HAS_CONFIG:
    check_results = [
        check for check in check_results
        if not should_skip_test(check.test_id, check.category, profile)
    ]
```

#### Profile Use Cases

- **Environment Optimization:** Different profiles for production, staging, development
- **Compliance Scanning:** Run only tests relevant to specific frameworks (PCI-DSS, HIPAA, CIS)
- **Performance Tuning:** Skip time-intensive checks for faster CI/CD execution
- **Noise Reduction:** Exclude false positives from expected configurations
- **Team Collaboration:** Share standardized profiles across security teams
- **Multi-Tenancy:** Different scan configurations for different customers/departments

---

## Docker Deployment

### Production Image Build

```bash
# Standard build
docker build -t auditless:latest .

# Multi-architecture build (ARM64 + AMD64)
docker buildx build --platform linux/amd64,linux/arm64 \
  -t auditless:latest .

# Build with version tags
docker build \
  -t auditless:latest \
  -t auditless:1.0.0 \
  -t auditless:stable .
```

### Container Execution

```bash
# Basic scan execution
docker run --rm auditless 192.168.1.100 admin password

# Persistent report generation
docker run --rm \
  -v "$(pwd)/reports:/reports" \
  auditless 192.168.1.100 admin password \
  --format md --output /reports/scan-$(date +%Y%m%d).md

# Interactive password entry
docker run -it --rm auditless \
  192.168.1.100 admin - --ask-password

# Extended timeout configuration
docker run --rm auditless \
  192.168.1.100 admin password \
  --timeout 60 --command-timeout 180
```

### Docker Compose Orchestration

```yaml
version: '3.8'

services:
  auditless:
    build:
      context: .
      dockerfile: Dockerfile
    image: auditless:latest
    container_name: security-scanner
    environment:
      - PYTHONUNBUFFERED=1
      - PYTHONIOENCODING=utf-8
    volumes:
      - ./reports:/app/reports:rw
    networks:
      - security-net
    restart: "no"

networks:
  security-net:
    driver: bridge
```

```bash
# Execute scan
docker-compose run --rm auditless host user password

# Generate report
docker-compose run --rm auditless \
  host user password \
  --format md --output /app/reports/report.md
```

### Advanced Docker Features

#### Volume Mounts (Cross-Platform)

```bash
# Unix/Linux/macOS
docker run --rm -v "$(pwd)/reports:/reports" auditless ...

# Windows PowerShell
docker run --rm -v "${PWD}/reports:/reports" auditless ...

# Windows CMD
docker run --rm -v "%cd%\reports:/reports" auditless ...
```

#### Environment Variables

```bash
docker run --rm \
  -e PYTHONUNBUFFERED=1 \
  -e TIMEOUT=30 \
  -e PORT=2222 \
  auditless host user password
```

#### Network Configurations

```bash
# Host network mode (Linux only) - Required for scanning localhost
docker run --rm --network host auditless localhost user password

# Scanning the host machine from container (macOS/Windows Docker Desktop)
docker run --rm auditless host.docker.internal user password

# Custom bridge network
docker network create --driver bridge security-network
docker run --rm --network security-network auditless host user password
```

### Important: Scanning Localhost from Docker Container

When running the scanner in Docker to audit the **host machine itself**, the container needs special network configuration:

**Linux:**

```bash
# Use host network mode to access localhost SSH
docker run --rm --network host auditless localhost username password

# The --network host flag shares the host's network stack
# This allows the container to connect to 127.0.0.1:22 on the host
```

**macOS / Windows (Docker Desktop):**

```bash
# Docker Desktop provides a special DNS name
docker run --rm auditless host.docker.internal username password

# host.docker.internal resolves to the internal IP of the host machine
# This works because Docker Desktop runs VMs with special networking
```

**Why this is needed:**

- Docker containers run in isolated network namespaces
- `localhost` inside a container refers to the container itself, not the host
- Without `--network host` (Linux) or `host.docker.internal` (Mac/Win), the SSH connection fails
- Remote hosts (non-localhost) don't require special configuration

#### Resource Constraints

```bash
docker run --rm \
  --memory 512m \
  --cpus 1.0 \
  --pids-limit 100 \
  auditless host user password
```

### Container Registry Deployment

#### Docker Hub

```bash
# Tag for registry
docker tag auditless:latest username/auditless:latest
docker tag auditless:latest username/auditless:1.0.0

# Authenticate and push
docker login
docker push username/auditless:latest
docker push username/auditless:1.0.0

# Pull on target system
docker pull username/auditless:latest
```

#### GitHub Container Registry (GHCR)

```bash
# Authenticate
echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_USER --password-stdin

# Tag for GHCR
docker tag auditless:latest ghcr.io/$GITHUB_USER/auditless:latest

# Push to registry
docker push ghcr.io/$GITHUB_USER/auditless:latest
```

---

## Development Guide

### Project Architecture

```text
linux_health/
├── linux_health/                    # Core application package
│   ├── __init__.py                 # Package initialization, version metadata
│   ├── __main__.py                 # CLI entry point
│   ├── checks.py                   # Security check functions (2,400+ lines)
│   ├── cli.py                      # Command-line interface & orchestration (169 lines)
│   ├── report.py                   # Report rendering (text/markdown) (374 lines)
│   ├── scanner.py                  # TCP port scanner (lightweight) (56 lines)
│   └── ssh_client.py               # Paramiko SSH wrapper (60 lines)
├── tests/
│   └── test_linux_health.py        # Comprehensive test suite (87 tests, 1,100+ lines)
├── .github/
│   └── copilot-instructions.md     # Development agent configuration
├── Dockerfile                       # Production container image definition
├── docker-compose.yml              # Local development orchestration
├── requirements.txt                # Runtime dependencies (paramiko)
├── requirements-dev.txt            # Development tools (pytest, ruff, black, coverage)
├── .gitignore                      # Version control exclusions
├── .dockerignore                   # Container build exclusions
└── README.md                       # This documentation
```

### Core Module Descriptions

#### `checks.py` (2,400+ lines)

- 36+ independent security check functions
- Threat detection and vulnerability assessment logic
- Modular architecture enabling parallel execution
- Comprehensive error handling and timeout management
- Helper functions: `_run()`, `_pass()`, `_warn()`, `_fail()`
- Optional scan integration: rkhunter, package analysis

#### `cli.py` (169 lines)

- argparse-based command-line interface
- SSH session lifecycle management
- Report generation coordination
- Secure password handling (interactive + file)
- Optional check orchestration

#### `report.py` (374 lines)

- Text format renderer (80-column terminal optimized)
- Markdown format renderer (GitHub-compatible)
- Status-grouped check sorting (FAIL → WARN → PASS)
- Port scan result formatting
- System information collection and display

#### `scanner.py` (56 lines)

- Lightweight TCP connect scanner
- Non-invasive connection-based detection
- Concurrent port scanning (ThreadPoolExecutor)
- Customizable port lists and timeouts

#### `ssh_client.py` (60 lines)

- Paramiko SSHClient wrapper
- Connection pooling compatible
- Configurable timeout and retry logic
- Graceful error handling and resource cleanup

### Development Environment Setup

```bash
# Clone repository
git clone https://github.com/Greg-2600/linux_health.git
cd linux_health

# Create isolated environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\Activate.ps1

# Install all dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Verify setup
python -m linux_health --help
pytest tests/ -v
ruff check linux_health/ tests/
black --check linux_health/ tests/
```

### Adding Custom Security Checks

#### Step 1: Implement Check Function

```python
# linux_health/checks.py

def check_custom_vulnerability(ssh: SSHSession, password: str = "") -> CheckResult:
    """
    Detect custom security vulnerability or misconfiguration.
    
    Args:
        ssh: Active SSH session to target host
        password: User password for sudo-requiring commands
    
    Returns:
        CheckResult with status (pass/warn/fail), details, and recommendations
    """
    category = "Custom Security"
    
    try:
        # Execute detection command
        code, output, error = _run(
            ssh,
            "your-detection-command",
            password
        )
        
        # Critical vulnerability detection
        if code != 0 or "critical_indicator" in output:
            return _fail(
                "Vulnerability Name",
                f"Critical issue detected: {output[:200]}",
                "Immediate remediation: sudo fix-command",
                category
            )
        
        # Warning condition
        if "warning_pattern" in output:
            return _warn(
                "Vulnerability Name",
                f"Potential issue: {output[:100]}",
                "Recommended action: verify-command",
                category
            )
        
        # Secure state
        return _pass(
            "Vulnerability Name",
            "No vulnerabilities detected",
            "No action required",
            category
        )
    
    except Exception as exc:
        return _fail(
            "Vulnerability Name",
            f"Check execution failed: {exc}",
            "Review logs and retry",
            category
        )
```

#### Step 2: Register in Check Runner

```python
# linux_health/checks.py, in run_all_checks() function

def run_all_checks(ssh: SSHSession, password: str = "") -> List[CheckResult]:
    results: list[CheckResult] = []
    
    # ... existing checks ...
    
    results.append(check_custom_vulnerability(ssh, password))
    
    return results
```

#### Step 3: Write Comprehensive Tests

```python
# tests/test_auditless.py

from unittest.mock import Mock, MagicMock
from linux_health.checks import check_custom_vulnerability

class TestCustomVulnerability:
    """Test suite for custom vulnerability detection."""
    
    def test_pass_when_secure(self):
        """Verify check passes in secure configuration."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "secure_output", ""))
        
        result = check_custom_vulnerability(mock_ssh)
        
        assert result.status == "pass"
        assert "Vulnerability Name" in result.item
        assert result.category == "Custom Security"
    
    def test_warn_on_potential_issue(self):
        """Verify check warns on suspicious indicators."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "warning_pattern found", ""))
        
        result = check_custom_vulnerability(mock_ssh)
        
        assert result.status == "warn"
        assert "verify-command" in result.recommendation
    
    def test_fail_on_critical_vulnerability(self):
        """Verify check fails on confirmed vulnerability."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "critical_indicator", "error"))
        
        result = check_custom_vulnerability(mock_ssh)
        
        assert result.status == "fail"
        assert "fix-command" in result.recommendation
    
    def test_handle_execution_error(self):
        """Verify graceful error handling."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=Exception("SSH connection lost"))
        
        result = check_custom_vulnerability(mock_ssh)
        
        assert result.status == "fail"
        assert "execution failed" in result.details.lower()
```

#### Step 4: Validate Implementation

```bash
# Run specific test class
pytest tests/test_auditless.py::TestCustomVulnerability -v

# Run all tests
pytest tests/ -v

# Check coverage for new code
pytest tests/ --cov=linux_health --cov-report=html

# View coverage report
# Open htmlcov/index.html in browser
```

### Code Quality Standards

```bash
# Format code (PEP 8 compliance)
black linux_health/ tests/

# Lint code (error/warning detection)
ruff check linux_health/ tests/

# Auto-fix linting issues
ruff check --fix linux_health/ tests/

# Combined quality check
black linux_health/ tests/ && ruff check linux_health/ tests/
```

**Standards:**

- **Formatter:** Black (88-character line length)
- **Linter:** Ruff (E, F, W rule categories)
- **Type Hints:** Recommended for all new functions
- **Docstrings:** Google style (mandatory for public functions)
- **Test Coverage:** Target >70% for new code

---

## Testing & Quality Assurance

### Test Suite Overview

**Status:** 469 unit tests passing + 14 end-to-end tests (100% pass rate)  
**Coverage:** 85% overall  
**Framework:** pytest 7.0+  
**Execution Time:** ~8 seconds (unit), ~1 minute (e2e, containerized)

### Module Coverage Breakdown

| Module | Stmts | Cover | Focus Areas |
| ------ | ----- | ------- | -------- | ----------- |
| `checks.py` | 1337 | **74%** | Security check logic, threat detection |
| `cli.py` | 122 | **90%** | Argument parsing, orchestration |
| `report.py` | 361 | **88%** | Text/Markdown/JSON formatting |
| `scanner.py` | 29 | **100%** | Port scanning logic |
| `ssh_client.py` | 37 | **100%** | SSH connection wrapper |
| `dashboard.py` | 648 | **90%** | FastAPI app, UI, API routes |
| `store.py` / `scheduler.py` / `compliance.py` / `client.py` | — | **90–100%** | Persistence, scheduling, scoring, API client |

### Test Categories

#### Unit Tests (107 total)

- **Check Logic** (70 tests): Pass/warn/fail scenarios, error handling
- **CLI Interface** (13 tests): Argument parsing, validation
- **Port Scanner** (5 tests): Port scanning, connection handling
- **SSH Session** (3 tests): Connection management, command execution
- **Report Rendering** (6 tests): Text/Markdown formatting, status grouping
- **Data Structures** (10 tests): CheckResult, SystemInfo, detailed security info

#### Test Execution

```bash
# Quick test run (summary)
pytest tests/ -q

# Verbose output (all test names)
pytest tests/ -v

# With coverage report (terminal)
pytest tests/ --cov=linux_health --cov-report=term-missing

# Generate HTML coverage report
pytest tests/ --cov=linux_health --cov-report=html
# Open htmlcov/index.html

# Run specific test class
pytest tests/test_auditless.py::TestCheckDiskUsage -v

# Run tests matching pattern
pytest tests/ -k "crypto" -v
pytest tests/ -k "privilege" -v

# Parallel execution (requires pytest-xdist)
pip install pytest-xdist
pytest tests/ -n auto

# Stop on first failure
pytest tests/ -x

# Show print output
pytest tests/ -s

# Full traceback on error
pytest tests/ -vv --tb=long
```

#### End-to-End Suite (`tests/test_e2e.py`, 15 tests)

Spins up real containers — a throwaway OpenSSH server plus the app image —
and exercises every feature through the public `ApiClient`: CLI scans in
all three formats, password + key auth, strict host-key rejection, version
/ profiles / UI / Swagger, host CRUD, write-only keys, persisted scans,
report diffing, and persistence across a container restart.

```bash
# Requires a working docker daemon + ssh-keygen (skips otherwise)
AUDITLESS_E2E=1 pytest tests/test_e2e.py -v
```

CI runs the same in the `e2e` workflow job on every push/PR to `main`.

#### Detection Accuracy (`test_detection_accuracy_weakened_target`)

The suite deliberately weakens the throwaway SSH target (extra UID-0
account, world-writable `/usr/bin` file, 30 extra SUID binaries, weak
SSH directives, a fake `xmrig` process) and locks the expected verdict
per check — planted threats must be caught, clean areas must stay
green. It runs last and repairs the target afterwards. Lessons encoded
as comments (busybox multicall binaries refuse renamed `argv[0]`).

#### Fleet Benchmark (`scripts/bench_fleet.py`)

Boots N throwaway SSH servers and times sequential API scans against one
parallel `POST /api/fleet/scan` call (measured 3.0x on 3 targets —
linear, as expected for network-bound scans):

```bash
python scripts/bench_fleet.py 3
```

### Continuous Integration

#### GitHub Actions Workflow (`.github/workflows/tests.yml`)

Every push/PR to `main` runs three jobs:

- `test` (ubuntu/windows/macos × Python 3.11/3.12): editable install,
  ruff, black, pylint (10/10 gate), mypy, bandit HIGH gate, pytest,
  coverage upload
- `security`: bandit + safety reports (non-blocking)
- `e2e` (ubuntu): the containerized end-to-end suite
  (`AUDITLESS_E2E=1 pytest tests/test_e2e.py`)

`.github/workflows/docker.yml` builds + publishes `ghcr.io` images and
runs a Trivy scan whose SARIF uploads to the Security tab. The same six
gates run locally via `pre-commit run --all-files`.

---

## Integration Examples

### CI/CD Pipeline Integration

#### GitLab CI/CD

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  image: auditless:latest
  variables:
    TARGET_HOST: "${CI_ENVIRONMENT_NAME}.example.com"
  script:
    # Execute security scan with JSON output
    - >
      python -m linux_health 
      $TARGET_HOST 
      $SSH_USER 
      $SSH_PASS
      --profile ci-profile.yaml
      --format json > security-report.json
    
    # Extract hardening index
    - SCORE=$(jq -r '.summary.hardening_index' security-report.json)
    - echo "Hardening Index: $SCORE/100"
    
    # Quality gate: Fail if score below threshold
    - |
      if [ $SCORE -lt 70 ]; then
        echo "❌ Security score $SCORE below minimum threshold (70)"
        jq -r '.checks[] | select(.status=="fail") | "FAIL: \(.test_id) - \(.item): \(.recommendation)"' security-report.json
        exit 1
      fi
    
    # Warning threshold
    - |
      if [ $SCORE -lt 85 ]; then
        echo "⚠️  Security score $SCORE below recommended threshold (85)"
      else
        echo "✅ Security posture excellent: $SCORE/100"
      fi
  
  artifacts:
    paths:
      - security-report.json
    reports:
      junit: security-report.json
    expire_in: 30 days
  
  only:
    - main
    - staging
    - production
```

#### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Assessment

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      
      - name: Run security scan
        env:
          SSH_USER: ${{ secrets.SSH_USER }}
          SSH_PASS: ${{ secrets.SSH_PASS }}
        run: |
          python -m linux_health \
            ${{ vars.TARGET_HOST }} \
            $SSH_USER \
            $SSH_PASS \
            --profile production.yaml \
            --format json \
            --output security-report.json
      
      - name: Evaluate security posture
        run: |
          SCORE=$(jq -r '.summary.hardening_index' security-report.json)
          FAILED=$(jq -r '.summary.failed' security-report.json)
          WARNED=$(jq -r '.summary.warned' security-report.json)
          
          echo "::notice::Hardening Index: $SCORE/100"
          echo "::notice::Failed Checks: $FAILED"
          echo "::notice::Warning Checks: $WARNED"
          
          if [ $FAILED -gt 0 ]; then
            echo "::error::$FAILED critical security issues detected"
            jq -r '.checks[] | select(.status=="fail") | "::error file=security::[\(.test_id)] \(.item) - \(.recommendation)"' security-report.json
            exit 1
          fi
          
          if [ $SCORE -lt 70 ]; then
            echo "::error::Security score $SCORE below threshold"
            exit 1
          fi
      
      - name: Upload security report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-report
          path: security-report.json
          retention-days: 90
      
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('security-report.json', 'utf8'));
            const score = report.summary.hardening_index;
            const level = report.summary.hardening_level;
            
            const comment = `## 🔒 Security Assessment Results
            
            **Hardening Index:** ${score}/100 (${level})
            
            - ✅ Passed: ${report.summary.passed}
            - ⚠️  Warnings: ${report.summary.warned}
            - ❌ Failed: ${report.summary.failed}
            
            ${report.summary.failed > 0 ? '### ❌ Critical Issues\n' + 
              report.checks.filter(c => c.status === 'fail')
                .map(c => `- **${c.test_id}**: ${c.item}\n  _${c.recommendation}_`)
                .join('\n') : ''}
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

#### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        TARGET_HOST = "${env.DEPLOY_ENV}.example.com"
        SSH_CREDENTIALS = credentials('ssh-scanner-credentials')
    }
    
    stages {
        stage('Security Assessment') {
            agent {
                docker {
                    image 'auditless:latest'
                    args '--network host'
                }
            }
            
            steps {
                script {
                    // Execute security scan
                    sh """
                        python -m linux_health \
                            ${TARGET_HOST} \
                            ${SSH_CREDENTIALS_USR} \
                            ${SSH_CREDENTIALS_PSW} \
                            --profile jenkins-profile.yaml \
                            --format json > security-report.json
                    """
                    
                    // Parse results
                    def report = readJSON file: 'security-report.json'
                    def score = report.summary.hardening_index
                    def failed = report.summary.failed
                    
                    echo "Hardening Index: ${score}/100"
                    echo "Failed Checks: ${failed}"
                    
                    // Quality gate
                    if (score < 70) {
                        error("Security score ${score} below threshold 70")
                    }
                    
                    if (failed > 0) {
                        unstable("${failed} security checks failed")
                    }
                }
            }
            
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.json', fingerprint: true
                    
                    // Send notifications
                    emailext (
                        subject: "Security Scan: ${currentBuild.currentResult}",
                        body: """
                            <h2>Security Assessment Complete</h2>
                            <p><strong>Target:</strong> ${TARGET_HOST}</p>
                            <p><strong>Hardening Index:</strong> ${score}/100</p>
                            <p><strong>Build:</strong> ${BUILD_URL}</p>
                        """,
                        to: 'security-team@example.com',
                        mimeType: 'text/html'
                    )
                }
            }
        }
    }
}
```

#### Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - staging

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: ssh-credentials
  - name: targetHost
    value: 'prod-server.example.com'

stages:
  - stage: SecurityAssessment
    displayName: 'Security Assessment'
    jobs:
      - job: SecurityScan
        displayName: 'Run Security Scan'
        steps:
          - task: UsePythonVersion@0
            inputs:
              versionSpec: '3.11'
              addToPath: true
          
          - script: |
              pip install -r requirements.txt
            displayName: 'Install Dependencies'
          
          - script: |
              python -m linux_health \
                $(targetHost) \
                $(sshUser) \
                $(sshPassword) \
                --profile azure-pipeline.yaml \
                --format json \
                --output $(Build.ArtifactStagingDirectory)/security-report.json
            displayName: 'Execute Security Scan'
            env:
              sshUser: $(SSH_USER)
              sshPassword: $(SSH_PASSWORD)
          
          - task: PublishBuildArtifacts@1
            inputs:
              PathtoPublish: '$(Build.ArtifactStagingDirectory)'
              ArtifactName: 'security-reports'
              publishLocation: 'Container'
            condition: always()
          
          - script: |
              SCORE=$(jq -r '.summary.hardening_index' $(Build.ArtifactStagingDirectory)/security-report.json)
              echo "##vso[task.setvariable variable=hardeningScore]$SCORE"
              
              if [ $SCORE -lt 70 ]; then
                echo "##vso[task.logissue type=error]Security score $SCORE below threshold"
                echo "##vso[task.complete result=Failed;]"
              fi
            displayName: 'Evaluate Security Posture'
```

### Python Integration

```python
#!/usr/bin/env python3
"""
Enterprise security scanner wrapper with custom reporting and alerting.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

def run_security_scan(host: str, user: str, password: str, profile: str = None) -> dict:
    """Execute Linux Health Security Scanner and return parsed results."""
    
    cmd = [
        'python', '-m', 'linux_health',
        host, user, password,
        '--format', 'json'
    ]
    
    if profile:
        cmd.extend(['--profile', profile])
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    
    if result.returncode != 0:
        raise RuntimeError(f"Scanner failed: {result.stderr}")
    
    return json.loads(result.stdout)

def analyze_results(report: dict) -> dict:
    """Analyze scan results and generate insights."""
    
    summary = report['summary']
    checks = report['checks']
    
    # Categorize failures
    critical_failures = [
        c for c in checks 
        if c['status'] == 'fail' and c['category'] in [
            'Malware Detection', 'Authentication', 'Privilege Escalation'
        ]
    ]
    
    # Calculate risk score
    risk_score = (
        (summary['failed'] * 10) +
        (summary['warned'] * 3) -
        (summary['passed'] * 0.1)
    )
    
    return {
        'hardening_index': summary['hardening_index'],
        'risk_score': round(risk_score, 2),
        'critical_failures': len(critical_failures),
        'total_issues': summary['failed'] + summary['warned'],
        'requires_immediate_action': len(critical_failures) > 0 or risk_score > 50
    }

def generate_executive_summary(report: dict, analysis: dict) -> str:
    """Generate executive summary for leadership."""
    
    template = f"""
    SECURITY ASSESSMENT EXECUTIVE SUMMARY
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    TARGET SYSTEM
    - Host: {report['system']['hostname']}
    - OS: {report['system']['os']}
    - Kernel: {report['system']['kernel']}
    
    SECURITY POSTURE
    - Hardening Index: {analysis['hardening_index']}/100 ({report['summary']['hardening_level']})
    - Risk Score: {analysis['risk_score']}
    - Critical Issues: {analysis['critical_failures']}
    - Total Findings: {analysis['total_issues']}
    
    ASSESSMENT RESULTS
    - Passed Checks: {report['summary']['passed']}
    - Warnings: {report['summary']['warned']}
    - Failures: {report['summary']['failed']}
    
    RECOMMENDATION
    {"🔴 IMMEDIATE ACTION REQUIRED - Critical security vulnerabilities detected" 
     if analysis['requires_immediate_action'] 
     else "🟢 System security posture acceptable - Continue monitoring"}
    """
    
    return template

def main():
    """Execute security assessment with custom analysis."""
    
    # Configuration
    targets = [
        {'host': 'web-prod-01', 'user': 'scanner', 'password': 'secure123', 'profile': 'production.yaml'},
        {'host': 'db-prod-01', 'user': 'scanner', 'password': 'secure123', 'profile': 'database.yaml'},
        {'host': 'app-prod-01', 'user': 'scanner', 'password': 'secure123', 'profile': 'application.yaml'},
    ]
    
    results = []
    
    for target in targets:
        print(f"Scanning {target['host']}...")
        
        try:
            # Execute scan
            report = run_security_scan(
                target['host'],
                target['user'],
                target['password'],
                target.get('profile')
            )
            
            # Analyze results
            analysis = analyze_results(report)
            
            # Store results
            results.append({
                'host': target['host'],
                'report': report,
                'analysis': analysis
            })
            
            # Generate executive summary
            summary = generate_executive_summary(report, analysis)
            print(summary)
            
            # Save detailed report
            output_file = Path(f"reports/{target['host']}-{datetime.now().strftime('%Y%m%d')}.json")
            output_file.parent.mkdir(exist_ok=True)
            output_file.write_text(json.dumps(report, indent=2))
            
        except Exception as e:
            print(f"❌ Scan failed for {target['host']}: {e}")
            results.append({
                'host': target['host'],
                'error': str(e)
            })
    
    # Fleet-wide summary
    print("\n" + "="*80)
    print("FLEET SECURITY SUMMARY")
    print("="*80)
    
    avg_hardening = sum(r['analysis']['hardening_index'] for r in results if 'analysis' in r) / len(results)
    critical_hosts = [r['host'] for r in results if r.get('analysis', {}).get('requires_immediate_action')]
    
    print(f"Average Hardening Index: {avg_hardening:.1f}/100")
    print(f"Hosts Requiring Attention: {len(critical_hosts)}")
    
    if critical_hosts:
        print(f"\nCritical Hosts:")
        for host in critical_hosts:
            print(f"  - {host}")
        sys.exit(1)
    else:
        print("\n✅ All hosts meet minimum security standards")
        sys.exit(0)

if __name__ == '__main__':
    main()
```

### Scheduled Scanning (Cron)

```bash
#!/bin/bash
# /etc/cron.daily/security-scan.sh

REPORT_DIR="/var/log/security-scans"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SSH_PASS=$(vault kv get -field=password secret/ssh/scanner)

mkdir -p "$REPORT_DIR"

python -m linux_health localhost scanuser "$SSH_PASS" \
  --format md \
  --output "$REPORT_DIR/scan-$TIMESTAMP.md" \
  --enable-rootkit-scan \
  --check-package-hygiene

# Rotate old reports (keep 30 days)
find "$REPORT_DIR" -name "scan-*.md" -mtime +30 -delete

# Alert on failures
if grep -q "❌ FAIL" "$REPORT_DIR/scan-$TIMESTAMP.md"; then
  mail -s "Security Scan FAILED on $(hostname)" security@example.com \
    < "$REPORT_DIR/scan-$TIMESTAMP.md"
fi
```

### Ansible Integration

```yaml
---
# playbooks/security-assessment.yml
- name: Execute security assessment across fleet
  hosts: all
  tasks:
    - name: Run Linux Health Security Scanner
      command: >
        docker run --rm
        -v /tmp:/reports
        auditless:latest
        {{ inventory_hostname }}
        {{ ansible_user }}
        {{ ansible_password }}
        --format md
        --output /reports/scan-{{ inventory_hostname }}.md
      delegate_to: localhost
      register: scan_result
      failed_when: "'❌ FAIL' in scan_result.stdout"
    
    - name: Collect reports
      fetch:
        src: /tmp/scan-{{ inventory_hostname }}.md
        dest: ./security-reports/
        flat: yes
```

### Nagios/Icinga Monitoring

```bash
#!/bin/bash
# /usr/lib/nagios/plugins/check_linux_health.sh

TARGET_HOST=$1
SSH_USER=$2
SSH_PASS=$3

# Execute scan
RESULT=$(python -m linux_health "$TARGET_HOST" "$SSH_USER" "$SSH_PASS" 2>&1)

# Count failures
FAIL_COUNT=$(echo "$RESULT" | grep -c "^\[FAIL\]")
WARN_COUNT=$(echo "$RESULT" | grep -c "^\[WARN\]")

# Determine exit status
if [ $FAIL_COUNT -gt 0 ]; then
  echo "CRITICAL: $FAIL_COUNT security failures detected | fails=$FAIL_COUNT;;;; warns=$WARN_COUNT;;;;"
  exit 2
elif [ $WARN_COUNT -gt 5 ]; then
  echo "WARNING: $WARN_COUNT security warnings detected | warns=$WARN_COUNT;;;; fails=$FAIL_COUNT;;;;"
  exit 1
else
  echo "OK: All security checks passed | fails=$FAIL_COUNT;;;; warns=$WARN_COUNT;;;;"
  exit 0
fi
```

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: security-scanner
  namespace: monitoring
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: auditless
            image: ghcr.io/username/auditless:latest
            args:
              - "target-host.cluster.local"
              - "$(SSH_USER)"
              - "$(SSH_PASS)"
              - "--format"
              - "md"
              - "--output"
              - "/reports/scan.md"
            env:
            - name: SSH_USER
              valueFrom:
                secretKeyRef:
                  name: ssh-credentials
                  key: username
            - name: SSH_PASS
              valueFrom:
                secretKeyRef:
                  name: ssh-credentials
                  key: password
            volumeMounts:
            - name: reports
              mountPath: /reports
          volumes:
          - name: reports
            persistentVolumeClaim:
              claimName: security-reports-pvc
          restartPolicy: OnFailure
```

---

## Troubleshooting

### SSH Connection Issues

**Symptom:** Connection timeout or refused

```bash
# Increase connection timeout
python -m linux_health host user password --timeout 60

# Verify SSH connectivity
ssh -vvv user@host

# Test non-standard port
python -m linux_health host user password --port 2222 --timeout 30

# Check firewall rules
sudo iptables -L -n | grep 22
sudo ufw status verbose
```

**Symptom:** Authentication failure

```bash
# Verify credentials
ssh user@host whoami

# Use interactive password
python -m linux_health host user - --ask-password

# Check SSH key conflicts
ssh -o PasswordAuthentication=yes -o PubkeyAuthentication=no user@host
```

### Unicode/Encoding Errors

**Windows:**

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m linux_health host user password
```

**Linux/macOS:**

```bash
export PYTHONIOENCODING=utf-8
export LC_ALL=en_US.UTF-8
python -m linux_health host user password
```

### Permission Denied for Specific Checks

Some checks require elevated privileges. Configure sudo access:

```bash
# Edit sudoers (use visudo)
sudo visudo

# Add lines (adjust commands as needed):
scanuser ALL=(ALL) NOPASSWD: /bin/ss
scanuser ALL=(ALL) NOPASSWD: /sbin/iptables
scanuser ALL=(ALL) NOPASSWD: /usr/bin/apt-get
scanuser ALL=(ALL) NOPASSWD: /usr/bin/yum
scanuser ALL=(ALL) NOPASSWD: /usr/sbin/rkhunter
```

### Docker Issues

**Image build failures:**

```bash
# Clear build cache
docker builder prune --all

# Build with verbose output
docker build -t auditless . --progress=plain --no-cache

# Check Dockerfile syntax
docker build --check -f Dockerfile .
```

**Container runtime errors:**

```bash
# View container logs
docker logs <container-id>

# Interactive debugging
docker run -it --rm auditless /bin/bash

# Inspect image
docker inspect auditless:latest

# Check entrypoint
docker inspect auditless:latest | grep -A 5 Entrypoint
```

**Volume mount issues (Windows):**

```powershell
# Use absolute paths
docker run --rm -v "C:\reports:/reports" auditless ...

# Check Docker Desktop settings
# Settings > Resources > File Sharing
```

### Report Generation Issues

**Output file not created:**

```bash
# Verify write permissions
ls -la $(dirname /path/to/output.md)
touch /path/to/output.md  # Test writability

# Use absolute paths
python -m linux_health host user password \
  --output /home/user/reports/scan.md

# Test stdout first
python -m linux_health host user password --format text
```

**Malformed Markdown:**

```bash
# Validate Markdown syntax
pip install mdformat
mdformat --check scan_report.md

# View in compatible renderer
cat scan_report.md | pandoc -f markdown -t html > report.html
```

### Performance Issues

**Slow scan execution:**

```bash
# Increase per-command timeout
python -m linux_health host user password \
  --command-timeout 180

# Skip optional scans
python -m linux_health host user password \
  # Omit --enable-rootkit-scan and --check-package-hygiene

# Reduce port scan surface
python -m linux_health host user password \
  --scan-ports 22,80,443
```

**High latency networks:**

```bash
# Optimize all timeouts
python -m linux_health host user password \
  --timeout 120 \
  --command-timeout 240
```

---

## Security Considerations

### Credential Management

### ⚠️ Security Best Practices

1. **SSH Keys (Recommended)**

   ```bash
   # Generate key pair
   ssh-keygen -t ed25519 -C "security-scanner"
   
   # Copy to target
   ssh-copy-id -i ~/.ssh/id_ed25519.pub user@host
   
   # Use key-based auth (future enhancement)
   ```

2. **Interactive Passwords**

   ```bash
   python -m linux_health host user - --ask-password
   # Password not logged or visible in process list
   ```

3. **Environment Variables**

   ```bash
   read -s SSH_PASS
   python -m linux_health host user "$SSH_PASS"
   unset SSH_PASS
   ```

4. **Secrets Management**

   ```bash
   # HashiCorp Vault
   export SSH_PASS=$(vault kv get -field=password secret/ssh/scanner)
   python -m linux_health host user "$SSH_PASS"
   
   # AWS Secrets Manager
   export SSH_PASS=$(aws secretsmanager get-secret-value \
     --secret-id ssh/scanner --query SecretString --output text)
   ```

### Network Security

- **Trusted Networks:** Execute scanner from secure management VLANs
- **Firewall Rules:** Ensure SSH (port 22) access from scanner IP
- **Logging:** All SSH sessions logged in target's auth.log
- **Encryption:** All communication over SSH (AES-256-CTR, ChaCha20-Poly1305)

### Data Privacy

- **Read-Only Operations:** No system modifications performed
- **No Data Exfiltration:** Reports contain only metadata (no file contents)
- **Local Processing:** All analysis performed on target system
- **Credential Handling:** Passwords never logged or persisted

### Audit Trail

```bash
# Scanner leaves these artifacts:
# - SSH session logs in /var/log/auth.log
# - Process executions in audit logs (if auditd enabled)
# - Network connections in connection tracking

# View scanner activity
sudo grep "linux_health" /var/log/auth.log
sudo ausearch -k scanner_activity  # If auditd configured
```

---

## Requirements

### Runtime Requirements

| Component | Version | Purpose |
| --------- | ------- | ------- |
| **Python** | 3.11+ | Core runtime environment |
| **paramiko** | 3.0.0+ | SSH protocol implementation |
| **PyYAML** | 6.0+ | Profile/configuration support (optional) |
| **SSH Access** | — | Target system connectivity |
| **Network** | — | TCP/IP connectivity to targets |

**Note:** PyYAML is optional. If not installed, profile features will be unavailable but all other functionality works normally.

### Development Requirements

| Component | Version | Purpose |
| --------- | ------- | ------- |
| **pytest** | 7.0.0+ | Test framework |
| **pytest-cov** | 4.0.0+ | Coverage reporting |
| **pytest-mock** | 3.10.0+ | Mocking utilities |
| **ruff** | 0.1.0+ | Fast Python linter |
| **black** | 23.0.0+ | Code formatter |

### System Requirements

**Scanner Host:**

- Linux, macOS, or Windows
- Python 3.11+ installed
- Network access to targets
- SSH client (for manual verification)

**Target Systems:**

- Any Linux distribution (Ubuntu, Debian, RHEL, CentOS, Fedora, Alpine, etc.)
- SSH server running (OpenSSH recommended)
- User account with appropriate privileges
- Standard Unix utilities (df, ps, ss, etc.)

---

## Performance Characteristics

| Metric | Typical | Optimized | Notes |
| ------ | ------- | --------- | ----- |
| **Single Host Scan** | 45-75s | 30-45s | Depends on system load, network latency |
| **SSH Connection** | 2-5s | 1-2s | With key-based auth |
| **Port Scan** | 5-10s | 2-5s | Default ports (5), concurrent execution |
| **Check Execution** | 30-60s | 20-40s | 36+ checks, sequential execution |
| **Report Generation** | <1s | <1s | Negligible impact |

**Optimization Opportunities:**

- Parallel check execution (future enhancement)
- SSH connection pooling
- Cached system information
- Batch command execution

---

## Support

### Documentation

- **Installation:** See [Installation](#installation)
- **Usage Examples:** See [Usage](#usage)
- **Docker Guide:** See [Docker Deployment](#docker-deployment)
- **Development:** See [Development Guide](#development-guide)
- **Testing:** See [Testing & Quality Assurance](#testing--quality-assurance)

### Issue Reporting

**Before opening an issue:**

1. ✅ Check [Troubleshooting](#troubleshooting) section
2. ✅ Review existing GitHub issues
3. ✅ Verify you're using latest version
4. ✅ Test with `--timeout 60 --command-timeout 180`

**When reporting issues, include:**

- Host OS and Python version (`python --version`)
- Target OS and kernel version
- Complete error message and stack trace
- Scan command used (redact credentials)
- Output of `python -m linux_health --help`

### Contributing

See [Development Guide](#development-guide) for contribution guidelines.

**Quick Contribution Checklist:**

- [ ] All tests passing (`pytest tests/ -v`)
- [ ] Code linted (`ruff check --fix . && black .`)
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] CHANGELOG.md updated

---

## Publishing to GitHub

### Initial Setup (First Time Only)

```bash
# 1. Create repository on GitHub (github.com/new)

# 2. Add remote and push
git remote add origin https://github.com/YOUR_USERNAME/linux_health.git
git branch -M main
git push -u origin main

# 3. Configure secrets (Settings → Secrets and variables → Actions)
#    - Add PYPI_API_TOKEN for automated PyPI releases

# 4. Create release tag (triggers automated releases)
git tag -a v2.0.0 -m "Release v2.0.0"
git push origin v2.0.0
```

### Automated Workflows

**`.github/workflows/tests.yml`** — Runs on push/PR  
Automated testing: Python 3.11, 3.12 on Ubuntu, Windows, macOS + coverage + linting

**`.github/workflows/docker.yml`** — Builds Docker image  
Publishes to GitHub Container Registry (GHCR) + Trivy security scan

**`.github/workflows/release.yml`** — Triggered by git tags  
Creates GitHub Release + publishes to PyPI + Docker Hub

### Contributing Guidelines

See [`.github/CONTRIBUTING.md`](./.github/CONTRIBUTING.md) for detailed guidelines on:

- Setting up development environment
- Code standards (Black, Ruff, type hints)
- Testing requirements (>70% coverage)
- Adding new security checks
- Pull request process

### Code of Conduct

Community standards and inclusive environment: [`.github/CODE_OF_CONDUCT.md`](./.github/CODE_OF_CONDUCT.md)

### Security Reporting

Report vulnerabilities privately (do not use issues): See [SECURITY.md](./SECURITY.md)

---

## License

MIT License

Copyright (c) 2026 Linux Health Security Scanner Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Changelog

### v2.0.0 — Lynis Parity Release (2026-01-10)

### 95%+ Feature Parity with Lynis Achieved

#### Major Features

- ✅ **Test ID System** — Lynis-compatible test identifiers (e.g., `STOR-6310`, `AUTH-9328`, `BOOT-5122`)
  - Precise test identification for debugging and tracking
  - Cross-run comparison and historical trend analysis
  - External platform integration (JIRA, ServiceNow, ticketing systems)
  - Profile-based test filtering by ID

- ✅ **JSON Output Format** — Machine-readable structured reports
  - Complete scan metadata (timestamp, version, target info)
  - System information (hostname, OS, kernel, uptime)
  - Summary statistics (pass/warn/fail counts, hardening index)
  - Category-level hardening breakdown
  - Individual check results with test IDs
  - Port discovery details
  - CI/CD pipeline integration ready
  - Security orchestration platform compatible

- ✅ **Profile/Configuration System** — YAML-based scan customization
  - Skip specific tests by test ID
  - Skip entire security categories
  - Exclusive mode (run only specified tests)
  - Configurable timeouts (connection and command)
  - Environment-specific profiles (production, development, compliance)
  - Auto-discovery from `~/.config/linux_health/profiles/`, `/etc/linux_health/profiles/`
  - Template profile generator

- ✅ **Test Filtering** — Granular control over scan execution
  - Filter by test ID or category
  - Reduce scan time by skipping irrelevant checks
  - Focus on compliance-specific requirements
  - Avoid false positives from expected configurations

- ✅ **Enhanced CLI** — New command-line arguments
  - `--format {text|md|json}` — Choose output format
  - `--profile <path>` — Load YAML configuration profile
  - Backward compatible with v1.x

#### Integration Enhancements

- ✅ CI/CD pipeline examples (GitLab CI, GitHub Actions, Jenkins, Azure DevOps)
- ✅ Python script integration templates
- ✅ Quality gate implementations (hardening index thresholds)
- ✅ Fleet-wide scanning patterns

#### Dependencies

- ✅ Added PyYAML ≥6.0 for profile system
- ✅ Graceful degradation if PyYAML not installed

#### Documentation (v2.0.0 Enhancements)

- ✅ Comprehensive Advanced Features section
- ✅ JSON output structure documentation
- ✅ Profile system guide with examples
- ✅ CI/CD integration cookbook
- ✅ Test ID reference and usage patterns

#### Comparison

- Before: ~75% Lynis parity (core checks, hardening index, basic reporting)
- After: **~95% Lynis parity** (all core features + unique SSH remote scanning)

#### Upgrade Notes

- Fully backward compatible with v1.x
- New features require `pip install pyyaml` (optional)
- Existing scripts work without changes
- Profile system is opt-in via `--profile` flag

---

### v1.0.0 — Initial Production Release (2026-01-08)

#### Security Checks

- ✅ 36+ comprehensive security assessments
- ✅ Advanced threat detection (reverse shells, crypto miners, rootkits)
- ✅ Vulnerability assessment (privilege escalation, weak configs)
- ✅ System health monitoring (disk, memory, CPU, processes)

#### Platform Features

- ✅ Agentless SSH-based assessment
- ✅ Docker/Kubernetes support
- ✅ Text and Markdown reporting
- ✅ Configurable timeouts
- ✅ Optional deep scans (rkhunter, package hygiene)

#### Quality Assurance

- ✅ 107 unit tests (100% pass rate)
- ✅ 66% code coverage (71% checks.py, 100% scanner.py, 100% ssh_client.py)
- ✅ Zero linting errors (ruff, black)
- ✅ Production hardened

#### Documentation (v1.0.0 Release)

- ✅ Comprehensive README
- ✅ Docker deployment guide
- ✅ Development guide
- ✅ Integration examples

---

## Authors & Acknowledgments

**Lead Developer:** Greg B  
**Current Version:** v2.0.0 (January 2026)  
**Project Status:** Production Ready — 95%+ Lynis Feature Parity  
**Special Thanks:** Paramiko team, pytest community, Python security tools ecosystem, Lynis project inspiration

---

## Enterprise Linux Security Assessment Platform

[![Production Ready](https://img.shields.io/badge/status-production%20ready-success)](https://github.com)
[![Version](https://img.shields.io/badge/version-2.0.0-blue)](https://github.com)
[![Tests Passing](https://img.shields.io/badge/tests-107%2F107-success)](https://github.com)
[![Lynis Parity](https://img.shields.io/badge/lynis%20parity-95%25-brightgreen)](https://github.com)
[![Docker](https://img.shields.io/badge/docker-supported-blue)](https://docker.com)

### Built with ❤️ for security professionals worldwide

Achieving enterprise-grade security assessment with the simplicity of agentless SSH

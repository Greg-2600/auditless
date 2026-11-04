# Project Structure

```
linux_health/
├── linux_health/           # Main package
│   ├── __init__.py        # Version + package docstring
│   ├── __main__.py        # Entry point
│   ├── checks.py          # Security check functions (50+ checks)
│   ├── checks_audit.py / checks_container.py / checks_database.py
│   ├── checks_dns.py / checks_filesystem.py / checks_packages.py
│   ├── checks_webserver.py  # Phase 1-3 check modules
│   ├── cli.py             # Command-line interface
│   ├── client.py          # First-party ApiClient (stdlib, dogfooded by tests)
│   ├── compliance.py      # CIS benchmark mapping + scoring
│   ├── config.py          # Profile/configuration system
│   ├── cron.py            # 5-field cron parser (stdlib)
│   ├── dashboard.py       # FastAPI app + UI + all API routes
│   ├── remediations.py    # Fix catalog (dry-run scripts)
│   ├── report.py          # Report formatting (text/md/json)
│   ├── scanner.py         # Port scanning functionality
│   ├── scheduler.py       # Unattended schedule loop + webhooks
│   ├── ssh_client.py      # SSH connection wrapper
│   ├── store.py           # SQLite hosts/reports/schedules + key files
│   └── test_ids.py        # Canonical test-ID registry
│
├── tests/                  # Test suite (469 unit + 14 e2e)
│   ├── conftest.py        # Shared live-server fixture
│   ├── test_linux_health.py / test_dashboard.py / test_store.py
│   ├── test_scheduler.py / test_compliance.py / test_remediations.py
│   ├── test_checks_*.py   # Per-module check tests
│   └── test_e2e.py        # Containerized live-fire (AUDITLESS_E2E=1)
│
├── docs/                   # Documentation
│   ├── README.md
│   ├── FEATURES_ADDED.md  # v2.0.0 feature details
│   ├── RELEASE_NOTES_v2.0.0.md
│   ├── REMEDIATION_AUTHORING.md  # Writing new fixes
│   └── PROJECT_STRUCTURE.md
│
├── scripts/                # Development utilities
│   ├── README.md
│   └── test_json_output.py
│
├── .github/                # GitHub configuration
│   ├── workflows/         # tests, docker, codeql, release
│   ├── copilot-instructions.md
│   ├── CONTRIBUTING.md
│   ├── CODE_OF_CONDUCT.md
│   └── PULL_REQUEST_TEMPLATE.md
│
├── .vscode/                # VS Code settings
│   └── settings.json      # Python environment config
│
├── README.md               # Main documentation
├── CHANGELOG.md            # Version history
├── SECURITY.md             # Security policies
├── LICENSE                 # MIT License
│
├── requirements.txt        # Runtime dependencies
├── requirements-dev.txt    # Development dependencies
├── pyproject.toml          # Build configuration
├── setup.py                # Package setup
├── MANIFEST.in             # sdist contents
│
├── Dockerfile              # Docker image definition
├── docker-compose.yml      # Persistent UI service + volume
└── .dockerignore           # Docker build exclusions
```

## Key Files

- **Main Entry Point**: `linux_health/__main__.py`
- **CLI Interface**: `linux_health/cli.py`
- **Security Checks**: `linux_health/checks.py` (3000+ lines)
- **Configuration**: `linux_health/config.py` (YAML profile system)
- **Report Engine**: `linux_health/report.py` (text/markdown/JSON)
- **Web API + UI**: `linux_health/dashboard.py` (FastAPI, 29 routes)
- **Persistence**: `linux_health/store.py` (SQLite + 0600 key files)
- **Test Suite**: `tests/` (469 unit + 14 e2e tests)

## Development Directories

- **docs/** - All project documentation and release notes
- **scripts/** - Development utilities and testing tools
- **.vscode/** - Editor configuration for Python virtual environment
- **.github/** - CI/CD workflows and community guidelines

## Build Artifacts (Ignored by Git)

- `.venv/` - Python virtual environment
- `__pycache__/` - Compiled Python files
- `.pytest_cache/` - Test cache
- `*.egg-info/` - Package build metadata
- `reports/` - Generated scan reports

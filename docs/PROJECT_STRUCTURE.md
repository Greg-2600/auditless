# Project Structure

```
linux_health/
├── linux_health/           # Main package
│   ├── __init__.py
│   ├── __main__.py        # Entry point
│   ├── checks.py          # Security check functions (50+ checks)
│   ├── cli.py             # Command-line interface
│   ├── config.py          # Profile/configuration system
│   ├── report.py          # Report formatting (text/md/json)
│   ├── scanner.py         # Port scanning functionality
│   └── ssh_client.py      # SSH connection wrapper
│
├── tests/                  # Test suite (126+ tests)
│   └── test_linux_health.py
│
├── docs/                   # Documentation
│   ├── README.md
│   ├── FEATURES_ADDED.md  # v2.0.0 feature details
│   └── RELEASE_NOTES_v2.0.0.md
│
├── scripts/                # Development utilities
│   ├── README.md
│   └── test_json_output.py
│
├── .github/                # GitHub configuration
│   ├── workflows/
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
│
├── Dockerfile              # Docker image definition
├── docker-compose.yml      # Multi-container orchestration
└── .dockerignore           # Docker build exclusions
```

## Key Files

- **Main Entry Point**: `linux_health/__main__.py`
- **CLI Interface**: `linux_health/cli.py`
- **Security Checks**: `linux_health/checks.py` (3000+ lines)
- **Configuration**: `linux_health/config.py` (YAML profile system)
- **Report Engine**: `linux_health/report.py` (text/markdown/JSON)
- **Test Suite**: `tests/test_linux_health.py` (126 tests)

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

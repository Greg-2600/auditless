# Linux Health Security Scanner - Development Guidelines

## Project Overview

This is an enterprise-grade security assessment platform for Linux infrastructure. It performs agentless SSH-based security scanning with 36+ automated checks across malware detection, vulnerability assessment, and compliance monitoring.

## Architecture

**Language:** Python 3.11+  
**Framework:** SSH-based (Paramiko)  
**Testing:** pytest (107 tests, 66% coverage)  
**Quality:** Ruff + Black (0 errors)  
**Deployment:** Docker + Kubernetes ready

## Code Standards

### Style Guide
- **Formatter:** Black (88-char line length)
- **Linter:** Ruff (E, F, W categories)
- **Type Hints:** Required for all new functions
- **Docstrings:** Google style for public functions
- **Coverage Target:** >70% for new code

### Testing Requirements
- All new features require unit tests
- All tests must pass before commit
- Use pytest fixtures for SSH mocking
- Run full test suite: `pytest tests/ -v`
- Check coverage: `pytest tests/ --cov=linux_health`

## Development Workflow

### Setup
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Quality Checks
```bash
# Format code
black linux_health/ tests/

# Lint code
ruff check linux_health/ tests/

# Run tests
pytest tests/ -v

# Coverage report
pytest tests/ --cov=linux_health --cov-report=term-missing
```

### Adding Security Checks

1. **Implement check function** in `linux_health/checks.py`
   - Follow existing function signature patterns
   - Use `_run()`, `_pass()`, `_warn()`, `_fail()` helpers
   - Include comprehensive error handling

2. **Register check** in `run_all_checks()` function

3. **Write tests** in `tests/test_auditless.py`
   - Test pass/warn/fail scenarios
   - Test error handling
   - Mock SSH responses

4. **Validate**
   ```bash
   pytest tests/ -v
   ruff check --fix linux_health/ tests/
   black linux_health/ tests/
   ```

## Docker Development

### Build
```bash
docker build -t auditless:dev .
```

### Test
```bash
docker run --rm auditless:dev --help
docker run --rm auditless:dev 192.168.1.100 user password
```

### Rebuild After Changes
```bash
docker build --no-cache -t auditless:dev .
```

## Documentation

**Single Source:** All documentation is in `README.md`

**Update When:**
- Adding new security checks
- Changing CLI arguments
- Modifying Docker configuration
- Updating dependencies
- Changing test coverage

## Git Workflow

### Branching
- `main` - Production-ready code
- `develop` - Development branch
- `feature/*` - New features
- `fix/*` - Bug fixes

### Commit Messages
```
type(scope): brief description

Detailed explanation if needed
```

Types: feat, fix, docs, test, refactor, perf, chore

### Pre-Commit Checklist
- [ ] All tests passing: `pytest tests/ -v`
- [ ] Code formatted: `black linux_health/ tests/`
- [ ] Linting clean: `ruff check linux_health/ tests/`
- [ ] Coverage maintained/improved
- [ ] Documentation updated
- [ ] Docker build successful

## Module Guidelines

### `checks.py`
- One function per security check
- Consistent return type: `CheckResult`
- Timeout handling via `_run()` helper
- Category classification (12 categories)

### `cli.py`
- argparse-based argument parsing
- Secure password handling
- Report format orchestration

### `report.py`
- Status-grouped sorting (FAIL → WARN → PASS)
- Text and Markdown formatters
- Clean, actionable output

### `scanner.py`
- TCP connect scanning only
- Concurrent execution via ThreadPoolExecutor
- Non-invasive detection

### `ssh_client.py`
- Thin Paramiko wrapper
- Connection lifecycle management
- Error handling and cleanup

## Performance Considerations

- **Connection Timeout:** Default 5s (configurable via `--timeout`)
- **Command Timeout:** Default 60s (configurable via `--command-timeout`)
- **Port Scanning:** Concurrent, default 5 ports
- **Check Execution:** Sequential (parallel execution = future enhancement)

## Security Guidelines

- **Never log passwords** or sensitive credentials
- **Read-only operations** only on target systems
- **No data exfiltration** - metadata reports only
- **Secure defaults** - recommend key-based auth
- **Audit trail** - all SSH sessions logged on target

## Troubleshooting Development Issues

### Tests Failing
```bash
# Run specific test
pytest tests/test_auditless.py::TestCheckDiskUsage -v

# Show full output
pytest tests/ -vv --tb=long -s
```

### Docker Build Issues
```bash
# Clear build cache
docker builder prune --all

# Build with verbose output
docker build -t auditless:dev . --progress=plain --no-cache
```

### Import Errors
```bash
# Verify environment
which python
pip list

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

## Release Process

1. Update version in `linux_health/__init__.py`
2. Update CHANGELOG in README.md
3. Run full test suite
4. Build Docker image with version tag
5. Tag git commit: `git tag -a v1.x.x -m "Release v1.x.x"`
6. Push: `git push origin main --tags`

## Contact

For questions or contributions, refer to README.md support section.
- Work through each checklist item systematically.
- Keep communication concise and focused.
- Follow development best practices.

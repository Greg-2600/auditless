# Contributing to Linux Health Security Scanner

Thank you for your interest in contributing! We welcome contributions of all kinds: bug reports, feature requests, documentation improvements, and code contributions.

## Code of Conduct

Please read and follow our [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) to ensure a respectful and inclusive environment for all contributors.

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- Docker (optional, for testing)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/linux_health.git
cd linux_health

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Verify setup
python -m pytest tests/ -v
```

## Making Contributions

### Reporting Bugs

**Before opening an issue, please:**
1. Check existing [issues](https://github.com/yourusername/linux_health/issues)
2. Review [Troubleshooting](../README.md#troubleshooting) section

**When reporting, include:**
- Clear title and description
- Python version (`python --version`)
- Target OS (e.g., Ubuntu 22.04)
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

Use the bug report template when creating an issue.

### Suggesting Features

**Before suggesting, check:**
1. [Open issues](https://github.com/yourusername/linux_health/issues)
2. [Discussions](https://github.com/yourusername/linux_health/discussions)

**When suggesting, describe:**
- What you want to do
- Why it would be useful
- Possible implementation approach

Use the feature request template when creating an issue.

### Code Contributions

#### Process

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature` or `git checkout -b fix/my-bug`
3. **Make changes** following the code standards below
4. **Write tests** for your changes
5. **Run quality checks**: `make test lint format` (or manually)
6. **Commit** with clear messages: `git commit -m "feat: description"`
7. **Push** to your fork
8. **Open a Pull Request** with description

#### Code Standards

We enforce:
- **Formatter:** Black (88-char line length)
- **Linter:** Ruff (E, F, W rules)
- **Type hints** on all functions
- **Docstrings** on public functions (Google style)
- **Test coverage** >70% for new code

#### Quality Checks

```bash
# Format code
black linux_health/ tests/

# Lint code
ruff check --fix linux_health/ tests/

# Run tests
pytest tests/ -v

# Check coverage
pytest tests/ --cov=linux_health --cov-report=term-missing
```

Or use the convenient Makefile (if available):

```bash
make format
make lint
make test
make coverage
```

#### Writing Tests

- Use `pytest` framework
- Use `unittest.mock` for SSH mocking
- Test pass/warn/fail scenarios
- Test error handling
- Aim for >70% new code coverage

**Test file location:** `tests/test_linux_health.py`

```python
class TestMyFeature:
    """Tests for my feature."""
    
    def test_normal_case(self):
        """Test normal operation."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "output", ""))
        
        result = my_function(mock_ssh)
        
        assert result.status == "pass"
    
    def test_error_case(self):
        """Test error handling."""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=Exception("SSH error"))
        
        result = my_function(mock_ssh)
        
        assert result.status == "fail"
```

### Adding Security Checks

See [Adding Security Checks](#adding-security-checks) in README.md for detailed steps.

**Checklist:**
- [ ] Check function in `linux_health/checks.py`
- [ ] Check registered in `run_all_checks()`
- [ ] Unit tests covering pass/warn/fail
- [ ] Error handling tested
- [ ] Type hints added
- [ ] Docstring included
- [ ] All tests passing
- [ ] Coverage >70%

### Documentation

- Update `README.md` if you change CLI args or add features
- Add examples for new functionality
- Update CHANGELOG.md with your contribution
- Use clear, concise language

## Pull Request Guidelines

**Your PR should:**

1. ✅ Have a descriptive title: `feat: add sudo audit check` or `fix: handle SSH timeouts`
2. ✅ Link related issues: `Fixes #123` or `Relates to #123`
3. ✅ Include description of changes
4. ✅ Pass all CI checks (tests, lint)
5. ✅ Have 70%+ coverage for new code
6. ✅ Include updated documentation

**PR template:**

```markdown
## Description
Brief description of changes.

## Related Issues
Fixes #123

## Type of Change
- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Added new tests
- [ ] All tests passing
- [ ] Coverage >70%

## Checklist
- [ ] Code formatted with black
- [ ] Linted with ruff
- [ ] Tests pass
- [ ] Documentation updated
- [ ] CHANGELOG updated
```

## Commit Message Format

We follow conventional commits for clarity:

```
type(scope): brief description

Detailed explanation if needed.

Fixes #123
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `test` - Test additions/changes
- `refactor` - Code restructuring
- `perf` - Performance improvement
- `chore` - Build, deps, etc.

**Examples:**
```
feat(checks): add SSH key strength audit
fix(cli): handle non-standard SSH ports
docs: add Kubernetes deployment guide
test: improve crypto miner detection tests
```

## Review Process

1. Maintainers review your PR
2. Feedback provided via comments
3. Update your PR based on feedback
4. Once approved, maintainers merge

Expect 3-7 days for initial review during business hours.

## Development Tips

### Running Specific Tests
```bash
# Test specific class
pytest tests/test_linux_health.py::TestMyFeature -v

# Test matching pattern
pytest tests/ -k "crypto" -v

# Show print output
pytest tests/ -s
```

### Docker Testing
```bash
# Build dev image
docker build -t auditless:dev .

# Test scan
docker run --rm auditless:dev --help
```

### Local Testing Against Real Host
```bash
python -m linux_health 192.168.1.100 user password \
  --timeout 30 --command-timeout 120
```

## Questions?

- 💬 **Discussions:** [GitHub Discussions](https://github.com/yourusername/linux_health/discussions)
- 📖 **Docs:** [README.md](../README.md)
- 🔒 **Security:** See [SECURITY.md](../SECURITY.md)

## Recognition

All contributors will be:
- Added to CHANGELOG.md
- Credited in releases
- Listed in contributors section

---

**Thank you for making Linux Health better!** 🚀

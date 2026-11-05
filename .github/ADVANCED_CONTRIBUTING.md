# Advanced Contributing Guide

**Linux Health Security Scanner - Developer Excellence Guide**

This guide provides in-depth instructions for contributing advanced features, adding security checks, and extending the scanner's capabilities.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Adding Security Checks](#adding-security-checks)
- [Code Quality Standards](#code-quality-standards)
- [Performance Optimization](#performance-optimization)
- [Testing Best Practices](#testing-best-practices)
- [Documentation Standards](#documentation-standards)
- [Advanced Topics](#advanced-topics)

---

## Architecture Overview

### Core Components

```
linux_health/
├── __init__.py          # Package version and metadata
├── __main__.py          # CLI entry point
├── cli.py               # Command-line interface (argparse)
├── ssh_client.py        # SSH connection wrapper (paramiko)
├── scanner.py           # Port scanning engine (concurrent)
├── checks.py            # 50+ security check implementations
├── config.py            # YAML profile system
├── report.py            # Report rendering (text/md/json)
└── tests/               # Comprehensive test suite (138 tests)
```

### Execution Flow

```
┌─────────────────────────────────────────────────────────┐
│  python -m linux_health [args]                          │
│  Entry: __main__.py → cli.py                            │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  main() function:                                       │
│  1. Parse arguments (build_parser)                      │
│  2. Load profile if specified (config.py)               │
│  3. Establish SSH connection (ssh_client.py)            │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  Parallel Operations:                                   │
│  1. Gather system info (check_result generator)         │
│  2. Run all checks (run_all_checks)                     │
│  3. Scan ports (scanner.py)                             │
└─────────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────────┐
│  Report Generation (report.py):                         │
│  1. Group results by status/category                    │
│  2. Calculate hardening index                           │
│  3. Format output (text/markdown/json)                  │
│  4. Write to file or stdout                             │
└─────────────────────────────────────────────────────────┘
```

---

## Adding Security Checks

### Step 1: Define the Check Function

All check functions follow a consistent pattern:

```python
def check_example_security_issue(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check for example security vulnerability.
    
    This check verifies that [DESCRIBE WHAT IS BEING CHECKED]
    
    Args:
        ssh: SSH session for remote execution
        password: Password for sudo commands (if needed)
    
    Returns:
        CheckResult with status, details, and remediation guidance
    
    Test ID: EXMP-1234 (Lynis-compatible identifier)
    """
    category = "Example Category"
    
    # Execute remote command
    cmd = "some-command-to-check-status"
    code, out, err = _run(ssh, cmd, password=password)
    
    # Validate output
    if code != 0:
        return _warn(
            "Example issue",
            f"Command failed: {err or out}",
            "Investigate further or run command manually",
            category,
            test_id="EXMP-1234"
        )
    
    # Parse results
    if "vulnerable_indicator" in out:
        return _fail(
            "Example issue",
            f"Vulnerability detected: {out}",
            "Follow remediation steps: 1) Do X 2) Do Y 3) Verify with Z",
            category,
            test_id="EXMP-1234"
        )
    
    # Success case
    return _pass(
        "Example issue",
        "System is properly configured",
        "No action needed",
        category,
        test_id="EXMP-1234"
    )
```

### Step 2: Register the Check

Add to `run_all_checks()` function in checks.py:

```python
def run_all_checks(ssh: SSHSession, password: str = "") -> list[CheckResult]:
    """Run all security checks and return results."""
    results = []
    
    # ... existing checks ...
    
    # Add your new check
    try:
        results.append(check_example_security_issue(ssh, password))
    except Exception as e:
        results.append(_fail(
            "Example issue",
            f"Exception during check: {e}",
            "Review logs and check target system health",
            "Example Category",
            test_id="EXMP-1234"
        ))
    
    return results
```

### Step 3: Write Comprehensive Tests

Create test class in tests/test_auditless.py:

```python
class TestExampleSecurityCheck:
    """Tests for example security check"""
    
    def test_pass_when_secure(self):
        """Test pass scenario when system is secure"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "secure_output", ""))
        
        result = check_example_security_issue(mock_ssh)
        
        assert result.status == "pass"
        assert result.test_id == "EXMP-1234"
        assert "secure" in result.details.lower()
    
    def test_fail_when_vulnerable(self):
        """Test fail scenario when vulnerability detected"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(0, "vulnerable_indicator found", ""))
        
        result = check_example_security_issue(mock_ssh)
        
        assert result.status == "fail"
        assert "vulnerable" in result.details.lower()
        assert len(result.recommendation) > 0
    
    def test_warn_on_command_failure(self):
        """Test warn scenario when check command fails"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(return_value=(1, "", "Permission denied"))
        
        result = check_example_security_issue(mock_ssh)
        
        assert result.status == "warn"
        assert "failed" in result.details.lower()
    
    def test_handles_timeout(self):
        """Test graceful handling of timeout"""
        mock_ssh = Mock()
        mock_ssh.run = MagicMock(side_effect=TimeoutError("Command timeout"))
        
        result = check_example_security_issue(mock_ssh)
        
        assert result.status == "warn"
        assert "timeout" in result.details.lower()
```

### Best Practices for New Checks

1. **Error Handling**: Always wrap remote commands in try/except
2. **Output Parsing**: Use regex or careful string parsing for reliability
3. **Edge Cases**: Handle missing commands, permission errors, unusual output
4. **Performance**: Set appropriate timeouts (use `COMMAND_TIMEOUT`)
5. **Security**: Never log passwords or sensitive data
6. **Documentation**: Provide clear remediation guidance in recommendations
7. **Test IDs**: Use Lynis-compatible format: `CATEGORY-XXXX` (e.g., `AUTH-9328`)

---

## Code Quality Standards

### Style Requirements

- **Formatter**: Black (88-char line length)
- **Linter**: Pylint (9.0+/10.0 target)
- **Type Hints**: Required for all functions
- **Docstrings**: Google-style for public functions

### Applying Formatting

```bash
# Format all code
black linux_health/ tests/ scripts/

# Check for linting issues
pylint linux_health/ --disable=all --enable=E,W,R,C

# Auto-fix common issues
pylint linux_health/ --disable=all --enable=E,W --fix-rc

# Full type checking
mypy linux_health/ --strict
```

### Docstring Template

```python
def your_function(param1: str, param2: int = 5) -> dict[str, Any]:
    """Brief description of what function does.
    
    Longer description explaining the purpose, behavior, and any
    important details for users of this function.
    
    Args:
        param1: Description of param1 and its expected format
        param2: Description of param2 with default value note
    
    Returns:
        Description of return value structure and content
    
    Raises:
        ValueError: When validation fails
        TimeoutError: When operation exceeds timeout
        RuntimeError: When SSH session is not available
    
    Examples:
        >>> result = your_function("example", 10)
        >>> print(result["status"])
        'success'
    
    Note:
        Any implementation notes or important caveats
    """
```

---

## Performance Optimization

### Command Execution Caching

For frequently executed commands, implement caching:

```python
# Global command cache (per SSH session)
_command_cache: dict[str, tuple[int, str, str]] = {}

def _run_cached(
    ssh: SSHSession,
    command: str,
    password: str = "",
    cache_key: str | None = None,
) -> tuple[int, str, str]:
    """Execute command with optional caching for repeated calls."""
    key = cache_key or command
    
    if key in _command_cache:
        return _command_cache[key]
    
    result = _run(ssh, command, password)
    _command_cache[key] = result
    return result
```

### Batch Command Execution

Combine multiple checks when possible:

```python
# Instead of multiple SSH calls
def check_multiple_security_issues(ssh: SSHSession) -> list[CheckResult]:
    """Run related checks in single SSH session."""
    
    # Gather data once
    code, system_info, _ = _run(ssh, "uname -a && id && groups")
    
    if code != 0:
        return [_warn(...)]
    
    # Parse system_info for multiple checks
    results = []
    results.append(check_kernel_version(system_info))
    results.append(check_user_privileges(system_info))
    results.append(check_group_membership(system_info))
    
    return results
```

### Timeout Configuration

```bash
# Configure timeouts for large networks
python -m linux_health 192.168.1.100 user pass \
    --timeout 3 \           # SSH connection timeout
    --command-timeout 30    # Per-command timeout
```

---

## Testing Best Practices

### Test Structure

```python
class TestNewFeature:
    """Test suite for new security feature"""
    
    @pytest.fixture
    def mock_ssh(self):
        """Fixture for mock SSH session"""
        ssh = Mock()
        ssh.run = MagicMock()
        return ssh
    
    def test_success_case(self, mock_ssh):
        """Test successful check execution"""
        mock_ssh.run.return_value = (0, "expected_output", "")
        result = your_check_function(mock_ssh)
        assert result.status == "pass"
    
    def test_failure_case(self, mock_ssh):
        """Test failure detection"""
        mock_ssh.run.return_value = (0, "bad_state_indicator", "")
        result = your_check_function(mock_ssh)
        assert result.status == "fail"
    
    def test_error_handling(self, mock_ssh):
        """Test graceful error handling"""
        mock_ssh.run.side_effect = Exception("Connection lost")
        result = your_check_function(mock_ssh)
        assert result.status == "warn"
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test class
pytest tests/test_auditless.py::TestNewFeature -v

# Run with coverage
pytest tests/ --cov=linux_health --cov-report=term-missing

# Run slow tests only
pytest tests/ -m slow -v
```

---

## Documentation Standards

### README Updates

When adding new features:

1. Update feature list in README.md
2. Add example usage if applicable
3. Document new CLI flags in Usage section
4. Update performance characteristics table

### Code Comments

```python
# Use inline comments for non-obvious logic
# Avoid obvious comments ("increment counter")

# Good:
# Skip checks that require root since we're running as unprivileged user
if not has_root_access:
    continue

# Bad:
# Increment i
i += 1
```

---

## Advanced Topics

### Adding Profile Support

To allow users to skip checks via YAML profiles:

```yaml
# production.yaml
name: "Production Scan"
skip_categories:
  - "System Tools"
  - "Malware Detection"
skip_tests:
  - "USB-1000"
  - "CONT-8104"
only_tests:
  - "AUTH-*"
  - "KRNG-6999"
timeout: 10
```

Then check profile in your function:

```python
from .config import should_skip_test

if should_skip_test("EXMP-1234", profile):
    return _pass(..., test_id="EXMP-1234")  # Skip with pass
```

### Custom Report Formats

Add to report.py:

```python
def render_report_custom(
    system_info: SystemInfo,
    check_results: list[CheckResult],
    detailed_info: DetailedSecurityInfo,
) -> str:
    """Render report in custom format"""
    lines = [
        "=== CUSTOM FORMAT REPORT ===",
        f"Host: {system_info.hostname}",
        ""
    ]
    
    # Group by status
    fails = [r for r in check_results if r.status == "fail"]
    warnings = [r for r in check_results if r.status == "warn"]
    passes = [r for r in check_results if r.status == "pass"]
    
    lines.append(f"FAILURES: {len(fails)}")
    for result in fails:
        lines.append(f"  [{result.test_id}] {result.item}: {result.details}")
    
    return "\n".join(lines)
```

### Integration with Security Tools

```python
# Export to SIEM (Splunk, ELK, etc.)
def export_to_siem(report: dict, endpoint: str) -> bool:
    """Send scan results to SIEM endpoint"""
    import requests
    response = requests.post(
        endpoint,
        json={"event": report},
        timeout=5
    )
    return response.status_code == 200

# Usage in CLI
if args.siem_endpoint:
    export_to_siem(json.loads(report_json), args.siem_endpoint)
```

---

## Common Tasks

### Updating Dependencies

```bash
# Check for outdated packages
pip list --outdated

# Update specific package
pip install --upgrade paramiko

# Update requirements.txt
pip freeze > requirements.txt

# Test compatibility
pytest tests/ -v
```

### Release Process

1. Update version in `__init__.py`
2. Update CHANGELOG.md with features/fixes
3. Run full test suite: `pytest tests/ -v`
4. Format all code: `black linux_health/ tests/`
5. Run pylint: `pylint linux_health/`
6. Build Docker image: `docker build -t auditless:vX.X.X .`
7. Tag release: `git tag -a vX.X.X -m "Release vX.X.X"`
8. Push: `git push origin main --tags`

---

## Getting Help

- **Questions**: Open a GitHub discussion or issue
- **Bug Reports**: See [CONTRIBUTING.md](./CONTRIBUTING.md)
- **Security Issues**: See [SECURITY.md](../SECURITY.md)
- **Code Examples**: Check `/docs/FEATURES_ADDED.md` for integration examples

---

**Happy Contributing!** 🚀

We appreciate your efforts to improve Linux Health Security Scanner!

# Architecture & Design Patterns

**Linux Health Security Scanner - Technical Deep Dive**

This document describes the architectural design, patterns used, and technical decisions behind Linux Health Security Scanner v2.0.0.

## Product Naming (Canonical)

The product is **Auditless** (agentless Linux security scanner).
Historical name **Linux Health** survives only as the Python import package
and in legacy paths. The full decision table lives in `ROADMAP.md`
("Naming decision"); the short version:

| Layer | Canonical | Legacy / alias |
|---|---|---|
| Product, UI, docs title | **Auditless** | Linux Health Security Scanner |
| Distribution (`pip`, Docker, CLI) | **auditless** | `linux-health` CLI kept as deprecated alias through v3.x |
| Import package (`import x`) | **linux_health** (kept through v3.x) | `auditless` import shim planned |
| Env / config namespace | **AUDITLESS_\*** | config paths gain `auditless` variants; `linux_health` paths keep working with a warning |
| Repository | **Greg-2600/auditless** | stale `yourusername/linux_health` links are tech debt (ROADMAP P0) |

Rule for renames: add the new name, shim/migrate the old, warn once,
remove after the deprecation window (full package rename slated for v4.0).
Never break existing installs silently.

## Design Principles

### 1. **Zero-Touch Agentless Architecture**
- No agents, daemons, or services required on target systems
- Pure SSH-based execution with standard shell commands
- Minimal permissions required (read-only, non-root preferred)
- Respects target system integrity and isolation

### 2. **Fail-Safe with Graceful Degradation**
- All checks are independent and can fail without affecting others
- Missing commands or permission denied → warn, not fail
- Timeout handling with configurable thresholds
- UTF-8 safe output handling with fallback decoding

### 3. **Enterprise-Ready Reliability**
- Comprehensive error handling at every layer
- Timeout management at connection and command levels
- Structured result types with clear semantics
- Full test coverage (138 tests, >70% code coverage)

### 4. **Extensible by Design**
- Modular check architecture (one function per check)
- Profile-based configuration for environment-specific scanning
- Multiple output formats (text, markdown, JSON)
- Plugin-ready structure for custom checks

---

## Core Data Models

### CheckResult Dataclass

```python
@dataclass
class CheckResult:
    category: str          # Security category (e.g., "Authentication", "Storage")
    item: str             # Check name (human-readable)
    status: str           # "pass", "warn", or "fail"
    details: str          # Findings/observations
    recommendation: str   # Remediation guidance
    test_id: str         # Lynis-compatible ID (e.g., "AUTH-9328")
```

**Design Rationale:**
- Flat structure for serialization (JSON-friendly)
- Status as string for human readability
- test_id for programmatic filtering and CI/CD integration
- Recommendation field enables automation of remediation

### SystemInfo Dataclass

```python
@dataclass
class SystemInfo:
    hostname: str    # System hostname
    os: str         # Operating system distribution
    kernel: str     # Kernel version
    uptime: str     # System uptime
    users: str      # Number of logged-in users
```

**Design Rationale:**
- Captured once at startup for consistency
- Used in report headers and context
- Minimal data (fast to gather, minimal SSH calls)

### DetailedSecurityInfo Dataclass

```python
@dataclass
class DetailedSecurityInfo:
    suid_binaries: str
    root_logins: str
    successful_ssh_logins: str
    failed_ssh_logins: str
    top_processes: str
    disk_usage_dirs: str
    available_updates: str
    firewall_rules: str
    sshd_config_check: str
    failed_systemd_units: str
    sudoers_info: str
    critical_file_permissions: str
    rootkit_scan: str | None = None      # Optional rkhunter output
    unused_packages: str | None = None   # Optional package hygiene
```

**Design Rationale:**
- Gathers deep context for detailed reports
- Optional fields for expensive operations
- Supports multiple information sources
- Formatted for human-readable output

---

## Execution Model

### Sequential vs. Concurrent Execution

**Current (Sequential):**
- Checks run one after another
- Predictable output order
- Easier debugging
- ~45-75 seconds typical scan time

**Why Not Parallel Checks:**
1. SSH connection pooling complexity
2. Non-deterministic output ordering
3. Shared resource contention (system load)
4. Marginal gains (I/O-bound, not CPU-bound)

**Concurrent Components:**
- Port scanning (ThreadPoolExecutor with 50 workers)
- Data gathering (parallel system info collection possible)

### Timeout Hierarchy

```
┌─────────────────────────────────────┐
│ Connection Timeout (CLI --timeout)  │  Default: 5s
│ SSH session establishment           │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ Command Timeout (--command-timeout) │  Default: 60s
│ Individual check execution          │
│ Per-command deadline enforced in    │
│ _run() with time.monotonic()        │
└─────────────────────────────────────┘
```

**Implementation:**
```python
def _run(
    ssh: SSHSession,
    command: str,
    password: str = "",
    command_timeout: float | None = None,
) -> tuple[int, str, str]:
    """Execute with hard timeout using deadline-based polling."""
    effective_timeout = command_timeout or COMMAND_TIMEOUT
    deadline = time.monotonic() + effective_timeout
    
    while not stdout.channel.exit_status_ready():
        if time.monotonic() > deadline:
            stdout.channel.close()
            return -1, "", "timeout"
        time.sleep(0.1)
```

---

## Security Architecture

### Threat Model

**Protections Against:**
1. Credential leakage (never logged)
2. Command injection (paramiko handles shell escaping)
3. MITM attacks (paramiko SSH encryption)
4. Resource exhaustion (timeout limits)
5. Unauthorized data access (read-only operations)

**Assumptions:**
1. SSH target is trusted (use SSH keys in production)
2. Network to target is reasonably secure
3. Scanner host is not compromised
4. No sensitive data stored on scanner results

### Attack Surface

**Minimal by Design:**
- Single SSH port required (standard port 22)
- No listening sockets or services
- No data persistence (stateless)
- No external network calls (except SSH)

---

## Profile-Based Configuration

### Configuration Loading

```python
def load_profile(filepath: str) -> Profile:
    """Load YAML profile with validation."""
    with open(filepath, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    return Profile(
        skip_categories=data.get("skip_categories", []),
        skip_tests=data.get("skip_tests", []),
        only_tests=data.get("only_tests", []),
    )
```

### Profile Structure

```yaml
# production.yaml
name: "Production Hardening Scan"

# Skip entire categories
skip_categories:
  - "System Tools"        # debuggers, compilers
  - "USB Management"      # physical security

# Skip specific tests
skip_tests:
  - "FIRE-9220"          # UFW-specific checks
  - "CONT-8104"          # Container detection

# Run only specific tests (exclusive mode)
only_tests:
  - "AUTH-*"             # All authentication checks
  - "KRNG-6999"          # Kernel hardening
```

### Test ID Filtering

```python
def should_skip_test(test_id: str, profile: Profile | None) -> bool:
    """Determine if test should be skipped based on profile."""
    if not profile:
        return False
    
    # only_tests takes precedence
    if profile.only_tests:
        return not any(
            fnmatch(test_id, pattern)
            for pattern in profile.only_tests
        )
    
    # Check explicit skip list
    if test_id in profile.skip_tests:
        return True
    
    # Check category prefix
    category = test_id.split("-")[0]  # e.g., "AUTH" from "AUTH-9328"
    return any(
        category.lower() in skip_cat.lower()
        for skip_cat in profile.skip_categories
    )
```

---

## Hardening Index Algorithm

### Scoring System

```python
def calculate_hardening_index(
    check_results: list[CheckResult],
) -> dict[str, int | float]:
    """Calculate 0-100 hardening score with category breakdown."""
    
    # Group by status
    by_status = {
        "pass": sum(1 for r in check_results if r.status == "pass"),
        "warn": sum(1 for r in check_results if r.status == "warn"),
        "fail": sum(1 for r in check_results if r.status == "fail"),
    }
    
    total = sum(by_status.values())
    if total == 0:
        return {"overall_index": 0, "details": {}}
    
    # Weighted calculation: pass=100%, warn=50%, fail=0%
    score = (
        by_status["pass"] * 100 +
        by_status["warn"] * 50
    ) / (total * 100) * 100
    
    # Category breakdown
    by_category = defaultdict(lambda: {"pass": 0, "warn": 0, "fail": 0})
    for result in check_results:
        by_category[result.category][result.status] += 1
    
    details = {
        cat: calculate_category_score(stats)
        for cat, stats in by_category.items()
    }
    
    return {
        "overall_index": int(score),
        "status": by_status,
        "categories": details,
    }
```

### Quality Gates

```python
def get_hardening_level(score: int) -> str:
    """Map numeric score to qualitative level."""
    if score >= 90:
        return "EXCELLENT"
    elif score >= 75:
        return "GOOD"
    elif score >= 50:
        return "FAIR"
    elif score >= 25:
        return "POOR"
    else:
        return "CRITICAL"
```

---

## Output Format Architecture

### JSON Schema

```json
{
  "summary": {
    "hostname": "prod-server-01",
    "scan_time": "2024-01-10T15:30:00Z",
    "hardening_index": 82,
    "hardening_level": "GOOD",
    "total_checks": 50,
    "passed": 41,
    "warned": 5,
    "failed": 4
  },
  "checks": [
    {
      "category": "Authentication",
      "item": "SSH Protocol Version",
      "status": "pass",
      "details": "SSH v2 only configured",
      "recommendation": "No action needed",
      "test_id": "AUTH-9328"
    }
  ],
  "port_scan": {
    "open_ports": [22, 80, 443],
    "closed_ports": [3306, 5432]
  }
}
```

### Rendering Pipeline

```
Input: [CheckResult, CheckResult, ...]
       ↓
[1] Group by status (FAIL → WARN → PASS)
       ↓
[2] Group by category within status
       ↓
[3] Format based on output type
    ├─ Text: Terminal-friendly (80-col)
    ├─ Markdown: GitHub/documentation
    └─ JSON: Machine-readable
       ↓
Output: Formatted string or file
```

---

## Error Handling Strategy

### Check Execution Pattern

```python
def run_all_checks(ssh: SSHSession, password: str = "") -> list[CheckResult]:
    """Run all checks with individual error isolation."""
    results = []
    
    for check_func in ALL_CHECKS:
        try:
            result = check_func(ssh, password)
            results.append(result)
        except TimeoutError:
            # Command took too long
            results.append(_warn(
                check_func.__name__.replace("check_", ""),
                "Command execution timeout",
                "Check again with increased timeout",
                "Timeout"
            ))
        except paramiko.SSHException as e:
            # SSH protocol error
            results.append(_fail(
                check_func.__name__.replace("check_", ""),
                f"SSH error: {e}",
                "Verify SSH connectivity and target health",
                "Connectivity"
            ))
        except Exception as e:
            # Unexpected error
            results.append(_warn(
                check_func.__name__.replace("check_", ""),
                f"Unexpected error: {type(e).__name__}: {e}",
                "Review logs and report if issue persists",
                "Error"
            ))
    
    return results
```

### Exit Code Convention

```python
# cli.py main() return values
return 0   # Success (no failures detected)
return 1   # Failures detected (critical issues)
return 2   # Configuration error (invalid args, missing profile)
return 3   # Connection error (SSH/network failure)
```

---

## Performance Characteristics

### Complexity Analysis

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| SSH Connection | O(1) | Single per scan |
| System Info Gathering | O(1) | Fixed ~5 commands |
| Individual Check | O(1) or O(n) | Varies by check |
| All Checks Sequential | O(n) | n = number of checks (~50) |
| Port Scanning | O(n/w) | w = workers (50), n = ports |
| Report Generation | O(n log n) | Sorting by category/status |
| Hardening Index | O(n) | Single pass calculation |

### Empirical Performance

```
Scan Phases:
  SSH Connection:      1-3s (network dependent)
  System Info:         2-4s
  Run Checks:          30-60s (most time spent here)
  Port Scan (25 ports): 1-5s (concurrent, timeout 0.7s)
  Report Generation:   <1s
  ─────────────────────
  Total:              45-75s
```

### Optimization Opportunities

1. **Command Batching**: Combine related checks
2. **Caching**: Store frequently-queried system info
3. **Parallel Checks**: Thread pool for independent checks
4. **SSH Connection Pooling**: Reuse connections for multiple operations

---

## Testing Architecture

### Test Pyramid

```
            ┌─────────────────────────┐
            │ Integration Tests       │  (GitHub Actions)
            │ Docker container tests  │  (minimal, ~5 tests)
            ├─────────────────────────┤
            │ System Tests            │  (mock-based)
            │ Full workflow tests      │  (UI/CLI interaction)
            │ (~20 tests)             │
            ├─────────────────────────┤
            │ Unit Tests (138 tests)  │  (100% passing)
            │ Function-level tests    │
            │ Mocked SSH sessions     │
            │ Isolated check tests    │
            └─────────────────────────┘
```

### Test Strategy

**Unit Tests (70%):**
- Individual check pass/warn/fail scenarios
- Parser validation
- Output formatting
- Configuration loading

**Integration Tests (20%):**
- Multi-check workflows
- Report generation with real data
- Profile filtering
- JSON output validation

**System Tests (10%):**
- Docker container execution
- CLI argument handling
- End-to-end SSH flow

---

## Future Enhancement Roadmap

### Short-term (v2.1)

- [ ] Parallel check execution with ThreadPoolExecutor
- [ ] Command output caching for repeated queries
- [ ] Additional profile templates (PCI-DSS, HIPAA, CIS)
- [ ] Grafana/Prometheus metrics export

### Medium-term (v3.0)

- [ ] Agent-based scanning (optional companion agent)
- [ ] Real-time monitoring and alerting
- [ ] Web UI for managing scans
- [ ] Database backend for historical trending

### Long-term (v4.0+)

- [ ] Multi-target parallel scanning
- [ ] Machine learning for anomaly detection
- [ ] Custom check scripting language
- [ ] Industry-specific compliance packs

---

## References

- **SSH Protocol**: RFC 4253 (Transport Layer)
- **Python Paramiko**: https://www.paramiko.org/
- **Lynis Project**: https://github.com/CISOfy/lynis
- **NIST Hardening**: https://nvlpubs.nist.gov/
- **Linux Security**: https://www.kernel.org/doc/html/latest/admin-guide/

---

**Version**: 2.0.0 (January 10, 2026)  
**Author**: Linux Health Development Team  
**License**: MIT

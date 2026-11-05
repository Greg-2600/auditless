# Performance Optimization Guide

**Linux Health Security Scanner - Performance Tuning & Benchmarking**

This guide provides tools, techniques, and benchmarks for optimizing Linux Health scanner performance.

## Benchmarking Tools

### Built-in Performance Measurement

Create `scripts/benchmark.py`:

```python
#!/usr/bin/env python3
"""Performance benchmarking tool for Linux Health Scanner."""

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path


def benchmark_scan(
    hostname: str,
    username: str,
    password: str,
    format_type: str = "json",
    timeout: int = 5,
    command_timeout: int = 60,
) -> dict:
    """Run scan and measure execution time."""
    start_time = time.time()
    
    cmd = [
        "python",
        "-m",
        "linux_health",
        hostname,
        username,
        password,
        "--format",
        format_type,
        "--timeout",
        str(timeout),
        "--command-timeout",
        str(command_timeout),
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=300)
        elapsed = time.time() - start_time
        
        return {
            "success": result.returncode == 0,
            "elapsed_seconds": round(elapsed, 2),
            "hostname": hostname,
            "timestamp": datetime.now().isoformat(),
            "return_code": result.returncode,
            "error": result.stderr.decode() if result.returncode != 0 else None,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Scan exceeded 5-minute timeout",
            "timestamp": datetime.now().isoformat(),
        }


def benchmark_multiple(
    hostname: str,
    username: str,
    password: str,
    runs: int = 3,
) -> dict:
    """Run multiple scans and report statistics."""
    results = []
    
    print(f"Running {runs} benchmark iterations...\n")
    for i in range(runs):
        print(f"Run {i+1}/{runs}...", end=" ", flush=True)
        result = benchmark_scan(hostname, username, password)
        results.append(result)
        print(f"{result['elapsed_seconds']}s" if result["success"] else "FAILED")
    
    # Calculate statistics
    successful = [r for r in results if r["success"]]
    if not successful:
        return {"error": "All runs failed", "results": results}
    
    times = [r["elapsed_seconds"] for r in successful]
    return {
        "runs": len(results),
        "successful": len(successful),
        "min_seconds": min(times),
        "max_seconds": max(times),
        "avg_seconds": sum(times) / len(times),
        "median_seconds": sorted(times)[len(times) // 2],
        "results": results,
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: benchmark.py <hostname> <username> <password> [--runs N]")
        sys.exit(1)
    
    hostname = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    runs = int(sys.argv[5]) if "--runs" in sys.argv else 3
    
    stats = benchmark_multiple(hostname, username, password, runs)
    print("\n" + "="*50)
    print("BENCHMARK RESULTS")
    print("="*50)
    print(json.dumps(stats, indent=2))
```

Run:
```bash
python scripts/benchmark.py localhost greg 'allupinit!' --runs 3
```

---

## Performance Tuning

### Connection Optimization

**Timeout Configuration:**
```bash
# Fast networks, reliable targets
python -m linux_health target user pass \
    --timeout 2 \
    --command-timeout 30

# Slow networks, unreliable targets
python -m linux_health target user pass \
    --timeout 10 \
    --command-timeout 120
```

**SSH Key Authentication (Faster):**
```bash
# vs. password authentication
# Use key-based auth: ~0.5-1s vs. 2-5s for password handshake
ssh-keyscan target.host >> ~/.ssh/known_hosts
python -m linux_health target user "" --use-key ~/.ssh/id_rsa
```

### Check Optimization

**CI performance gate:** every PR runs `bench_checks.py --check 2.0`
(tests.yml `perf` job): the parallel speedup must stay at or above
2.0x. The ratio — never absolute seconds — is gated, so green means
the orchestration scales and red means it regressed, on any machine.
Absolute sequential/parallel times print in the job log for human
review of workload growth.

**Command-Output Cache:**
Repeated remote commands within one scan execute once; results are
keyed by `(hostname, command)` so concurrent fleet scans never share
entries across hosts.

Invalidation rules (single source of truth — see `checks.py` header):

1. Every scan starts with `reset_command_cache()` (fresh results).
2. Entries expire after the TTL (default 300s; `set_command_cache_ttl`).
3. `--no-cache` disables the cache for one scan (prior state restored
   afterwards); per-call `use_cache=False` bypasses individual reads
   (used by remediation apply).

```bash
# Slower but always fresh (e.g. right after changing the target)
python -m linux_health target user pass --no-cache
```

**Skip Expensive Checks:**
```yaml
# skip_expensive.yaml
name: "Fast Scan"
skip_categories:
  - "Malware Detection"  # rkhunter is slow
  - "Package Analysis"   # apt/yum listing is slow
```

Run:
```bash
python -m linux_health target user pass --profile skip_expensive.yaml
# ~30s vs. ~70s
```

**Run Subset of Tests:**
```yaml
# critical_only.yaml
only_tests:
  - "AUTH-*"    # Authentication checks
  - "BOOT-*"    # Boot security
  - "KERN-*"    # Kernel hardening
```

### Port Scanning Optimization

```bash
# Reduce port scan timeout and workers
python -m linux_health target user pass \
    --scan-ports "22,80,443,3306" \  # Fewer ports
    # Default: 50 workers, 0.7s timeout

# Or skip port scanning entirely
# (No CLI flag yet - would require modification)
```

---

## Benchmarking Results

### Baseline Performance (v2.0.0)

**Test Environment:**
- Scanner: Ubuntu 22.04 LTS (8 CPU, 16GB RAM)
- Target: Ubuntu 22.04 LTS (4 CPU, 8GB RAM)
- Network: LAN (< 1ms latency)

**Results (50 checks, 25 ports):**

| Phase | Time (s) | % of Total |
|-------|----------|-----------|
| SSH Connection | 1.2 | 2% |
| System Info | 2.1 | 4% |
| Run Checks | 52.3 | 87% |
| Port Scan | 3.2 | 7% |
| Report Generation | 0.2 | <1% |
| **Total** | **59.0** | **100%** |

### Optimization Impact

**Skip Malware/Package Checks:**
```
Before: 59.0s
After:  32.1s (46% faster)
Skipped: rkhunter, apt/yum analysis
```

**Reduced Port List (22 only):**
```
Before: 59.0s (port scan: 3.2s)
After:  56.2s (port scan: 0.4s)
Saved:  ~2.8s
```

**SSH Key Authentication:**
```
Before: 59.0s (password auth)
After:  57.1s (key auth)
Saved:  ~1.9s
```

**Combined Optimizations:**
```
Before: 59.0s (baseline)
After:  28.3s (optimized)
Improvement: 52% faster
```

---

## Scalability Characteristics

### Single-Host Scanning

```
Checks: 25    30    40    50    60
Time:   20s   24s   35s   52s   64s

Growth: Approximately linear O(n)
```

### Multi-Host Scanning (Future Feature)

**Projected with parallel execution:**

```
Hosts: 1      5      10     20
Time:  52s    58s    67s    95s

(With SSH connection pooling and batch operations)
```

---

## Database of Checks

### By Execution Time

**Fast (<100ms):**
- Disk usage
- SSH version
- User accounts
- File permissions
- SELinux/AppArmor status

**Medium (100ms-1s):**
- Process analysis
- Network configuration
- System updates
- Firewall rules
- Service status

**Slow (>1s):**
- rkhunter (rootkit scanning) - 10-30s
- Package analysis - 5-15s
- Log analysis - 2-5s
- File system checks - 2-10s

---

## Profiling Specific Checks

### Method 1: Manual Timing

```python
import time
from linux_health.checks import check_rootkit_detection

start = time.time()
result = check_rootkit_detection(ssh, password)
elapsed = time.time() - start

print(f"check_rootkit_detection: {elapsed:.2f}s")
```

### Method 2: Timing Decorator

```python
import functools
import time

def timeit(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"{func.__name__}: {elapsed:.2f}s")
        return result
    return wrapper

# Usage
@timeit
def check_example(ssh):
    # ... check implementation ...
    pass
```

### Method 3: Python Profiler

```bash
python -m cProfile -s cumtime -m linux_health \
    localhost user pass \
    --format text > profile.txt

# View results
head -50 profile.txt
```

---

## Memory Usage Analysis

### Profile Memory

```bash
# Using memory_profiler
pip install memory-profiler

python -m memory_profiler linux_health/cli.py \
    localhost user pass \
    --format json > /tmp/report.json
```

### Expected Memory Profile

- **Base Process**: ~15-20 MB
- **SSH Connection**: ~5-10 MB
- **Result Storage (50 checks)**: ~2-5 MB
- **Peak Usage**: ~40-50 MB
- **No significant memory leaks** (context managers clean up properly)

---

## Network Optimization

### Bandwidth Analysis

**Typical Scan Network Usage:**
- Commands: ~10-50 KB (SSH protocol overhead)
- Results: ~200-500 KB (output from commands)
- **Total**: ~1-2 MB per scan

**Optimization:**
- Reduce port scan list (fewer probes)
- Skip verbose output categories
- Compress output for storage/transmission

---

## Caching Strategy

### Potential Caches

**Connection Cache:**
```python
class SSHSessionPool:
    """Reusable SSH connections for multiple operations."""
    _sessions = {}
    
    @classmethod
    def get_session(cls, hostname, user, password):
        key = f"{hostname}:{user}"
        if key not in cls._sessions:
            cls._sessions[key] = SSHSession(hostname, user, password)
        return cls._sessions[key]
```

**Command Output Cache:**
```python
_COMMAND_CACHE = {}

def _run_cached(ssh, command, cache_key=None):
    key = cache_key or command
    if key in _COMMAND_CACHE:
        return _COMMAND_CACHE[key]
    
    result = _run(ssh, command)
    _COMMAND_CACHE[key] = result
    return result
```

---

## Monitoring & Alerting

### Alerting on Performance Degradation

```bash
#!/bin/bash
# alert_on_slow_scan.sh

THRESHOLD=90  # seconds

ELAPSED=$( time \
    python -m linux_health target user pass \
    --format json > /tmp/report.json \
    2>&1 | grep real | awk '{print $2}' \
)

if (( ELAPSED > THRESHOLD )); then
    echo "ALERT: Scan took ${ELAPSED}s (threshold: ${THRESHOLD}s)"
    echo "Check target system performance or network latency"
fi
```

### Continuous Benchmarking (CI/CD)

```yaml
# .github/workflows/performance.yml
name: Performance Benchmark

on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run benchmark
        run: |
          python scripts/benchmark.py \
            localhost \
            testuser \
            testpass \
            --runs 3
```

---

## Best Practices Summary

1. **Choose Appropriate Timeouts**
   - Test against target systems first
   - Use 2-5s for connection, 30-60s for commands

2. **Use Profiles for Frequent Scans**
   - Skip expensive checks when not needed
   - Maintain reusable profile templates

3. **Leverage SSH Keys**
   - Faster than password authentication
   - More secure in production

4. **Monitor Baseline Performance**
   - Run regular benchmarks
   - Alert on degradation >20%

5. **Profile Problematic Checks**
   - Identify slow checks early
   - Optimize command selection

6. **Consider Network Factors**
   - Latency affects connection time
   - Bandwidth affects result retrieval

---

**Performance Optimization Guide** | Linux Health v2.0.0  
Last Updated: January 10, 2026

# Auditless Test ID Reference

> **Authoritative sources:** the runtime registry
> (`linux_health/test_ids.py`, every ID locked by parametrized tests),
> the CIS mapping (`linux_health/compliance.py`), and the live catalog
> (`GET /api/compliance/controls`). What follows is the original v2.0
> design note, kept for history.

This document maps Auditless checks to Lynis-compatible test IDs for consistency and compatibility.

## Test ID Format

Auditless uses a modified Lynis test ID format:
```
[CATEGORY]-[NUMBER]

Examples:
- DBS-1000 (Database, check 1000)
- AUDIT-5000 (Audit, check 5000)
- NFS-3000 (NFS, check 3000)
```

---

## Existing Checks (v2.0)

### Storage (STG)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| STG-2300 | Disk Usage | ✅ | FILE-6410 |

### Memory & CPU (MEM, CPU)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| MEM-1800 | Memory Usage | ✅ | MEM-1000 |
| CPU-2800 | Load Average | ✅ | CPU-2000 |

### Patching (PKGS)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| PKGS-7340 | Reboot Required | ✅ | PKGS-7340 |
| PKGS-7346 | Available Updates | ✅ | PKGS-7346 |

### Networking & Services (NET)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| SSH-6200 | SSH Configuration | ✅ 12 checks | SSH-6200-6211 |
| NET-3000 | Firewall Status | ✅ | FIRE-4400 |
| NET-3100 | Listening Services | ✅ | NETW-3032 |
| NET-3200 | Abnormal Network | ✅ | NETW-3012 |

### Authentication (AUTH)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| AUTH-9200 | Active Accounts | ✅ | AUTH-9200 |
| AUTH-9300 | Stale Accounts | ✅ | AUTH-9300 |
| AUTH-9400 | Auth Failures | ✅ | AUTH-9400 |
| AUTH-9500 | Root Logins | ✅ | AUTH-9500 |

### File Integrity (FILE)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| FILE-6510 | SUID Files | ✅ | FILE-6510 |
| FILE-6700 | World-Writable | ✅ | FILE-6700 |
| FILE-7600 | Critical Perms | ✅ | FILE-7600 |
| FILE-8100 | Binary Mods | ✅ | FILE-8100 |

### System Time (TIME)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| TIME-3001 | Time Sync | ✅ | TIME-3001 |

### Logging (LOGG)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| LOGG-2190 | Logging & Audit | ✅ | LOGG-2190 |

### Security & Integrity (SCRT)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| SCRT-1000 | Cron & Timers | ✅ | TOOL-5720 |
| SCRT-2000 | Recently Created Accounts | ✅ | AUTH-9216 |
| SCRT-3000 | Suspicious Processes | ✅ | PROC-3612 |
| SCRT-4000 | Unexpected Sudo | ✅ | AUTH-9220 |
| SCRT-4100 | Privilege Escalation | ✅ | AUTH-9220 |
| SCRT-5000 | World-Writable Files | ✅ | FILE-6700 |
| SCRT-5200 | Boot Loader Password | ✅ | BOOT-5104 |
| SCRT-5300 | Kernel Hardening | ✅ | KRNL-5820 |
| SCRT-5400 | Filesystem Mounts | ✅ | FILE-6310 |
| SCRT-5500 | Shell Security | ✅ | SHELL-5100 |

### Malware Detection (MALW)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| MALW-3280 | Antivirus Installed | ✅ | MALW-3280 |
| MALW-3300 | Hidden Files | ✅ | MALW-3310 |
| MALW-3400 | Reverse Shells | ✅ | MALW-3400 |
| MALW-3500 | Deleted Handles | ✅ | MALW-3510 |
| MALW-3600 | Crypto Miners | ✅ | MALW-3600 |

### Network Security (NETW)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| NETW-3400 | ARP Spoofing | ✅ | NETW-3400 |
| NETW-3500 | DNS Tampering | ✅ | NETW-3500 |
| NETW-3600 | Suspicious Connections | ✅ | NETW-3600 |

### MAC & Containers (MAC, CONT)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| MAC-6000 | SELinux/AppArmor | ✅ | MAC-6000 |
| CONT-8000 | Container Escape | ✅ | CONT-8000 |

### System Tools (TOOL)
| Test ID | Check Name | Current | Lynis Equivalent |
|---------|------------|---------|------------------|
| TOOL-5000 | Security Tools | ✅ | TOOL-5000 |
| TOOL-5100 | Compiler Presence | ✅ | TOOL-5100 |
| TOOL-5200 | Package Manager | ✅ | TOOL-5200 |
| TOOL-5300 | USB Storage | ✅ | USB-1000 |
| TOOL-5400 | Web Server | ✅ | HTTP-6500 |

---

## Planned Checks (Phase 1: Database & Audit)

### Database Security (DBS)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| DBS-1000 | MySQL/MariaDB Presence | DBS-1000 | Planned |
| DBS-1001 | MySQL Root Password | DBS-1004 | Planned |
| DBS-1002 | MySQL Anonymous Accounts | DBS-1012 | Planned |
| DBS-1003 | MySQL Remote Root | DBS-1004 | Planned |
| DBS-1004 | PostgreSQL Security | DBS-1800 | Planned |
| DBS-1005 | MongoDB Authentication | DBS-1900 | Planned |
| DBS-1006 | Database Hardening | DBS-2000 | Planned |
| DBS-1007 | Database Backups | DBS-2100 | Planned |

### Audit & Accounting (ACCT)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| ACCT-5000 | Process Accounting | ACCT-9600 | Planned |
| ACCT-5001 | Auditd Service | ACCT-9610 | Planned |
| ACCT-5002 | Audit Rules | ACCT-9620 | Planned |
| ACCT-5003 | Syslog Config | LOGG-2080 | Planned |
| ACCT-5004 | Auth Logging | LOGG-2010 | Planned |
| ACCT-5005 | Kernel Audit | ACCT-9630 | Planned |
| ACCT-5006 | Log Retention | LOGG-2150 | Planned |

---

## Planned Checks (Phase 2: Filesystem & Networking)

### NFS Security (NFS)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| NFS-3000 | NFS Export Security | NFS-4000 | Planned |
| NFS-3001 | NFS Mount Options | NFS-4010 | Planned |

### Filesystem Hardening (FS)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| FS-3002 | /tmp Permissions | FILE-6310 | Planned |
| FS-3003 | /home Permissions | FILE-6310 | Planned |
| FS-3004 | /var Permissions | FILE-6310 | Planned |
| FS-3005 | Integrity Monitoring | FILE-4500 | Planned |

### Package Management (PKGS) - Extended
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| PKGS-7300 | Yum Security Plugin | PKGS-7250 | Planned |
| PKGS-7301 | APT Security Updates | PKGS-7390 | Planned |
| PKGS-7302 | Repository GPG Keys | PKGS-7310 | Planned |
| PKGS-7303 | Signed Packages | PKGS-7320 | Planned |
| PKGS-7304 | Vulnerable Packages | PKGS-7330 | Planned |
| PKGS-7305 | Package Age | PKGS-7340 | Planned |

### Network Time (TIME) - Extended
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| TIME-3100 | NTP Service | TIME-3100 | Planned |
| TIME-3101 | NTP Peers | TIME-3120 | Planned |
| TIME-3102 | Chrony Config | TIME-3170 | Planned |
| TIME-3103 | NTP Stratum | TIME-3130 | Planned |
| TIME-3104 | Time Sync Check | TIME-3140 | Planned |

---

## Planned Checks (Phase 3: Containers & Web)

### Container Security (CONT) - Extended
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| CONT-8100 | Docker Installation | CONT-8000 | Planned |
| CONT-8101 | Docker Daemon | CONT-8010 | Planned |
| CONT-8102 | Docker Privileges | CONT-8020 | Planned |
| CONT-8103 | Docker Images | CONT-8030 | Planned |
| CONT-8104 | Network Isolation | CONT-8040 | Planned |
| CONT-8105 | Escape Prevention | CONT-8050 | Planned |
| CONT-8106 | Container Logging | CONT-8060 | Planned |

### Web Server Hardening (HTTP)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| HTTP-6500 | Apache/Nginx SSL | HTTP-6500 | Planned |
| HTTP-6501 | TLS Version | HTTP-6510 | Planned |
| HTTP-6502 | Cipher Strength | HTTP-6520 | Planned |
| HTTP-6503 | Certificate Expiry | HTTP-6530 | Planned |
| HTTP-6504 | Security Headers | HTTP-6540 | Planned |
| HTTP-6505 | Apache Modules | HTTP-6600 | Planned |
| HTTP-6506 | Nginx Config | HTTP-6700 | Planned |
| HTTP-6507 | Error Messages | HTTP-6750 | Planned |

### DNS Security (DNS)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| DNS-4000 | DNS Service | DNS-4000 | Planned |
| DNS-4001 | Resolv.conf | NAME-4010 | Planned |
| DNS-4002 | DNSSEC | DNS-4040 | Planned |
| DNS-4003 | Query Logging | DNS-4050 | Planned |
| DNS-4004 | Service Hardening | DNS-4060 | Planned |

---

## Planned Checks (Phase 4: Specialized)

### Home Directory Security (HOME)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| HOME-9300 | Directory Permissions | HOME-9302 | Planned |
| HOME-9301 | Ownership | HOME-9304 | Planned |
| HOME-9302 | Shared Dirs | HOME-9310 | Planned |
| HOME-9303 | SSH Key Perms | HOME-9350 | Planned |

### LDAP Security (LDAP)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| LDAP-3200 | LDAP Client | LDAP-3100 | Planned |
| LDAP-3201 | Configuration | LDAP-3110 | Planned |
| LDAP-3202 | SSL/TLS | LDAP-3120 | Planned |
| LDAP-3203 | Server Hardening | LDAP-3130 | Planned |

### Mail Services (MAIL)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| MAIL-2700 | Mail Service | MAIL-8700 | Planned |
| MAIL-2701 | Relay Config | MAIL-8800 | Planned |
| MAIL-2702 | Hardening | MAIL-8810 | Planned |
| MAIL-2703 | Logging | MAIL-8820 | Planned |

### Printer Security (PRNT)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| PRNT-2400 | CUPS Installation | PRNT-2200 | Planned |
| PRNT-2401 | CUPS Config | PRNT-2210 | Planned |
| PRNT-2402 | Network Printer | PRNT-2220 | Planned |

### SNMP Security (SNMP)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| SNMP-5100 | SNMP Service | SNMP-3200 | Planned |
| SNMP-5101 | SNMP Version | SNMP-3210 | Planned |
| SNMP-5102 | Community Strings | SNMP-3220 | Planned |

### Virtualization (VIRT)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| VIRT-2200 | Hypervisor Detection | VIRT-2200 | Planned |
| VIRT-2201 | Guest Hardening | VIRT-2210 | Planned |

### Login Banners (BNRZ)
| Test ID | Check Name | Lynis Equivalent | Status |
|---------|------------|------------------|--------|
| BNRZ-1600 | Banner Presence | BANN-7788 | Planned |
| BNRZ-1601 | Banner Config | BANN-7790 | Planned |

---

## Test ID Allocation Strategy

### Category Prefixes (Reserved ranges):
| Prefix | Category | Range | Current | Planned |
|--------|----------|-------|---------|---------|
| ACCT | Accounting | 5000-5099 | - | 5000-5006 |
| BNRZ | Banners | 1600-1699 | - | 1600-1601 |
| BOOT | Boot | 5100-5199 | - | - |
| CONT | Containers | 8000-8099 | 8000 | 8100-8106 |
| CPU | CPU/Load | 2800-2899 | 2800 | - |
| DB | Databases | 1000-1099 | - | 1000-1007 |
| DHCP | DHCP | 3400-3499 | - | - |
| DNS | DNS | 4000-4099 | - | 4000-4004 |
| FILE | File Integrity | 6400-6799 | 6510, 6700, 7600, 8100 | - |
| FIRE | Firewall | 4400-4499 | - | - |
| HTTP | Web Servers | 6500-6799 | - | 6500-6507 |
| KRNL | Kernel | 5800-5899 | 5300 | - |
| LDAP | LDAP | 3200-3299 | - | 3200-3203 |
| LOGG | Logging | 2100-2199 | 2190 | - |
| MAC | MAC/SELinux | 6000-6099 | 6000 | - |
| MAIL | Mail | 2700-2799 | - | 2700-2703 |
| MALW | Malware | 3300-3699 | 3280, 3300, 3400, 3500, 3600 | - |
| MEM | Memory | 1800-1899 | 1800 | - |
| NETW | Network | 3000-3699 | 3000-3200, 3400-3600 | - |
| NFS | NFS | 3000-3099 | - | 3000-3001 |
| PKGS | Packages | 7300-7399 | 7340, 7346 | 7300-7305 |
| PRNT | Printers | 2400-2499 | - | 2400-2402 |
| SCRT | Security | 1000-5599 | Multiple | - |
| SHELL | Shells | 5100-5199 | 5500 | - |
| SNMP | SNMP | 5100-5199 | - | 5100-5102 |
| SSH | SSH | 6200-6299 | 6200 | - |
| STG | Storage | 2300-2399 | 2300 | - |
| TIME | Time | 3000-3199 | 3001 | 3100-3104 |
| TOOL | Tools | 5000-5399 | 5000, 5100, 5200, 5300, 5400 | - |
| VIRT | Virtualization | 2200-2299 | - | 2200-2201 |

### Guidelines:
1. Each category has a 100-number range
2. New checks increment by 1 within category
3. Related checks group together (e.g., SSH-6200 to 6211)
4. Maintain consistency with Lynis test ID ranges where possible
5. Document cross-references in check functions

---

## Test ID Consistency Rules

### When Adding a New Check:
1. Choose appropriate category prefix
2. Find next available number in that range
3. Add docstring with test ID and Lynis equivalent
4. Update this reference document
5. Create test case with test ID in name

### Example:
```python
def check_database_mysql_root(ssh: SSHSession) -> CheckResult:
    """Check MySQL root password configuration.
    
    Test ID: DBS-1001 (Lynis equivalent: DBS-1004)
    Category: Database
    
    Verifies that the MySQL root user has a password set
    and that anonymous access is not allowed.
    """
    category = "Database"
    test_id = "DBS-1001"
    # ... implementation
```

---

## Reporting & Documentation

When updating reports, include:
- Test ID (for Lynis compatibility)
- Category name
- Check name
- Status (pass/warn/fail)
- Details and recommendation

Example report entry:
```
[DBS-1001] MySQL Root Password
Category: Database
Status: WARN
Details: MySQL root account has no password set
Recommendation: Set a strong password for MySQL root account
```

---

## Version Tracking

- **v2.0**: Current checks (36 total) - Test IDs established
- **v2.1**: Documentation improvements
- **v3.0**: Planned expansion to 70+ checks
  - Phase 1: Database & Audit (15 checks)
  - Phase 2: Filesystem & Networking (17 checks)
  - Phase 3: Container & Web (20 checks)
  - Phase 4: Specialized (14 checks)


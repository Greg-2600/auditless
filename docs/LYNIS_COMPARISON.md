# Auditless vs Lynis: Feature Comparison & Roadmap

## Overview

This document compares Auditless security scanner with Lynis (CISOfy's security auditing tool). Both are agentless SSH-based Linux security assessment tools, but serve different purposes and have different feature sets.

## Architecture Comparison

| Aspect | Auditless | Lynis |
|--------|---|---|
| **Language** | Python 3.11+ | Bash/Shell |
| **Execution Model** | SSH-based (remote) | Local + SSH-based |
| **Test Categories** | ~35 checks | 500+ individual tests |
| **Test Organization** | Single category per check | 42 test modules + subcategories |
| **Output Formats** | Text, Markdown, JSON | Text, JSON, HTML (Enterprise) |
| **License** | Open Source | GPLv3 (Enterprise: Commercial) |
| **Plugin System** | Built-in module approach | Explicit plugin system |

## Auditless Current Categories (36 checks)

**Storage & Performance:**
- Disk Usage (Storage)
- Memory Usage (Memory)
- Load Average (CPU/Load)
- Process Resource Usage (Process Health)

**System Updates & Patching:**
- Reboot Required (Patching)
- Available Updates (Patching)

**Network & Services:**
- SSH Configuration (SSH) - 12+ individual checks
- Firewall Status (Network)
- Listening Services (Network)
- Abnormal Network Processes (Network)
- Suspicious Network Connections (Network Security)
- Legacy Services (Network Security)

**User & Authentication:**
- Active User Accounts (Accounts)
- Stale User Accounts (Accounts)
- Authentication Failures (Auth)
- Root Logins (Auth)
- Weak Password Policy (Authentication)
- Failed Login Spike (Authentication)

**File & System Integrity:**
- SUID Files (Filesystem)
- World-Writable Files (File Permissions)
- Critical File Permissions (File Integrity)
- File Integrity Tools (System Integrity)
- System Binary Modifications (File Integrity)
- Filesystem Mounts (File System)
- Deleted File Handles (Malware/Backdoors)

**Security & Hardening:**
- Boot Loader Password (Boot/Kernel)
- Kernel Hardening Parameters (Boot/Kernel)
- SELinux/AppArmor Status (MAC Security)
- Kernel Module Integrity (Kernel Security)
- Container Escape Indicators (Container Security)

**Logging & Auditing:**
- Time Synchronization (Time)
- Logging and Auditing (Logging & Auditing)

**Threat Detection:**
- Cron and Timers (Persistence)
- Recently Created Accounts (Account Integrity)
- Suspicious Process Locations (Process Integrity)
- Unexpected Sudo Usage (Privilege Escalation)
- Privilege Escalation Vectors (Privilege Escalation)
- Hidden Files in System Dirs (Malware/Backdoors)
- Reverse Shell Detection (Malware/Backdoors)
- ARP Spoofing (Network Security)
- DNS Tampering (Network Security)
- Crypto Miners (Malware/Backdoors)
- Log Tampering (Log Security)

**System Tools & Services:**
- Security Tools (Security Tools)
- Compiler Presence (System Tools)
- Package Manager Security (Package Management)
- USB Storage Disabled (Hardware Security)
- Web Server Security (Web Server)

---

## Lynis Test Modules (42 categories)

Lynis organizes tests into 42 distinct modules:

### Account Management (3)
- **accounting** - Process accounting, audit logs, job accounting
- **authentication** - Login attempts, password policies, 2FA, PAM
- **homedirs** - Home directory permissions, integrity, stale accounts

### Boot & Kernel (3)
- **boot_services** - Boot loader configuration, secure boot, service managers
- **kernel** - Kernel version, loaded modules, security patches
- **kernel_hardening** - Kernel parameters (ASLR, DEP, SYN cookies, etc.)

### System Integrity (5)
- **file_integrity** - File integrity monitoring tools (AIDE, Samhain, Tripwire)
- **file_permissions** - File permission security checks
- **hardening** - General hardening practices and recommendations
- **mac_frameworks** - SELinux, AppArmor, TOMOYO configurations
- **system_integrity** - Miscellaneous integrity checks

### Networking (10)
- **dns** - DNS configuration, DNSSEC, resolver security
- **firewalls** - iptables, firewalld, pf configuration
- **insecure_services** - Rsh, telnet, NFS exports, NIS
- **mail_messaging** - Exim, Postfix, mail relay configuration
- **nameservices** - DNS, NIS, LDAP, bind configuration
- **networking** - Network configuration, IPv6, IP forwarding
- **snmp** - SNMP configuration and community strings
- **ssh** - Extensive SSH security hardening
- **squid** - Squid proxy configuration
- **webservers** - Apache, Nginx configuration security

### Storage & Filesystems (4)
- **containers** - Docker, Solaris zones, container security
- **filesystems** - Mount points (/tmp, /home, /var), filesystem options
- **storage** - USB storage, Firewire, device security
- **storage_nfs** - NFS-specific security checks

### Services & Processes (12)
- **databases** - MySQL, PostgreSQL, Oracle, MongoDB security
- **kerberos** - Kerberos authentication configuration
- **ldap** - LDAP client and server configuration
- **memory_processes** - Memory usage, process monitoring
- **php** - PHP configuration security
- **ports_packages** - Package management, vulnerable packages
- **printers_spoolers** - CUPS, printer configuration
- **scheduling** - Cron jobs, at jobs, systemd timers
- **shells** - Shell security, ~/.bashrc, ~/.profile
- **time** - NTP configuration, chrony, openntpd
- **tooling** - Security tools (Ansible, Puppet), automation
- **virtualization** - VM detection, Xen, KVM, VirtualBox

### Security & Threats (4)
- **banners** - Login banners, /etc/issue
- **crypto** - Cryptographic settings, SSL/TLS configuration
- **malware** - Antivirus tools, rootkit detection
- **usb** - USB device management, USBGuard

---

## Feature Parity Analysis

### ✅ Good Coverage (Auditless has good equivalents)

| Feature | Auditless | Lynis |
|---------|---|---|
| SSH Security | ✅ 12+ checks | ✅ Comprehensive |
| Authentication | ✅ Password policy, failures | ✅ Full PAM, 2FA, policies |
| File Integrity | ✅ Basic (SUID, permissions) | ✅ Monitoring tools + permissions |
| Kernel Hardening | ✅ Parameter checks | ✅ Detailed parameter matrix |
| Firewall | ✅ Basic status | ✅ Deep iptables/firewalld |
| System Integrity | ✅ Binary modifications | ✅ AIDE, Samhain, Tripwire |
| Malware Detection | ✅ Crypto miners, reverse shells | ✅ Antivirus, rootkit tools |
| Network Security | ✅ ARP, DNS tampering | ✅ Service-specific hardening |

### 🔶 Partial Coverage (Auditless has gaps)

| Feature | Auditless | Lynis |
|---------|---|---|
| Filesystem Hardening | ⚠️ Mount options only | ✅ Mount options + FHS checks |
| Container Security | ⚠️ Escape indicators | ✅ Docker, Solaris zones |
| Package Management | ⚠️ Security tool check | ✅ Vulnerable packages, repos |
| Database Security | ❌ None | ✅ MySQL, PostgreSQL, Oracle |
| NFS Security | ❌ None | ✅ Dedicated NFS module |
| LDAP Security | ❌ None | ✅ Full LDAP checks |
| Mail Services | ❌ None | ✅ Postfix, Exim security |
| Web Server Security | ⚠️ Basic checks | ✅ Apache/Nginx deep analysis |

### ❌ Missing Features (Auditless gaps)

| Category | Lynis Features | Auditless |
|----------|---|---|
| **Accounting** | Process/job accounting, audit logs | ❌ Missing |
| **Home Directories** | User home dir permissions/integrity | ⚠️ Only stale account detection |
| **Crypto** | SSL/TLS certificate security | ❌ Missing |
| **Time Services** | NTP (ntpd, chrony, openntpd) | ⚠️ Basic time sync only |
| **DNS Security** | Resolver security, DNSSEC | ⚠️ DNS tampering detection only |
| **Insecure Services** | Legacy services (rsh, telnet) | ⚠️ In legacy services check |
| **SNMP** | SNMP configuration security | ❌ Missing |
| **Squid Proxy** | Proxy configuration | ❌ Missing |
| **Printer Security** | CUPS, printer configuration | ❌ Missing |
| **PHP Security** | PHP configuration checks | ❌ Missing |
| **Kerberos** | Kerberos authentication | ❌ Missing |
| **Banners** | Login banners (/etc/issue) | ❌ Missing |
| **Virtualization** | VM detection and configuration | ❌ Missing |

---

## Recommendations for Feature Parity

### Priority 1: High-Value Additions (would significantly improve coverage)

1. **Database Security Module** (DATABASE)
   - MySQL: root password, authentication, log settings
   - PostgreSQL: password policies, SSL, role configuration
   - MongoDB: authentication, encryption, network binding
   - Oracle: account security, audit settings
   - Estimated: 8-12 new checks

2. **Accounting & Auditing Module** (AUDIT)
   - Process accounting status
   - Audit framework (auditd) configuration
   - Audit rule review
   - Syslog/rsyslog security
   - Estimated: 6-8 new checks

3. **NFS & Filesystem Security** (NFS, FILESYSTEMS)
   - NFS export security (/etc/exports)
   - Mount options validation
   - Filesystem-specific hardening
   - Estimated: 6-8 new checks

4. **Package Management** (PACKAGES)
   - Vulnerable package scanning
   - Repository security (GPG keys, signed packages)
   - Yum/apt plugin security
   - Estimated: 6-8 new checks

5. **Network Time Security** (TIME)
   - NTP daemon configuration (ntpd, chrony, openntpd)
   - Time source validation
   - Estimated: 4-6 new checks

### Priority 2: Medium-Value Additions (improves specific use cases)

6. **Home Directory Security** (HOMEDIRS)
   - User home directory permissions (750+)
   - Shared directory detection
   - Estimated: 4-5 new checks

7. **Container Security** (CONTAINERS)
   - Docker daemon security
   - Container image scanning
   - Seccomp, AppArmor profiles
   - Estimated: 6-8 new checks

8. **Web Server Hardening** (WEBSERVERS)
   - Apache/Nginx SSL configuration
   - HTTP security headers
   - Module security
   - Estimated: 6-8 new checks

9. **DNS Security** (DNS)
   - DNSSEC validation
   - Resolver (/etc/resolv.conf) security
   - DNS service hardening
   - Estimated: 4-5 new checks

10. **Login Banners** (BANNERS)
    - /etc/issue, /etc/issue.net validation
    - Banner compliance checks
    - Estimated: 2-3 new checks

### Priority 3: Optional Additions (niche but valuable)

11. **LDAP Security** (LDAP)
    - LDAP client configuration
    - LDAP server hardening
    - Estimated: 4-5 new checks

12. **Mail Services** (MAIL)
    - Postfix/Exim configuration
    - Mail relay security
    - Estimated: 4-5 new checks

13. **Printer Security** (PRINTERS)
    - CUPS configuration
    - Network printer security
    - Estimated: 3-4 new checks

14. **SNMP Security** (SNMP)
    - SNMP v3 vs v2c
    - Community string security
    - Estimated: 2-3 new checks

15. **Virtualization Detection** (VIRTUALIZATION)
    - Hypervisor detection (Xen, KVM, VirtualBox)
    - Guest OS detection
    - Estimated: 2-3 new checks

---

## Implementation Strategy

### Phase 1: Quick Wins (Est. 15-20 new checks)
1. Implement Database Security Module (Priority 1.1)
2. Implement Accounting Module (Priority 1.2)
3. Add NFS/Filesystem checks (Priority 1.3)

### Phase 2: Core Hardening (Est. 15-20 new checks)
4. Package Management Module (Priority 1.4)
5. Network Time Hardening (Priority 1.5)
6. Home Directory Security (Priority 2.1)

### Phase 3: Advanced Features (Est. 15-20 new checks)
7. Container Security (Priority 2.2)
8. Web Server Hardening (Priority 2.3)
9. DNS Security (Priority 2.4)

### Phase 4: Polish & Niche Features (Est. 10-15 new checks)
10. LDAP, Mail, Printers, SNMP, Virtualization
11. Login Banners

---

## Testing Standards

When implementing new checks, follow Auditless's established patterns:

### Check Implementation Checklist
- [ ] Function signature: `def check_xxx(ssh: SSHSession, password: str = "") -> CheckResult`
- [ ] Type hints for all parameters and return values
- [ ] Google-style docstring with description
- [ ] Category name in uppercase (e.g., "Database", "Networking")
- [ ] Test ID in Lynis-style format (e.g., "DBS-1000", "AUDIT-5000")
- [ ] Comprehensive error handling
- [ ] Timeout management using `_run()` helper
- [ ] Proper status returns: "pass", "warn", "fail"
- [ ] Detailed recommendation text

### Test Coverage Requirements
- [ ] Unit tests for all pass/warn/fail scenarios
- [ ] Mock SSH responses for all test cases
- [ ] Error handling tests
- [ ] Coverage maintained at >70%

### Code Quality Requirements
- [ ] Pass Black formatter: `black auditless/ tests/`
- [ ] Pass Ruff linter: `ruff check auditless/ tests/`
- [ ] All type hints in place
- [ ] No unused imports
- [ ] Comprehensive docstrings

---

## Comparison Metrics

### Coverage Comparison

```
Auditless:     36 checks across 20 categories
Lynis:            500+ checks across 42 modules

Potential Auditless v2.0: ~70-80 checks across 30+ categories
```

### Feature Prioritization

When deciding which Lynis features to implement in Auditless:

1. **Impact**: How many systems would this check help secure?
2. **Complexity**: How difficult is it to implement correctly?
3. **Reliability**: Can it be implemented without false positives?
4. **Scope**: Does it fit Auditless's mission as an agentless SSH scanner?

### Technology Alignment

Focus on checks that:
- Can be performed remotely via SSH (no local agent required)
- Don't require interactive command execution
- Work across multiple Linux distributions
- Have clear pass/warn/fail criteria
- Provide actionable recommendations

---

## Notes

- Lynis uses shell script plugins for extensibility; Auditless uses Python modules
- Lynis tests multiple compliance frameworks (CIS, PCI-DSS, HIPAA, ISO27001); Auditless focuses on security hardening
- Lynis has extensive manual test support; Auditless is fully automated
- Auditless's SSH-based approach is more suitable for CI/CD integration and remote scanning
- Consider creating a "Lynis-Compatible" mode in future versions for users wanting feature parity


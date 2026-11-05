# Linux Health v3.0 Roadmap: Lynis Feature Parity

> **Historical — superseded by [`ROADMAP.md`](../ROADMAP.md).**
> Kept as the v3.0 Lynis-parity design record; its DB/audit/filesystem/
> packages/container/web/DNS modules have largely shipped. For current
> naming, see [`NAMING.md`](NAMING.md).

## Executive Summary

This roadmap outlines how to expand Linux Health from 36 checks to 70+ checks with 30+ test categories, bringing it closer to Lynis feature parity while maintaining its SSH-based simplicity and Python implementation.

**Estimated Implementation Time:** 4-6 months for full roadmap  
**Estimated New Checks:** 35-45 new checks  
**Risk Level:** Low (follows proven Lynis patterns, leverages existing infrastructure)

---

## Phase 1: Database & Accounting (Weeks 1-3)

### 1.1 Database Security Module (8 checks)

**File:** `linux_health/checks_database.py` (new)

```
DBS-1000: MySQL/MariaDB Presence
  - Check if MySQL/MariaDB is installed and running
  - Detect version information
  - Status: PASS/WARN/FAIL

DBS-1001: MySQL Root Password
  - Verify root account has password set
  - Check for empty passwords
  - Status: FAIL if no password

DBS-1002: MySQL Anonymous Accounts
  - Detect anonymous user accounts
  - Check database privileges
  - Status: WARN if anonymous access exists

DBS-1003: MySQL Remote Root Access
  - Check if root can connect remotely
  - Verify bind address configuration
  - Status: WARN if remote root possible

DBS-1004: PostgreSQL Configuration
  - Check pg_hba.conf security
  - Verify authentication methods
  - Status: WARN for weak authentication

DBS-1005: MongoDB Authentication
  - Check if authentication is enabled
  - Verify user roles configuration
  - Status: FAIL if no auth

DBS-1006: Database Service Hardening
  - Check for security best practices
  - Verify database logs enabled
  - Status: WARN for missing hardening

DBS-1007: Database Backup Configuration
  - Check if backups are configured
  - Verify backup encryption
  - Status: WARN if no backups
```

**Implementation Notes:**
- Use query commands (mysql -u root -e "SELECT user, host FROM mysql.user;")
- Parse PostgreSQL pg_hba.conf
- Check MongoDB authorization mode
- Cache database connection status

**Testing:**
- Mock successful/failed database connections
- Test with/without auth configured
- Test remote vs local bindings

---

### 1.2 Accounting & Auditing Module (7 checks)

**File:** `linux_health/checks_audit.py` (new)

```
AUDIT-5000: Process Accounting Status
  - Check if process accounting is enabled
  - Verify accounting logs exist
  - Status: WARN if disabled

AUDIT-5001: Auditd Service
  - Check if auditd daemon is running
  - Verify audit framework enabled
  - Status: WARN if not running

AUDIT-5002: Audit Rules Configuration
  - Check if audit rules are loaded
  - Count rules for system calls
  - Status: WARN for minimal rules

AUDIT-5003: Syslog Configuration
  - Verify rsyslog or syslog-ng running
  - Check log rotation configuration
  - Status: WARN if not configured

AUDIT-5004: Auth Logging
  - Check auth.log rotation
  - Verify login attempt logging
  - Status: WARN for missing logs

AUDIT-5005: Kernel Audit Status
  - Check audit=1 kernel parameter
  - Verify immutable flag status
  - Status: WARN if audit disabled

AUDIT-5006: Log Retention Policy
  - Check log retention settings
  - Verify disk space allocation
  - Status: WARN for short retention
```

**Implementation Notes:**
- Check `/proc/sys/kernel/audit_enabled`
- Parse `/etc/audit/audit.rules`
- Check rsyslog config in `/etc/rsyslog.conf` and `/etc/rsyslog.d/`
- Verify systemd-journald configuration

**Testing:**
- Mock auditd running/stopped
- Parse various audit rule configurations
- Test rsyslog configurations

---

## Phase 2: Filesystem & Networking (Weeks 4-6)

### 2.1 NFS & Filesystem Hardening (6 checks)

**File:** `linux_health/checks_filesystem.py` (extend existing)

```
NFS-3000: NFS Export Security
  - Parse /etc/exports
  - Check for world-readable exports
  - Status: FAIL for insecure exports

NFS-3001: NFS Mount Options
  - Check nosuid, nodev, noexec
  - Verify mount permissions
  - Status: WARN for weak options

FS-3002: Filesystem Permissions (/tmp)
  - Verify /tmp is separate filesystem
  - Check mount options (nodev, nosuid, noexec)
  - Status: WARN for missing options

FS-3003: Filesystem Permissions (/home)
  - Verify /home separate from /
  - Check mount options
  - Status: WARN if not separated

FS-3004: Filesystem Permissions (/var)
  - Verify /var separate from /
  - Check mount options
  - Status: WARN if not separated

FS-3005: Filesystem Integrity Monitoring
  - Check if AIDE/Samhain configured
  - Verify regular integrity checks
  - Status: WARN if none configured
```

**Implementation Notes:**
- Parse `/etc/exports` for NFS exports
- Check `/etc/fstab` for mount options
- Use `mount` command to verify current mounts
- Check cron jobs for integrity monitoring

**Testing:**
- Mock various /etc/exports scenarios
- Test different mount option combinations
- Verify parsing of /etc/fstab

---

### 2.2 Package Management Security (6 checks)

**File:** `linux_health/checks_packages.py` (extend existing)

```
PKGS-7300: Yum Security Plugin
  - Check if yum security plugin installed
  - Verify it's enabled
  - Status: WARN if not installed

PKGS-7301: APT Security Updates
  - Check if unattended-upgrades installed
  - Verify security updates enabled
  - Status: WARN if not configured

PKGS-7302: Repository GPG Keys
  - Check if repository keys are valid
  - Verify key signatures
  - Status: WARN for missing keys

PKGS-7303: Signed Packages
  - Verify packages are GPG signed
  - Check signature verification
  - Status: WARN for unsigned packages

PKGS-7304: Vulnerable Packages
  - Scan for known CVEs
  - Cross-reference with distro advisories
  - Status: FAIL for critical CVEs

PKGS-7305: Package Update Status
  - Check age of package cache
  - Verify security updates available
  - Status: WARN for stale packages
```

**Implementation Notes:**
- Parse yum/dnf configuration
- Check apt configuration
- Verify GPG key existence and validity
- Use package manager security features

**Testing:**
- Mock yum/apt configurations
- Test with various GPG key states
- Verify package update detection

---

### 2.3 Network Time Hardening (5 checks)

**File:** `linux_health/checks_time.py` (extend existing)

```
TIME-3100: NTP Service Configuration
  - Check if NTP daemon running
  - Detect ntpd, chrony, or openntpd
  - Status: WARN if none running

TIME-3101: NTP Peer Configuration
  - Verify NTP servers configured
  - Check peer authentication
  - Status: WARN for unconfigured NTP

TIME-3102: Chrony Configuration
  - Parse chrony.conf
  - Verify NTP sources
  - Status: WARN for weak config

TIME-3103: NTP Stratum
  - Check NTP stratum level
  - Verify time source quality
  - Status: WARN for high stratum

TIME-3104: Time Synchronization
  - Verify time drift is acceptable
  - Check frequency of updates
  - Status: WARN for high drift
```

**Implementation Notes:**
- Check for `/etc/ntp.conf`, `/etc/chrony.conf`, `/etc/openntpd/ntpd.conf`
- Use `timedatectl` for systemd systems
- Check `ntpq -p` output for peer status
- Verify `ntpstat` shows synchronized

**Testing:**
- Mock different NTP daemon scenarios
- Test chrony vs ntpd detection
- Verify time drift calculation

---

## Phase 3: Container & Web Security (Weeks 7-9)

### 3.1 Container Security (7 checks)

**File:** `linux_health/checks_containers.py` (new)

```
CONT-8100: Docker Installation
  - Check if Docker is installed
  - Detect Docker version
  - Status: INFO if installed

CONT-8101: Docker Daemon Security
  - Check docker daemon socket permissions
  - Verify TLS configuration
  - Status: WARN for insecure socket

CONT-8102: Docker User Privileges
  - Check docker group membership
  - Verify non-root execution
  - Status: WARN if root access

CONT-8103: Docker Image Security
  - Check for signed images
  - Verify image sources
  - Status: WARN for unsigned images

CONT-8104: Docker Network Isolation
  - Check for bridge network isolation
  - Verify seccomp profiles
  - Status: WARN for weak isolation

CONT-8105: Container Escape Prevention
  - Check for AppArmor/SELinux profiles
  - Verify kernel capabilities dropped
  - Status: WARN for missing protections

CONT-8106: Container Logging
  - Verify container logs are collected
  - Check logging configuration
  - Status: WARN for missing logs
```

**Implementation Notes:**
- Check Docker installation: `which docker`
- Verify daemon socket: `ls -l /var/run/docker.sock`
- Parse Docker daemon config: `/etc/docker/daemon.json`
- Check running containers with `docker ps`

**Testing:**
- Mock Docker installed/not installed scenarios
- Test various Docker socket permissions
- Verify daemon configuration parsing

---

### 3.2 Web Server Hardening (8 checks)

**File:** `linux_health/checks_webservers.py` (extend existing)

```
HTTP-6500: Apache/Nginx SSL Configuration
  - Check if SSL/TLS is configured
  - Verify certificate validity
  - Status: FAIL for missing SSL

HTTP-6501: SSL/TLS Version
  - Check minimum TLS version
  - Detect old/weak protocols
  - Status: FAIL for SSLv3/TLS1.0

HTTP-6502: SSL Cipher Strength
  - Analyze cipher configuration
  - Check for weak ciphers
  - Status: WARN for weak ciphers

HTTP-6503: Certificate Expiration
  - Check certificate expiration date
  - Alert for upcoming expiration
  - Status: WARN if <30 days

HTTP-6504: HTTP Headers Security
  - Check for security headers
  - Verify HSTS, CSP, X-Frame-Options
  - Status: WARN for missing headers

HTTP-6505: Apache Module Security
  - Check for dangerous modules
  - Verify secure module list
  - Status: WARN for risky modules

HTTP-6506: Nginx FastCGI Security
  - Check FastCGI configuration
  - Verify PHP-FPM socket security
  - Status: WARN for insecure config

HTTP-6507: Web Server Error Messages
  - Check for information disclosure
  - Verify error page customization
  - Status: WARN for verbose errors
```

**Implementation Notes:**
- Parse Apache config: `/etc/apache2/apache2.conf`, `/etc/apache2/sites-enabled/`
- Parse Nginx config: `/etc/nginx/nginx.conf`, `/etc/nginx/sites-enabled/`
- Use `openssl s_client` to check SSL configuration
- Verify certificate with `openssl x509`

**Testing:**
- Mock Apache/Nginx configurations
- Test various SSL/TLS configurations
- Verify certificate parsing

---

### 3.3 DNS Security (5 checks)

**File:** `linux_health/checks_dns.py` (new)

```
DNS-4000: DNS Service Status
  - Check if DNS resolver is working
  - Detect systemd-resolved or bind
  - Status: WARN if no resolver

DNS-4001: /etc/resolv.conf Security
  - Check resolver configuration
  - Verify secure nameservers
  - Status: WARN for localhost only

DNS-4002: DNSSEC Validation
  - Check if DNSSEC is enabled
  - Verify validation status
  - Status: WARN if not enabled

DNS-4003: DNS Query Logging
  - Verify DNS queries are logged
  - Check query log retention
  - Status: WARN for missing logs

DNS-4004: DNS Service Hardening
  - Check bind/dnsmasq security
  - Verify access controls
  - Status: WARN for weak config
```

**Implementation Notes:**
- Check `/etc/resolv.conf` content
- Verify `systemd-resolved` status with `resolvectl`
- Check bind9 config: `/etc/bind/named.conf`
- Test DNS resolution with `nslookup` or `dig`

**Testing:**
- Mock various resolv.conf configurations
- Test DNS service detection
- Verify DNSSEC status

---

## Phase 4: Specialized Modules (Weeks 10-12)

### 4.1 Home Directory Security (4 checks)

**File:** `linux_health/checks_homedirs.py` (new)

```
HOME-9300: Home Directory Permissions
  - Check user home directory permissions
  - Verify 700 or 750 permissions
  - Status: WARN for world-readable

HOME-9301: Home Directory Ownership
  - Verify correct user ownership
  - Check for mismatched ownership
  - Status: WARN for incorrect owner

HOME-9302: Shared Home Directories
  - Detect shared home directories
  - Check for group-writable homes
  - Status: WARN if shared

HOME-9303: SSH Key Permissions
  - Check ~/.ssh directory permissions
  - Verify authorized_keys security
  - Status: WARN for insecure perms
```

**Implementation Notes:**
- Parse `/etc/passwd` for home directories
- Use `stat` command to check permissions
- Check all user home directories
- Verify SSH key files permissions

**Testing:**
- Mock various permission scenarios
- Test with different ownership configurations
- Verify symlink handling

---

### 4.2 LDAP Security (4 checks)

**File:** `linux_health/checks_ldap.py` (new)

```
LDAP-3200: LDAP Client Installation
  - Check if LDAP client is installed
  - Detect nss-ldap or sssd
  - Status: INFO if installed

LDAP-3201: LDAP Configuration
  - Check /etc/ldap.conf or /etc/nslcd.conf
  - Verify LDAP servers configured
  - Status: WARN if misconfigured

LDAP-3202: LDAP SSL/TLS
  - Check if LDAP uses TLS/SSL
  - Verify certificate validation
  - Status: WARN if unencrypted

LDAP-3203: LDAP Server Hardening
  - Check LDAP directory permissions
  - Verify access controls
  - Status: WARN for weak config
```

**Implementation Notes:**
- Check `/etc/ldap.conf` and `/etc/ldap/ldap.conf`
- Check `/etc/nslcd.conf` for nslcd
- Verify LDAP service status
- Test LDAP connectivity if configured

**Testing:**
- Mock LDAP configurations
- Test with/without TLS
- Verify configuration parsing

---

### 4.3 Mail Services (4 checks)

**File:** `linux_health/checks_mail.py` (new)

```
MAIL-2700: Mail Service Installation
  - Detect Postfix, Exim, Sendmail
  - Check mail service status
  - Status: INFO if installed

MAIL-2701: Mail Relay Configuration
  - Check if mail relay is restricted
  - Verify relay restrictions
  - Status: WARN for open relay

MAIL-2702: Mail Service Hardening
  - Check service configuration
  - Verify security settings
  - Status: WARN for weak config

MAIL-2703: Mail Logging
  - Check if mail logs are enabled
  - Verify log rotation
  - Status: WARN for missing logs
```

**Implementation Notes:**
- Detect Postfix: `/etc/postfix/main.cf`
- Detect Exim: `/etc/exim4/exim4.conf`
- Check mail service status
- Verify relay restrictions in config

**Testing:**
- Mock various mail service configurations
- Test Postfix/Exim detection
- Verify relay configuration parsing

---

### 4.4 Printer Security (3 checks)

**File:** `linux_health/checks_printers.py` (new)

```
PRNT-2400: CUPS Installation
  - Check if CUPS is installed
  - Detect printer services
  - Status: INFO if installed

PRNT-2401: CUPS Configuration
  - Check CUPS security configuration
  - Verify access controls
  - Status: WARN for weak config

PRNT-2402: Network Printer Security
  - Check for SNMP printers
  - Verify printer network isolation
  - Status: WARN for insecure setup
```

**Implementation Notes:**
- Check for CUPS: `/etc/cups/cupsd.conf`
- Verify CUPS daemon status
- Check for network printers in configuration
- Verify access controls

**Testing:**
- Mock CUPS configurations
- Test with/without CUPS installed
- Verify configuration parsing

---

### 4.5 SNMP Security (3 checks)

**File:** `linux_health/checks_snmp.py` (new)

```
SNMP-5100: SNMP Service Status
  - Check if SNMP is installed/running
  - Detect snmpd daemon
  - Status: INFO if running

SNMP-5101: SNMP Version
  - Check SNMP version configured
  - Prefer SNMPv3 over v2c
  - Status: WARN if using SNMPv2c

SNMP-5102: SNMP Community Strings
  - Check for weak community strings
  - Verify access controls
  - Status: FAIL for default strings
```

**Implementation Notes:**
- Check `/etc/snmp/snmpd.conf`
- Verify SNMP daemon status
- Parse community string configuration
- Check SNMP trap configuration

**Testing:**
- Mock SNMP configurations
- Test SNMPv2c vs SNMPv3
- Verify community string detection

---

### 4.6 Virtualization Detection (2 checks)

**File:** `linux_health/checks_virtualization.py` (new)

```
VIRT-2200: Hypervisor Detection
  - Detect if running on hypervisor
  - Identify hypervisor type
  - Status: INFO only

VIRT-2201: Guest Hardening
  - Check for VM-specific hardening
  - Verify appropriate kernel modules
  - Status: WARN for missing hardening
```

**Implementation Notes:**
- Check `/sys/hypervisor/type` for Xen
- Check `CPUID` for hypervisor detection
- Use `dmidecode` for manufacturer hints
- Check `/proc/cpuinfo` for virtualization flags

**Testing:**
- Mock Xen/KVM/VirtualBox detection
- Test on real hardware vs VMs
- Verify hypervisor identification

---

### 4.7 Login Banners (2 checks)

**File:** `linux_health/checks_banners.py` (new)

```
BNRZ-1600: Login Banner Presence
  - Check if /etc/issue exists
  - Verify banner content
  - Status: WARN if missing

BNRZ-1601: Banner Configuration
  - Check /etc/issue and /etc/issue.net
  - Verify sshd_config references banner
  - Status: WARN for misconfigured
```

**Implementation Notes:**
- Check `/etc/issue` and `/etc/issue.net`
- Verify SSH banner configuration
- Check banner content for warnings
- Verify file permissions

**Testing:**
- Mock various banner configurations
- Test with/without banner files
- Verify sshd configuration parsing

---

## Phase 5: Integration & Polish (Weeks 13-16)

### 5.1 Module Integration

1. **Update [cli.py](cli.py)**
   - Add new check functions to `run_all_checks()`
   - Update help text and documentation
   - Add category filters for new modules

2. **Update [report.py](report.py)**
   - Add new category colors/formatting
   - Update report template
   - Add category statistics

3. **Update tests**
   - Create comprehensive test files for each module
   - Maintain >70% coverage target
   - Add integration tests

### 5.2 Documentation Updates

1. **README.md**
   - Add new checks to feature list
   - Update check count (36→70+)
   - Add new categories section

2. **docs/FEATURES_ADDED.md**
   - Document all new checks
   - Add phase information
   - Document implementation details

3. **docs/PROJECT_STRUCTURE.md**
   - Update with new module descriptions
   - Add architecture diagrams
   - Document module relationships

### 5.3 Quality Assurance

1. **Testing**
   - Run full test suite
   - Achieve >70% coverage across new modules
   - Test on multiple Linux distributions

2. **Code Quality**
   - Run Black formatter
   - Run Ruff linter
   - Verify type hints complete

3. **Performance**
   - Measure execution time
   - Optimize slow checks
   - Verify timeout handling

---

## Implementation Checklist

### For Each New Check:
- [ ] Define check function with proper signature
- [ ] Implement with error handling
- [ ] Add Lynis-style test ID
- [ ] Create unit tests (pass/warn/fail)
- [ ] Mock SSH responses
- [ ] Add to `run_all_checks()`
- [ ] Update report generation
- [ ] Update documentation
- [ ] Run linter and formatter
- [ ] Verify >70% coverage

### For Each New Module:
- [ ] Create module file `checks_xxx.py`
- [ ] Define module-level docstring
- [ ] Import required dependencies
- [ ] Implement all check functions
- [ ] Create comprehensive test file
- [ ] Add module to `cli.py`
- [ ] Update category system
- [ ] Add to documentation

---

## Success Metrics

### Code Quality
- ✅ 0 linting errors (Ruff)
- ✅ 0 formatting issues (Black)
- ✅ >70% test coverage
- ✅ All type hints present
- ✅ All docstrings complete

### Feature Coverage
- ✅ 35-45 new checks implemented
- ✅ 30+ total test categories
- ✅ 95% Lynis feature parity (in terms of check categories)
- ✅ All checks working across Ubuntu, CentOS, Debian, RHEL

### Performance
- ✅ Total scan time <5 minutes
- ✅ No timeout errors
- ✅ Efficient SSH command usage
- ✅ Command caching working

### Documentation
- ✅ All checks documented
- ✅ README updated with new features
- ✅ Category system documented
- ✅ Examples provided for all new checks

---

## Risk Assessment

### Low Risk Areas
- Database checks (well-defined configs, standard tools)
- Filesystem checks (standard mount options)
- Accounting checks (standard audit tools)

### Medium Risk Areas
- Container checks (Docker API changes frequently)
- Web server checks (complex configurations)
- Mail service checks (many variations)

### Mitigation Strategies
- Stay compatible with LTS versions (Ubuntu 20.04+, CentOS 7+)
- Test against multiple distributions
- Implement fallback detection methods
- Add configuration validation before checks
- Comprehensive error handling for all SSH commands

---

## Timeline & Resources

### Estimated Effort
- **Phase 1** (Weeks 1-3): 40 development hours
- **Phase 2** (Weeks 4-6): 35 development hours
- **Phase 3** (Weeks 7-9): 40 development hours
- **Phase 4** (Weeks 10-12): 30 development hours
- **Phase 5** (Weeks 13-16): 25 development hours

**Total: ~170 hours (4-5 months for single developer)**

### Resources Required
- Linux test environments (4+ distributions)
- SSH access to test systems
- Reference documentation (Lynis source code)
- Database/service instances for testing
- Container runtime (Docker) for container testing

---

## Approval & Sign-Off

- [ ] Architecture review
- [ ] Risk assessment approved
- [ ] Timeline confirmed
- [ ] Resources allocated
- [ ] Development started

**Prepared by:** Linux Health Development Team  
**Date:** [Current Date]  
**Status:** Ready for Implementation


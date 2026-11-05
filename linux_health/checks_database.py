"""Database Security Module for Linux Health Security Scanner.

This module implements database security checks for MySQL/MariaDB, PostgreSQL,
MongoDB, and Oracle databases following Lynis-compatible test patterns.

Test IDs: DBS-1000 to DBS-1007
Category: Database Security
"""

from __future__ import annotations

from typing import List

from .checks import CheckResult, _fail, _pass, _run, _warn
from .ssh_client import SSHSession
from .test_ids import CHECK_TEST_IDS


def check_mysql_presence(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if MySQL/MariaDB is installed and running.

    Test ID: DBS-1000 (Lynis equivalent: DBS-1000)
    Category: Database

    Detects MySQL or MariaDB installation and verifies if the service is running.
    """
    category = "Database"
    test_id = "DBS-1000"

    # Check for MySQL/MariaDB binaries
    ret, out, err = _run(ssh, "which mysql mysqld mariadb 2>/dev/null")
    if ret != 0 or not out:
        return _pass(
            "MySQL/MariaDB Presence",
            "MySQL/MariaDB not installed",
            "No action required if database not needed",
            category,
            test_id,
        )

    # Check if service is running
    ret, out, err = _run(
        ssh,
        "systemctl is-active mysql mysqld mariadb 2>/dev/null || service mysql status 2>/dev/null || service mysqld status 2>/dev/null",
    )

    # Check for active status (but not "inactive")
    if ret == 0 and ("active" in out.lower() or "running" in out.lower()):
        return _pass(
            "MySQL/MariaDB Presence",
            f"MySQL/MariaDB installed and running: {out.split()[0] if out else 'detected'}",
            "Review database security configuration",
            category,
            test_id,
        )
    else:
        return _warn(
            "MySQL/MariaDB Presence",
            "MySQL/MariaDB installed but not running",
            "Start database service if needed: systemctl start mysql",
            category,
            test_id,
        )


def check_mysql_root_password(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if MySQL root account has a password set.

    Test ID: DBS-1001 (Lynis equivalent: DBS-1004)
    Category: Database

    Verifies that the MySQL root user has a password configured and that
    passwordless root access is not allowed.
    """
    category = "Database"
    test_id = "DBS-1001"

    # Check if MySQL is installed
    ret, out, err = _run(ssh, "which mysql 2>/dev/null")
    if ret != 0:
        return _pass(
            "MySQL Root Password",
            "MySQL not installed",
            "No action required",
            category,
            test_id,
        )

    # Try to connect without password (should fail if secure)
    ret, out, err = _run(
        ssh, "mysql -u root -e 'SELECT 1' 2>&1 | head -5", command_timeout=5.0
    )

    if ret == 0 and "ERROR" not in out:
        return _fail(
            "MySQL Root Password",
            "MySQL root account has no password or allows passwordless access",
            "Set MySQL root password: ALTER USER 'root'@'localhost' IDENTIFIED BY 'strong_password';",
            category,
            test_id,
        )
    elif "Access denied" in out or "ERROR 1045" in out:
        return _pass(
            "MySQL Root Password",
            "MySQL root account appears to be password-protected",
            "Ensure password meets complexity requirements",
            category,
            test_id,
        )
    else:
        return _warn(
            "MySQL Root Password",
            "Could not verify MySQL root password status",
            "Manually verify: mysql -u root -p",
            category,
            test_id,
        )


def check_mysql_anonymous_accounts(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check for MySQL anonymous user accounts.

    Test ID: DBS-1002 (Lynis equivalent: DBS-1012)
    Category: Database

    Detects anonymous MySQL user accounts which pose a security risk.
    """
    category = "Database"
    test_id = "DBS-1002"

    # Check if MySQL is installed
    ret, out, err = _run(ssh, "which mysql 2>/dev/null")
    if ret != 0:
        return _pass(
            "MySQL Anonymous Accounts",
            "MySQL not installed",
            "No action required",
            category,
            test_id,
        )

    # Check for anonymous accounts (requires mysql root access)
    ret, out, err = _run(
        ssh,
        "sudo -S mysql -e \"SELECT User, Host FROM mysql.user WHERE User=''\" 2>&1 | grep -v 'User'",
        password=password,
        command_timeout=5.0,
    )

    if ret == 0 and out and len(out.strip().split("\n")) > 0:
        return _fail(
            "MySQL Anonymous Accounts",
            f"Found {len(out.strip().split())} anonymous MySQL accounts",
            "Remove anonymous accounts: DELETE FROM mysql.user WHERE User=''; FLUSH PRIVILEGES;",
            category,
            test_id,
        )
    elif "Access denied" in err or "ERROR" in err:
        return _warn(
            "MySQL Anonymous Accounts",
            "Cannot verify - insufficient MySQL permissions",
            "Grant appropriate permissions or run as MySQL admin",
            category,
            test_id,
        )
    else:
        return _pass(
            "MySQL Anonymous Accounts",
            "No anonymous MySQL accounts found",
            "Continue monitoring user accounts",
            category,
            test_id,
        )


def check_mysql_remote_root(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if MySQL root can connect remotely.

    Test ID: DBS-1003 (Lynis equivalent: DBS-1004)
    Category: Database

    Verifies that MySQL root user cannot connect from remote hosts.
    """
    category = "Database"
    test_id = "DBS-1003"

    # Check if MySQL is installed
    ret, out, err = _run(ssh, "which mysql 2>/dev/null")
    if ret != 0:
        return _pass(
            "MySQL Remote Root Access",
            "MySQL not installed",
            "No action required",
            category,
            test_id,
        )

    # Check bind-address in MySQL config
    ret, out, err = _run(
        ssh,
        "grep -r 'bind-address' /etc/mysql /etc/my.cnf /etc/my.cnf.d 2>/dev/null | grep -v '#' | head -5",
    )

    bind_localhost = False
    if "127.0.0.1" in out or "localhost" in out:
        bind_localhost = True

    # Check for root@% or root@non-localhost in user table
    ret, out, err = _run(
        ssh,
        "sudo -S mysql -e \"SELECT User, Host FROM mysql.user WHERE User='root'\" 2>&1 | grep -v localhost | grep -v '127.0.0.1' | grep root",
        password=password,
        command_timeout=5.0,
    )

    if (
        ret == 0
        and "root" in out
        and ("%" in out or any(host in out for host in ["10.", "192.", "172."]))
    ):
        return _fail(
            "MySQL Remote Root Access",
            "MySQL root account can connect remotely",
            "Restrict root to localhost: DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1'); FLUSH PRIVILEGES;",
            category,
            test_id,
        )
    elif bind_localhost:
        return _pass(
            "MySQL Remote Root Access",
            "MySQL bound to localhost only",
            "Maintain secure bind-address configuration",
            category,
            test_id,
        )
    elif "Access denied" in err or "ERROR" in err:
        return _warn(
            "MySQL Remote Root Access",
            "Cannot verify - insufficient MySQL permissions",
            "Grant appropriate permissions or run as MySQL admin",
            category,
            test_id,
        )
    else:
        return _pass(
            "MySQL Remote Root Access",
            "MySQL root appears restricted to localhost",
            "Verify bind-address and user host restrictions",
            category,
            test_id,
        )


def check_postgresql_security(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check PostgreSQL security configuration.

    Test ID: DBS-1004 (Lynis equivalent: DBS-1800)
    Category: Database

    Verifies PostgreSQL pg_hba.conf authentication methods and security settings.
    """
    category = "Database"
    test_id = "DBS-1004"

    # Check if PostgreSQL is installed
    ret, out, err = _run(ssh, "which psql postgres 2>/dev/null")
    if ret != 0:
        return _pass(
            "PostgreSQL Security",
            "PostgreSQL not installed",
            "No action required",
            category,
            test_id,
        )

    # Check if PostgreSQL is running
    ret, out, err = _run(
        ssh,
        "systemctl is-active postgresql 2>/dev/null || service postgresql status 2>/dev/null",
    )

    if (
        ret != 0
        or ("active" not in out.lower() or "inactive" in out.lower())
        and "running" not in out.lower()
    ):
        return _warn(
            "PostgreSQL Security",
            "PostgreSQL installed but not running",
            "Start PostgreSQL: systemctl start postgresql",
            category,
            test_id,
        )

    # Check pg_hba.conf for weak authentication
    ret, out, err = _run(
        ssh,
        "sudo -S find /etc/postgresql /var/lib/pgsql -name pg_hba.conf 2>/dev/null | head -1",
        password=password,
    )

    if out:
        pg_hba_file = out.strip()
        ret, out, err = _run(
            ssh,
            f"sudo -S grep -v '^#' {pg_hba_file} | grep -E '(trust|password)' 2>/dev/null",
            password=password,
        )

        if "trust" in out:
            return _fail(
                "PostgreSQL Security",
                f"PostgreSQL using 'trust' authentication in {pg_hba_file}",
                "Use stronger authentication methods (md5, scram-sha-256): Edit pg_hba.conf and reload PostgreSQL",
                category,
                test_id,
            )
        elif "password" in out.lower() and "md5" not in out and "scram" not in out:
            return _warn(
                "PostgreSQL Security",
                "PostgreSQL using plain 'password' authentication",
                "Use encrypted authentication (md5 or scram-sha-256)",
                category,
                test_id,
            )
        else:
            return _pass(
                "PostgreSQL Security",
                "PostgreSQL using secure authentication methods",
                "Continue monitoring PostgreSQL configuration",
                category,
                test_id,
            )
    else:
        return _warn(
            "PostgreSQL Security",
            "Could not locate pg_hba.conf",
            "Verify PostgreSQL configuration files permissions",
            category,
            test_id,
        )


def check_mongodb_authentication(ssh: SSHSession, password: str = "") -> CheckResult:
    """Check if MongoDB authentication is enabled.

    Test ID: DBS-1005 (Lynis equivalent: DBS-1900)
    Category: Database

    Verifies that MongoDB has authentication enabled and configured.
    """
    category = "Database"
    test_id = "DBS-1005"

    # Check if MongoDB is installed
    ret, out, err = _run(ssh, "which mongo mongod 2>/dev/null")
    if ret != 0:
        return _pass(
            "MongoDB Authentication",
            "MongoDB not installed",
            "No action required",
            category,
            test_id,
        )

    # Check if MongoDB is running
    ret, out, err = _run(
        ssh, "systemctl is-active mongod 2>/dev/null || pgrep -f mongod"
    )

    if ret != 0 and not out:
        return _warn(
            "MongoDB Authentication",
            "MongoDB installed but not running",
            "Start MongoDB: systemctl start mongod",
            category,
            test_id,
        )

    # Check MongoDB config for authentication
    ret, out, err = _run(
        ssh,
        "sudo -S grep -E 'security:|authorization:' /etc/mongod.conf 2>/dev/null | head -10",
        password=password,
    )

    if "authorization: enabled" in out or "authorization:enabled" in out.replace(
        " ", ""
    ):
        return _pass(
            "MongoDB Authentication",
            "MongoDB authentication is enabled",
            "Ensure strong user passwords are configured",
            category,
            test_id,
        )
    elif (
        "authorization: disabled" in out
        or "authorization:disabled" in out.replace(" ", "")
        or "# authorization:" in out
    ):
        return _fail(
            "MongoDB Authentication",
            "MongoDB authentication appears disabled",
            "Enable authentication: Add 'security.authorization: enabled' to /etc/mongod.conf and restart",
            category,
            test_id,
        )
    elif "security:" in out:
        return _warn(
            "MongoDB Authentication",
            "MongoDB has security section but authorization unclear",
            "Verify authorization is enabled in /etc/mongod.conf",
            category,
            test_id,
        )
    else:
        return _fail(
            "MongoDB Authentication",
            "MongoDB authentication configuration not found",
            "Enable authentication: Add 'security.authorization: enabled' to /etc/mongod.conf and restart",
            category,
            test_id,
        )


def check_database_service_hardening(
    ssh: SSHSession, password: str = ""
) -> CheckResult:
    """Check for database service hardening best practices.

    Test ID: DBS-1006 (Lynis equivalent: DBS-2000)
    Category: Database

    Verifies general database security best practices across all detected databases.
    """
    category = "Database"
    test_id = "DBS-1006"

    issues = []
    recommendations = []

    # Check for databases running as root
    ret, out, err = _run(
        ssh, "ps aux | grep -E '(mysqld|postgres|mongod)' | grep -v grep"
    )

    if "root" in out:
        issues.append("Database process running as root user")
        recommendations.append("Configure databases to run as dedicated non-root user")

    # Check for database logs
    ret, out, err = _run(
        ssh,
        "ls -la /var/log/mysql* /var/log/postgresql* /var/log/mongodb* 2>/dev/null | head -10",
    )

    if not out:
        issues.append("No database log files found")
        recommendations.append("Enable database logging for security auditing")

    # Check for test/default databases
    ret, out, err = _run(
        ssh,
        "sudo -S mysql -e 'SHOW DATABASES' 2>/dev/null | grep -E '(test|sample)'",
        password=password,
        command_timeout=5.0,
    )

    if "test" in out.lower():
        issues.append("Test databases found in MySQL")
        recommendations.append("Remove test databases: DROP DATABASE test;")

    if not issues:
        return _pass(
            "Database Service Hardening",
            "Database services follow security best practices",
            "Continue monitoring database configuration",
            category,
            test_id,
        )
    else:
        return _warn(
            "Database Service Hardening",
            f"Found {len(issues)} hardening issues: {', '.join(issues[:2])}",
            " | ".join(recommendations[:2]),
            category,
            test_id,
        )


def check_database_backup_configuration(
    ssh: SSHSession, password: str = ""
) -> CheckResult:
    """Check if database backups are configured.

    Test ID: DBS-1007 (Lynis equivalent: DBS-2100)
    Category: Database

    Verifies that database backup mechanisms are in place.
    """
    category = "Database"
    test_id = "DBS-1007"

    backup_indicators = []

    # Check for common backup tools
    ret, out, err = _run(
        ssh, "which mysqldump pg_dump mongodump automysqlbackup 2>/dev/null"
    )

    if out:
        backup_indicators.append(f"Backup tools installed: {', '.join(out.split())}")

    # Check for backup cron jobs
    ret, out, err = _run(
        ssh,
        "sudo -S grep -r -E '(mysqldump|pg_dump|mongodump|backup)' /etc/cron* /var/spool/cron 2>/dev/null | head -5",
        password=password,
    )

    if out and "dump" in out.lower():
        backup_indicators.append("Database backup cron jobs found")

    # Check for recent backup files
    ret, out, err = _run(
        ssh,
        "find /var/backups /backup /home/backup -name '*.sql*' -o -name '*.dump*' -mtime -7 2>/dev/null | head -5",
    )

    if out:
        backup_count = len(out.strip().split("\n"))
        backup_indicators.append(f"{backup_count} recent backup files found")

    if len(backup_indicators) >= 2:
        return _pass(
            "Database Backup Configuration",
            f"Database backups appear configured: {'; '.join(backup_indicators)}",
            "Verify backup retention and test restore procedures",
            category,
            test_id,
        )
    elif len(backup_indicators) == 1:
        return _warn(
            "Database Backup Configuration",
            f"Limited backup evidence: {backup_indicators[0]}",
            "Implement comprehensive backup strategy with automated scheduling",
            category,
            test_id,
        )
    else:
        return _warn(
            "Database Backup Configuration",
            "No database backup configuration detected",
            "Implement automated database backups (mysqldump, pg_dump, mongodump) with proper retention",
            category,
            test_id,
        )


def run_all_database_checks(ssh: SSHSession, password: str = "") -> List[CheckResult]:
    """Run all database security checks.

    Returns:
        List of CheckResult objects for all database security checks.
    """
    checks = [
        check_mysql_presence,
        check_mysql_root_password,
        check_mysql_anonymous_accounts,
        check_mysql_remote_root,
        check_postgresql_security,
        check_mongodb_authentication,
        check_database_service_hardening,
        check_database_backup_configuration,
    ]

    results = []
    for check in checks:
        try:
            result = check(ssh, password)
            results.append(result)
        except Exception as e:
            # Create a failure result if check crashes
            results.append(
                CheckResult(
                    category="Database",
                    item=check.__name__.replace("check_", "").replace("_", " ").title(),
                    status="unknown",
                    details=f"Check failed with error (not assessed): {str(e)}",
                    recommendation="Review check implementation and SSH connection",
                    test_id=CHECK_TEST_IDS.get(check.__name__, "DBS-XXXX"),
                )
            )

    return results

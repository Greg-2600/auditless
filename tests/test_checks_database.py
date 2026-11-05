"""Unit tests for Database Security Module (checks_database.py).

Tests all 8 database security checks (DBS-1000 through DBS-1007) with
pass/warn/fail scenarios and error handling.
"""

# pylint: disable=protected-access,duplicate-code,line-too-long,too-many-lines,too-few-public-methods,redefined-outer-name,import-outside-toplevel,trailing-newlines

from unittest.mock import MagicMock

import pytest

from linux_health.checks import disable_command_cache, reset_command_cache
from linux_health.checks_database import (
    check_database_backup_configuration,
    check_database_service_hardening,
    check_mongodb_authentication,
    check_mysql_anonymous_accounts,
    check_mysql_presence,
    check_mysql_remote_root,
    check_mysql_root_password,
    check_postgresql_security,
    run_all_database_checks,
)


# Disable command caching for tests to ensure fresh mocks
@pytest.fixture(scope="session", autouse=True)
def _disable_cache_for_tests():
    """Disable command cache during testing to prevent stale mock data."""
    disable_command_cache()
    yield
    reset_command_cache()


def mock_ssh_exec(return_values):
    """Helper to create properly structured SSH mock.

    Args:
        return_values: List of tuples (exit_code, stdout_str, stderr_str)

    Returns:
        MagicMock SSH session with properly configured exec_command
    """
    ssh = MagicMock()
    ssh._client = MagicMock()

    responses = []
    for exit_code, stdout_str, stderr_str in return_values:
        stdin = MagicMock(write=MagicMock(), flush=MagicMock(), close=MagicMock())
        stdout = MagicMock(
            read=MagicMock(return_value=stdout_str.encode()),
            channel=MagicMock(
                exit_status_ready=MagicMock(return_value=True),
                recv_exit_status=MagicMock(return_value=exit_code),
            ),
        )
        stderr = MagicMock(read=MagicMock(return_value=stderr_str.encode()))
        responses.append((stdin, stdout, stderr))

    ssh._client.exec_command.side_effect = responses
    return ssh


class TestCheckMySQLPresence:
    """Test check_mysql_presence function (DBS-1000)."""

    def test_mysql_not_installed(self):
        """Test when MySQL/MariaDB is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which mysql
            ]
        )

        result = check_mysql_presence(ssh)

        assert result.status == "pass"
        assert "not installed" in result.details.lower()
        assert result.test_id == "DBS-1000"
        assert result.category == "Database"

    def test_mysql_running(self):
        """Test when MySQL is installed and running."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysql\n/usr/sbin/mysqld", ""),  # which mysql
                (0, "active", ""),  # systemctl is-active
            ]
        )

        result = check_mysql_presence(ssh)

        assert result.status == "pass"
        assert "running" in result.details.lower()
        assert result.test_id == "DBS-1000"

    def test_mysql_installed_not_running(self):
        """Test when MySQL is installed but not running."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysql", ""),  # which mysql
                (1, "inactive", ""),  # systemctl is-active
            ]
        )

        result = check_mysql_presence(ssh)

        assert result.status == "warn"
        assert "not running" in result.details.lower()
        assert "start" in result.recommendation.lower()


class TestCheckMySQLRootPassword:
    """Test check_mysql_root_password function (DBS-1001)."""

    def test_mysql_not_installed(self):
        """Test when MySQL is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which mysql
            ]
        )

        result = check_mysql_root_password(ssh)

        assert result.status == "pass"
        assert "not installed" in result.details.lower()

    def test_passwordless_root_access(self):
        """Test when root can access MySQL without password."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysql", ""),  # which mysql
                (0, "1\n1", ""),  # mysql -u root -e 'SELECT 1'
            ]
        )

        result = check_mysql_root_password(ssh)

        assert result.status == "fail"
        assert "no password" in result.details.lower()
        assert "alter user" in result.recommendation.lower()
        assert result.test_id == "DBS-1001"

    def test_password_protected(self):
        """Test when root access requires password."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysql", ""),  # which mysql
                (
                    1,
                    "ERROR 1045 (28000): Access denied for user 'root'@'localhost'",
                    "",
                ),
            ]
        )

        result = check_mysql_root_password(ssh)

        assert result.status == "pass"
        assert "password-protected" in result.details.lower()


class TestCheckMySQLAnonymousAccounts:
    """Test check_mysql_anonymous_accounts function (DBS-1002)."""

    def test_mysql_not_installed(self):
        """Test when MySQL is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which mysql
            ]
        )

        result = check_mysql_anonymous_accounts(ssh)

        assert result.status == "pass"

    def test_anonymous_accounts_found(self):
        """Test when anonymous accounts exist."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysql", ""),  # which mysql
                (0, "  localhost\n  %", ""),  # SELECT User, Host
            ]
        )

        result = check_mysql_anonymous_accounts(ssh, password="test")

        assert result.status == "fail"
        assert "anonymous" in result.details.lower()
        assert "delete from mysql.user" in result.recommendation.lower()
        assert result.test_id == "DBS-1002"

    def test_no_anonymous_accounts(self):
        """Test when no anonymous accounts exist."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysql", ""),  # which mysql
                (0, "", ""),  # SELECT User, Host (no results)
            ]
        )

        result = check_mysql_anonymous_accounts(ssh, password="test")

        assert result.status == "pass"
        assert "no anonymous" in result.details.lower()


class TestCheckMySQLRemoteRoot:
    """Test check_mysql_remote_root function (DBS-1003)."""

    def test_mysql_not_installed(self):
        """Test when MySQL is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which mysql
            ]
        )

        result = check_mysql_remote_root(ssh)

        assert result.status == "pass"

    def test_bound_to_localhost(self):
        """Test when MySQL is bound to localhost."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysql", ""),  # which mysql
                (0, "bind-address = 127.0.0.1", ""),  # grep bind-address
                (1, "", ""),  # SELECT User, Host (no remote root)
            ]
        )

        result = check_mysql_remote_root(ssh, password="test")

        assert result.status == "pass"
        assert "localhost" in result.details.lower()
        assert result.test_id == "DBS-1003"

    def test_remote_root_access(self):
        """Test when root can connect remotely."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysql", ""),  # which mysql
                (1, "", ""),  # grep bind-address (not found)
                (0, "root  %", ""),  # SELECT User, Host (root@%)
            ]
        )

        result = check_mysql_remote_root(ssh, password="test")

        assert result.status == "fail"
        assert "remotely" in result.details.lower()
        assert "delete from mysql.user" in result.recommendation.lower()


class TestCheckPostgreSQLSecurity:
    """Test check_postgresql_security function (DBS-1004)."""

    def test_postgresql_not_installed(self):
        """Test when PostgreSQL is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which psql postgres
            ]
        )

        result = check_postgresql_security(ssh)

        assert result.status == "pass"
        assert result.test_id == "DBS-1004"

    def test_postgresql_not_running(self):
        """Test when PostgreSQL is installed but not running."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/psql", ""),  # which psql
                (1, "inactive", ""),  # systemctl is-active
            ]
        )

        result = check_postgresql_security(ssh)

        assert result.status == "warn"
        assert "not running" in result.details.lower()

    def test_trust_authentication(self):
        """Test when PostgreSQL uses 'trust' authentication."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/psql", ""),  # which psql
                (0, "active", ""),  # systemctl is-active
                (0, "/etc/postgresql/14/main/pg_hba.conf", ""),  # find pg_hba.conf
                (0, "local   all   all   trust", ""),  # grep trust
            ]
        )

        result = check_postgresql_security(ssh, password="test")

        assert result.status == "fail"
        assert "trust" in result.details.lower()
        assert (
            "md5" in result.recommendation.lower()
            or "scram" in result.recommendation.lower()
        )

    def test_secure_authentication(self):
        """Test when PostgreSQL uses secure authentication."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/psql", ""),  # which psql
                (0, "active", ""),  # systemctl is-active
                (0, "/etc/postgresql/14/main/pg_hba.conf", ""),  # find pg_hba.conf
                (0, "local   all   all   scram-sha-256", ""),  # grep
            ]
        )

        result = check_postgresql_security(ssh, password="test")

        assert result.status == "pass"
        assert "secure" in result.details.lower()


class TestCheckMongoDBAuthentication:
    """Test check_mongodb_authentication function (DBS-1005)."""

    def test_mongodb_not_installed(self):
        """Test when MongoDB is not installed."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which mongo mongod
            ]
        )

        result = check_mongodb_authentication(ssh)

        assert result.status == "pass"
        assert result.test_id == "DBS-1005"

    def test_mongodb_not_running(self):
        """Test when MongoDB is installed but not running."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mongod", ""),  # which mongod
                (1, "", ""),  # systemctl is-active
            ]
        )

        result = check_mongodb_authentication(ssh)

        assert result.status == "warn"
        assert "not running" in result.details.lower()

    def test_authentication_disabled(self):
        """Test when MongoDB authentication is disabled."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mongod", ""),  # which mongod
                (0, "12345", ""),  # pgrep mongod
                (0, "security:\n  # authorization: disabled", ""),  # grep security
            ]
        )

        result = check_mongodb_authentication(ssh, password="test")

        assert result.status == "fail"
        assert "disabled" in result.details.lower()
        assert "enable authentication" in result.recommendation.lower()

    def test_authentication_enabled(self):
        """Test when MongoDB authentication is enabled."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mongod", ""),  # which mongod
                (0, "12345", ""),  # pgrep mongod
                (0, "security:\n  authorization: enabled", ""),  # grep security
            ]
        )

        result = check_mongodb_authentication(ssh, password="test")

        assert result.status == "pass"
        assert "enabled" in result.details.lower()


class TestCheckDatabaseServiceHardening:
    """Test check_database_service_hardening function (DBS-1006)."""

    def test_database_running_as_root(self):
        """Test when database process runs as root."""
        ssh = mock_ssh_exec(
            [
                (0, "root     12345  mysqld\nroot     12346  postgres", ""),  # ps aux
                (1, "", ""),  # ls /var/log
                (1, "", ""),  # mysql SHOW DATABASES
            ]
        )

        result = check_database_service_hardening(ssh, password="test")

        assert result.status == "warn"
        assert "root" in result.details.lower()
        assert result.test_id == "DBS-1006"

    def test_test_databases_found(self):
        """Test when test databases are found."""
        ssh = mock_ssh_exec(
            [
                (0, "mysql    12345  mysqld", ""),  # ps aux (not root)
                (0, "/var/log/mysql.log", ""),  # ls /var/log
                (0, "test\ntest_db", ""),  # SHOW DATABASES
            ]
        )

        result = check_database_service_hardening(ssh, password="test")

        assert result.status == "warn"
        assert "test" in result.details.lower()

    def test_all_hardening_checks_pass(self):
        """Test when all hardening checks pass."""
        ssh = mock_ssh_exec(
            [
                (0, "mysql    12345  mysqld", ""),  # ps aux (not root)
                (0, "/var/log/mysql.log", ""),  # ls /var/log
                (1, "", ""),  # SHOW DATABASES (no test DB)
            ]
        )

        result = check_database_service_hardening(ssh, password="test")

        assert result.status == "pass"
        assert "best practices" in result.details.lower()


class TestCheckDatabaseBackupConfiguration:
    """Test check_database_backup_configuration function (DBS-1007)."""

    def test_no_backup_evidence(self):
        """Test when no backup configuration is found."""
        ssh = mock_ssh_exec(
            [
                (1, "", ""),  # which mysqldump
                (1, "", ""),  # grep cron
                (1, "", ""),  # find backup files
            ]
        )

        result = check_database_backup_configuration(ssh, password="test")

        assert result.status == "warn"
        assert "no" in result.details.lower() and "backup" in result.details.lower()
        assert result.test_id == "DBS-1007"

    def test_backup_tools_installed_only(self):
        """Test when backup tools are installed but not scheduled."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysqldump\n/usr/bin/pg_dump", ""),  # which
                (1, "", ""),  # grep cron (no cron jobs)
                (1, "", ""),  # find backup files (none)
            ]
        )

        result = check_database_backup_configuration(ssh, password="test")

        assert result.status == "warn"
        assert "limited" in result.details.lower()

    def test_comprehensive_backup_setup(self):
        """Test when backup tools, cron, and files are present."""
        ssh = mock_ssh_exec(
            [
                (0, "/usr/bin/mysqldump", ""),  # which
                (
                    0,
                    "0 2 * * * /usr/bin/mysqldump -u root db > /backup/db.sql",
                    "",
                ),  # grep cron
                (
                    0,
                    "/var/backups/mysql/db-20240101.sql\n/var/backups/mysql/db-20240102.sql",
                    "",
                ),  # find
            ]
        )

        result = check_database_backup_configuration(ssh, password="test")

        assert result.status == "pass"
        assert "configured" in result.details.lower()


class TestRunAllDatabaseChecks:
    """Test run_all_database_checks function."""

    def test_all_checks_executed(self):
        """Test that all 8 database checks are executed."""
        ssh = MagicMock()
        ssh.exec.return_value = (1, "", "")  # Default: not installed

        results = run_all_database_checks(ssh, password="test")

        assert len(results) == 8
        assert all(isinstance(r.test_id, str) for r in results)
        assert all(r.category in ["Database", "Accounting"] for r in results)

    def test_error_handling_in_checks(self):
        """Test that exceptions in individual checks are caught."""
        ssh = MagicMock()
        ssh.exec.side_effect = Exception("SSH connection lost")

        results = run_all_database_checks(ssh, password="test")

        # Should still return 8 results, all marked unknown (not fail)
        assert len(results) == 8
        assert all(r.status == "unknown" for r in results)
        assert all("error" in r.details.lower() for r in results)

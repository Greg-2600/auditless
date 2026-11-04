"""Unit tests for container security checks module."""

import unittest
from unittest.mock import MagicMock

from linux_health.checks_container import (
    check_docker_container_runtime,
    check_docker_daemon_config,
    check_docker_image_security,
    check_docker_installed,
    check_docker_network_isolation,
    check_docker_resource_limits,
    check_docker_socket_permissions,
    run_all_checks,
)


def mock_ssh_exec(return_values):
    """Create a mock SSH client that returns sequential responses.

    Uses the real SSHSession interface (.run) so tests fail if checks
    call methods that do not exist in production.
    """
    mock_client = MagicMock()
    mock_client.run.side_effect = return_values
    return mock_client


class TestCheckDockerInstalled(unittest.TestCase):
    """Tests for check_docker_installed function."""

    def test_docker_installed_with_version(self):
        """Test Docker is installed and version is readable."""
        client = mock_ssh_exec(
            [
                (0, "/usr/bin/docker\n", ""),
                (0, "Docker version 24.0.7, build afdd53b\n", ""),
            ]
        )
        result = check_docker_installed(client)
        assert result.status == "pass"
        assert "Docker is installed: Docker version 24.0.7" in result.details

    def test_docker_installed_no_version(self):
        """Test Docker is installed but version command fails."""
        client = mock_ssh_exec(
            [
                (0, "/usr/bin/docker\n", ""),
                (1, "", "command not found"),
            ]
        )
        result = check_docker_installed(client)
        assert result.status == "pass"
        assert result.details == "Docker is installed"

    def test_docker_not_installed(self):
        """Test Docker is not installed."""
        client = mock_ssh_exec(
            [
                (1, "", ""),
            ]
        )
        result = check_docker_installed(client)
        assert result.status == "warn"
        assert result.details == "Docker is not installed"

    def test_docker_check_exception(self):
        """Test exception handling during Docker check."""
        client = mock_ssh_exec(
            [
                Exception("Connection timeout"),
            ]
        )
        result = check_docker_installed(client)
        assert result.status == "fail"
        assert "Error checking Docker installation" in result.details


class TestCheckDockerSocketPermissions(unittest.TestCase):
    """Tests for check_docker_socket_permissions function."""

    def test_socket_secure_permissions(self):
        """Test Docker socket has secure permissions."""
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (0, "660 root:docker\n", ""),
            ]
        )
        result = check_docker_socket_permissions(client)
        assert result.status == "pass"
        assert "permissions are secure: 660 (root:docker)" in result.details

    def test_socket_not_found(self):
        """Test Docker socket does not exist."""
        client = mock_ssh_exec(
            [
                (1, "", ""),
            ]
        )
        result = check_docker_socket_permissions(client)
        assert result.status == "warn"
        assert "Docker socket not found" in result.details

    def test_socket_world_readable(self):
        """Test Docker socket has world-readable permissions."""
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (0, "666 root:docker\n", ""),
            ]
        )
        result = check_docker_socket_permissions(client)
        assert result.status == "fail"
        assert "insecure permissions: 666" in result.details

    def test_socket_world_writable(self):
        """Test Docker socket has world-writable permissions."""
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (0, "667 root:docker\n", ""),
            ]
        )
        result = check_docker_socket_permissions(client)
        assert result.status == "fail"
        assert "insecure permissions: 667" in result.details

    def test_socket_wrong_ownership(self):
        """Test Docker socket not owned by root."""
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (0, "660 dockeruser:docker\n", ""),
            ]
        )
        result = check_docker_socket_permissions(client)
        assert result.status == "warn"
        assert "not owned by root: dockeruser:docker" in result.details

    def test_socket_permission_read_error(self):
        """Test unable to read socket permissions."""
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (1, "", "Permission denied"),
            ]
        )
        result = check_docker_socket_permissions(client)
        assert result.status == "fail"
        assert "Unable to read Docker socket permissions" in result.details


class TestCheckDockerDaemonConfig(unittest.TestCase):
    """Tests for check_docker_daemon_config function."""

    def test_daemon_config_secure(self):
        """Test Docker daemon has secure configuration."""
        config_content = """{
    "userns-remap": "default",
    "live-restore": true,
    "disable-legacy-registry": true,
    "tlsverify": true
}"""
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (0, config_content, ""),
            ]
        )
        result = check_docker_daemon_config(client)
        assert result.status == "pass"
        assert "user namespace remapping" in result.details
        assert "live restore" in result.details

    def test_daemon_config_missing(self):
        """Test Docker daemon.json does not exist."""
        client = mock_ssh_exec(
            [
                (1, "", ""),
            ]
        )
        result = check_docker_daemon_config(client)
        assert result.status == "warn"
        assert "daemon config file not found" in result.details

    def test_daemon_config_missing_userns(self):
        """Test Docker daemon config missing user namespace remapping."""
        config_content = """{
    "live-restore": true
}"""
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (0, config_content, ""),
            ]
        )
        result = check_docker_daemon_config(client)
        assert result.status == "warn"
        assert "user namespace remapping not enabled" in result.details
        assert "live restore" in result.details

    def test_daemon_config_empty(self):
        """Test Docker daemon config is empty/minimal."""
        config_content = "{}"
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (0, config_content, ""),
            ]
        )
        result = check_docker_daemon_config(client)
        assert result.status == "warn"
        assert "user namespace remapping not enabled" in result.details

    def test_daemon_config_read_error(self):
        """Test unable to read daemon config file."""
        client = mock_ssh_exec(
            [
                (0, "exists\n", ""),
                (1, "", "Permission denied"),
            ]
        )
        result = check_docker_daemon_config(client)
        assert result.status == "fail"
        assert "Unable to read Docker daemon configuration" in result.details


class TestCheckDockerImageSecurity(unittest.TestCase):
    """Tests for check_docker_image_security function."""

    def test_images_properly_tagged(self):
        """Test Docker images are properly tagged (no latest)."""
        client = mock_ssh_exec(
            [
                (0, "", ""),  # docker info
                (0, "nginx:1.21.6\nredis:7.0.5\npostgres:14.5\n", ""),
            ]
        )
        result = check_docker_image_security(client)
        assert result.status == "pass"
        assert "properly tagged: 3 images" in result.details

    def test_docker_not_running(self):
        """Test Docker daemon is not running."""
        client = mock_ssh_exec(
            [
                (1, "", "Cannot connect to the Docker daemon"),
            ]
        )
        result = check_docker_image_security(client)
        assert result.status == "warn"
        assert "Docker daemon is not running" in result.details

    def test_images_using_latest(self):
        """Test some images using latest tag."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "nginx:latest\nredis:7.0.5\nubuntu:latest\n", ""),
            ]
        )
        result = check_docker_image_security(client)
        assert result.status == "warn"
        assert "2 images using 'latest' tag" in result.details

    def test_excessive_images(self):
        """Test excessive number of images."""
        images = "\n".join([f"image{i}:v1.0" for i in range(60)])
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, images, ""),
            ]
        )
        result = check_docker_image_security(client)
        assert result.status == "warn"
        assert "excessive image count (60)" in result.details

    def test_no_images(self):
        """Test no Docker images on system."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "", ""),
            ]
        )
        result = check_docker_image_security(client)
        assert result.status == "pass"
        assert result.details == "No Docker images found on system"

    def test_image_list_error(self):
        """Test unable to list Docker images."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (1, "", "permission denied"),
            ]
        )
        result = check_docker_image_security(client)
        assert result.status == "fail"
        assert "Unable to list Docker images" in result.details


class TestCheckDockerContainerRuntime(unittest.TestCase):
    """Tests for check_docker_container_runtime function."""

    def test_containers_secure(self):
        """Test running containers have secure configuration."""
        client = mock_ssh_exec(
            [
                (0, "", ""),  # docker info
                (0, "5\n", ""),  # container count
                (0, "0\n", ""),  # privileged count
                (0, "0\n", ""),  # host network count
            ]
        )
        result = check_docker_container_runtime(client)
        assert result.status == "pass"
        assert "5 containers running with secure configuration" in result.details

    def test_no_running_containers(self):
        """Test no running containers."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "0\n", ""),
            ]
        )
        result = check_docker_container_runtime(client)
        assert result.status == "pass"
        assert result.details == "No running containers found"

    def test_privileged_containers(self):
        """Test some containers running privileged."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "3\n", ""),
                (0, "2\n", ""),  # 2 privileged
                (0, "0\n", ""),
            ]
        )
        result = check_docker_container_runtime(client)
        assert result.status == "fail"
        assert "2 privileged containers" in result.details

    def test_host_network_containers(self):
        """Test some containers using host network."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "4\n", ""),
                (0, "0\n", ""),
                (0, "1\n", ""),  # 1 host network
            ]
        )
        result = check_docker_container_runtime(client)
        assert result.status == "fail"
        assert "1 containers using host network" in result.details

    def test_excessive_containers(self):
        """Test excessive number of running containers."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "150\n", ""),
                (0, "0\n", ""),
                (0, "0\n", ""),
            ]
        )
        result = check_docker_container_runtime(client)
        assert result.status == "fail"
        assert "excessive running containers (150)" in result.details

    def test_docker_not_running(self):
        """Test Docker daemon not running."""
        client = mock_ssh_exec(
            [
                (1, "", ""),
            ]
        )
        result = check_docker_container_runtime(client)
        assert result.status == "warn"
        assert "Docker daemon is not running" in result.details


class TestCheckDockerNetworkIsolation(unittest.TestCase):
    """Tests for check_docker_network_isolation function."""

    def test_custom_networks_configured(self):
        """Test custom Docker networks are configured."""
        client = mock_ssh_exec(
            [
                (0, "", ""),  # docker info
                (0, "bridge\nhost\nnone\napp-network\ndb-network\n", ""),
                (0, "0\n", ""),  # no containers on default bridge
            ]
        )
        result = check_docker_network_isolation(client)
        assert result.status == "pass"
        assert "2 custom networks in use" in result.details

    def test_no_custom_networks(self):
        """Test only default networks exist."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "bridge\nhost\nnone\n", ""),
            ]
        )
        result = check_docker_network_isolation(client)
        assert result.status == "warn"
        assert "No custom Docker networks found" in result.details

    def test_containers_on_default_bridge(self):
        """Test some containers still using default bridge."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "bridge\nhost\nnone\ncustom-net\n", ""),
                (0, "3\n", ""),  # 3 containers on default bridge
            ]
        )
        result = check_docker_network_isolation(client)
        assert result.status == "warn"
        assert "1 custom networks" in result.details
        assert "3 containers on default bridge" in result.details

    def test_docker_not_running(self):
        """Test Docker daemon not running."""
        client = mock_ssh_exec(
            [
                (1, "", ""),
            ]
        )
        result = check_docker_network_isolation(client)
        assert result.status == "warn"
        assert "Docker daemon is not running" in result.details

    def test_network_list_error(self):
        """Test unable to list Docker networks."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (1, "", "permission denied"),
            ]
        )
        result = check_docker_network_isolation(client)
        assert result.status == "fail"
        assert "Unable to list Docker networks" in result.details


class TestCheckDockerResourceLimits(unittest.TestCase):
    """Tests for check_docker_resource_limits function."""

    def test_all_containers_have_limits(self):
        """Test all containers have resource limits."""
        client = mock_ssh_exec(
            [
                (0, "", ""),  # docker info
                (0, "3\n", ""),  # 3 containers
                (0, "0\n", ""),  # no containers without memory limits
                (0, "0\n", ""),  # no containers without CPU limits
            ]
        )
        result = check_docker_resource_limits(client)
        assert result.status == "pass"
        assert "All 3 containers have resource limits configured" in result.details

    def test_no_running_containers(self):
        """Test no running containers."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "0\n", ""),
            ]
        )
        result = check_docker_resource_limits(client)
        assert result.status == "pass"
        assert result.details == "No running containers to check"

    def test_containers_without_memory_limits(self):
        """Test some containers without memory limits."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "5\n", ""),
                (0, "2\n", ""),  # 2 without memory limits
                (0, "0\n", ""),
            ]
        )
        result = check_docker_resource_limits(client)
        assert result.status == "warn"
        assert "2 containers without memory limits" in result.details

    def test_containers_without_cpu_limits(self):
        """Test some containers without CPU limits."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "4\n", ""),
                (0, "0\n", ""),
                (0, "3\n", ""),  # 3 without CPU limits
            ]
        )
        result = check_docker_resource_limits(client)
        assert result.status == "warn"
        assert "3 containers without CPU limits" in result.details

    def test_containers_without_any_limits(self):
        """Test containers without memory or CPU limits."""
        client = mock_ssh_exec(
            [
                (0, "", ""),
                (0, "10\n", ""),
                (0, "5\n", ""),  # 5 without memory limits
                (0, "7\n", ""),  # 7 without CPU limits
            ]
        )
        result = check_docker_resource_limits(client)
        assert result.status == "warn"
        assert "5 containers without memory limits" in result.details
        assert "7 containers without CPU limits" in result.details

    def test_docker_not_running(self):
        """Test Docker daemon not running."""
        client = mock_ssh_exec(
            [
                (1, "", ""),
            ]
        )
        result = check_docker_resource_limits(client)
        assert result.status == "warn"
        assert "Docker daemon is not running" in result.details


class TestRunAllChecks(unittest.TestCase):
    """Tests for run_all_checks function."""

    def test_run_all_checks(self):
        """Test running all container checks."""
        client = MagicMock()
        client.exec_command.return_value = (0, "output", "")

        results = run_all_checks(client)

        assert len(results) == 7
        # Check that all results are CheckResult objects with correct test_ids
        expected_test_ids = [
            "CONT-8100",
            "CONT-8101",
            "CONT-8102",
            "CONT-8103",
            "CONT-8104",
            "CONT-8105",
            "CONT-8106",
        ]
        actual_test_ids = [result.test_id for result in results]
        assert actual_test_ids == expected_test_ids


class TestRealSessionInterface(unittest.TestCase):
    """Regression: checks must only use the real SSHSession interface.

    Production passes a genuine SSHSession (which exposes .run, not
    .exec_command). A spec'd mock rejects any other attribute, so a
    recurrence of the exec_command bug fails here instead of in prod.
    """

    def test_run_all_checks_with_specd_session(self):
        """Full container suite runs against the true session API."""
        from linux_health.checks import CheckResult
        from linux_health.ssh_client import SSHSession

        client = MagicMock(spec=SSHSession)
        client.run.return_value = (0, "", "")
        results = run_all_checks(client)
        assert len(results) == 7
        assert all(isinstance(r, CheckResult) for r in results)

    def test_docker_installed_uses_run_not_exec_command(self):
        """Spot-check one probe goes through .run."""
        from linux_health.ssh_client import SSHSession

        client = MagicMock(spec=SSHSession)
        client.run.return_value = (0, "/usr/bin/docker", "")
        result = check_docker_installed(client)
        assert result.status in ("pass", "warn", "fail")
        assert client.run.called


if __name__ == "__main__":
    unittest.main()

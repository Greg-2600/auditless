"""Container security checks for Docker and container runtime environments.

This module implements container security checks following Lynis test patterns
(CONT-8100 to CONT-8106 range). Checks include Docker installation, daemon
configuration, image security, runtime hardening, and network isolation.

Author: Auditless Security Scanner
"""

from typing import TYPE_CHECKING

from auditless.checks import CheckResult, _fail, _pass, _unknown, _warn

if TYPE_CHECKING:
    from auditless.ssh_client import SSHSession


_CONTAINER_SOCKET_PROBE = (
    "for p in /var/run/docker.sock /run/podman/podman.sock "
    "/run/containerd/containerd.sock /run/user/*/podman/podman.sock "
    "/run/user/*/docker.sock; do "
    '[ -S "$p" ] || continue; '
    'if info=$(stat -Lc "%a %U:%G" "$p" 2>/dev/null); then '
    'printf "%s %s\\n" "$p" "$info"; '
    'else printf "unreadable %s\\n" "$p"; fi; '
    "done"
)

_ROOT_EQUIVALENT_GROUPS = frozenset({"root", "docker", "podman", "containerd"})


def check_docker_installed(client: "SSHSession", timeout: int = 60) -> CheckResult:
    """Check if Docker is installed on the system.

    Test ID: CONT-8100
    Category: Containers
    """
    category = "Containers"
    test_id = "CONT-8100"

    try:
        exit_code, stdout, stderr = client.run("which docker", timeout=timeout)

        if exit_code == 0 and stdout.strip():
            # Get Docker version
            exit_code, version_out, _ = client.run("docker --version", timeout=timeout)
            if exit_code == 0:
                return _pass(
                    "Docker Installation",
                    f"Docker is installed: {version_out.strip()}",
                    "Verify Docker security configuration",
                    category,
                    test_id,
                )
            return _pass(
                "Docker Installation",
                "Docker is installed",
                "Verify Docker security configuration",
                category,
                test_id,
            )

        return _warn(
            "Docker Installation",
            "Docker is not installed",
            "Install Docker if container workloads are needed",
            category,
            test_id,
        )
    except Exception as e:
        return _fail(
            "Docker Installation",
            f"Error checking Docker installation: {str(e)}",
            "Verify SSH connectivity and permissions",
            category,
            test_id,
        )


def check_docker_socket_permissions(
    client: "SSHSession", timeout: int = 60
) -> CheckResult:
    """Check Docker socket file permissions for security.

    Test ID: CONT-8101
    Category: Containers
    """
    category = "Containers"
    test_id = "CONT-8101"

    try:
        # Check if Docker socket exists
        exit_code, stdout, _ = client.run(
            "test -S /var/run/docker.sock && echo exists", timeout=timeout
        )

        if exit_code != 0 or "exists" not in stdout:
            return _warn(
                "Docker Socket Permissions",
                "Docker socket not found at /var/run/docker.sock",
                "Verify Docker is installed and socket path",
                category,
                test_id,
            )

        # Check socket permissions
        exit_code, stdout, _ = client.run(
            "stat -c '%a %U:%G' /var/run/docker.sock", timeout=timeout
        )

        if exit_code != 0:
            return _fail(
                "Docker Socket Permissions",
                "Unable to read Docker socket permissions",
                "Verify permissions to read socket metadata",
                category,
                test_id,
            )

        perms, ownership = stdout.strip().split(" ", 1)

        # Check for overly permissive settings (world-readable/writable)
        if perms.endswith("6") or perms.endswith("7"):
            return _fail(
                "Docker Socket Permissions",
                f"Docker socket has insecure permissions: {perms} ({ownership})",
                "Set secure permissions: chmod 660 /var/run/docker.sock",
                category,
                test_id,
            )

        # Verify root ownership
        if not ownership.startswith("root:"):
            return _warn(
                "Docker Socket Permissions",
                f"Docker socket not owned by root: {ownership}",
                "Change ownership: chown root:docker /var/run/docker.sock",
                category,
                test_id,
            )

        return _pass(
            "Docker Socket Permissions",
            f"Docker socket permissions are secure: {perms} ({ownership})",
            "Maintain current secure configuration",
            category,
            test_id,
        )

    except Exception as e:
        return _fail(
            "Docker Socket Permissions",
            f"Error checking Docker socket permissions: {str(e)}",
            "Verify SSH connectivity and permissions",
            category,
            test_id,
        )


def check_docker_daemon_config(client: "SSHSession", timeout: int = 60) -> CheckResult:
    """Check Docker daemon security configuration.

    Test ID: CONT-8102
    Category: Containers
    """
    category = "Containers"
    test_id = "CONT-8102"

    try:
        # Check if daemon.json exists
        exit_code, stdout, _ = client.run(
            "test -f /etc/docker/daemon.json && echo exists", timeout=timeout
        )

        if exit_code != 0 or "exists" not in stdout:
            return _warn(
                "Docker Daemon Configuration",
                "Docker daemon config file not found at /etc/docker/daemon.json",
                "Create /etc/docker/daemon.json with security settings",
                category,
                test_id,
            )

        # Read daemon.json content
        exit_code, stdout, _ = client.run(
            "cat /etc/docker/daemon.json", timeout=timeout
        )

        if exit_code != 0:
            return _fail(
                "Docker Daemon Configuration",
                "Unable to read Docker daemon configuration",
                "Verify file permissions on /etc/docker/daemon.json",
                category,
                test_id,
            )

        config = stdout.strip()
        security_issues = []
        security_features = []

        # Check for security features
        if '"userns-remap"' in config:
            security_features.append("user namespace remapping")
        else:
            security_issues.append("user namespace remapping not enabled")

        if '"live-restore": true' in config:
            security_features.append("live restore")

        if '"disable-legacy-registry": true' in config:
            security_features.append("legacy registry disabled")

        if '"tlsverify": true' in config:
            security_features.append("TLS verification")

        if security_issues:
            message = (
                f"Docker daemon security issues found: {', '.join(security_issues)}"
            )
            if security_features:
                message += f" | Enabled: {', '.join(security_features)}"
            return _warn(
                "Docker Daemon Configuration",
                message,
                "Enable user namespace remapping: userns-remap=default",
                category,
                test_id,
            )

        if security_features:
            return _pass(
                "Docker Daemon Configuration",
                f"Docker daemon security features enabled: {', '.join(security_features)}",
                "Maintain current secure configuration",
                category,
                test_id,
            )

        return _warn(
            "Docker Daemon Configuration",
            "Docker daemon configuration lacks recommended security settings",
            "Add security settings to /etc/docker/daemon.json",
            category,
            test_id,
        )

    except Exception as e:
        return _fail(
            "Docker Daemon Configuration",
            f"Error checking Docker daemon configuration: {str(e)}",
            "Verify SSH connectivity and permissions",
            category,
            test_id,
        )


def check_docker_image_security(client: "SSHSession", timeout: int = 60) -> CheckResult:
    """Check for untrusted or vulnerable Docker images.

    Test ID: CONT-8103
    Category: Containers
    """
    category = "Containers"
    test_id = "CONT-8103"

    try:
        # Check if Docker is running
        exit_code, _, _ = client.run("docker info > /dev/null 2>&1", timeout=timeout)

        if exit_code != 0:
            return _warn(
                "Docker Image Security",
                "Docker daemon is not running",
                "Start Docker daemon: systemctl start docker",
                category,
                test_id,
            )

        # Get image list
        exit_code, stdout, _ = client.run(
            "docker images --format '{{.Repository}}:{{.Tag}}'", timeout=timeout
        )

        if exit_code != 0:
            return _fail(
                "Docker Image Security",
                "Unable to list Docker images",
                "Verify Docker permissions for current user",
                category,
                test_id,
            )

        if not stdout.strip():
            return _pass(
                "Docker Image Security",
                "No Docker images found on system",
                "Pull only images from trusted registries",
                category,
                test_id,
            )

        images = stdout.strip().split("\n")
        latest_images = [img for img in images if img.endswith(":latest")]

        total_count = len(images)
        latest_count = len(latest_images)

        issues = []

        if latest_count > 0:
            issues.append(f"{latest_count} images using 'latest' tag")

        if total_count > 50:
            issues.append(f"excessive image count ({total_count})")

        if issues:
            return _warn(
                "Docker Image Security",
                f"Docker image security concerns: {', '.join(issues)}",
                "Pin image versions and remove unused images",
                category,
                test_id,
            )

        return _pass(
            "Docker Image Security",
            f"Docker images properly tagged: {total_count} images found",
            "Regularly scan images for vulnerabilities",
            category,
            test_id,
        )

    except Exception as e:
        return _fail(
            "Docker Image Security",
            f"Error checking Docker image security: {str(e)}",
            "Verify SSH connectivity and Docker permissions",
            category,
            test_id,
        )


def check_docker_container_runtime(
    client: "SSHSession", timeout: int = 60
) -> CheckResult:
    """Check running containers for security issues.

    Test ID: CONT-8104
    Category: Containers
    """
    category = "Containers"
    test_id = "CONT-8104"

    try:
        # Check if Docker is running
        exit_code, _, _ = client.run("docker info > /dev/null 2>&1", timeout=timeout)

        if exit_code != 0:
            return _warn(
                "Container Runtime Security",
                "Docker daemon is not running",
                "Start Docker daemon: systemctl start docker",
                category,
                test_id,
            )

        # Get running container count
        exit_code, stdout, _ = client.run("docker ps -q | wc -l", timeout=timeout)

        if exit_code != 0:
            return _fail(
                "Container Runtime Security",
                "Unable to list running containers",
                "Verify Docker permissions for current user",
                category,
                test_id,
            )

        container_count = int(stdout.strip())

        if container_count == 0:
            return _pass(
                "Container Runtime Security",
                "No running containers found",
                "Follow security best practices when running containers",
                category,
                test_id,
            )

        # Check for privileged containers
        exit_code, stdout, _ = client.run(
            "docker ps --format '{{.ID}}' | xargs -I {} docker inspect --format '{{.Id}}:{{.HostConfig.Privileged}}' {} | grep ':true' | wc -l",
            timeout=timeout,
        )

        privileged_count = int(stdout.strip()) if exit_code == 0 else 0

        # Check for host network mode
        exit_code, stdout, _ = client.run(
            "docker ps --format '{{.ID}}' | xargs -I {} docker inspect --format '{{.Id}}:{{.HostConfig.NetworkMode}}' {} | grep ':host' | wc -l",
            timeout=timeout,
        )

        host_network_count = int(stdout.strip()) if exit_code == 0 else 0

        issues = []

        if privileged_count > 0:
            issues.append(f"{privileged_count} privileged containers")

        if host_network_count > 0:
            issues.append(f"{host_network_count} containers using host network")

        if container_count > 100:
            issues.append(f"excessive running containers ({container_count})")

        if issues:
            return _fail(
                "Container Runtime Security",
                f"Container runtime security issues: {', '.join(issues)}",
                "Avoid privileged containers and host network mode",
                category,
                test_id,
            )

        return _pass(
            "Container Runtime Security",
            f"{container_count} containers running with secure configuration",
            "Regularly review container security settings",
            category,
            test_id,
        )

    except Exception as e:
        return _fail(
            "Container Runtime Security",
            f"Error checking container runtime security: {str(e)}",
            "Verify SSH connectivity and Docker permissions",
            category,
            test_id,
        )


def check_docker_network_isolation(
    client: "SSHSession", timeout: int = 60
) -> CheckResult:
    """Check Docker network isolation and security.

    Test ID: CONT-8105
    Category: Containers
    """
    category = "Containers"
    test_id = "CONT-8105"

    try:
        # Check if Docker is running
        exit_code, _, _ = client.run("docker info > /dev/null 2>&1", timeout=timeout)

        if exit_code != 0:
            return _warn(
                "Docker Network Isolation",
                "Docker daemon is not running",
                "Start Docker daemon: systemctl start docker",
                category,
                test_id,
            )

        # Get network list
        exit_code, stdout, _ = client.run(
            "docker network ls --format '{{.Name}}'", timeout=timeout
        )

        if exit_code != 0:
            return _fail(
                "Docker Network Isolation",
                "Unable to list Docker networks",
                "Verify Docker permissions for current user",
                category,
                test_id,
            )

        networks = stdout.strip().split("\n") if stdout.strip() else []

        # Filter out default networks
        default_networks = {"bridge", "host", "none"}
        custom_networks = [n for n in networks if n not in default_networks]

        if not custom_networks:
            return _warn(
                "Docker Network Isolation",
                "No custom Docker networks found - using default bridge network",
                "Create custom networks: docker network create app-network",
                category,
                test_id,
            )

        # Check if containers are using default bridge
        exit_code, stdout, _ = client.run(
            "docker ps --format '{{.ID}}' | xargs -I {} docker inspect --format '{{.NetworkSettings.Networks}}' {} | grep -c 'bridge' || true",
            timeout=timeout,
        )

        default_bridge_count = (
            int(stdout.strip()) if stdout.strip() and stdout.strip().isdigit() else 0
        )

        if default_bridge_count > 0:
            return _warn(
                "Docker Network Isolation",
                f"Network isolation: {len(custom_networks)} custom networks, but {default_bridge_count} containers on default bridge",
                "Move containers to custom networks for better isolation",
                category,
                test_id,
            )

        return _pass(
            "Docker Network Isolation",
            f"Docker network isolation configured: {len(custom_networks)} custom networks in use",
            "Maintain network segmentation for security",
            category,
            test_id,
        )

    except Exception as e:
        return _fail(
            "Docker Network Isolation",
            f"Error checking Docker network isolation: {str(e)}",
            "Verify SSH connectivity and Docker permissions",
            category,
            test_id,
        )


def check_docker_resource_limits(
    client: "SSHSession", timeout: int = 60
) -> CheckResult:
    """Check if containers have resource limits configured.

    Test ID: CONT-8106
    Category: Containers
    """
    category = "Containers"
    test_id = "CONT-8106"

    try:
        # Check if Docker is running
        exit_code, _, _ = client.run("docker info > /dev/null 2>&1", timeout=timeout)

        if exit_code != 0:
            return _warn(
                "Container Resource Limits",
                "Docker daemon is not running",
                "Start Docker daemon: systemctl start docker",
                category,
                test_id,
            )

        # Get running container count
        exit_code, stdout, _ = client.run("docker ps -q | wc -l", timeout=timeout)

        if exit_code != 0:
            return _fail(
                "Container Resource Limits",
                "Unable to list running containers",
                "Verify Docker permissions for current user",
                category,
                test_id,
            )

        container_count = int(stdout.strip())

        if container_count == 0:
            return _pass(
                "Container Resource Limits",
                "No running containers to check",
                "Use --memory and --cpus flags when running containers",
                category,
                test_id,
            )

        # Check for containers without memory limits
        exit_code, stdout, _ = client.run(
            "docker ps --format '{{.ID}}' | xargs -I {} docker inspect --format '{{.Id}}:{{.HostConfig.Memory}}' {} | grep ':0$' | wc -l",
            timeout=timeout,
        )

        no_memory_limit = int(stdout.strip()) if exit_code == 0 else container_count

        # Check for containers without CPU limits
        exit_code, stdout, _ = client.run(
            "docker ps --format '{{.ID}}' | xargs -I {} docker inspect --format '{{.Id}}:{{.HostConfig.NanoCpus}}' {} | grep ':0$' | wc -l",
            timeout=timeout,
        )

        no_cpu_limit = int(stdout.strip()) if exit_code == 0 else container_count

        issues = []

        if no_memory_limit > 0:
            issues.append(f"{no_memory_limit} containers without memory limits")

        if no_cpu_limit > 0:
            issues.append(f"{no_cpu_limit} containers without CPU limits")

        if issues:
            return _warn(
                "Container Resource Limits",
                f"Container resource limits not configured: {', '.join(issues)}",
                "Add resource limits: docker run --memory=512m --cpus=0.5",
                category,
                test_id,
            )

        return _pass(
            "Container Resource Limits",
            f"All {container_count} containers have resource limits configured",
            "Regularly review and adjust resource limits",
            category,
            test_id,
        )

    except Exception as e:
        return _fail(
            "Container Resource Limits",
            f"Error checking container resource limits: {str(e)}",
            "Verify SSH connectivity and Docker permissions",
            category,
            test_id,
        )


def check_container_runtime_socket_exposure(
    client: "SSHSession", timeout: int = 60
) -> CheckResult:
    """Check Docker, Podman, and containerd runtime socket exposure.

    Test ID: CONT-8107
    Category: Containers
    """
    category = "Containers"
    test_id = "CONT-8107"

    try:
        exit_code, stdout, stderr = client.run(_CONTAINER_SOCKET_PROBE, timeout=timeout)
        if exit_code != 0 and not stdout.strip():
            return _unknown(
                "Container Runtime Socket Exposure",
                f"Unable to probe container runtime sockets: {stderr.strip()}",
                "Verify SSH connectivity and permission to inspect runtime sockets",
                category,
                test_id,
            )

        checked: list[str] = []
        world_accessible: list[str] = []
        group_writable: list[str] = []
        root_equivalent_group: list[str] = []
        unreadable: list[str] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("unreadable "):
                unreadable.append(line.split(None, 1)[1])
                continue
            parts = line.split(None, 2)
            if len(parts) != 3:
                continue
            path, mode, ownership = parts
            try:
                bits = int(mode, 8)
            except ValueError:
                unreadable.append(path)
                continue
            checked.append(f"{path} ({mode} {ownership})")
            if bits & 0o007:
                world_accessible.append(f"{path} ({mode} {ownership})")
            elif bits & 0o020:
                owner, _, group = ownership.partition(":")
                if owner == "root" and group in _ROOT_EQUIVALENT_GROUPS:
                    root_equivalent_group.append(f"{path} ({mode} {ownership})")
                else:
                    group_writable.append(f"{path} ({mode} {ownership})")

        if world_accessible:
            details = "World-accessible container runtime socket(s): " + ", ".join(
                world_accessible
            )
            if group_writable:
                details += "; group-writable: " + ", ".join(group_writable)
            if unreadable:
                details += "; unreadable: " + ", ".join(unreadable)
            return _fail(
                "Container Runtime Socket Exposure",
                details,
                "Restrict runtime sockets to root or a dedicated admin group "
                "and remove world access",
                category,
                test_id,
            )

        if group_writable:
            details = "Group-writable container runtime socket(s): " + ", ".join(
                group_writable
            )
            if unreadable:
                details += "; unreadable: " + ", ".join(unreadable)
            return _warn(
                "Container Runtime Socket Exposure",
                details + " (runtime group access is root-equivalent)",
                "Remove group write access to runtime sockets or restrict the "
                "group to trusted administrators",
                category,
                test_id,
            )

        if unreadable:
            return _unknown(
                "Container Runtime Socket Exposure",
                "Unable to inspect container runtime socket(s): "
                + ", ".join(unreadable),
                "Verify permission to stat runtime sockets",
                category,
                test_id,
            )

        if checked:
            details = (
                "Container runtime sockets use compliant permissions: "
                + ", ".join(checked)
            )
            if root_equivalent_group:
                details += (
                    "; membership in the root/docker/podman/containerd group is "
                    "root-equivalent: " + ", ".join(root_equivalent_group)
                )
            return _pass(
                "Container Runtime Socket Exposure",
                details,
                "Maintain restricted access to container runtime sockets",
                category,
                test_id,
            )

        return _pass(
            "Container Runtime Socket Exposure",
            "No container runtime sockets found",
            "Maintain root-only access to runtime sockets if containers are added",
            category,
            test_id,
        )

    except Exception as e:
        return _fail(
            "Container Runtime Socket Exposure",
            f"Error checking container runtime socket exposure: {str(e)}",
            "Verify SSH connectivity and permissions",
            category,
            test_id,
        )


def run_all_checks(client: "SSHSession", timeout: int = 60) -> list[CheckResult]:
    """Run all container security checks.

    Args:
        client: SSH client connection to target system
        timeout: Command execution timeout in seconds

    Returns:
        List of CheckResult objects
    """
    return [
        check_docker_installed(client, timeout),
        check_docker_socket_permissions(client, timeout),
        check_docker_daemon_config(client, timeout),
        check_docker_image_security(client, timeout),
        check_docker_container_runtime(client, timeout),
        check_docker_network_isolation(client, timeout),
        check_docker_resource_limits(client, timeout),
        check_container_runtime_socket_exposure(client, timeout),
    ]

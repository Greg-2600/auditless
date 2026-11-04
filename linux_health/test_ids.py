"""Canonical Lynis-style test-ID registry (one identifier per check).

Supersedes scripts/add_test_ids.py (a regex source patcher that was only
ever applied partially): IDs are attached at runtime by the
``with_test_id`` decorator in checks.py, driven by this table.
"""

from __future__ import annotations

# Check function name -> test ID. Duplicates are historical (two checks
# sharing AUTH-9408/FILE-6310/NETW-3032); profile filtering treats them
# as one identifier, which the compliance mapper also accounts for.
CHECK_TEST_IDS: dict[str, str] = {
    "check_disk_usage": "STOR-6310",
    "check_memory": "MEM-2914",
    "check_load": "CPU-1620",
    "check_reboot_required": "KERN-5830",
    "check_updates": "PKGS-7380",
    "check_ssh_config": "SSH-7408",
    "check_firewall": "FIRE-4512",
    "check_time_sync": "TIME-3104",
    "check_accounts": "AUTH-9234",
    "check_auth_failures": "AUTH-9252",
    "check_root_logins": "AUTH-9262",
    "check_listening_services": "NETW-3030",
    "check_abnormal_network_processes": "NETW-3032",
    "check_suspicious_process_locations": "MALW-3280",
    "check_unexpected_sudo_usage": "AUTH-9328",
    "check_recently_created_accounts": "AUTH-9340",
    "check_system_binary_modifications": "FINT-4350",
    "check_failed_login_spike": "AUTH-9408",
    "check_suid_files": "FILE-6310",
    "check_cron_and_timers": "SCHD-7230",
    "check_stale_user_accounts": "AUTH-9408",
    "check_process_resource_usage": "PROC-3612",
    "check_suspicious_network_connections": "NETW-3200",
    "check_hidden_files_in_system_dirs": "FILE-6374",
    "check_kernel_module_integrity": "KRNL-5788",
    "check_active_reverse_shells": "MALW-3288",
    "check_weak_password_policy": "AUTH-9230",
    "check_container_escape_indicators": "CONT-8104",
    "check_arp_spoofing": "NETW-3032",
    "check_dns_tampering": "NETW-3035",
    "check_crypto_miners": "MALW-3292",
    "check_file_integrity_critical_binaries": "FINT-4402",
    "check_log_tampering": "LOGG-2154",
    "check_privilege_escalation_vectors": "AUTH-9283",
    "check_world_writable_system_files": "FILE-7524",
    "check_deleted_file_handles": "PROC-3602",
    "check_boot_loader_password": "BOOT-5122",
    "check_kernel_hardening": "KERN-5820",
    "check_file_integrity_tools": "FINT-4316",
    "check_package_manager_security": "PKGS-7388",
    "check_logging_and_auditing": "LOGG-2138",
    "check_selinux_apparmor": "MACF-6234",
    "check_security_tools": "TOOL-5002",
    "check_filesystem_mounts": "FILE-6310",
    "check_shell_security": "SHLL-6202",
    "check_compiler_presence": "HRDN-7220",
    "check_legacy_services": "INSE-8016",
    "check_usb_storage": "USB-1000",
    "check_web_server_security": "HTTP-6622",
    "check_database_security": "DBS-1804",
    "check_mail_server_security": "MAIL-8816",
    "check_php_security": "PHP-2320",
    "check_dns_configuration": "NAME-4016",
}

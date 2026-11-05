"""Linux Health Security Scanner - Enterprise-Grade Security Assessment Platform.

A comprehensive SSH-based security scanning tool that performs 50+ automated checks
for malware detection, vulnerability assessment, compliance monitoring, and system
health analysis without requiring agent installation.

Features:
    - Zero-touch SSH-based deployment (agentless)
    - 50+ security checks across 20+ categories
    - Lynis-compatible test IDs for precise tracking
    - JSON output for automation and CI/CD integration
    - YAML-based profile system for environment-specific scanning
    - Hardening index scoring (0-100 scale)
    - Multiple output formats (text, markdown, JSON)
    - Enterprise-ready error handling and timeout management
    - Full Docker and Kubernetes support

Version: 2.0.0 (95% Lynis parity)
Author: Linux Health Team
License: MIT
"""

__all__ = ["__version__"]
__version__ = "2.5.0"

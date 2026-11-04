"""Setup configuration for Auditless (Linux Health Security Scanner).

Thin setuptools shim: authoritative metadata lives in pyproject.toml.
Paths resolve relative to this file so isolated builds (python -m build,
pip install .) work regardless of the backend's working directory.
"""

import re
from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).resolve().parent

long_description = (ROOT / "README.md").read_text(encoding="utf-8")

requirements = [
    line.strip()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith(("#", "-"))
]

init_text = (ROOT / "linux_health" / "__init__.py").read_text(encoding="utf-8")
version = re.search(r'__version__\s*=\s*"([^"]+)"', init_text).group(1)  # type: ignore[union-attr]

setup(
    name="auditless",
    version=version,
    author="Greg Baker",
    description="Agentless Linux security assessment with hardening index",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Greg-2600/auditless",
    project_urls={
        "Bug Tracker": "https://github.com/Greg-2600/auditless/issues",
        "Documentation": "https://github.com/Greg-2600/auditless#readme",
        "Source Code": "https://github.com/Greg-2600/auditless",
    },
    packages=find_packages(include=["linux_health", "linux_health.*"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "auditless=linux_health.cli:main",
            "linux-health=linux_health.cli:main",
        ],
    },
    include_package_data=True,
    keywords=[
        "security",
        "scanning",
        "linux",
        "malware",
        "vulnerability",
        "compliance",
        "audit",
    ],
)

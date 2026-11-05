"""Tests for CI/CD workflow definitions (parsed, never executed here)."""

import pathlib

import yaml

WORKFLOWS = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows"


def _load(name):
    with open(WORKFLOWS / name, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def test_all_workflows_parse():
    """Every workflow file is valid YAML with jobs."""
    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc = _load(path.name)
        assert isinstance(doc, dict), path.name
        assert doc.get("jobs"), f"{path.name} has no jobs"


def test_no_moving_action_pins():
    """Actions pin to versions, never @master/@main (supply-chain hygiene)."""
    import re

    text = " ".join(
        (WORKFLOWS / name).read_text()
        for name in ("docker.yml", "release.yml", "tests.yml", "codeql.yml")
    )
    for bad in re.findall(r"uses:\s*\S+@(master|main)\b", text):
        raise AssertionError(f"moving action pin found: {bad}")


def test_release_signs_and_verifies():
    """Release pipeline has the full sign -> verify chain."""
    doc = _load("release.yml")
    jobs = doc["jobs"]
    assert set(jobs) >= {
        "create-release",
        "publish-docker",
        "sign-image",
        "verify-release",
    }
    build = jobs["publish-docker"]["steps"]
    assert any("provenance" in str(s) for s in build)
    assert any("sbom" in str(s).lower() for s in build)
    verify_steps = jobs["verify-release"]["steps"]
    blob = " ".join(str(s) for s in verify_steps)
    assert "cosign verify" in blob
    assert "verify-attestation" in blob
    assert "download sbom" in blob


def test_docker_workflow_uses_pinned_trivy():
    """Trivy runs from a pinned image, uploading SARIF with permission."""
    doc = _load("docker.yml")
    job = doc["jobs"]["security-scan"]
    assert job["permissions"].get("security-events") == "write"
    blob = " ".join(str(s) for s in job["steps"])
    assert "aquasec/trivy:" in blob
    assert "trivy-action@master" not in blob

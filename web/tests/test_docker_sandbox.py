"""Real isolation checks against Docker. Run with AGW_DOCKER_TESTS=1 after
building the scanner image (docker build -f web/docker/scanner.Dockerfile -t agentguard-scanner:local .)."""

from __future__ import annotations

import json
import os

import pytest
from conftest import tarball, LURE

from agentguard_web.cli import check_sandbox
from agentguard_web.config import Settings
from agentguard_web.sandbox import DockerSandbox, SandboxError

pytestmark = pytest.mark.skipif(os.environ.get("AGW_DOCKER_TESTS") != "1", reason="set AGW_DOCKER_TESTS=1 to run Docker tests")
IMAGE = os.environ.get("AGW_SCANNER_IMAGE", "agentguard-scanner:local")
SPEC = {"source": {"kind": "npm", "locator": "pdf-helper-mcp", "resolved": "1.2.3", "integrity": "sha512:00"},
        "strip_components": 1}


def test_scan_runs_in_the_container():
    out = DockerSandbox(IMAGE).run(tarball({"SKILL.md": LURE}), SPEC, 120)
    report = json.loads(out)
    assert report["target"]["resolved"] == "1.2.3"
    assert any(f["rule_id"].startswith("AG-SKL-SE-") for f in report["findings"])


def test_container_report_is_deterministic():
    data = tarball({"SKILL.md": LURE})
    assert DockerSandbox(IMAGE).run(data, SPEC, 120) == DockerSandbox(IMAGE).run(data, SPEC, 120)


def test_container_has_no_network_egress():
    assert check_sandbox(Settings(scanner_image=IMAGE)) == 0


def test_garbage_archive_is_an_error_not_a_crash():
    with pytest.raises(SandboxError):
        DockerSandbox(IMAGE).run(b"not an archive", SPEC, 60)


def test_timeout_kills_the_container():
    import subprocess
    import time

    with pytest.raises(SandboxError, match="exceeded"):
        DockerSandbox(IMAGE).run(tarball({"SKILL.md": LURE}), SPEC, 0.05)  # shorter than container start-up
    time.sleep(3)  # let a late container create finish, so a leak would show
    left = subprocess.run(["docker", "ps", "-aq", "--filter", "name=agw-scan-"], capture_output=True, text=True).stdout
    assert not left.strip(), "a timed-out scan container was left behind"

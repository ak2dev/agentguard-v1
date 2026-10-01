"""Where scans run.

``DockerSandbox`` (the only option allowed in production) starts one fresh
container per job from the scanner image, with:

* ``--network none``: no network interface except loopback;
* ``--read-only`` root filesystem plus a small noexec tmpfs;
* a non-root user, all capabilities dropped, ``no-new-privileges``;
* CPU, memory, PID and wall-clock limits;
* an optional hardened runtime (``--runtime runsc`` for gVisor);
* no environment, no mounts, no credentials.

The archive and job spec go in on stdin; the report JSON comes back on stdout;
the container is always force-removed afterwards, including on timeout. The container
runs Agent Guard's own scanner, never the scanned code.

``InProcessSandbox`` runs the same entry point in-process, with no isolation;
it exists for tests and local development and is refused in production.
"""

from __future__ import annotations

import io
import json
import secrets
import subprocess
from typing import Protocol

from agentguard.sandbox_entry import frame
from agentguard.sandbox_entry import run as run_entry

MAX_REPORT_BYTES = 32 * 1024 * 1024


class SandboxError(RuntimeError):
    pass


class Sandbox(Protocol):
    def run(self, archive: bytes, spec: dict, timeout_s: int) -> str: ...


def _parse(out: str) -> str:
    try:
        doc = json.loads(out)
    except ValueError as exc:
        raise SandboxError("the scanner returned no valid report") from exc
    if isinstance(doc, dict) and "error" in doc and "findings" not in doc:
        raise SandboxError(str(doc["error"])[:300])
    return out


class InProcessSandbox:
    """No isolation — tests and local development only."""

    def run(self, archive: bytes, spec: dict, timeout_s: int) -> str:  # noqa: ARG002
        _code, out = run_entry(io.BytesIO(frame(spec, archive)))
        return _parse(out)


class DockerSandbox:
    def __init__(self, image: str, *, runtime: str = "", memory: str = "768m", cpus: str = "1",
                 pids: int = 64, docker: str = "docker") -> None:
        self.image = image
        self.runtime = runtime
        self.memory = memory
        self.cpus = cpus
        self.pids = pids
        self.docker = docker

    def flags(self) -> list[str]:
        """The isolation every scan container gets."""
        flags = [
            "--network", "none",
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--user", "65534:65534",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids),
            "--memory", self.memory, "--memory-swap", self.memory,
            "--cpus", self.cpus,
            "--ulimit", "nofile=256:256",
            "--log-driver", "none",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
        ]
        if self.runtime:
            flags += ["--runtime", self.runtime]
        return flags

    def argv(self, name: str) -> list[str]:
        """A one-shot `docker run` with the same isolation (used by check-sandbox)."""
        return [self.docker, "run", "--rm", "-i", "--name", name, *self.flags(), self.image]

    def _docker(self, *args: str, timeout: float = 30, data: bytes | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([self.docker, *args], input=data, capture_output=True, timeout=timeout, check=False)  # noqa: S603

    def run(self, archive: bytes, spec: dict, timeout_s: float) -> str:
        """create (returns once the container exists) → start with a time limit → always remove.
        Separating create from start means a timeout can never leave a container behind."""
        name = f"agw-scan-{secrets.token_hex(8)}"
        try:
            created = self._docker("create", "-i", "--name", name, *self.flags(), self.image)
        except FileNotFoundError as exc:
            raise SandboxError("docker is not available to the dispatcher") from exc
        if created.returncode != 0:
            raise SandboxError(f"could not create the scanner container: {created.stderr.decode(errors='replace').strip()[-200:]}")
        try:
            proc = self._docker("start", "-ai", name, timeout=timeout_s, data=frame(spec, archive))
        except subprocess.TimeoutExpired as exc:
            raise SandboxError(f"scan exceeded {timeout_s} s and was stopped") from exc
        finally:
            self._docker("rm", "-f", name)
        if len(proc.stdout) > MAX_REPORT_BYTES:
            raise SandboxError("the scanner's report was too large")
        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode not in (0, 2):
            raise SandboxError(f"scanner container failed (exit {proc.returncode}): "
                               f"{proc.stderr.decode('utf-8', 'replace').strip()[-200:]}")
        return _parse(out)


def make_sandbox(kind: str, image: str, runtime: str = "") -> Sandbox:
    if kind == "docker":
        return DockerSandbox(image, runtime=runtime)
    if kind == "inprocess":
        return InProcessSandbox()
    raise ValueError(f"unknown sandbox {kind!r}")

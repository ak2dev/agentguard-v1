"""The only process Agent Guard ever starts: a hardened, read-only ``git``
used by PR mode (``--changed-since``) and to read config from the base ref.

Hardening: repo-local config cannot run commands (fsmonitor, hooks, external
diff, textconv are disabled on the command line), system config is ignored,
no pager/prompt, commit-to-commit diffs only (no worktree filters), and the
exact argv is pre-authorized with the no-exec audit guard.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import regex

from . import guard

_REF = regex.compile(r"^(?!-)[A-Za-z0-9._/~^@{}+\-]{1,200}$")
_PATH = regex.compile(r"^(?!-)[^\x00:]{1,500}$")


class GitError(RuntimeError):
    pass


def _base_argv(repo: Path) -> list[str]:
    return [
        "git",
        "-c", "core.fsmonitor=false",
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "diff.external=",
        "-c", "core.pager=cat",
        "-c", "protocol.allow=never",
        "--no-pager",
        "-C", str(repo),
    ]


def _env() -> dict[str, str]:
    keep = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "HOME", "USERPROFILE", "TEMP", "TMP")}
    keep.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "PAGER": "cat",
                 "GIT_ASKPASS": "", "SSH_ASKPASS": "", "LC_ALL": "C"})
    return keep


def _run(argv: list[str], timeout: float = 30) -> bytes:
    with guard.allow_exact(argv):
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout, shell=False, env=_env(), check=False)  # noqa: S603
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitError(f"git failed: {type(exc).__name__}") from exc
    if proc.returncode != 0:
        raise GitError(proc.stderr.decode("utf-8", "replace").strip()[:300] or "git failed")
    return proc.stdout


def changed_files(repo: Path, ref: str) -> list[str]:
    if not _REF.match(ref):
        raise GitError(f"refusing unusual ref {ref!r}")
    argv = [*_base_argv(repo), "diff", "--name-only", "--no-ext-diff", "--no-textconv", "--no-renames", "-z",
            f"{ref}...HEAD", "--"]
    out = _run(argv)
    return sorted(p for p in out.decode("utf-8", "replace").split("\x00") if p)


def read_at_ref(repo: Path, ref: str, path: str, max_bytes: int = 1 << 20) -> bytes | None:
    if not _REF.match(ref) or not _PATH.match(path):
        raise GitError("refusing unusual ref or path")
    argv = [*_base_argv(repo), "cat-file", "blob", f"{ref}:{path}"]
    try:
        data = _run(argv)
    except GitError:
        return None
    return data if len(data) <= max_bytes else None

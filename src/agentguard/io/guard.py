"""Process-level no-execution guard.

Installs a ``sys.addaudithook`` hook that raises on any attempt to start a
process. Audit hooks cannot be removed once installed, so after the CLI calls
``install()`` nothing in this interpreter — including a bug in a parser or a
dependency — can execute a scanned target.

The single exception is the hardened ``git`` invocation used by PR mode
(``allow_git()`` context manager), which only permits the exact argv built by
``agentguard.io.git``.
"""

from __future__ import annotations

import contextlib
import sys
import threading
from collections.abc import Iterator, Sequence

_BLOCKED_EVENTS = {
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "os.startfile",
    "os.fork",
    "os.forkpty",
    "pty.spawn",
    "_winapi.CreateProcess",
}

_state = threading.local()
_installed = False


class ExecutionBlocked(RuntimeError):
    pass


def _hook(event: str, args: tuple) -> None:
    if event not in _BLOCKED_EVENTS:
        return
    allowed: Sequence[str] | None = getattr(_state, "allowed_argv", None)
    if allowed is not None:
        if event == "subprocess.Popen" and len(args) > 1 and list(args[1]) == list(allowed):
            _state.popen_ok = True
            return
        if event in ("_winapi.CreateProcess", "os.posix_spawn") and getattr(_state, "popen_ok", False):
            _state.popen_ok = False
            return
    raise ExecutionBlocked(f"Agent Guard never executes processes (blocked audit event {event!r})")


def install() -> None:
    global _installed
    if _installed:
        return
    sys.addaudithook(_hook)
    _installed = True


def is_installed() -> bool:
    return _installed


@contextlib.contextmanager
def allow_exact(argv: Sequence[str]) -> Iterator[None]:
    """Permit exactly one argv (used only by the hardened git helper)."""
    _state.allowed_argv = list(argv)
    _state.popen_ok = False
    try:
        yield
    finally:
        _state.allowed_argv = None
        _state.popen_ok = False

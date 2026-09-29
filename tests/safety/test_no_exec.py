"""Agent Guard must never execute a scanned target.

Runs in a subprocess so the (irremovable) audit hook does not leak into the
rest of the test session. Inside it: install the guard, scan every fixture
and bench item, and prove process creation is impossible.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

CHILD = textwrap.dedent(
    """
    import os, subprocess, sys
    from pathlib import Path
    sys.path.insert(0, str(Path(sys.argv[1]) / "src"))
    from agentguard.io import guard
    guard.install()
    from agentguard.core.engine import scan
    from agentguard.core.models import ScanOptions
    from agentguard.io.fs_loader import load_path
    from agentguard.core.archive import from_archive

    repo = Path(sys.argv[1])
    n = 0
    for base in (repo / "fixtures" / "rules", repo / "bench" / "corpus"):
        if not base.exists():
            continue
        for case in sorted(p for p in base.glob("*/*/*") if p.is_dir()):
            z = case / "_archive.zip"
            tree = from_archive(z.read_bytes()) if z.exists() else load_path(case)
            scan(tree, ScanOptions())
            n += 1
    blocked = 0
    for attempt in (lambda: subprocess.run(["echo", "x"]), lambda: os.system("echo x"),
                    lambda: subprocess.Popen([sys.executable, "-c", "print(1)"])):
        try:
            attempt()
        except guard.ExecutionBlocked:
            blocked += 1
        except Exception as exc:  # noqa: BLE001
            print("unexpected", type(exc).__name__, exc)
    print(f"scanned={n} blocked={blocked}")
    """
)


def test_scanning_never_executes_and_exec_is_blocked(tmp_path):
    script = tmp_path / "child.py"
    script.write_text(CHILD, encoding="utf-8")
    proc = subprocess.run([sys.executable, str(script), str(REPO)], capture_output=True, text=True, timeout=600)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "blocked=3" in out, out
    scanned = int(out.split("scanned=")[1].split()[0])
    assert scanned > 100, out

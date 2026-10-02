"""Entry point run inside Agent Guard Web's isolated scanner sandbox.

    python -m agentguard.sandbox_entry  < (job spec JSON line + "\\n" + archive bytes)  > report.json

The sandbox has no network, a read-only filesystem and no credentials. This
program reads one compact JSON line (the job spec, at most MAX_SPEC bytes)
followed by one payload (at most MAX_ARCHIVE bytes) from stdin: an archive, or
for ``mode: remote_mcp`` the JSON a read-only remote MCP probe recorded. It scans it with
the pure engine, and writes the report JSON to stdout. On failure it writes
{"error": "..."} to stdout and exits 2. It never executes anything: the
process-creation guard is installed before any input is read.
"""

from __future__ import annotations

import json
import sys
from typing import BinaryIO

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_SPEC = 512 * 1024


def frame(spec: dict, archive: bytes) -> bytes:
    """What the dispatcher writes to the sandbox's stdin."""
    return json.dumps(spec, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n" + archive


def run(stdin: BinaryIO) -> tuple[int, str]:
    line = stdin.readline(MAX_SPEC + 1)
    if not line.endswith(b"\n"):
        return 2, json.dumps({"error": "missing or oversized job spec line"})
    try:
        spec = json.loads(line)
        mode = str(spec.get("mode") or "archive")
        source_json = json.dumps(spec["source"])
        hosts = [str(h) for h in spec.get("hosts") or []]
        strip = int(spec.get("strip_components", 0))
        subpath = str(spec.get("subpath") or "")
        events = spec.get("events") or []
        extra = {str(k): str(v) for k, v in (spec.get("extra_files") or {}).items()}
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return 2, json.dumps({"error": f"bad job spec: {type(exc).__name__}"})
    data = stdin.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        return 2, json.dumps({"error": f"archive larger than {MAX_ARCHIVE} bytes"})
    from . import webscan

    try:
        if mode == "remote_mcp":   # the payload is the dispatcher's recorded probe, not an archive
            return 0, webscan.scan_remote_probe(data, source_json, hosts)
        if mode != "archive":
            return 2, json.dumps({"error": f"unknown job mode {mode[:40]!r}"})
        report = webscan.scan_fetched_archive(
            data, source_json, strip_components=strip, subpath=subpath,
            events_json=json.dumps(events) if events else None, extra_files=extra,
        )
    except ValueError as exc:   # includes pydantic.ValidationError of a malformed probe
        return 2, json.dumps({"error": str(exc)[:500]})
    return 0, report


def main() -> int:
    from .io import guard

    guard.install()
    code, out = run(sys.stdin.buffer)
    sys.stdout.write(out)
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main())

"""Entry points for the in-browser scanner (Pyodide Web Worker).

The worker passes bytes in and gets JSON strings back; the findings JSON
(``schemas/report.v1.json``) is the only contract with the page. Everything
here is pure Python over the core engine: no filesystem access beyond the
bundled rule pack and intel feed, no network, no clock except today's date
for intel-feed expiry.

A scanned target's own ``.agentguard.yaml`` is deliberately ignored: content
under review must not be able to suppress its own findings.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
from typing import Any

from .core.archive import ArchiveError, from_archive
from .core.engine import ENGINE_VERSION, scan
from .core.fetchplan import RemoteEntry, plan_fetch
from .core.inputs import ParsedInput, gist_ref, github_ref, parse
from .core.intel.feed import FeedError, IntelFeed, load_trusted_keys, verify_feed
from .core.models import ImmutableRef, LimitEvent, LoadLimits, Report, ScanOptions, SourceRef
from .core.models.enums import SourceKind
from .core.report.html import render_html
from .core.report.render import render_cyclonedx, render_json, render_markdown, render_sarif
from .core.rules.pack import RulePack, data_dirs
from .core.tree import ArtifactTree

LIMITS = LoadLimits.web()
# The browser fetches each file separately; keep a scan to a sensible number of requests.
MAX_REMOTE_FILES = 1500

_pack: RulePack | None = None
_intel: tuple[IntelFeed | None, str] | None = None
_last: Report | None = None


def _rule_pack() -> RulePack:
    global _pack
    if _pack is None:
        _pack = RulePack.default()
    return _pack


def _feed() -> tuple[IntelFeed | None, str]:
    global _intel
    if _intel is None:
        rules_dir, _ = data_dirs()
        base = rules_dir.parent / "intel"
        keys = load_trusted_keys({p.name: p.read_bytes() for p in sorted((base / "keys").glob("*.pub.json"), key=lambda p: p.name)})
        try:
            feed = verify_feed((base / "sample-feed.json").read_bytes(), (base / "sample-feed.json.sig").read_bytes(),
                               keys, today=dt.date.today())
            _intel = (feed, f"bundled {feed.describe()}")
        except (FeedError, OSError) as exc:
            _intel = (None, f"no intel feed ({exc})")
    return _intel


def engine_info() -> str:
    pack = _rule_pack()
    return json.dumps({
        "engine_version": ENGINE_VERSION,
        "rule_pack": {"version": pack.version, "digest": pack.digest, "rule_count": len(pack.rules)},
        "intel": _feed()[1],
        "python": sys.version.split()[0],
    })


# -- input parsing and fetch planning (called before any network request) ----

def parse_input(text: str) -> str:
    result = parse(text)
    if isinstance(result, ParsedInput):
        return json.dumps({"ok": True, **result.model_dump(mode="json")})
    return json.dumps({"ok": False, **result.model_dump(mode="json")})


def plan_github(entries_json: str, subpath: str, truncated: bool) -> str:
    entries = [RemoteEntry.model_validate(e) for e in json.loads(entries_json)]
    plan = plan_fetch(entries, LIMITS, subpath=subpath, max_files=MAX_REMOTE_FILES, truncated=truncated)
    return plan.model_dump_json()


# -- pasted text ---------------------------------------------------------------

_FM_NAME = re.compile(r"(?m)^name:\s*[\"']?([^\"'\n]+?)[\"']?\s*$")
_SAFE_DIR = re.compile(r"[^a-z0-9-]+")


def guess_pasted_name(text: str) -> str:
    """Pick a file name that makes the engine treat pasted text as what it is."""
    s = text.lstrip("﻿ \t\r\n")
    if re.search(r"(?m)^\[mcp_servers[.\]]", s):
        return ".codex/config.toml"
    if s.startswith(("{", "[")):
        try:
            v = json.loads(s)
        except ValueError:
            return "pasted.json"
        if isinstance(v, dict):
            if "mcpServers" in v:
                return ".mcp.json"
            if "servers" in v:
                return ".vscode/mcp.json"
            if "context_servers" in v:
                return ".zed/settings.json"
            if "packages" in v or "remotes" in v or "server.schema.json" in str(v.get("$schema", "")):
                return "server.json"
        return "tools.json"
    if s.startswith("---"):
        end = s.find("\n---", 3)
        fm = s[3:end] if end > 0 else ""
        if re.search(r"(?m)^(globs|alwaysApply):", fm):
            return ".cursor/rules/pasted.mdc"
        m = _FM_NAME.search(fm)
        name = _SAFE_DIR.sub("-", m.group(1).strip().lower()).strip("-")[:64] if m else ""
        return f"{name or 'pasted-skill'}/SKILL.md"
    if s.startswith("#!"):
        first = s.split("\n", 1)[0]
        if "python" in first:
            return "pasted.py"
        if "node" in first:
            return "pasted.js"
        return "pasted.sh"
    return "AGENTS.md"


# -- scanning ------------------------------------------------------------------

def _as_bytes(data: Any) -> bytes | str:
    """Accept bytes, str, or a Pyodide proxy of a JS Uint8Array / ArrayBuffer."""
    if isinstance(data, (bytes, str)):
        return data
    if hasattr(data, "to_bytes"):
        return bytes(data.to_bytes())
    return bytes(data)


def _source(source_json: str | None) -> SourceRef | ImmutableRef:
    if not source_json:
        return SourceRef(kind=SourceKind.pasted, locator="pasted")
    raw: dict[str, Any] = json.loads(source_json)
    if raw.get("resolved"):
        if raw.get("kind") == "github":
            owner, repo = raw["locator"].split("/")[:2]
            return github_ref(owner, repo, raw["resolved"], raw.get("subpath") or None)
        if raw.get("kind") == "gist":
            return gist_ref(raw["locator"], raw["resolved"])
    return SourceRef(kind=SourceKind(raw.get("kind", "pasted")), locator=str(raw.get("locator", "pasted"))[:200])


def _options() -> ScanOptions:
    feed, _ = _feed()
    return ScanOptions(limits=LIMITS, intel=feed)


def _finish(tree: ArtifactTree, extra_events: list[LimitEvent]) -> str:
    global _last
    tree.limit_events.extend(extra_events)
    _last = scan(tree, _options(), _rule_pack())
    return render_json(_last)


def scan_files(files: dict[str, bytes], source_json: str | None = None, events_json: str | None = None) -> str:
    """Scan pasted text, dropped files or fetched repository files. Returns the report JSON."""
    excluded = {d.lower() for d in LIMITS.excluded_dirs}
    kept = {str(p): _as_bytes(b) for p, b in files.items() if not any(seg.lower() in excluded for seg in p.replace("\\", "/").split("/")[:-1])}
    tree = ArtifactTree.from_mapping(kept, LIMITS, source=_source(source_json))  # type: ignore[arg-type]
    events = [LimitEvent.model_validate(e) for e in json.loads(events_json)] if events_json else []
    return _finish(tree, events)


def scan_archive(data: bytes, name: str) -> str:
    """Scan a dropped .zip / .tar / .tgz without extracting it anywhere."""
    source = SourceRef(kind=SourceKind.pasted, locator=(name or "archive")[:200])
    try:
        tree = from_archive(_as_bytes(data), None, LIMITS, source=source)  # type: ignore[arg-type]
    except (ArchiveError, ValueError, OSError) as exc:
        raise ValueError(f"{name}: {exc}") from exc
    return _finish(tree, [])


def render_last(fmt: str) -> str:
    if _last is None:
        raise ValueError("nothing scanned yet")
    renderers = {
        "json": render_json, "sarif": render_sarif, "markdown": render_markdown,
        "html": render_html, "cyclonedx": render_cyclonedx,
    }
    if fmt not in renderers:
        raise ValueError(f"unknown format {fmt!r}")
    return renderers[fmt](_last)

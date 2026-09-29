"""agentguard.lock: content hashes of skill files and normalized tool
definitions per component, used to detect rug pulls and update drift."""

from __future__ import annotations

import difflib
import json

from .models import Artifact, Component, LockEntry, Lockfile, Report, ToolSnapshot, canonical_json
from .models.enums import CapLabel, ComponentKind
from .textutil import visible_escape

LOCKED_KINDS = (ComponentKind.skill, ComponentKind.mcp_server, ComponentKind.package, ComponentKind.instruction_file,
                ComponentKind.subagent, ComponentKind.command)
FLOW_LABELS = {CapLabel.reads_private_data, CapLabel.ingests_untrusted_content, CapLabel.external_egress,
               CapLabel.destructive, CapLabel.code_exec, CapLabel.persistence}


def lock_key(c: Component) -> str:
    return f"{c.kind.value}:{c.name}@{c.root}"


def build_lock(report: Report) -> Lockfile:
    return Lockfile(entries=build_entries(report.inventory, report.artifacts))


def build_entries(components: list[Component], artifacts: list[Artifact]) -> list[LockEntry]:
    arts_by_comp: dict[str, list] = {}
    for a in artifacts:
        arts_by_comp.setdefault(a.component_id, []).append(a)
    entries: list[LockEntry] = []
    for c in sorted(components, key=lambda c: c.id):
        if c.kind not in LOCKED_KINDS:
            continue
        files = None
        if c.kind != ComponentKind.mcp_server or c.metadata.get("source_package"):
            files = {}
            for a in sorted(arts_by_comp.get(c.id, []), key=lambda a: a.path):
                rel = a.path[len(c.root) + 1:] if c.root and a.path.startswith(c.root + "/") else a.path
                files[rel] = a.sha256
        tools = {t.name: ToolSnapshot(hash=t.normalized_hash(), definition=t.canonical()) for t in c.tools} or None
        entries.append(LockEntry(
            key=lock_key(c), kind=c.kind.value, name=c.name, version=c.version, content_hash=c.content_hash,
            skill_files=files or None, tools=tools,
            capability_labels=sorted({cap.label for cap in c.capabilities if cap.label in FLOW_LABELS and cap.observed}),
        ))
    entries.sort(key=lambda e: e.key)
    return entries


def dump_lock(lock: Lockfile) -> str:
    return json.dumps(json.loads(lock.model_dump_json(exclude_none=True)), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def tool_diff(old: dict, new: dict, name: str, max_lines: int = 60) -> str:
    a = json.dumps(old, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    b = json.dumps(new, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    diff = list(difflib.unified_diff(a, b, fromfile=f"locked/{name}", tofile=f"current/{name}", lineterm="", n=1))
    if len(diff) > max_lines:
        diff = diff[:max_lines] + [f"… ({len(diff) - max_lines} more lines)"]
    return visible_escape("\n".join(diff))


__all__ = ["build_lock", "dump_lock", "lock_key", "tool_diff", "canonical_json"]

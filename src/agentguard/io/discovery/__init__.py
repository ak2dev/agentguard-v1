"""Host discovery: find agent configs, skills and instruction files on this
machine and in a project, and assemble them into one ArtifactTree.

Paths inside the tree are virtual so reports never leak a username:
user files appear under ``~/``, system files under ``@system/``, and project
files relative to the project root.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ...core.models import LimitEvent, LoadLimits, SourceRef
from ...core.models.enums import SourceKind
from ...core.tree import ArtifactTree
from ..fs_loader import load_path
from .locations import PROJECT_PATTERNS, Location, user_locations


@dataclass
class DiscoveryRecord:
    client: str
    scope: str
    kind: str
    path: str          # virtual path used in reports
    exists: bool
    verified: bool
    note: str = ""


@dataclass
class Discovery:
    tree: ArtifactTree
    records: list[DiscoveryRecord] = field(default_factory=list)


def _find_skill_files(root: Path, excluded: set[str], max_depth: int) -> list[Path]:
    """Walk without following links, pruning excluded directories."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = len(Path(dirpath).relative_to(root).parts)
        dirnames[:] = sorted(d for d in dirnames if d not in excluded and depth < max_depth)
        if "SKILL.md" in filenames:
            found.append(Path(dirpath) / "SKILL.md")
    return sorted(found)


def _virtual(p: Path, home: Path) -> str:
    try:
        return "~/" + p.resolve().relative_to(home.resolve()).as_posix()
    except (ValueError, OSError):
        s = p.as_posix()
        if len(s) > 1 and s[1] == ":":
            s = s[0].lower() + s[2:]
        return "@system/" + s.lstrip("/")


def _merge(dst: ArtifactTree, src: ArtifactTree, prefix: str, limits: LoadLimits, hint: dict[str, str]) -> None:
    for path, blob in src.files.items():
        vpath = f"{prefix}/{path}" if prefix else path
        if dst.add(vpath, blob.data, limits):
            dst.hints[vpath] = dict(hint)
    for ev in src.limit_events:
        dst.limit_events.append(LimitEvent(kind=ev.kind, path=f"{prefix}/{ev.path}" if prefix else ev.path, detail=ev.detail))


def discover(
    project: Path | None = None,
    *,
    include_user: bool = True,
    limits: LoadLimits | None = None,
    home: Path | None = None,
    locations: list[Location] | None = None,
) -> Discovery:
    limits = limits or LoadLimits()
    home = home or Path.home()
    tree = ArtifactTree(source=SourceRef(kind=SourceKind.local, locator="discover"))
    records: list[DiscoveryRecord] = []
    seen: set[str] = set()

    def load(p: Path, prefix: str, hint: dict[str, str]) -> bool:
        try:
            sub = load_path(p, limits)
        except (OSError, ValueError):
            return False
        if p.is_file():
            # load_path names a single file by its basename; keep the full virtual path.
            parent_prefix = prefix.rsplit("/", 1)[0] if "/" in prefix else ""
            _merge(tree, sub, parent_prefix, limits, hint)
        else:
            _merge(tree, sub, prefix, limits, hint)
        return True

    if include_user:
        for loc in locations if locations is not None else user_locations(home):
            vpath = _virtual(loc.path, home)
            exists = loc.path.exists()
            records.append(DiscoveryRecord(loc.client, loc.scope, loc.kind, vpath, exists, loc.verified, loc.note))
            if exists and vpath not in seen:
                seen.add(vpath)
                load(loc.path, vpath, {"client": loc.client, "scope": loc.scope})
    if project is not None:
        root = project.resolve()
        for rel, client, kind, verified in PROJECT_PATTERNS:
            p = root / rel
            exists = p.exists()
            records.append(DiscoveryRecord(client, "project", kind, rel, exists, verified))
            if exists and rel not in seen:
                seen.add(rel)
                load(p, rel, {"client": client, "scope": "project"})
        # Skills anywhere in the project (Codex/OpenClaw/custom layouts).
        for skill_md in _find_skill_files(root, set(limits.excluded_dirs), limits.max_depth):
            rel_dir = skill_md.parent.relative_to(root).as_posix()
            if any(rel_dir == s or rel_dir.startswith(s + "/") for s in seen):
                continue
            seen.add(rel_dir)
            load(skill_md.parent, rel_dir, {"client": "generic", "scope": "project"})
    return Discovery(tree=tree, records=records)

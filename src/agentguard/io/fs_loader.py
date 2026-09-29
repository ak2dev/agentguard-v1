"""Safe real-filesystem → ArtifactTree loading (host only; not used in Pyodide).

* Never follows symlinks or Windows junctions/reparse points; they are
  recorded as limit events instead.
* Only regular files are read (FIFOs, sockets and devices would block or be
  infinite).
* Every path is confined to the scan root.
* Files are read with a hard size cap.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..core.models import LimitEvent, LoadLimits, SourceRef
from ..core.models.enums import SourceKind
from ..core.tree import ArtifactTree

_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_O_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def _is_link_like(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & _REPARSE)


def _read_file(path: str, cap: int) -> bytes | None:
    fd = os.open(path, _O_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > cap:
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_path(
    target: str | os.PathLike[str],
    limits: LoadLimits | None = None,
    extra_excludes: tuple[str, ...] = (),
) -> ArtifactTree:
    """Load a directory or a single file into an ArtifactTree."""
    limits = limits or LoadLimits()
    target_path = Path(target)
    st = os.lstat(target_path)
    if _is_link_like(st):
        tree = ArtifactTree(source=SourceRef(kind=SourceKind.local, locator=str(target_path)))
        tree.limit_events.append(LimitEvent(kind="symlink", path=target_path.name, detail="scan target is a link"))
        return tree
    if stat.S_ISREG(st.st_mode):
        root = target_path.resolve().parent
        tree = ArtifactTree(
            source=SourceRef(kind=SourceKind.local, locator=str(target_path)),
            display_root=str(root),
        )
        data = _read_file(str(target_path), limits.max_file_bytes)
        if data is None:
            tree.limit_events.append(LimitEvent(kind="too_large", path=target_path.name))
        else:
            tree.add(target_path.name, data, limits)
        return tree
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError(f"not a regular file or directory: {target_path}")

    root = target_path.resolve()
    tree = ArtifactTree(source=SourceRef(kind=SourceKind.local, locator=str(target_path)), display_root=str(root))
    excluded = set(limits.excluded_dirs) | set(extra_excludes)
    stack: list[tuple[Path, str, int]] = [(root, "", 0)]
    while stack:
        dir_path, rel_dir, depth = stack.pop()
        if depth > limits.max_depth:
            tree.limit_events.append(LimitEvent(kind="too_deep", path=rel_dir))
            continue
        try:
            entries = sorted(os.scandir(dir_path), key=lambda e: e.name)
        except OSError as exc:
            tree.limit_events.append(LimitEvent(kind="unreadable", path=rel_dir or ".", detail=type(exc).__name__))
            continue
        subdirs: list[tuple[Path, str, int]] = []
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            try:
                est = entry.stat(follow_symlinks=False)
            except OSError:
                tree.limit_events.append(LimitEvent(kind="unreadable", path=rel))
                continue
            if _is_link_like(est) or (hasattr(entry, "is_junction") and entry.is_junction()):
                tree.limit_events.append(LimitEvent(kind="symlink", path=rel))
                continue
            if stat.S_ISDIR(est.st_mode):
                if entry.name in excluded:
                    continue
                subdirs.append((Path(entry.path), rel, depth + 1))
                continue
            if not stat.S_ISREG(est.st_mode):
                tree.limit_events.append(LimitEvent(kind="special_file", path=rel))
                continue
            # Defence in depth: confirm the entry is still inside the root.
            try:
                resolved = Path(entry.path).resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_relative_to(root):
                tree.limit_events.append(LimitEvent(kind="path_escape", path=rel))
                continue
            if est.st_size > limits.max_file_bytes:
                tree.limit_events.append(LimitEvent(kind="too_large", path=rel, detail=f"{est.st_size} bytes"))
                continue
            if len(tree.files) >= limits.max_files:
                tree.limit_events.append(LimitEvent(kind="too_many_files", path=rel))
                return tree
            try:
                data = _read_file(entry.path, limits.max_file_bytes)
            except OSError:
                tree.limit_events.append(LimitEvent(kind="unreadable", path=rel))
                continue
            if data is None:
                tree.limit_events.append(LimitEvent(kind="too_large", path=rel))
                continue
            tree.add(rel, data, limits)
        stack.extend(reversed(subdirs))
    return tree

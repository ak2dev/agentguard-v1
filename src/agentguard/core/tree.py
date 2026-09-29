"""ArtifactTree: an in-memory, read-only virtual filesystem.

The engine only ever sees an ArtifactTree. It never touches the real
filesystem or the network, which is what lets the same engine run in the CLI,
in hosted workers, and in the browser under Pyodide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .models import LimitEvent, LoadLimits, SourceRef
from .models.enums import SourceKind
from .textutil import sha256_hex

_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


class UnsafePath(ValueError):
    pass


def normalize_member_path(raw: str) -> str:
    """Normalize an untrusted relative path. Raises UnsafePath on escapes.

    Rejects absolute paths, drive letters, UNC paths, ``..`` segments, NUL
    bytes, and NTFS alternate data streams. Backslashes are treated as
    separators because archives built on Windows use them.
    """
    if "\x00" in raw:
        raise UnsafePath("NUL byte in path")
    p = raw.replace("\\", "/")
    if p.startswith("/") or p.startswith("//"):
        raise UnsafePath("absolute path")
    if len(p) >= 2 and p[1] == ":":
        raise UnsafePath("drive-letter path")
    parts: list[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            raise UnsafePath("parent-directory segment")
        if ":" in seg:
            raise UnsafePath("alternate data stream or device path")
        parts.append(seg)
    if not parts:
        raise UnsafePath("empty path")
    return str(PurePosixPath(*parts))


def windows_hazard(path: str) -> str | None:
    """Names that are legal in archives but dangerous on Windows."""
    for seg in path.split("/"):
        stem = seg.split(".")[0].lower()
        if stem in _WINDOWS_RESERVED:
            return f"reserved device name {seg!r}"
        if seg.endswith((" ", ".")):
            return f"trailing dot/space in {seg!r}"
    return None


@dataclass(frozen=True)
class FileBlob:
    path: str
    data: bytes
    size: int
    sha256: str

    @classmethod
    def of(cls, path: str, data: bytes) -> FileBlob:
        return cls(path=path, data=data, size=len(data), sha256=sha256_hex(data))


@dataclass
class ArtifactTree:
    files: dict[str, FileBlob] = field(default_factory=dict)
    limit_events: list[LimitEvent] = field(default_factory=list)
    source: SourceRef | None = None
    # Real-filesystem root, recorded for display only (never read by the engine).
    display_root: str = ""
    # Some inputs carry out-of-band metadata (e.g. discovered config scope).
    hints: dict[str, dict[str, str]] = field(default_factory=dict)

    # -- construction -------------------------------------------------------
    def add(self, path: str, data: bytes, limits: LoadLimits) -> bool:
        if len(self.files) >= limits.max_files:
            self.limit_events.append(LimitEvent(kind="too_many_files", path=path))
            return False
        if len(data) > limits.max_file_bytes:
            self.limit_events.append(
                LimitEvent(kind="too_large", path=path, detail=f"{len(data)} bytes > {limits.max_file_bytes}")
            )
            return False
        if self.total_bytes + len(data) > limits.max_total_bytes:
            self.limit_events.append(LimitEvent(kind="total_bytes_exceeded", path=path))
            return False
        if path.count("/") >= limits.max_depth:
            self.limit_events.append(LimitEvent(kind="too_deep", path=path))
            return False
        self.files[path] = FileBlob.of(path, data)
        return True

    @classmethod
    def from_mapping(
        cls,
        files: dict[str, bytes | str],
        limits: LoadLimits | None = None,
        source: SourceRef | None = None,
    ) -> ArtifactTree:
        """Build a tree from pasted text or dropped files (browser path)."""
        limits = limits or LoadLimits()
        tree = cls(source=source or SourceRef(kind=SourceKind.pasted, locator="pasted"))
        for raw_path in sorted(files):
            content = files[raw_path]
            data = content.encode("utf-8") if isinstance(content, str) else content
            try:
                path = normalize_member_path(raw_path)
            except UnsafePath as exc:
                tree.limit_events.append(LimitEvent(kind="path_escape", path=raw_path[:200], detail=str(exc)))
                continue
            tree.add(path, data, limits)
        return tree

    # -- access -------------------------------------------------------------
    @property
    def total_bytes(self) -> int:
        return sum(b.size for b in self.files.values())

    def paths(self) -> list[str]:
        return sorted(self.files)

    def get(self, path: str) -> FileBlob | None:
        return self.files.get(path)

    def under(self, prefix: str) -> list[str]:
        if not prefix:
            return self.paths()
        pre = prefix.rstrip("/") + "/"
        return [p for p in self.paths() if p.startswith(pre)]

    def digest(self) -> str:
        return sha256_hex("\n".join(f"{p}\0{self.files[p].sha256}" for p in self.paths()))

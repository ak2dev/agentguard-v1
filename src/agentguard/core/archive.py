"""Safe archive → ArtifactTree extraction (pure Python; works under Pyodide).

Nothing is written to disk. Members are streamed with hard caps so a lying
header cannot cause unbounded reads. Symlinks, hardlinks, devices and path
escapes are dropped and recorded as limit events. Nested archives are kept as
opaque blobs (they are flagged by rules, never extracted).
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile

from .models import LimitEvent, LoadLimits, SourceRef
from .tree import ArtifactTree, UnsafePath, normalize_member_path, windows_hazard

_CHUNK = 64 * 1024


class ArchiveError(ValueError):
    pass


class _StreamCapExceeded(Exception):
    pass


class _CappedReader(io.RawIOBase):
    def __init__(self, inner, cap: int) -> None:
        self._inner = inner
        self._cap = cap
        self._count = 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = _CHUNK
        chunk = self._inner.read(min(n, _CHUNK * 4))
        self._count += len(chunk)
        if self._count > self._cap:
            raise _StreamCapExceeded()
        return chunk


def _read_capped(fh: io.BufferedIOBase, cap: int) -> bytes | None:
    buf = bytearray()
    while True:
        chunk = fh.read(_CHUNK)
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
        if len(buf) > cap:
            return None


def sniff_format(data: bytes) -> str | None:
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "tgz"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def from_archive(
    data: bytes,
    fmt: str | None = None,
    limits: LoadLimits | None = None,
    source: SourceRef | None = None,
    strip_components: int = 0,
) -> ArtifactTree:
    limits = limits or LoadLimits()
    fmt = fmt or sniff_format(data)
    if fmt not in ("zip", "tar", "tgz"):
        raise ArchiveError("unsupported or unrecognized archive format")
    tree = ArtifactTree(source=source)
    compressed = len(data)
    budget = min(limits.max_total_bytes, int(max(compressed, 1) * limits.max_archive_ratio) + limits.max_file_bytes)

    def accept(raw_name: str) -> str | None:
        try:
            name = normalize_member_path(raw_name)
        except UnsafePath as exc:
            tree.limit_events.append(LimitEvent(kind="path_escape", path=raw_name[:200], detail=str(exc)))
            return None
        if strip_components:
            parts = name.split("/")
            if len(parts) <= strip_components:
                return None
            name = "/".join(parts[strip_components:])
        hazard = windows_hazard(name)
        if hazard:
            tree.limit_events.append(LimitEvent(kind="windows_hazard", path=name, detail=hazard))
        return name

    total = 0
    if fmt == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_archive_members:
                tree.limit_events.append(
                    LimitEvent(kind="archive_bomb", path="(archive)", detail=f"{len(infos)} members")
                )
                infos = infos[: limits.max_archive_members]
            for info in infos:
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    tree.limit_events.append(LimitEvent(kind="symlink", path=info.filename[:200]))
                    continue
                if info.flag_bits & 0x1:
                    tree.limit_events.append(LimitEvent(kind="encrypted_member", path=info.filename[:200]))
                    continue
                name = accept(info.filename)
                if name is None:
                    continue
                if info.file_size > limits.max_file_bytes:
                    tree.limit_events.append(LimitEvent(kind="too_large", path=name, detail=f"{info.file_size} bytes"))
                    continue
                if info.compress_size and info.file_size / info.compress_size > limits.max_archive_ratio * 10:
                    tree.limit_events.append(
                        LimitEvent(kind="archive_bomb", path=name, detail="member compression ratio")
                    )
                    continue
                with zf.open(info) as fh:
                    content = _read_capped(fh, limits.max_file_bytes)
                if content is None:
                    tree.limit_events.append(LimitEvent(kind="archive_bomb", path=name, detail="size header lied"))
                    continue
                total += len(content)
                if total > budget:
                    tree.limit_events.append(
                        LimitEvent(kind="archive_bomb", path=name, detail="decompression ratio cap reached")
                    )
                    break
                tree.add(name, content, limits)
    else:
        # Stream mode over a byte-counting reader: skipping an oversized member
        # still has to decompress it, so the *stream* is capped, not just members.
        raw: io.RawIOBase | gzip.GzipFile = io.BytesIO(data)
        if fmt == "tgz":
            raw = gzip.GzipFile(fileobj=io.BytesIO(data))
        reader = _CappedReader(raw, budget + 1024 * 1024)
        try:
            tf = tarfile.open(fileobj=reader, mode="r|")
        except (tarfile.TarError, OSError, _StreamCapExceeded) as exc:
            raise ArchiveError(str(exc)) from exc
        with tf:
            count = 0
            while True:
                try:
                    member = tf.next()
                except _StreamCapExceeded:
                    tree.limit_events.append(
                        LimitEvent(kind="archive_bomb", path="(archive)", detail="decompressed stream cap reached")
                    )
                    break
                except (tarfile.TarError, OSError, EOFError) as exc:
                    tree.limit_events.append(LimitEvent(kind="archive_error", path="(archive)", detail=str(exc)))
                    break
                if member is None:
                    break
                count += 1
                if count > limits.max_archive_members:
                    tree.limit_events.append(LimitEvent(kind="archive_bomb", path="(archive)", detail="member count"))
                    break
                if member.isdir():
                    continue
                if member.issym():
                    tree.limit_events.append(LimitEvent(kind="symlink", path=member.name[:200]))
                    continue
                if member.islnk():
                    tree.limit_events.append(LimitEvent(kind="hardlink", path=member.name[:200]))
                    continue
                if not member.isfile():
                    tree.limit_events.append(LimitEvent(kind="special_file", path=member.name[:200]))
                    continue
                name = accept(member.name)
                if name is None:
                    continue
                if member.size > limits.max_file_bytes:
                    tree.limit_events.append(LimitEvent(kind="too_large", path=name, detail=f"{member.size} bytes"))
                    continue
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                try:
                    content = _read_capped(fh, limits.max_file_bytes)
                except _StreamCapExceeded:
                    tree.limit_events.append(
                        LimitEvent(kind="archive_bomb", path=name, detail="decompressed stream cap reached")
                    )
                    break
                if content is None:
                    tree.limit_events.append(LimitEvent(kind="too_large", path=name))
                    continue
                total += len(content)
                if total > budget:
                    tree.limit_events.append(
                        LimitEvent(kind="archive_bomb", path=name, detail="decompression ratio cap reached")
                    )
                    break
                tree.add(name, content, limits)
    return tree

import gzip
import io
import os
import sys
import tarfile
import zipfile

import pytest

from agentguard.core.archive import ArchiveError, from_archive
from agentguard.core.models import LoadLimits
from agentguard.core.tree import ArtifactTree, UnsafePath, normalize_member_path, windows_hazard
from agentguard.io.fs_loader import load_path


@pytest.mark.parametrize(
    "raw",
    ["/etc/passwd", "../x", "a/../../x", "C:\\Windows\\x", "\\\\server\\share", "a/b:stream", "a\x00b", ""],
)
def test_normalize_rejects_escapes(raw):
    with pytest.raises(UnsafePath):
        normalize_member_path(raw)


def test_normalize_accepts_and_cleans():
    assert normalize_member_path("./a//b\\c.md") == "a/b/c.md"


def test_windows_hazard():
    assert windows_hazard("x/CON.txt")
    assert windows_hazard("x/name. ")
    assert windows_hazard("x/normal.md") is None


def test_from_mapping_drops_escapes():
    tree = ArtifactTree.from_mapping({"ok/SKILL.md": "---\nname: ok\n---\n", "../evil": "x"})
    assert tree.paths() == ["ok/SKILL.md"]
    assert tree.limit_events[0].kind == "path_escape"


def _zip(entries: dict[str, bytes], symlink: str | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
    return buf.getvalue()


def test_zip_symlink_and_escape_dropped():
    data = _zip({"skill/SKILL.md": b"hello", "../../evil.sh": b"rm"}, symlink="skill/link")
    tree = from_archive(data)
    assert tree.paths() == ["skill/SKILL.md"]
    kinds = {e.kind for e in tree.limit_events}
    assert {"symlink", "path_escape"} <= kinds


def test_zip_bomb_ratio_cap():
    big = b"\0" * (8 * 1024 * 1024)
    data = _zip({f"f{i}.bin": big for i in range(4)})
    limits = LoadLimits(max_file_bytes=16 * 1024 * 1024, max_archive_ratio=10)
    tree = from_archive(data, limits=limits)
    assert any(e.kind == "archive_bomb" for e in tree.limit_events)
    assert tree.total_bytes <= len(data) * 10 + limits.max_file_bytes


def test_tgz_stream_cap():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        payload = b"\0" * (20 * 1024 * 1024)
        info = tarfile.TarInfo("big.bin")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tf.addfile(link)
    data = gzip.compress(raw.getvalue())
    tree = from_archive(data, limits=LoadLimits(max_file_bytes=1024 * 1024, max_archive_ratio=5))
    assert not tree.files
    kinds = {e.kind for e in tree.limit_events}
    assert kinds & {"too_large", "archive_bomb"}


def test_unknown_archive_rejected():
    with pytest.raises(ArchiveError):
        from_archive(b"not an archive")


def test_fs_loader_skips_symlinks_and_excluded(tmp_path):
    (tmp_path / "skill").mkdir()
    (tmp_path / "skill" / "SKILL.md").write_text("---\nname: skill\n---\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("x", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("secret", encoding="utf-8")
    try:
        os.symlink(outside, tmp_path / "skill" / "link.txt")
        made_link = True
    except (OSError, NotImplementedError):
        made_link = False
    tree = load_path(tmp_path)
    assert "skill/SKILL.md" in tree.files
    assert "node_modules/x.js" not in tree.files
    assert "skill/link.txt" not in tree.files
    if made_link:
        assert any(e.kind == "symlink" for e in tree.limit_events)


def test_fs_loader_size_cap(tmp_path):
    (tmp_path / "big.md").write_bytes(b"a" * 2048)
    tree = load_path(tmp_path, LoadLimits(max_file_bytes=1024))
    assert not tree.files
    assert tree.limit_events[0].kind == "too_large"


def test_fs_loader_single_file(tmp_path):
    f = tmp_path / ".mcp.json"
    f.write_text("{}", encoding="utf-8")
    tree = load_path(f)
    assert tree.paths() == [".mcp.json"]


@pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX-only")
def test_fs_loader_fifo_not_read(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    tree = load_path(tmp_path)
    assert any(e.kind == "special_file" for e in tree.limit_events)

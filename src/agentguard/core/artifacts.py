"""Per-artifact text preparation: decoding bytes, markdown structure, and the
``TextUnit`` views that regex rules and detectors scan."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Artifact, Span
from .models.enums import ArtifactRole
from .normalize.decode import find_blobs
from .normalize.markdown import (
    BangCommand,
    Fence,
    Region,
    Section,
    claude_bang_commands,
    fences,
    hidden_regions,
    mask,
    section_at,
    sections,
)
from .normalize.unicode import Normalized, normalize, tag_character_runs
from .parsers.frontmatter import FrontmatterDoc, split_frontmatter
from .textutil import LineIndex

_BINARY_MAGIC = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xca\xfe\xba\xbe", "macho-fat-or-java-class"),
    (b"\x00asm", "wasm"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
)
ARCHIVE_KINDS = {"zip", "gzip", "7z", "rar", "bzip2", "xz"}
EXECUTABLE_KINDS = {"elf", "pe", "macho", "macho-fat-or-java-class", "wasm"}
_EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".ps1": "powershell", ".psm1": "powershell", ".bat": "batch", ".cmd": "batch",
    ".rb": "ruby", ".pl": "perl", ".php": "php", ".go": "go", ".rs": "rust", ".lua": "lua",
    ".applescript": "applescript", ".scpt": "applescript", ".vbs": "vbscript",
}
_MD_EXT = (".md", ".mdc", ".markdown", ".mdx", ".txt")


def language_for(path: str, data: bytes | None = None) -> str | None:
    lower = path.lower()
    for ext, lang in _EXT_LANG.items():
        if lower.endswith(ext):
            return lang
    if data and data.startswith(b"#!"):
        first = data.split(b"\n", 1)[0].decode("latin-1")
        if "python" in first:
            return "python"
        if "node" in first or "deno" in first or "bun" in first:
            return "javascript"
        if any(s in first for s in ("sh", "bash", "zsh")):
            return "shell"
    return None


def binary_kind(data: bytes) -> str | None:
    for magic, kind in _BINARY_MAGIC:
        if data.startswith(magic):
            if kind == "pe" and len(data) < 64:
                return None
            return kind
    if b"\x00" in data[:8192]:
        return "binary"
    return None


def decode_text(data: bytes) -> tuple[str | None, str | None]:
    """Return (text, anomaly)."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16"), "UTF-16 encoded text"
        except UnicodeDecodeError:
            return None, None
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return data.decode("latin-1"), "not valid UTF-8 (decoded as Latin-1)"


def is_markdown(path: str) -> bool:
    return path.lower().endswith(_MD_EXT)


@dataclass
class TextUnit:
    """A scannable view of (part of) an artifact.

    ``base`` maps unit offsets to the artifact text (``None`` for synthetic
    text such as decoded payloads, whose location is the ``anchor`` span).
    """

    path: str
    component_id: str
    role: str
    scope: str
    text: str
    norm: Normalized
    base: int | None
    anchor: tuple[int, int] | None = None
    hidden_kind: str | None = None
    decode_path: tuple[str, ...] = ()
    anchor_span: Span | None = None  # for units without an artifact text (tool metadata)
    label: str = ""                  # e.g. "tool:send_email.description"

    @property
    def hidden(self) -> bool:
        return self.hidden_kind is not None or bool(self.decode_path)


@dataclass
class ArtifactText:
    artifact: Artifact
    text: str
    index: LineIndex
    anomaly: str | None = None
    fm: FrontmatterDoc | None = None
    fence_list: list[Fence] = field(default_factory=list)
    section_list: list[Section] = field(default_factory=list)
    hidden: list[Region] = field(default_factory=list)
    bang: list[BangCommand] = field(default_factory=list)
    units: list[TextUnit] = field(default_factory=list)
    code_ranges: list[tuple[int, int]] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.artifact.path

    def span(self, start: int, end: int | None = None) -> Span:
        sl, sc = self.index.line_col(start)
        el, ec = self.index.line_col(end if end is not None else start)
        return Span(path=self.path, start_line=sl, start_col=sc, end_line=el, end_col=ec)

    def in_code(self, offset: int) -> bool:
        return any(s <= offset < e for s, e in self.code_ranges)

    def headings_at(self, offset: int) -> list[str]:
        return section_at(offset, self.section_list)

    def line_text(self, offset: int) -> str:
        start = self.text.rfind("\n", 0, offset) + 1
        end = self.text.find("\n", offset)
        return self.text[start : end if end >= 0 else len(self.text)]


def _unit(at: ArtifactText, scope: str, text: str, base: int | None, **kw) -> TextUnit:
    return TextUnit(
        path=at.path,
        component_id=at.artifact.component_id,
        role=at.artifact.role.value,
        scope=scope,
        text=text,
        norm=normalize(text),
        base=base,
        **kw,
    )


def prepare(artifact: Artifact, data: bytes, *, max_decode_depth: int = 3, max_decoded: int = 1 << 20) -> ArtifactText | None:
    text, anomaly = decode_text(data)
    if text is None:
        return None
    at = ArtifactText(artifact=artifact, text=text, index=LineIndex(text), anomaly=anomaly)
    role = artifact.role
    markdown = role in (ArtifactRole.skill_md, ArtifactRole.instruction_md) or (
        role in (ArtifactRole.reference, ArtifactRole.asset, ArtifactRole.other) and is_markdown(artifact.path)
    )
    if markdown:
        fm = split_frontmatter(text)
        at.fm = fm
        body = fm.body
        base = fm.body_offset
        at.fence_list = [
            Fence(f.start + base, f.end + base, f.info, f.body_start + base, f.body_end + base) for f in fences(body)
        ]
        at.code_ranges = [(f.start, f.end) for f in at.fence_list]
        at.section_list = [
            Section(s.start + base, s.end + base, s.heading, s.level)
            for s in sections(body, [(f.start - base, f.end - base) for f in at.fence_list])
        ]
        regions = hidden_regions(body, [(f.start - base, f.end - base) for f in at.fence_list])
        at.hidden = [
            Region(r.start + base, r.end + base, r.text, r.kind, r.text_start + base) for r in regions
        ]
        at.bang = [
            BangCommand(b.start + base, b.end + base, b.command, b.form, b.command_start + base)
            for b in claude_bang_commands(body, [
                Fence(f.start - base, f.end - base, f.info, f.body_start - base, f.body_end - base)
                for f in at.fence_list
            ])
        ]
        if fm.has_frontmatter and fm.raw:
            fm_start = text.find(fm.raw) if fm.raw else 0
            at.units.append(_unit(at, "frontmatter", fm.raw, max(fm_start, 0)))
        # The body view masks hidden regions so they are reported once, as hidden.
        masked = mask(body, [(r.start - base, r.end - base) for r in at.hidden])
        at.units.append(_unit(at, "body", masked, base))
        for r in at.hidden:
            at.units.append(_unit(at, "hidden", r.text, r.text_start, hidden_kind=r.kind))
        for b in at.bang:
            at.units.append(_unit(at, "command", b.command, b.command_start, label=f"claude-{b.form}-injection"))
    else:
        scope = "code" if role in (ArtifactRole.script, ArtifactRole.source_code) else "body"
        at.units.append(_unit(at, scope, text, 0))

    # Unicode tag-character payloads are invisible; decode and scan them as hidden text.
    for run in tag_character_runs(text):
        if run.decoded.strip():
            at.units.append(
                _unit(at, "hidden", run.decoded, None, anchor=(run.start, run.end), hidden_kind="unicode-tags")
            )
    # Encoded blobs (bounded depth) are decoded and rescanned.
    for blob in find_blobs(text, max_depth=max_decode_depth, max_bytes=max_decoded):
        at.units.append(
            _unit(at, "decoded", blob.text, None, anchor=(blob.start, blob.end), decode_path=blob.path)
        )
    return at

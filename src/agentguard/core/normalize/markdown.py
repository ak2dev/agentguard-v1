"""Markdown structure relevant to security: sections, code fences, content
that renders invisibly to humans but is read by models, and platform
execution surfaces embedded in markdown (Claude Code ``!`` injections)."""

from __future__ import annotations

from dataclasses import dataclass

import regex

from ..textutil import TIMEOUT

_HEADING = regex.compile(r"^(#{1,6})[ \t]+(.+?)[ \t#]*$", regex.MULTILINE)
_SETEXT = regex.compile(r"^([^\n]+)\n(=+|-+)[ \t]*$", regex.MULTILINE)
_FENCE_OPEN = regex.compile(r"^[ \t]{0,3}(`{3,}|~{3,})([^\n]*)$", regex.MULTILINE)
_COMMENT = regex.compile(r"<!--(.*?)(?:-->|\Z)", regex.DOTALL)
_LINKREF = regex.compile(r"^[ \t]{0,3}\[([^\]\n]+)\]:[ \t]*(\S+)(?:[ \t]+(?:\"([^\"\n]*)\"|'([^'\n]*)'|\(([^)\n]*)\)))?[ \t]*$", regex.MULTILINE)
_IMG_ALT = regex.compile(r"!\[([^\]\n]{1,2000})\]\(([^)\s]*)(?:\s+\"([^\"]*)\")?\)")
_LINK_TITLE = regex.compile(r"(?<!!)\[[^\]\n]*\]\([^)\s]*\s+\"([^\"]+)\"\)")
_WS_HIDDEN = regex.compile(r"^([^\n]*?\S)?([ \t  - 　]{40,})(\S[^\n]*)$", regex.MULTILINE)
_CSS_HIDDEN = regex.compile(
    r"<(\w+)\b[^>]*?(?:style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0(?:px|pt|em|rem)?\s*[;\"']|opacity\s*:\s*0(?:\.0+)?\s*[;\"']|color\s*:\s*(?:#fff(?:fff)?|white|transparent)\b)"
    r"[^\"']*[\"']|\shidden\b)[^>]*>(.*?)</\1\s*>",
    regex.DOTALL | regex.IGNORECASE,
)
_INLINE_BANG = regex.compile(r"(?<![\w`])!`([^`\n]+)`")


@dataclass
class Region:
    start: int
    end: int
    text: str
    kind: str
    text_start: int = -1  # absolute start of `text` within the document

    def __post_init__(self) -> None:
        if self.text_start < 0:
            self.text_start = self.start


@dataclass
class Section:
    start: int
    end: int
    heading: str
    level: int


@dataclass
class Fence:
    start: int
    end: int
    info: str
    body_start: int
    body_end: int


def _find(pattern: regex.Pattern[str], text: str):
    try:
        return list(pattern.finditer(text, timeout=TIMEOUT))
    except TimeoutError:
        return []


def fences(text: str) -> list[Fence]:
    out: list[Fence] = []
    pos = 0
    while True:
        m = _FENCE_OPEN.search(text, pos, timeout=TIMEOUT)
        if not m:
            break
        marker = m.group(1)
        close = regex.compile(r"^[ \t]{0,3}" + regex.escape(marker[0]) + "{" + str(len(marker)) + r",}[ \t]*$", regex.MULTILINE)
        body_start = m.end() + 1
        cm = close.search(text, body_start, timeout=TIMEOUT) if body_start <= len(text) else None
        if cm:
            out.append(Fence(m.start(), cm.end(), m.group(2).strip(), body_start, cm.start()))
            pos = cm.end()
        else:
            out.append(Fence(m.start(), len(text), m.group(2).strip(), body_start, len(text)))
            break
    return out


def in_ranges(offset: int, ranges: list[tuple[int, int]]) -> bool:
    return any(s <= offset < e for s, e in ranges)


def sections(text: str, code: list[tuple[int, int]] | None = None) -> list[Section]:
    code = code if code is not None else [(f.start, f.end) for f in fences(text)]
    heads: list[tuple[int, str, int]] = []
    for m in _find(_HEADING, text):
        if not in_ranges(m.start(), code):
            heads.append((m.start(), m.group(2).strip(), len(m.group(1))))
    for m in _find(_SETEXT, text):
        if not in_ranges(m.start(), code) and m.group(1).strip() and not m.group(1).lstrip().startswith(("-", "*", "|")):
            heads.append((m.start(), m.group(1).strip(), 1 if m.group(2).startswith("=") else 2))
    heads.sort()
    out: list[Section] = []
    for i, (start, title, level) in enumerate(heads):
        end = len(text)
        for later_start, _, later_level in heads[i + 1 :]:
            if later_level <= level:
                end = later_start
                break
        out.append(Section(start, end, title, level))
    return out


def section_at(offset: int, secs: list[Section]) -> list[str]:
    """All headings enclosing an offset, outermost first."""
    return [s.heading for s in secs if s.start <= offset < s.end]


def hidden_regions(text: str, code: list[tuple[int, int]] | None = None) -> list[Region]:
    """Content a human reader of rendered markdown will not see."""
    code = code if code is not None else [(f.start, f.end) for f in fences(text)]
    regions: list[Region] = []
    for m in _find(_COMMENT, text):
        if in_ranges(m.start(), code):
            continue
        body = m.group(1)
        if body.strip():
            regions.append(Region(m.start(), m.end(), body, "html-comment", m.start(1)))
    for m in _find(_LINKREF, text):
        if in_ranges(m.start(), code):
            continue
        title = next((g for g in (m.group(3), m.group(4), m.group(5)) if g), None)
        label = m.group(1)
        regions.append(Region(m.start(), m.end(), f"{label} {title or ''}".strip(), "link-reference", m.start(1)))
    for m in _find(_IMG_ALT, text):
        if in_ranges(m.start(), code):
            continue
        if len(m.group(1)) > 40:
            regions.append(Region(m.start(), m.end(), m.group(1), "image-alt", m.start(1)))
        if m.group(3):
            regions.append(Region(m.start(), m.end(), m.group(3), "image-title", m.start(3)))
    for m in _find(_LINK_TITLE, text):
        if not in_ranges(m.start(), code) and len(m.group(1)) > 20:
            regions.append(Region(m.start(), m.end(), m.group(1), "link-title", m.start(1)))
    for m in _find(_WS_HIDDEN, text):
        regions.append(Region(m.start(3), m.end(3), m.group(3), "after-whitespace", m.start(3)))
    for m in _find(_CSS_HIDDEN, text):
        if not in_ranges(m.start(), code) and m.group(2).strip():
            regions.append(Region(m.start(), m.end(), m.group(2), "css-hidden", m.start(2)))
    regions.sort(key=lambda r: (r.start, r.kind))
    return regions


@dataclass
class BangCommand:
    start: int
    end: int
    command: str
    form: str  # "inline" | "block"
    command_start: int


def claude_bang_commands(text: str, fence_list: list[Fence] | None = None) -> list[BangCommand]:
    """Claude Code dynamic context injection: ``!`cmd` `` inline and
    ```` ```! ```` fenced blocks. These run *before* the model sees the skill."""
    fence_list = fence_list if fence_list is not None else fences(text)
    out: list[BangCommand] = []
    code = [(f.start, f.end) for f in fence_list]
    for f in fence_list:
        if f.info == "!" or f.info.startswith("! "):
            out.append(BangCommand(f.start, f.end, text[f.body_start : f.body_end], "block", f.body_start))
    for m in _find(_INLINE_BANG, text):
        if not in_ranges(m.start(), code):
            out.append(BangCommand(m.start(), m.end(), m.group(1), "inline", m.start(1)))
    out.sort(key=lambda b: b.start)
    return out


def mask(text: str, spans: list[tuple[int, int]]) -> str:
    """Replace spans with spaces (keeping newlines) so offsets are preserved."""
    if not spans:
        return text
    chars = list(text)
    for s, e in spans:
        for i in range(max(0, s), min(e, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)

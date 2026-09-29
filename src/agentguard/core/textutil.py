"""Small text helpers used across the core (no third-party state)."""

from __future__ import annotations

import bisect
import hashlib
import unicodedata

# Per-regex-call timeout in seconds (the `regex` module supports this natively).
TIMEOUT = 0.5


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    return hashlib.sha256(data).hexdigest()


def short_hash(data: bytes | str, n: int = 8) -> str:
    return sha256_hex(data)[:n]


class LineIndex:
    """Map string offsets to 1-based (line, column) pairs."""

    def __init__(self, text: str) -> None:
        self._starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                self._starts.append(i + 1)
        self._len = len(text)

    def line_col(self, offset: int) -> tuple[int, int]:
        offset = max(0, min(offset, self._len))
        line = bisect.bisect_right(self._starts, offset) - 1
        return line + 1, offset - self._starts[line] + 1

    def line_start(self, line: int) -> int:
        return self._starts[max(0, min(line - 1, len(self._starts) - 1))]

    @property
    def line_count(self) -> int:
        return len(self._starts)


# Characters that render as nothing or re-order text. Rendered visibly in snippets.
INVISIBLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x200B, 0x200F),  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    (0x202A, 0x202E),  # bidi embeddings / overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0x180E, 0x180E),  # Mongolian vowel separator
    (0xFEFF, 0xFEFF),  # BOM / ZWNBSP
    (0x00AD, 0x00AD),  # soft hyphen
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x115F, 0x1160),  # Hangul fillers
    (0x3164, 0x3164),
    (0xFFA0, 0xFFA0),
    (0xE0000, 0xE007F),  # tag characters
    (0xFE00, 0xFE0F),  # variation selectors
    (0xE0100, 0xE01EF),  # variation selectors supplement
)


INVISIBLE_CODEPOINTS: frozenset[int] = frozenset(cp for lo, hi in INVISIBLE_RANGES for cp in range(lo, hi + 1))


def is_invisible(ch: str) -> bool:
    return ord(ch) in INVISIBLE_CODEPOINTS


def visible_escape(text: str) -> str:
    """Render invisible and control characters as ⟨U+XXXX⟩ so they are
    visible in reports and cannot drive a terminal (ANSI) or reorder text."""
    out: list[str] = []
    for ch in text:
        if ch in ("\n", "\t"):
            out.append(ch)
            continue
        cat = unicodedata.category(ch)
        if is_invisible(ch) or cat in ("Cc", "Cf", "Co", "Cs", "Zl", "Zp"):
            out.append(f"⟨U+{ord(ch):04X}⟩")
        else:
            out.append(ch)
    return "".join(out)

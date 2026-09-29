"""Unicode normalization with an offset map back to the original text, plus
detectors for hidden-Unicode techniques."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

import regex

from ..textutil import TIMEOUT, is_invisible

# Small, conservative confusables fold (Cyrillic/Greek/other → Latin). NFKC
# already handles fullwidth and mathematical alphanumerics.
_CONFUSABLES = {
    # Cyrillic lowercase
    "а": "a", "в": "b", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "к": "k", "м": "m", "н": "h", "т": "t", "ь": "b", "г": "r", "п": "n",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S", "Ԁ": "D", "Ԛ": "Q", "Ԝ": "W",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "υ": "u", "τ": "t", "ε": "e",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Armenian / Latin extensions / misc
    "օ": "o", "ս": "u", "զ": "q", "ց": "g", "ı": "i", "ȷ": "j", "ℓ": "l", "ɡ": "g", "ʏ": "y",
    "ᴀ": "a", "ᴄ": "c", "ᴏ": "o", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ᴢ": "z",
}

_BIDI_CONTROLS = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF}
_CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")


@dataclass
class Normalized:
    text: str
    omap: list[int]  # omap[i] = original index of normalized char i; omap[len] = len(original)

    def orig(self, i: int) -> int:
        return self.omap[max(0, min(i, len(self.omap) - 1))]


def normalize(original: str) -> Normalized:
    out: list[str] = []
    omap: list[int] = []
    for i, ch in enumerate(original):
        if is_invisible(ch):
            continue
        if ch.isascii():
            out.append(ch)
            omap.append(i)
            continue
        folded = _CONFUSABLES.get(ch)
        if folded is None:
            folded = unicodedata.normalize("NFKC", ch)
            folded = "".join(_CONFUSABLES.get(c, c) for c in folded)
        for c in folded:
            out.append(c)
            omap.append(i)
    omap.append(len(original))
    return Normalized("".join(out), omap)


# ---------------------------------------------------------------------------
# Detectors (operate on original text)
# ---------------------------------------------------------------------------


@dataclass
class HiddenRun:
    start: int
    end: int
    kind: str
    decoded: str = ""


def tag_character_runs(text: str) -> list[HiddenRun]:
    runs: list[HiddenRun] = []
    i, n = 0, len(text)
    while i < n:
        if 0xE0000 <= ord(text[i]) <= 0xE007F:
            j = i
            chars: list[str] = []
            while j < n and 0xE0000 <= ord(text[j]) <= 0xE007F:
                cp = ord(text[j]) - 0xE0000
                if 0x20 <= cp <= 0x7E:
                    chars.append(chr(cp))
                j += 1
            # Emoji subdivision flags (e.g. England/Scotland/Wales) are U+1F3F4 +
            # tag letters + CANCEL TAG; they are legitimate and short.
            is_flag = i > 0 and text[i - 1] == "🏴" and ord(text[j - 1]) == 0xE007F and j - i <= 7
            if not is_flag:
                runs.append(HiddenRun(i, j, "tag", "".join(chars)))
            i = j
        else:
            i += 1
    return runs


def bidi_controls(text: str) -> list[HiddenRun]:
    return [HiddenRun(i, i + 1, f"U+{ord(c):04X}") for i, c in enumerate(text) if ord(c) in _BIDI_CONTROLS]


def _is_word_char(c: str) -> bool:
    return c.isascii() and c.isalnum()


def suspicious_zero_width(text: str) -> list[HiddenRun]:
    """Zero-width characters splitting ASCII words, or in runs of 2+.

    ZWJ inside emoji sequences and ZWNJ/ZWJ between non-Latin letters (Arabic,
    Indic scripts, where they are orthographic) are not reported. A leading BOM
    is not reported here (it is a frontmatter anomaly instead).
    """
    hits: list[HiddenRun] = []
    n = len(text)
    i = 0
    while i < n:
        cp = ord(text[i])
        if cp in _ZERO_WIDTH and not (cp == 0xFEFF and i == 0):
            j = i
            while j < n and ord(text[j]) in _ZERO_WIDTH:
                j += 1
            prev = text[i - 1] if i > 0 else ""
            nxt = text[j] if j < n else ""
            run_len = j - i
            ascii_split = bool(prev) and bool(nxt) and _is_word_char(prev) and _is_word_char(nxt)
            if run_len >= 2 or ascii_split:
                if not (run_len == 1 and cp == 0x200D and not ascii_split):
                    hits.append(HiddenRun(i, j, f"U+{cp:04X}x{run_len}"))
            i = j
        else:
            i += 1
    return hits


_WORD = regex.compile(r"\w{2,}", regex.UNICODE)


def script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    return name.split(" ", 1)[0]


def mixed_script_tokens(text: str) -> list[HiddenRun]:
    hits: list[HiddenRun] = []
    try:
        matches = list(_WORD.finditer(text, timeout=TIMEOUT))
    except TimeoutError:
        return hits
    for m in matches:
        word = m.group(0)
        if word.isascii():
            continue
        scripts = {script_of(c) for c in word if c.isalpha()}
        if "LATIN" in scripts and scripts & set(_CONFUSABLE_SCRIPTS):
            hits.append(HiddenRun(m.start(), m.end(), "+".join(sorted(scripts))))
    return hits

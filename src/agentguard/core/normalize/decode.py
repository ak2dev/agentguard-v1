"""Bounded detection and decoding of encoded blobs (base64, hex, percent,
``\\x`` escapes, gzip-in-base64). Decoded text is rescanned by the caller."""

from __future__ import annotations

import base64
import binascii
import urllib.parse
import zlib
from dataclasses import dataclass

import regex

from ..textutil import TIMEOUT

_B64 = regex.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/_\-]{24,}={0,2}(?![A-Za-z0-9+/=_\-])")
_HEX = regex.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_XESC = regex.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_PCT = regex.compile(r"[^\s\"'<>`]*(?:%[0-9A-Fa-f]{2}){4,}[^\s\"'<>`]*")


@dataclass
class DecodedBlob:
    encoding: str
    start: int
    end: int
    text: str
    path: tuple[str, ...]  # decode path, outermost first


def _utf16le(data: bytes) -> bool:
    """PowerShell -EncodedCommand payloads are UTF-16LE: mostly-ASCII text
    with a zero high byte in (nearly) every code unit."""
    return len(data) >= 16 and len(data) % 2 == 0 and data[1::2].count(0) >= 0.9 * (len(data) // 2)


def _printable_text(data: bytes) -> str | None:
    if len(data) < 8:
        return None
    try:
        s = data.decode("utf-16-le") if _utf16le(data) else data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    letters = sum(1 for c in s if c.isalpha())
    if printable / len(s) < 0.92 or letters < 4:
        return None
    return s


def _maybe_decompress(data: bytes, cap: int) -> bytes:
    if data[:2] == b"\x1f\x8b" or data[:1] == b"\x78":
        try:
            d = zlib.decompressobj(zlib.MAX_WBITS | 32)
            out = d.decompress(data, cap)
            return out
        except zlib.error:
            return data
    return data


def _try_b64(s: str, cap: int) -> str | None:
    if s.isdigit() or s.isalpha() and (s.islower() or s.isupper()):
        return None  # a long word / identifier, not base64
    if not any(c.isdigit() or c in "+/=" for c in s) and s.count("_") + s.count("-") > len(s) // 6:
        return None  # snake/kebab identifiers
    padded = s + "=" * (-len(s) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        text = _printable_text(_maybe_decompress(raw, cap)[:cap])
        if text:
            return text
    return None


def _try_hex(s: str, cap: int) -> str | None:
    if len(s) in (32, 40, 64, 128) and s == s.lower():
        # Very likely a digest (md5/sha1/sha256/sha512). Only decode if it yields text.
        pass
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    return _printable_text(_maybe_decompress(raw, cap)[:cap])


def _try_xesc(s: str, cap: int) -> str | None:
    try:
        raw = bytes(int(h, 16) for h in regex.findall(r"\\x([0-9A-Fa-f]{2})", s))
    except ValueError:
        return None
    return _printable_text(raw[:cap])


def _try_pct(s: str, cap: int) -> str | None:
    decoded = urllib.parse.unquote(s)
    if decoded == s:
        return None
    return decoded[:cap] if _printable_text(decoded.encode("utf-8", "replace")) else None


_DECODERS = (
    ("base64", _B64, _try_b64),
    ("hex", _HEX, _try_hex),
    ("hex-escape", _XESC, _try_xesc),
    ("percent", _PCT, _try_pct),
)


def find_blobs(
    text: str,
    *,
    max_depth: int = 3,
    max_bytes: int = 1 << 20,
    max_blobs: int = 200,
    _path: tuple[str, ...] = (),
) -> list[DecodedBlob]:
    """Find and decode blobs; recurse into decoded text up to ``max_depth``.

    Offsets of nested blobs refer to the *outermost* text (the span of the
    top-level blob) because decoded content has no source position.
    """
    if len(_path) >= max_depth:
        return []
    found: list[DecodedBlob] = []
    taken: list[tuple[int, int]] = []
    for name, pattern, decoder in _DECODERS:
        try:
            matches = list(pattern.finditer(text, timeout=TIMEOUT))
        except TimeoutError:
            continue
        for m in matches:
            s, e = m.span()
            if any(s < te and ts < e for ts, te in taken):
                continue
            decoded = decoder(m.group(0), max_bytes)
            if not decoded:
                continue
            taken.append((s, e))
            path = (*_path, name)
            found.append(DecodedBlob(name, s, e, decoded, path))
            for child in find_blobs(decoded, max_depth=max_depth, max_bytes=max_bytes, _path=path):
                found.append(DecodedBlob(child.encoding, s, e, child.text, child.path))
            if len(found) >= max_blobs:
                return found
    found.sort(key=lambda b: (b.start, len(b.path)))
    return found

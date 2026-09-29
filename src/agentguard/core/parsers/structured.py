"""Bounded JSON / JSONC / TOML parsing plus a best-effort locator that maps a
key path back to a line number (the stdlib parsers do not keep positions)."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from typing import Any

import regex

from ..textutil import TIMEOUT, LineIndex


@dataclass
class Parsed:
    value: Any = None
    error: str | None = None
    fmt: str = "json"


def _nesting_depth(text: str) -> int:
    depth = best = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            best = max(best, depth)
        elif ch in "]}":
            depth -= 1
    return best


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, preserving newlines
    and offsets (comments are replaced by spaces) so line numbers stay valid."""
    out = list(text)
    i, n = 0, len(text)
    in_str = esc = False
    while i < n:
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for j in range(i, end):
                if out[j] != "\n":
                    out[j] = " "
            i = end
            continue
        i += 1
    cleaned = "".join(out)
    # trailing commas before } or ]
    return regex.sub(r",(\s*[}\]])", r" \1", cleaned, timeout=TIMEOUT)


def parse_json(text: str, *, jsonc: bool = False, max_depth: int = 64) -> Parsed:
    src = strip_jsonc(text) if jsonc else text
    if _nesting_depth(src) > max_depth:
        return Parsed(error="JSON nesting exceeds depth limit", fmt="jsonc" if jsonc else "json")
    try:
        return Parsed(value=json.loads(src), fmt="jsonc" if jsonc else "json")
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if not jsonc:
            # Many client configs (VS Code, Zed) are JSONC; retry leniently.
            retry = parse_json(text, jsonc=True, max_depth=max_depth)
            if retry.error is None:
                return retry
        return Parsed(error=f"JSON error: {str(exc)[:200]}", fmt="jsonc" if jsonc else "json")


def parse_toml(text: str) -> Parsed:
    try:
        return Parsed(value=tomllib.loads(text), fmt="toml")
    except (tomllib.TOMLDecodeError, RecursionError, ValueError) as exc:
        return Parsed(error=f"TOML error: {str(exc)[:200]}", fmt="toml")


def locate(text: str, *needles: str, start_line: int = 1) -> int:
    """Find the line of the last needle, searching each needle after the
    previous one (e.g. locate(t, '"mcpServers"', '"github"', '"command"'))."""
    idx = LineIndex(text)
    pos = idx.line_start(start_line)
    found_any = False
    for needle in needles:
        if not needle:
            continue
        hit = text.find(needle, pos)
        if hit < 0:
            break
        pos = hit
        found_any = True
    return idx.line_col(pos)[0] if found_any else start_line

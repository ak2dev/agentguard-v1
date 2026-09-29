"""YAML frontmatter splitting for SKILL.md, agents, commands, and .mdc rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .safe_yaml import YamlResult, safe_load


@dataclass
class FrontmatterDoc:
    has_frontmatter: bool
    raw: str = ""                 # raw YAML text
    data: dict[str, Any] | None = None
    body: str = ""
    body_offset: int = 0          # char offset of body within the original text
    body_line: int = 1            # 1-based line where the body starts
    fm_line: int = 2              # 1-based line where the YAML starts
    error: str | None = None
    duplicate_keys: list[tuple[str, int]] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)


def split_frontmatter(text: str, *, max_nodes: int = 50_000) -> FrontmatterDoc:
    lead = 0
    anomalies: list[str] = []
    if text.startswith("﻿"):
        lead = 1
        anomalies.append("byte-order mark before frontmatter")
    rest = text[lead:]
    first_nl = rest.find("\n")
    first_line = rest if first_nl < 0 else rest[:first_nl]
    if first_line.rstrip("\r ") != "---":
        return FrontmatterDoc(has_frontmatter=False, body=text, body_offset=0, body_line=1)

    pos = lead + first_nl + 1
    line_no = 2
    fm_start = pos
    while pos <= len(text):
        nl = text.find("\n", pos)
        line = text[pos:] if nl < 0 else text[pos:nl]
        if line.rstrip("\r ") in ("---", "..."):
            raw = text[fm_start:pos]
            body_offset = len(text) if nl < 0 else nl + 1
            res: YamlResult = safe_load(raw, max_nodes=max_nodes)
            data = res.value if isinstance(res.value, dict) else None
            err = res.error
            if err is None and res.value is not None and data is None:
                err = "frontmatter is not a mapping"
            return FrontmatterDoc(
                has_frontmatter=True,
                raw=raw,
                data=data if data is not None else ({} if res.value is None and err is None else None),
                body=text[body_offset:],
                body_offset=body_offset,
                body_line=line_no + 1,
                fm_line=2,
                error=err,
                duplicate_keys=res.duplicate_keys,
                anomalies=anomalies,
            )
        if nl < 0:
            break
        pos = nl + 1
        line_no += 1
    return FrontmatterDoc(
        has_frontmatter=False,
        body=text,
        error="unterminated frontmatter block",
        anomalies=anomalies,
    )

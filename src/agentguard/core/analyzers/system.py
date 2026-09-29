"""Loader limit events → coverage findings (AG-SYS-001/003/004)."""

from __future__ import annotations

from typing import ClassVar

from ..models import LimitEvent, Span
from ..models.enums import EvidenceKind
from .base import Context


def rule_for(ev: LimitEvent) -> str | None:
    if ev.kind == "archive_bomb":
        return "AG-SYS-004"
    if ev.kind in ("symlink", "hardlink", "path_escape"):
        return "AG-SYS-003"
    if ev.kind in ("too_large", "too_many_files", "too_deep", "total_bytes_exceeded", "encrypted_member",
                   "special_file", "unreadable", "archive_error", "windows_hazard"):
        return "AG-SYS-001"
    return None


class LimitsAnalyzer:
    id: ClassVar[str] = "sys.limits"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SYS-001", "AG-SYS-003", "AG-SYS-004")

    def run(self, ctx: Context) -> None:
        events: list[LimitEvent] = ctx.data.get("limit_events", [])  # type: ignore[assignment]
        for ev in sorted(events, key=lambda e: (e.kind, e.path)):
            rid = rule_for(ev)
            if rid is None:
                continue
            comp = ctx.inventory.component_for(ev.path)
            ctx.emit(rid, component_ids=[comp.id] if comp else [], span=Span(path=ev.path), snippet=ev.path,
                     match=f"{ev.kind}:{ev.path}", kind=EvidenceKind.loader, detail=f"{ev.kind}: {ev.detail}".strip(": "),
                     message={
                         "AG-SYS-001": f"Not scanned ({ev.kind.replace('_', ' ')}): {ev.path}",
                         "AG-SYS-003": f"Link or path escape blocked ({ev.kind}): {ev.path}",
                         "AG-SYS-004": f"Archive exceeded decompression limits: {ev.path}",
                     }[rid])

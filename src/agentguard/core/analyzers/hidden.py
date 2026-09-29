"""Hidden-content detectors (AG-SKL-HID-*, and AG-MCP-META-001 for tool metadata)."""

from __future__ import annotations

from typing import ClassVar

from ..artifacts import ArtifactText, TextUnit
from ..models import Span
from ..models.enums import EvidenceKind
from ..normalize.unicode import (
    bidi_controls,
    mixed_script_tokens,
    suspicious_zero_width,
    tag_character_runs,
)
from .base import Context
from .heuristics import AGENT_DIRECTED, EXECUTABLE_CONTENT, search, word_count

_TOOL_ROLES = {"tool_manifest", "server_json"}


class HiddenContentAnalyzer:
    id: ClassVar[str] = "text.hidden"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = (
        *(f"AG-SKL-HID-{i:03d}" for i in range(1, 11)),
        "AG-MCP-META-001",
    )

    def run(self, ctx: Context) -> None:
        for at in ctx.texts():
            self._unicode(ctx, at)
            self._regions(ctx, at)
            self._decoded(ctx, at)
        for unit in ctx.data.get("extra_units", []):  # type: ignore[union-attr]
            if unit.scope in ("tool_text", "server_instructions"):
                self._unicode_unit(ctx, unit)

    # -- Unicode tricks -------------------------------------------------------
    def _unicode(self, ctx: Context, at: ArtifactText) -> None:
        cid = at.artifact.component_id
        tool = at.artifact.role.value in _TOOL_ROLES
        text = at.text
        for run in tag_character_runs(text):
            rid = "AG-MCP-META-001" if tool else "AG-SKL-HID-001"
            ctx.emit(rid, component_ids=cid, span=at.span(run.start, run.end), snippet=at.line_text(run.start),
                     match=f"tag:{run.decoded}", kind=EvidenceKind.regex,
                     detail=f"decoded tag characters: {run.decoded[:120]!r}" if run.decoded else "tag characters",
                     message=f"Invisible Unicode tag characters ({run.end - run.start}) hide text"
                             + (f": \"{run.decoded[:80]}\"" if run.decoded else "."))
        seen: set[int] = set()
        for hit in bidi_controls(text):
            line = at.index.line_col(hit.start)[0]
            if line in seen:
                continue
            seen.add(line)
            ctx.emit("AG-MCP-META-001" if tool else "AG-SKL-HID-002", component_ids=cid, span=at.span(hit.start),
                     snippet=at.line_text(hit.start), match=f"bidi:{line}:{at.line_text(hit.start)}",
                     message=f"Bidirectional control character {hit.kind} can make displayed text differ from what is processed.")
        seen.clear()
        for hit in suspicious_zero_width(text):
            line = at.index.line_col(hit.start)[0]
            if line in seen:
                continue
            seen.add(line)
            ctx.emit("AG-MCP-META-001" if tool else "AG-SKL-HID-003", component_ids=cid, span=at.span(hit.start),
                     snippet=at.line_text(hit.start), match=f"zw:{at.line_text(hit.start)}",
                     message="Zero-width characters split words, which can evade keyword review and filters.")
        seen.clear()
        for hit in mixed_script_tokens(text):
            line = at.index.line_col(hit.start)[0]
            if line in seen:
                continue
            seen.add(line)
            word = text[hit.start : hit.end]
            ctx.emit("AG-MCP-META-001" if tool else "AG-SKL-HID-004", component_ids=cid, span=at.span(hit.start, hit.end),
                     snippet=at.line_text(hit.start), match=f"mixed:{word}",
                     message=f"Word mixes scripts ({hit.kind}), a homoglyph technique.")

    def _unicode_unit(self, ctx: Context, unit: TextUnit) -> None:
        text = unit.text
        problems = []
        if tag_character_runs(text):
            problems.append("tag characters")
        if bidi_controls(text):
            problems.append("bidi controls")
        if suspicious_zero_width(text):
            problems.append("zero-width characters")
        if mixed_script_tokens(text):
            problems.append("mixed-script words")
        if problems:
            ctx.emit("AG-MCP-META-001", component_ids=unit.component_id, span=unit.anchor_span, snippet=text[:200],
                     match=f"{unit.label}:{','.join(problems)}", kind=EvidenceKind.metadata,
                     detail=unit.label, message=f"Hidden Unicode in {unit.label}: {', '.join(problems)}.")

    # -- Invisible markdown regions ---------------------------------------------
    def _regions(self, ctx: Context, at: ArtifactText) -> None:
        cid = at.artifact.component_id
        for r in at.hidden:
            content = r.text.strip()
            span = at.span(r.text_start, r.text_start + len(r.text))
            if r.kind == "html-comment":
                if search(AGENT_DIRECTED, content) or search(EXECUTABLE_CONTENT, content) and word_count(content) >= 3:
                    ctx.emit("AG-SKL-HID-005", component_ids=cid, span=span, snippet=content, match=content,
                             message="HTML comment (invisible when rendered) contains agent-directed text.")
            elif r.kind == "after-whitespace":
                line = at.line_text(r.start)
                if "|" in line or at.in_code(r.start) or word_count(content) < 3:
                    continue
                ctx.emit("AG-SKL-HID-006", component_ids=cid, span=span, snippet=content, match=content,
                         message="Text is pushed off-screen by a long whitespace run.")
            elif r.kind in ("link-reference", "image-alt", "image-title", "link-title"):
                if search(AGENT_DIRECTED, content):
                    ctx.emit("AG-SKL-HID-007", component_ids=cid, span=span, snippet=content, match=content,
                             message=f"Agent-directed text in a {r.kind.replace('-', ' ')}, which readers rarely see.")
            elif r.kind == "css-hidden":
                if word_count(content) >= 3:
                    ctx.emit("AG-SKL-HID-010", component_ids=cid, span=span, snippet=content, match=content,
                             message="Text is hidden with HTML/CSS (display:none, zero size, invisible color or 'hidden').")

    # -- Encoded blobs ----------------------------------------------------------
    def _decoded(self, ctx: Context, at: ArtifactText) -> None:
        cid = at.artifact.component_id
        reported: set[tuple[int, int]] = set()
        for unit in at.units:
            if unit.scope != "decoded" or unit.anchor is None:
                continue
            span = at.span(*unit.anchor)
            layers = " → ".join(unit.decode_path)
            if unit.anchor not in reported:
                reported.add(unit.anchor)
                ctx.emit("AG-SKL-HID-008", component_ids=cid, span=span, snippet=unit.text[:200],
                         match=f"blob:{at.text[unit.anchor[0]:unit.anchor[1]][:200]}", decode_path=unit.decode_path,
                         detail=f"decoded via {layers}", message=f"Encoded blob ({layers}) decoded and rescanned.")
            m = search(AGENT_DIRECTED, unit.norm.text) or search(EXECUTABLE_CONTENT, unit.norm.text)
            if m:
                ctx.emit("AG-SKL-HID-009", component_ids=cid, span=span, snippet=unit.text[:240],
                         match=f"decoded:{unit.text[:200]}", decode_path=unit.decode_path,
                         detail=f"decoded via {layers}",
                         message=f"Encoded content ({layers}) decodes to instructions or executable content.")


def _unused(_: Span) -> None:  # keep Span import for type checkers
    return None

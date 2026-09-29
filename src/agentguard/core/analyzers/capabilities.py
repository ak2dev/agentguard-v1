"""Capability evidence (labels for the toxic-flow graph) from skills,
instruction files and bundled scripts, plus the deterministic
description/behavior mismatch rule (AG-SKL-MIS-001)."""

from __future__ import annotations

from typing import ClassVar

import regex

from ..models.enums import ArtifactRole, CapLabel, ComponentKind, Confidence, EvidenceKind
from .base import Context
from .heuristics import (
    CREDENTIAL_PATH,
    DESTRUCTIVE,
    EGRESS_CODE,
    ENV_DUMP,
    EXEC_CODE,
    INSTRUCTION_FILES,
    PERSISTENCE,
    READ_VERB,
    TOKEN_ENV,
    finditer,
    search,
)

_UNTRUSTED_SOURCES = regex.compile(
    r"\b(?:web ?pages?|websites?|urls?|browse|crawl|scrape|search results?|emails?|inbox|issues?|pull requests?|"
    r"comments?|tickets?|slack|discord|messages?|rss|feeds?|user[- ]supplied|untrusted|documents? from|pdfs?|uploads?)\b",
    regex.IGNORECASE,
)
_PRIVATE_SOURCES = regex.compile(
    r"\b(?:private|internal|confidential|secrets?|credentials?|database|customer|employee|payroll|medical|"
    r"repositor(?:y|ies)|files? on disk|local files?|home directory|filesystem|file system|emails?|inbox|calendar|"
    r"drive|notion|crm)\b",
    regex.IGNORECASE,
)
_NETWORK_WORDS = regex.compile(
    r"\b(?:api|http|web|url|online|remote|cloud|service|upload|download|fetch|send|post|sync|webhook|slack|github|gitlab|"
    r"jira|email|notify|network|internet|server|endpoint|publish|deploy|telemetry|analytics|report(?:s|ing)? to)\b",
    regex.IGNORECASE,
)
_SECRET_WORDS = regex.compile(
    r"\b(?:env(?:ironment)?|credential|secret|token|key|auth|login|password|config(?:uration)?|ssh|aws|cloud|deploy)\b",
    regex.IGNORECASE,
)


class CapabilityAnalyzer:
    id: ClassVar[str] = "capabilities"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SKL-MIS-001",)

    def run(self, ctx: Context) -> None:
        for at in ctx.texts():
            role = at.artifact.role
            cid = at.artifact.component_id
            comp = ctx.inventory.components.get(cid)
            if comp is None or comp.kind == ComponentKind.mcp_client_config:
                continue
            code = role in (ArtifactRole.script, ArtifactRole.source_code)
            for unit in at.units:
                if unit.scope not in ("body", "code", "command", "hidden", "decoded", "frontmatter"):
                    continue
                t = unit.norm.text
                explicit = code or unit.scope == "command"

                def cap(label: CapLabel, m: regex.Match[str], reason: str, c: Confidence | None = None) -> None:
                    if c is None:
                        abs_off = ctx.unit_abs(unit, m.start())
                        in_fence = unit.base is not None and abs_off is not None and at.in_code(abs_off)
                        c = Confidence.high if explicit or in_fence else Confidence.medium
                    ctx.add_capability(cid, label, confidence=c, span=ctx.unit_span(unit, m.start(), m.end()),
                                       snippet=_line(t, m.start()), reason=reason,
                                       kind=EvidenceKind.ast if code else EvidenceKind.regex)

                for m in finditer(EGRESS_CODE, t)[:3]:
                    cap(CapLabel.external_egress, m, "network request")
                for m in finditer(EXEC_CODE, t)[:3]:
                    cap(CapLabel.code_exec, m, "process/eval execution")
                for m in finditer(ENV_DUMP, t)[:2]:
                    cap(CapLabel.credential_access, m, "dumps the environment")
                    cap(CapLabel.reads_private_data, m, "dumps the environment")
                for m in finditer(CREDENTIAL_PATH, t)[:3]:
                    line = _line(t, m.start())
                    if code or search(READ_VERB, line):
                        cap(CapLabel.credential_access, m, "reads a credential store")
                        cap(CapLabel.reads_private_data, m, "reads a credential store")
                for m in finditer(TOKEN_ENV, t)[:2]:
                    if code:
                        cap(CapLabel.credential_access, m, "reads a token environment variable", Confidence.medium)
                for m in finditer(PERSISTENCE, t)[:2]:
                    cap(CapLabel.persistence, m, "writes a persistence location", Confidence.medium)
                for m in finditer(INSTRUCTION_FILES, t)[:2]:
                    line = _line(t, m.start())
                    if regex.search(r"(?i)\b(write|append|modify|edit|update|add|echo|>>|tee|insert)\b", line):
                        cap(CapLabel.persistence, m, "modifies agent instruction/memory files", Confidence.medium)
                for m in finditer(DESTRUCTIVE, t)[:2]:
                    cap(CapLabel.destructive, m, "destructive operation")
                if role in (ArtifactRole.skill_md, ArtifactRole.instruction_md) and unit.scope == "body":
                    m = search(_UNTRUSTED_SOURCES, t)
                    if m:
                        cap(CapLabel.ingests_untrusted_content, m, "processes external/untrusted content", Confidence.medium)
        self._mismatch(ctx)

    def _mismatch(self, ctx: Context) -> None:
        for comp in ctx.inventory.of_kind(ComponentKind.skill):
            md = next((t for t in ctx.texts("skill_md") if t.artifact.component_id == comp.id), None)
            if md is None or not md.fm or not md.fm.data:
                continue
            desc = str(md.fm.data.get("description") or "")
            if not desc:
                continue
            # What the skill *declares*: its description plus the visible SKILL.md body.
            body = next((u.norm.text for u in md.units if u.scope == "body"), "")
            declared = f"{desc}\n{body}"
            script_caps = [
                cap for cap in comp.capabilities
                if cap.observed and any(ev.location and _is_script(ctx, ev.location.path) for ev in cap.evidence)
            ]
            issues: list[tuple[str, object]] = []
            for cap in script_caps:
                if cap.label == CapLabel.external_egress and not search(_NETWORK_WORDS, declared):
                    issues.append(("makes network requests", cap))
                elif (cap.label == CapLabel.credential_access
                      and any(e.detail in _HARVEST_REASONS for e in cap.evidence)
                      and not search(_SECRET_WORDS, declared)):
                    issues.append(("reads credentials or dumps the environment", cap))
                elif cap.label == CapLabel.persistence and not regex.search(
                        r"(?i)\b(install|setup|config|startup|profile|cron|schedul)", declared):
                    issues.append(("writes persistence locations", cap))
            seen: set[str] = set()
            for what, cap in issues:
                if what in seen:
                    continue
                seen.add(what)
                ev = next(e for e in cap.evidence  # type: ignore[attr-defined]
                          if e.location and _is_script(ctx, e.location.path))
                ctx.emit("AG-SKL-MIS-001", component_ids=comp.id, span=ev.location, snippet=str(ev.snippet),
                         match=f"{what}", kind=EvidenceKind.metadata,
                         message=f"Description (\"{desc[:80]}\") does not mention it, but a bundled script {what}.")


_HARVEST_REASONS = {"dumps the environment", "reads a credential store"}


def _is_script(ctx: Context, path: str) -> bool:
    art = ctx.inventory.artifacts.get(path)
    return bool(art and art.role in (ArtifactRole.script, ArtifactRole.source_code))


def _line(text: str, offset: int) -> str:
    s = text.rfind("\n", 0, offset) + 1
    e = text.find("\n", offset)
    return text[s : e if e >= 0 else len(text)]


__all__ = ["CapabilityAnalyzer", "TOKEN_ENV"]

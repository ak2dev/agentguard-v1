"""AG-SKL-CRED-010: credential access and network egress in the same skill.

Requires *both* halves to be evidenced with at least one half from code or an
explicit command, so documentation that merely mentions ~/.ssh does not fire.
The halves are either in the same artifact, or in two artifacts of the skill
that are linked (see ``links``): a file one writes and the other reads, one
script running the other, or an import. Markdown links only at the ends of a
chain, so a SKILL.md that runs two unrelated scripts does not link them.
"""

from __future__ import annotations

import posixpath
from typing import ClassVar

from ..analyzers.base import Context
from ..models import Evidence, LimitEvent
from ..models.enums import ArtifactRole, CapLabel, ComponentKind, EvidenceKind
from ..redact import RedactedText
from .links import MAX_FILES, chain, component_links

_CRED_RULES = {"AG-SKL-CRED-001", "AG-SKL-CRED-002", "AG-CODE-020", "AG-CODE-021"}
_EGRESS_RULES = {"AG-SKL-EXF-001", "AG-SKL-EXF-002", "AG-SKL-EXF-003", "AG-SKL-EXF-004", "AG-SKL-EXF-005"}
_ROLES = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.reference, ArtifactRole.script,
          ArtifactRole.source_code)
_MARKDOWN = (ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.reference)
_VERB = {"file": ("writes", "reads"), "runs": ("runs", "is run by"), "import": ("imports", "is imported by")}


class CredEgressCorrelator:
    id: ClassVar[str] = "corr.cred_egress"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SKL-CRED-010",)

    def run(self, ctx: Context) -> None:
        by_comp: dict[str, list] = {}
        for at in ctx.texts(*(r.value for r in _ROLES)):
            by_comp.setdefault(at.artifact.component_id, []).append(at)
        for comp in ctx.inventory.of_kind(ComponentKind.skill, ComponentKind.instruction_file,
                                          ComponentKind.command, ComponentKind.subagent):
            cred_ev: list[Evidence] = []
            egress_ev: list[Evidence] = []
            for raw in ctx.raw:
                if comp.id not in raw.component_ids:
                    continue
                if raw.rule_id in _CRED_RULES:
                    cred_ev.extend(raw.evidence[:1])
                elif raw.rule_id in _EGRESS_RULES:
                    egress_ev.extend(raw.evidence[:1])
            for cap in comp.capabilities:
                if cap.label == CapLabel.credential_access and cap.observed and cap.confidence.rank >= 3:
                    cred_ev.extend(cap.evidence[:1])
                if cap.label == CapLabel.external_egress and cap.observed and cap.confidence.rank >= 3:
                    egress_ev.extend(cap.evidence[:1])
            if not cred_ev or not egress_ev:
                continue
            cred_paths = {e.location.path for e in cred_ev if e.location}
            egress_paths = {e.location.path for e in egress_ev if e.location}
            same = sorted(cred_paths & egress_paths)
            for path in same[:3]:
                c = next(e for e in cred_ev if e.location and e.location.path == path)
                g = next(e for e in egress_ev if e.location and e.location.path == path)
                ctx.emit(
                    "AG-SKL-CRED-010",
                    component_ids=comp.id,
                    span=c.location,
                    snippet=str(c.snippet),
                    match=f"{path}",
                    kind=EvidenceKind.metadata,
                    detail="credential access",
                    extra_evidence=[Evidence(kind=EvidenceKind.metadata, location=g.location, snippet=g.snippet,
                                             detail="network egress")],
                    related=[g.location] if g.location else [],
                    message=f"'{path}' both accesses credentials and sends data over the network.",
                )
            if same:
                continue
            self._linked(ctx, comp, by_comp.get(comp.id, []), cred_ev, egress_ev, cred_paths, egress_paths)

    def _linked(self, ctx: Context, comp, texts: list, cred_ev: list[Evidence], egress_ev: list[Evidence],
                cred_paths: set[str], egress_paths: set[str]) -> None:
        if len(texts) > MAX_FILES:
            ctx.data.setdefault("limit_events", []).append(  # type: ignore[union-attr]
                LimitEvent(kind="links_not_traced", path=comp.root or comp.id,
                           detail=f"{len(texts)} files > {MAX_FILES}; AG-SKL-CRED-010 compared files one by one"))
            return
        links = component_links(texts, comp.root)
        if not links:
            return
        markdown = {at.path for at in texts if at.artifact.role in _MARKDOWN}
        texts_by_path = {at.path: at for at in texts}
        emitted = 0
        for start in sorted(cred_paths):
            steps = chain(links, start, egress_paths, markdown)
            if not steps or emitted >= 3:
                continue
            end = steps[-1][0].dst if steps[-1][1] else steps[-1][0].src
            c = next(e for e in cred_ev if e.location and e.location.path == start)
            g = next(e for e in egress_ev if e.location and e.location.path == end)
            link_ev: list[Evidence] = []
            said: list[str] = []
            for link, forward in steps:
                src, dst = (link.src, link.dst) if forward else (link.dst, link.src)
                at = texts_by_path.get(link.src)
                span = at.span(link.src_offset) if at is not None else None
                snippet = at.line_text(link.src_offset).strip() if at is not None else ""
                verb = _VERB[link.kind][0]
                link_ev.append(Evidence(kind=EvidenceKind.metadata, location=span, snippet=RedactedText.of(snippet),
                                        detail=f"link: {link.src} {verb} {link.dst if link.kind != 'file' else link.via}"))
                if link.kind == "file":
                    said.append(f"{_name(src)} writes {link.via}, which {_name(dst)} reads")
                elif forward:
                    said.append(f"{_name(link.src)} {verb} {_name(link.dst)}")
                else:
                    said.append(f"{_name(src)} {_VERB[link.kind][1]} {_name(dst)}")
            ctx.emit(
                "AG-SKL-CRED-010",
                component_ids=comp.id,
                span=c.location,
                snippet=str(c.snippet),
                match=f"{start}->{end}",
                kind=EvidenceKind.metadata,
                detail="credential access",
                extra_evidence=[Evidence(kind=EvidenceKind.metadata, location=g.location, snippet=g.snippet,
                                         detail="network egress"), *link_ev],
                related=[e.location for e in (g, *link_ev) if e.location],
                message=(f"'{start}' accesses credentials and '{end}' sends data over the network, and the two are "
                         f"linked: {'; '.join(said)}."),
            )
            emitted += 1


def _name(path: str) -> str:
    return posixpath.basename(path)

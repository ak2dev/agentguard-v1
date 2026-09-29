"""AG-SKL-CRED-010: credential access and network egress in the same skill.

Requires *both* halves to be evidenced in the same artifact (or in a script
and the SKILL.md that runs it), with at least one half from code or an
explicit command, so documentation that merely mentions ~/.ssh does not fire.
"""

from __future__ import annotations

from typing import ClassVar

from ..analyzers.base import Context
from ..models import Evidence
from ..models.enums import CapLabel, ComponentKind, EvidenceKind

_CRED_RULES = {"AG-SKL-CRED-001", "AG-SKL-CRED-002", "AG-CODE-020", "AG-CODE-021"}
_EGRESS_RULES = {"AG-SKL-EXF-001", "AG-SKL-EXF-002", "AG-SKL-EXF-003", "AG-SKL-EXF-004", "AG-SKL-EXF-005"}


class CredEgressCorrelator:
    id: ClassVar[str] = "corr.cred_egress"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SKL-CRED-010",)

    def run(self, ctx: Context) -> None:
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
            if not cred_paths & egress_paths:
                continue
            for path in sorted(cred_paths & egress_paths)[:3]:
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

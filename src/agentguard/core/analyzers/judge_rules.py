"""AG-LLM-001/002 from recorded judge verdicts (pure; no model is called here).

Invariants: judge findings are tagged ``source: llm``, carry at most medium
confidence, and the engine caps them at HIGH. They never change or remove a
deterministic finding.
"""

from __future__ import annotations

from typing import ClassVar

from ..judge_models import ManipulationVerdict, MismatchVerdict
from ..models import Span
from ..models.enums import Confidence, EvidenceKind, FindingSource
from .base import Context


def _conf(value: str) -> Confidence:
    # The model's own confidence is advisory; judge findings never exceed medium.
    return Confidence.low if value == "low" else Confidence.medium


class JudgeAnalyzer:
    id: ClassVar[str] = "judge"
    requires: ClassVar[frozenset[str]] = frozenset({"network"})
    network_feature: ClassVar[str] = "llm_judge"
    rules: ClassVar[tuple[str, ...]] = ("AG-LLM-001", "AG-LLM-002")

    def run(self, ctx: Context) -> None:
        for r in sorted(ctx.options.judge_results, key=lambda r: (r.kind, r.path, r.component_id)):
            if r.verdict is None or r.component_id not in ctx.inventory.components:
                continue
            quote = r.verdict.quotes[0].text if r.verdict.quotes else ""
            note = f" (judge: {r.provider}/{r.model}{', input truncated' if r.truncated else ''})"
            span = Span(path=r.path)
            if isinstance(r.verdict, MismatchVerdict) and r.verdict.mismatch:
                what = "; ".join(r.verdict.undisclosed_behaviors[:3]) or "undisclosed behavior"
                ctx.emit("AG-LLM-001", component_ids=r.component_id, span=span, snippet=quote, match=f"{r.content_hash}:mismatch",
                         kind=EvidenceKind.llm, confidence=_conf(r.verdict.confidence), source=FindingSource.llm,
                         tags=["llm-judge"], detail=r.verdict.explanation[:300],
                         message=f"LLM judge: code behavior not disclosed by the description — {what}.{note}")
            elif isinstance(r.verdict, ManipulationVerdict) and r.verdict.manipulation:
                techniques = ", ".join(r.verdict.techniques) or "unspecified"
                ctx.emit("AG-LLM-002", component_ids=r.component_id, span=span, snippet=quote, match=f"{r.content_hash}:manip",
                         kind=EvidenceKind.llm, confidence=_conf(r.verdict.confidence), source=FindingSource.llm,
                         tags=["llm-judge"], detail=r.verdict.explanation[:300],
                         message=f"LLM judge: possible agent manipulation ({techniques}).{note}")

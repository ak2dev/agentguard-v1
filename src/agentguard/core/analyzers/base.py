"""Analyzer plugin interface and the per-scan context analyzers write into.

An analyzer is a deterministic function of (inventory, rule pack, options):
it reads the context and calls ``ctx.emit`` / ``ctx.add_capability``. It must
not perform I/O. Analyzers that need native code or the network declare it in
``requires`` and are skipped (and reported as skipped) when unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Protocol

from ..artifacts import ArtifactText, TextUnit
from ..models import Capability, Evidence, FlowPath, ScanOptions, Span
from ..models.enums import CapLabel, Confidence, EvidenceKind, FindingSource, Severity
from ..redact import RedactedText
from ..textutil import sha256_hex

if TYPE_CHECKING:
    from ..inventory import Inventory
    from ..rules.pack import RulePack


class Analyzer(Protocol):
    id: ClassVar[str]
    requires: ClassVar[frozenset[str]]
    rules: ClassVar[tuple[str, ...]]  # rule ids this analyzer may emit

    def run(self, ctx: Context) -> None: ...


@dataclass
class RawFinding:
    rule_id: str
    component_ids: list[str]
    primary: Span | None
    evidence: list[Evidence]
    match_key: str
    message: str | None = None
    severity: Severity | None = None
    confidence: Confidence | None = None
    hidden: bool = False
    tags: list[str] = field(default_factory=list)
    related: list[Span] = field(default_factory=list)
    flow: FlowPath | None = None
    source: FindingSource = FindingSource.deterministic


class EmitError(RuntimeError):
    pass


@dataclass
class Context:
    inventory: Inventory
    pack: RulePack
    options: ScanOptions
    raw: list[RawFinding] = field(default_factory=list)
    current: str = ""  # analyzer id currently running
    allowed_rules: frozenset[str] = frozenset()
    data: dict[str, object] = field(default_factory=dict)  # scratch shared between analyzers

    # -- helpers ------------------------------------------------------------
    def texts(self, *roles: str) -> list[ArtifactText]:
        out = [t for t in self.inventory.texts.values() if not roles or t.artifact.role.value in roles]
        return sorted(out, key=lambda t: t.path)

    def unit_span(self, unit: TextUnit, start: int, end: int) -> Span:
        at = self.inventory.texts.get(unit.path)
        if unit.base is not None and at is not None:
            return at.span(unit.base + unit.norm.orig(start), unit.base + unit.norm.orig(end))
        if unit.anchor is not None and at is not None:
            return at.span(*unit.anchor)
        if unit.anchor_span is not None:
            return unit.anchor_span
        return Span(path=unit.path)

    def unit_abs(self, unit: TextUnit, start: int) -> int | None:
        if unit.base is not None:
            return unit.base + unit.norm.orig(start)
        if unit.anchor is not None:
            return unit.anchor[0]
        return None

    def rule_enabled(self, rule_id: str) -> bool:
        rule = self.pack.rules.get(rule_id)
        return bool(rule and rule.enabled)

    # -- output -------------------------------------------------------------
    def emit(
        self,
        rule_id: str,
        *,
        component_ids: list[str] | str,
        span: Span | None,
        snippet: str = "",
        detail: str = "",
        kind: EvidenceKind = EvidenceKind.regex,
        match: str | None = None,
        message: str | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        hidden: bool = False,
        hidden_kind: str | None = None,
        decode_path: tuple[str, ...] | list[str] = (),
        tags: list[str] | None = None,
        related: list[Span] | None = None,
        extra_evidence: list[Evidence] | None = None,
        flow: FlowPath | None = None,
        source: FindingSource = FindingSource.deterministic,
    ) -> None:
        if self.allowed_rules and rule_id not in self.allowed_rules:
            raise EmitError(f"analyzer {self.current!r} emitted undeclared rule {rule_id}")
        if not self.rule_enabled(rule_id):
            return
        cids = [component_ids] if isinstance(component_ids, str) else list(component_ids)
        ev = Evidence(
            kind=kind,
            location=span,
            snippet=RedactedText.of(snippet),
            detail=detail,
            hidden=hidden,
            decode_path=[*([hidden_kind] if hidden_kind else []), *decode_path],
        )
        key_material = match if match is not None else snippet
        match_key = sha256_hex(f"{key_material}")[:16]
        self.raw.append(
            RawFinding(
                rule_id=rule_id,
                component_ids=sorted(set(cids)),
                primary=span,
                evidence=[ev, *(extra_evidence or [])],
                match_key=match_key,
                message=message,
                severity=severity,
                confidence=confidence,
                hidden=hidden,
                tags=list(tags or []),
                related=list(related or []),
                flow=flow,
                source=source,
            )
        )

    def add_capability(
        self,
        component_id: str,
        label: CapLabel,
        *,
        subject: str | None = None,
        observed: bool = True,
        declared: bool = False,
        confidence: Confidence = Confidence.medium,
        reason: str = "",
        span: Span | None = None,
        snippet: str = "",
        kind: EvidenceKind = EvidenceKind.regex,
    ) -> None:
        comp = self.inventory.components.get(component_id)
        if comp is None:
            return
        subj = subject or component_id
        for cap in comp.capabilities:
            if cap.label == label and cap.subject == subj:
                cap.observed = cap.observed or observed
                cap.declared = cap.declared or declared
                if confidence.rank > cap.confidence.rank:
                    cap.confidence = confidence
                if len(cap.evidence) < 5 and (span or snippet):
                    cap.evidence.append(Evidence(kind=kind, location=span, snippet=RedactedText.of(snippet), detail=reason))
                return
        comp.capabilities.append(
            Capability(
                label=label,
                subject=subj,
                observed=observed,
                declared=declared,
                confidence=confidence,
                reason=reason,
                evidence=[Evidence(kind=kind, location=span, snippet=RedactedText.of(snippet), detail=reason)]
                if (span or snippet)
                else [],
            )
        )

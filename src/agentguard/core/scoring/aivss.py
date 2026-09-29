"""Pluggable scoring. Default: an OWASP AIVSS v0.8-shaped scorer.

Formula (docs/sources.md; re-verify against the v0.8 PDF before 1.0):
    AARS  = (10 - CVSS_base) * (FactorSum / 10) * ThreatMultiplier
    AIVSS = (CVSS_base + AARS) * MitigationFactor           (capped at 10)
ThreatMultiplier: attacked 1.00, poc 0.97, unreported 0.50.
MitigationFactor: none/weak 1.00, partial 0.83, strong 0.67.

Honesty notes, surfaced in every score's ``components``:
* ``cvss_base_source`` is ``rule`` when the rule carries a calculator-computed
  CVSS v4.0 base score, otherwise ``severity-default`` (an approximation).
* The ten AIVSS Agentic Risk Amplification Factors are *not* individually
  assessed statically; ``factor_sum`` is a proxy derived from the capability
  labels evidenced for the affected components (``factor_source: capability-proxy``).
"""

from __future__ import annotations

from typing import Protocol

from ..models import Component, Finding, RuleDef, Score
from ..models.enums import CapLabel, Confidence, Severity

THREAT = {"attacked": 1.0, "poc": 0.97, "unreported": 0.5}
MITIGATION = {"none": 1.0, "partial": 0.83, "strong": 0.67}
SEVERITY_DEFAULT_BASE = {
    Severity.critical: 9.3,
    Severity.high: 7.7,
    Severity.medium: 5.3,
    Severity.low: 2.1,
    Severity.info: 0.0,
}
_PROXY_LABELS = (
    CapLabel.code_exec,
    CapLabel.external_egress,
    CapLabel.reads_private_data,
    CapLabel.ingests_untrusted_content,
    CapLabel.destructive,
    CapLabel.persistence,
    CapLabel.credential_access,
    CapLabel.auto_approved,
)


class Scorer(Protocol):
    name: str
    version: str

    def score(self, finding: Finding, rule: RuleDef, components: list[Component]) -> Score: ...


class AivssV08Scorer:
    name = "aivss"
    version = "0.8"

    def score(self, finding: Finding, rule: RuleDef, components: list[Component]) -> Score:
        if finding.severity == Severity.info:
            return Score(scorer=self.name, scorer_version=self.version, value=0.0, vector="",
                         components={"cvss_base": 0.0, "cvss_base_source": 0.0})
        base = rule.aivss.cvss_base
        base_from_rule = base is not None
        if base is None or finding.severity != rule.severity:
            base = SEVERITY_DEFAULT_BASE[finding.severity]
            base_from_rule = False
        factor_sum = 0.0
        labels: dict[CapLabel, Confidence] = {}
        for comp in components:
            for cap in comp.capabilities:
                if cap.label in _PROXY_LABELS and cap.observed:
                    prev = labels.get(cap.label)
                    if prev is None or cap.confidence.rank > prev.rank:
                        labels[cap.label] = cap.confidence
        for conf in labels.values():
            factor_sum += 1.0 if conf == Confidence.high else 0.5
        factor_sum = min(factor_sum, 10.0)
        thm = THREAT[rule.aivss.threat]
        mf = MITIGATION["none"]
        aars = (10.0 - base) * (factor_sum / 10.0) * thm
        value = round(min(10.0, (base + aars) * mf), 1)
        return Score(
            scorer=self.name,
            scorer_version=self.version,
            value=value,
            vector=rule.cvss4_vector or "",
            components={
                "cvss_base": base,
                "cvss_base_source": 1.0 if base_from_rule else 0.0,  # 1 = rule, 0 = severity-default
                "factor_sum": factor_sum,
                "factor_source_capability_proxy": 1.0,
                "threat_multiplier": thm,
                "mitigation_factor": mf,
                "aars": round(aars, 3),
            },
        )


DEFAULT_SCORER: Scorer = AivssV08Scorer()

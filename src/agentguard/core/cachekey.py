"""Cache keys and drift between reports (Agent Guard Web).

A report is fully determined by what was scanned (an immutable reference:
commit SHA, exact package version + archive integrity), the rule pack and the
engine version — so that triple is the cache key and the permalink identity.
"""

from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, Field

from .models import ImmutableRef, Report, RulePackInfo


def report_cache_key(ref: ImmutableRef, rule_pack: RulePackInfo, engine_version: str) -> str:
    """Stable 32-hex-character key; only an immutable reference can produce one."""
    material = {
        "kind": ref.kind.value,
        "locator": ref.locator,
        "resolved": ref.resolved,
        "integrity": ref.integrity,
        "rule_pack_digest": rule_pack.digest,
        "engine_version": engine_version,
    }
    canon = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:32]


class FindingDelta(BaseModel):
    fingerprint: str
    rule_id: str
    severity: str
    title: str
    path: str | None = None


class ReportDiff(BaseModel):
    """What changed between two scans of the same source (e.g. a rescan after an update)."""

    added: list[FindingDelta] = Field(default_factory=list)
    removed: list[FindingDelta] = Field(default_factory=list)
    unchanged: int = 0
    severity_before: dict[str, int] = Field(default_factory=dict)
    severity_after: dict[str, int] = Field(default_factory=dict)
    rule_pack_changed: bool = False
    target_changed: bool = False


def _delta(f) -> FindingDelta:  # noqa: ANN001 - Finding
    return FindingDelta(
        fingerprint=f.fingerprint, rule_id=f.rule_id, severity=f.severity.value, title=f.title,
        path=f.primary.path if f.primary else None,
    )


def diff_reports(old: Report, new: Report) -> ReportDiff:
    before = {f.fingerprint: f for f in old.findings}
    after = {f.fingerprint: f for f in new.findings}
    old_target = old.target.model_dump(mode="json") if old.target else None
    new_target = new.target.model_dump(mode="json") if new.target else None
    return ReportDiff(
        added=[_delta(after[k]) for k in sorted(after.keys() - before.keys())],
        removed=[_delta(before[k]) for k in sorted(before.keys() - after.keys())],
        unchanged=len(before.keys() & after.keys()),
        severity_before=dict(old.stats.findings_by_severity),
        severity_after=dict(new.stats.findings_by_severity),
        rule_pack_changed=old.rule_pack.digest != new.rule_pack.digest,
        target_changed=old_target != new_target,
    )

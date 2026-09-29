"""Suppressions, baselines and severity overrides (post-processing)."""

from __future__ import annotations

import datetime as dt
import fnmatch

from ..models import Finding, ScanOptions, Suppression, SuppressionState


def _matches(s: Suppression, f: Finding) -> bool:
    if s.rule_id and s.rule_id != f.rule_id:
        return False
    if s.fingerprint and s.fingerprint != f.fingerprint:
        return False
    if s.path_glob:
        path = f.primary.path if f.primary else ""
        if not fnmatch.fnmatchcase(path, s.path_glob):
            return False
    return True


def apply_suppressions(
    findings: list[Finding], options: ScanOptions
) -> tuple[list[Finding], list[Finding], list[tuple[Suppression, str]]]:
    """Return (kept, suppressed, problems). Expired suppressions do not hide
    findings; the finding resurfaces tagged ``suppression-expired``. Invalid
    suppressions (no reason / no expiry) are ignored and reported."""
    today = options.today or dt.date.today()
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    problems: list[tuple[Suppression, str]] = []
    valid: list[Suppression] = []
    for s in options.suppressions:
        if not s.is_valid():
            problems.append((s, "missing reason (>= 10 chars) or expires date"))
        else:
            valid.append(s)
    for f in findings:
        hit = next((s for s in valid if _matches(s, f)), None)
        if hit is None:
            kept.append(f)
            continue
        assert hit.expires is not None
        if hit.expires < today:
            f.suppression = SuppressionState(status="expired", reason=hit.reason, expires=hit.expires.isoformat())
            f.tags = sorted({*f.tags, "suppression-expired"})
            kept.append(f)
        else:
            f.suppression = SuppressionState(status="active", reason=hit.reason, expires=hit.expires.isoformat())
            suppressed.append(f)
    return kept, suppressed, problems


def apply_baseline(findings: list[Finding], options: ScanOptions) -> list[Finding]:
    if options.baseline is None:
        return findings
    out = []
    for f in findings:
        if f.fingerprint in options.baseline:
            f.baseline_state = "unchanged"
            continue
        f.baseline_state = "new"
        out.append(f)
    return out

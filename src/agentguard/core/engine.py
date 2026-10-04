"""The scan pipeline: inventory → text units → analyzers → correlation →
finalize (severity invariants, dedupe) → policy → score → report.

``scan`` is pure: no filesystem, no network, no wall clock (unless
``options.include_timestamps``). Same tree + same rule pack → identical report.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter

from .analyzers.base import Context, RawFinding
from .analyzers.registry import ANALYZERS, CORRELATORS, native_available
from .inventory import build_inventory
from .models import (
    AnalyzerMatch,
    AnalyzerRun,
    Finding,
    LimitEvent,
    ProgressEvent,
    Report,
    ReportStats,
    ScanOptions,
)
from .models.enums import Confidence, FindingSource, Severity
from .policy.apply import apply_baseline, apply_suppressions
from .rules.pack import RulePack
from .scoring.aivss import DEFAULT_SCORER, Scorer
from .textutil import sha256_hex, visible_escape
from .tree import ArtifactTree

ENGINE_VERSION = "0.1.0.dev0"

# Rules whose findings are *about* hidden content; they are not escalated for it.
_NO_HIDDEN_ESCALATION_PREFIXES = ("AG-SKL-HID-", "AG-MCP-META-001", "AG-SYS-")


def _progress(options: ScanOptions, stage: str, done: int, total: int) -> None:
    if options.on_progress is not None:
        options.on_progress(ProgressEvent(stage=stage, done=done, total=total))


def scan(tree: ArtifactTree, options: ScanOptions | None = None, pack: RulePack | None = None,
         scorer: Scorer | None = None) -> Report:
    options = options or ScanOptions()
    pack = pack or RulePack.default()
    scorer = scorer or DEFAULT_SCORER

    inv = build_inventory(tree, options.limits)
    ctx = Context(inventory=inv, pack=pack, options=options)
    ctx.data["limit_events"] = list(tree.limit_events)

    runs: list[AnalyzerRun] = []
    stages = [*ANALYZERS, *CORRELATORS]
    for i, analyzer_cls in enumerate(stages):
        _progress(options, analyzer_cls.id, i, len(stages))
        analyzer = analyzer_cls()
        reason = _skip_reason(analyzer_cls, options)
        if reason:
            runs.append(AnalyzerRun(id=analyzer_cls.id, status="skipped", reason=reason))
            continue
        ctx.current = analyzer_cls.id
        ctx.allowed_rules = frozenset(analyzer_cls.rules)
        try:
            analyzer.run(ctx)
            runs.append(AnalyzerRun(id=analyzer_cls.id, status="ran"))
        except Exception as exc:  # noqa: BLE001 — isolate analyzer failures; never fail open
            runs.append(AnalyzerRun(id=analyzer_cls.id, status="errored", reason=f"{type(exc).__name__}: {str(exc)[:200]}"))
            ctx.allowed_rules = frozenset()
            ctx.emit(
                "AG-SYS-002",
                component_ids=[],
                span=None,
                snippet="",
                detail=f"analyzer {analyzer_cls.id} failed: {type(exc).__name__}",
                message=f"Analyzer '{analyzer_cls.id}' failed; coverage is reduced.",
            )
    _progress(options, "finalize", len(stages), len(stages))

    ran = {r.id for r in runs if r.status == "ran"}
    evaluated = [
        r for r in pack.rules.values()
        if r.enabled and ((isinstance(r.match, AnalyzerMatch) and r.match.analyzer in ran) or
                          (not isinstance(r.match, AnalyzerMatch) and r.match.type in ran))  # "regex" / "yara" analyzers
    ]

    raw = ctx.raw
    if options.changed_paths is not None:
        raw = _pr_filter(raw, ctx, options.changed_paths)
    findings = _finalize(raw, ctx, pack, options)
    findings, suppressed, problems = apply_suppressions(findings, options)
    for s, why in problems:
        if pack.rules.get("AG-POL-006"):
            findings.append(_synthetic(pack, "AG-POL-006", f"Suppression for {s.rule_id or s.fingerprint or s.path_glob} ignored: {why}.",
                                       key=f"{s.rule_id}|{s.fingerprint}|{s.path_glob}"))
    for f in list(findings):
        if f.suppression and f.suppression.status == "expired" and pack.rules.get("AG-POL-005"):
            findings.append(_synthetic(pack, "AG-POL-005", f"Suppression of {f.rule_id} expired on {f.suppression.expires}; "
                                       "the finding is reported again.", key=f.fingerprint, primary=f.primary))
    for f in [*findings, *suppressed]:
        comps = [inv.components[c] for c in f.component_ids if c in inv.components]
        f.score = scorer.score(f, pack.rule(f.rule_id), comps)
    findings = apply_baseline(findings, options)
    findings.sort(key=Finding.sort_key)
    suppressed.sort(key=Finding.sort_key)

    by_sev = Counter(f.severity.value for f in findings)
    stats = ReportStats(
        files_scanned=len(tree.files),
        bytes_scanned=tree.total_bytes,
        components=len(inv.components),
        rules_evaluated=len(evaluated),
        findings_by_severity={s.value: by_sev.get(s.value, 0) for s in Severity},
        suppressed=len(suppressed),
        limit_events=sorted(tree.limit_events, key=lambda e: (e.kind, e.path)),
    )
    report = Report(
        engine_version=ENGINE_VERSION,
        rule_pack=pack.info,
        target=tree.source,
        network_features_used=options.network.enabled(),
        network_hosts=sorted(set(options.network_hosts)),
        analyzers=runs,
        inventory=sorted(inv.components.values(), key=lambda c: (c.kind.value, c.root, c.name, c.id)),
        artifacts=sorted(inv.artifacts.values(), key=lambda a: a.path),
        findings=findings,
        suppressed_findings=suppressed,
        flows=[f.flow for f in findings if f.flow is not None],
        stats=stats,
        fail_on=options.fail_on,
        summary=_summary(findings, len(evaluated), pack.version),
        generated_at=dt.datetime.now(dt.UTC).replace(microsecond=0) if options.include_timestamps else None,
    )
    return report


def _skip_reason(analyzer_cls, options: ScanOptions) -> str:
    if options.analyzers is not None and analyzer_cls.id not in options.analyzers:
        return "not selected"
    needs = analyzer_cls.requires
    if "network" in needs:
        feature = getattr(analyzer_cls, "network_feature", None)
        if not feature or not getattr(options.network, feature, False):
            return "network feature not enabled (opt-in)"
    if "native" in needs and not native_available(analyzer_cls):
        return "optional native dependency not installed"
    if "lock" in needs and options.lock is None:
        return "no lockfile supplied"
    if "intel" in needs and options.intel is None:
        return "no IOC feed loaded"
    return ""


def _summary(findings: list[Finding], n_rules: int, pack_version: str) -> str:
    if not findings:
        return f"No findings from {n_rules} rules (rule pack v{pack_version})."
    c = Counter(f.severity.value for f in findings)
    parts = ", ".join(f"{c[s.value]} {s.value}" for s in Severity if c.get(s.value))
    return f"{len(findings)} findings ({parts}) from {n_rules} rules (rule pack v{pack_version})."


def _finalize(raw: list[RawFinding], ctx: Context, pack: RulePack, options: ScanOptions) -> list[Finding]:
    merged: dict[str, Finding] = {}
    policy = options.policy
    for r in raw:
        rule = pack.rule(r.rule_id)
        severity = r.severity or rule.severity
        confidence = r.confidence or rule.confidence
        tags = set(r.tags) | set(rule.tags)
        if r.hidden and not r.rule_id.startswith(_NO_HIDDEN_ESCALATION_PREFIXES):
            severity = severity.bump(1)
            tags.add("hidden")
        if policy and r.rule_id in policy.severity_overrides:
            severity = policy.severity_overrides[r.rule_id]
        # Invariants: CRITICAL needs high confidence + deterministic evidence;
        # LLM-sourced findings cap at HIGH.
        if r.source == FindingSource.llm and severity == Severity.critical:
            severity = Severity.high
        if severity == Severity.critical and confidence != Confidence.high:
            severity = Severity.high
            tags.add("capped-by-confidence")
        comp_key = ",".join(r.component_ids)
        path = r.primary.path if r.primary else ""
        fp = sha256_hex(f"{r.rule_id}|{comp_key}|{path}|{r.match_key}")[:32]
        existing = merged.get(fp)
        if existing is not None:
            if r.primary and r.primary != existing.primary and r.primary not in existing.related and len(existing.related) < 20:
                existing.related.append(r.primary)
            if len(existing.evidence) < 10:
                existing.evidence.extend(r.evidence)
            if severity.rank > existing.severity.rank:
                existing.severity = severity
            existing.tags = sorted(set(existing.tags) | tags)
            continue
        merged[fp] = Finding(
            fingerprint=fp,
            rule_id=rule.id,
            rule_version=rule.version,
            title=rule.title,
            severity=severity,
            confidence=confidence,
            source=r.source,
            component_ids=r.component_ids,
            primary=r.primary,
            related=r.related,
            message=visible_escape(r.message or rule.title)[:500],
            explanation=rule.why or rule.description,
            remediation=rule.remediation,
            evidence=r.evidence,
            mappings=list(rule.mappings),
            references=list(rule.references),
            tags=sorted(tags),
            flow=r.flow,
        )
    return list(merged.values())


def _pr_filter(raw: list[RawFinding], ctx: Context, changed: set[str]) -> list[RawFinding]:
    """PR mode: keep findings for every component that contains a changed file
    (whole component, so payloads split into unchanged files are still seen),
    plus findings whose primary location changed, plus policy findings."""
    touched = {a.component_id for a in ctx.inventory.artifacts.values() if a.path in changed}
    for c in ctx.inventory.components.values():
        if c.server and c.server.config_path in changed:
            touched.add(c.id)
    out = []
    for r in raw:
        if r.rule_id.startswith(("AG-POL-", "AG-SYS-002")):
            out.append(r)
        elif set(r.component_ids) & touched or (r.primary and r.primary.path in changed):
            out.append(r)
    return out


def _synthetic(pack: RulePack, rule_id: str, message: str, *, key: str, primary=None) -> Finding:
    rule = pack.rule(rule_id)
    return Finding(
        fingerprint=sha256_hex(f"{rule_id}|{key}")[:32],
        rule_id=rule_id,
        rule_version=rule.version,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        source=FindingSource.policy,
        primary=primary,
        message=visible_escape(message)[:500],
        explanation=rule.why or rule.description,
        remediation=rule.remediation,
        mappings=list(rule.mappings),
        references=list(rule.references),
    )


def limit_event_rule(ev: LimitEvent) -> str | None:
    if ev.kind == "archive_bomb":
        return "AG-SYS-004"
    if ev.kind in ("symlink", "hardlink", "path_escape"):
        return "AG-SYS-003"
    if ev.kind in ("too_large", "too_many_files", "too_deep", "total_bytes_exceeded", "encrypted_member",
                   "special_file", "unreadable", "archive_error", "windows_hazard"):
        return "AG-SYS-001"
    return None

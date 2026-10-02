"""Every rule must have at least one positive and one negative fixture, and
each fixture must behave as labelled. CI fails otherwise."""

from __future__ import annotations

import os

import pytest

from agentguard.core.analyzers import registry
from agentguard.core.engine import scan
from agentguard.core.models import AnalyzerMatch
from agentguard.core.models.enums import Severity
from agentguard.core.rules.pack import RulePack

from fixture_harness import FIXTURES, iter_cases, load_case, missing_native

PACK = RulePack.default()
RULE_IDS = sorted(PACK.rules)
# Optional native analyzers CI installs and therefore must not be skipped.
REQUIRED_NATIVE = {a for a in os.environ.get("AG_REQUIRE_NATIVE", "").split(",") if a}


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_has_fixtures(rule_id):
    for side in ("positive", "negative"):
        d = FIXTURES / rule_id / side
        assert d.is_dir() and any(p.is_dir() for p in d.iterdir()), f"{rule_id}: missing {side} fixture"


@pytest.mark.parametrize(
    "rule_id,side,case_dir",
    iter_cases(RULE_IDS),
    ids=lambda v: v if isinstance(v, str) else v.name,
)
def test_fixture(rule_id, side, case_dir, monkeypatch):
    case = load_case(rule_id, side, case_dir)
    missing = missing_native(case)
    if missing:
        if REQUIRED_NATIVE & set(missing):
            pytest.fail(f"{case.id}: required analyzer not installed: {', '.join(sorted(REQUIRED_NATIVE & set(missing)))}")
        pytest.skip(f"optional analyzer not installed: {', '.join(missing)}")
    fault = case.config.get("fault")
    if fault:
        cls = next(c for c in registry.all_stages() if c.id == fault)

        def boom(self, ctx):
            raise RuntimeError("injected fault (fixture)")

        monkeypatch.setattr(cls, "run", boom)
    report = scan(case.tree, case.options, PACK)
    fired = {f.rule_id for f in [*report.findings, *report.suppressed_findings]}
    if side == "positive":
        assert rule_id in fired, f"{case.id}: expected {rule_id}; fired {sorted(fired)}"
    elif case.config.get("max_severity"):
        # A mention the rule reports at a lower severity (e.g. a quoted pattern in a
        # reference doc): it may fire, but never above max_severity.
        cap = Severity(case.config["max_severity"])
        over = [f for f in [*report.findings, *report.suppressed_findings] if f.rule_id == rule_id and f.severity.rank > cap.rank]
        assert not over, f"{case.id}: {rule_id} fired above {cap.value}: " + "; ".join(
            f"{f.severity.value}: {f.message}" for f in over)
    else:
        assert rule_id not in fired, f"{case.id}: {rule_id} fired on a negative fixture: " + "; ".join(
            f.message for f in report.findings if f.rule_id == rule_id
        )


def test_analyzer_rule_consistency():
    stages = {c.id: c for c in registry.all_stages()}
    for rule in PACK.rules.values():
        if isinstance(rule.match, AnalyzerMatch):
            if rule.match.analyzer == "engine":
                continue
            assert rule.match.analyzer in stages, f"{rule.id}: unknown analyzer {rule.match.analyzer}"
            assert rule.id in stages[rule.match.analyzer].rules, f"{rule.id} not declared by {rule.match.analyzer}"
    for cls in stages.values():
        for rid in cls.rules:
            assert rid in PACK.rules, f"{cls.id} declares unknown rule {rid}"


def test_every_rule_is_mapped():
    for rule in PACK.rules.values():
        frameworks = {m.framework for m in rule.mappings}
        assert "nsa-csi-mcp-2026-05" in frameworks, rule.id
        for m in rule.mappings:
            assert m.id or m.todo

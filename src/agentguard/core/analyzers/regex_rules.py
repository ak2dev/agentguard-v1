"""Generic evaluator for data-defined regex rules (``match.type: regex``)."""

from __future__ import annotations

import bisect
from functools import lru_cache
from typing import ClassVar

import regex

from ..artifacts import TextUnit
from ..models import RegexMatch, RuleDef
from ..models.enums import Confidence, EvidenceKind
from ..textutil import TIMEOUT
from .base import Context


@lru_cache(maxsize=4096)
def _compile(pattern: str, ignore_case: bool) -> regex.Pattern[str]:
    flags = regex.MULTILINE | (regex.IGNORECASE if ignore_case else 0)
    return regex.compile(pattern, flags)


def _line_starts(text: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _window(text: str, starts: list[int], start: int, end: int, lines: int) -> str:
    li = bisect.bisect_right(starts, start) - 1
    le = bisect.bisect_right(starts, max(start, end - 1)) - 1
    a = starts[max(0, li - lines)]
    b_line = le + lines + 1
    b = starts[b_line] if b_line < len(starts) else len(text)
    return text[a:b]


def units_for(ctx: Context) -> list[TextUnit]:
    units: list[TextUnit] = []
    for at in ctx.texts():
        units.extend(at.units)
    units.extend(ctx.data.get("extra_units", []))  # type: ignore[arg-type]
    return units


class RegexRuleAnalyzer:
    id: ClassVar[str] = "regex"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ()  # evaluates every rule with match.type == regex

    def run(self, ctx: Context) -> None:
        rules = [r for r in ctx.pack.rules.values() if r.enabled and isinstance(r.match, RegexMatch)]
        units = units_for(ctx)
        max_len = ctx.options.limits.max_line_length_for_regex
        for unit in units:
            text = unit.norm.text
            if not text.strip():
                continue
            starts: list[int] | None = None
            for rule in rules:
                m: RegexMatch = rule.match  # type: ignore[assignment]
                if unit.scope not in m.scopes:
                    continue
                if rule.applies_to and unit.role not in rule.applies_to:
                    continue
                starts = starts or _line_starts(text)
                self._eval(ctx, rule, m, unit, text, starts, max_len)

    def _eval(self, ctx: Context, rule: RuleDef, m: RegexMatch, unit: TextUnit, text: str, starts: list[int], max_len: int) -> None:
        at = ctx.inventory.texts.get(unit.path)
        seen_lines: set[int] = set()
        count = 0
        for pattern in m.patterns:
            rx = _compile(pattern, m.ignore_case)
            try:
                hits = list(rx.finditer(text, timeout=TIMEOUT))
            except TimeoutError:
                continue
            for hit in hits:
                s, e = hit.span()
                if e - s > max_len:
                    continue
                line_no = bisect.bisect_right(starts, s)
                if line_no in seen_lines:
                    continue
                abs_off = ctx.unit_abs(unit, s)
                if m.sections:
                    if at is None or abs_off is None or unit.base is None:
                        continue
                    heads = at.headings_at(abs_off)
                    if not any(regex.search(sp, h, regex.IGNORECASE, timeout=TIMEOUT) for sp in m.sections for h in heads):
                        continue
                if m.require or m.unless:
                    win = _window(text, starts, s, e, m.window)
                    try:
                        if m.require and not all(_compile(p, m.ignore_case).search(win, timeout=TIMEOUT) for p in m.require):
                            continue
                        if m.unless and any(_compile(p, m.ignore_case).search(win, timeout=TIMEOUT) for p in m.unless):
                            continue
                    except TimeoutError:
                        continue
                confidence = rule.confidence
                if m.lower_confidence_in_code and at is not None and abs_off is not None and unit.base is not None and at.in_code(abs_off):
                    confidence = confidence.lower()
                seen_lines.add(line_no)
                line = _window(text, starts, s, e, 0).strip("\n")
                ctx.emit(
                    rule.id,
                    component_ids=unit.component_id,
                    span=ctx.unit_span(unit, s, e),
                    snippet=line if len(line) <= 300 else text[max(0, s - 80) : e + 80],
                    match=hit.group(0).lower(),
                    detail=f"matched in {unit.scope}{' (' + unit.label + ')' if unit.label else ''}",
                    kind=EvidenceKind.regex,
                    confidence=confidence if confidence != rule.confidence else None,
                    hidden=unit.hidden,
                    hidden_kind=unit.hidden_kind,
                    decode_path=unit.decode_path,
                )
                count += 1
                if count >= m.max_matches:
                    return


__all__ = ["RegexRuleAnalyzer", "units_for", "Confidence"]

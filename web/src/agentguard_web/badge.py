"""README badge: factual finding counts for one report, e.g.
``Agent Guard | 0 high · a1b2c3d``.

It states counts at an exact commit or version, never a verdict: no "safe",
no "verified", no pass/fail colours. One neutral colour whatever the counts,
so a reader has to look at the numbers.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from agentguard.core.models import Report

LABEL = "Agent Guard"
_CHAR_W = 6.6   # approximate advance of 11px Verdana/DejaVu Sans, as other badge services assume
_PAD = 10


def _short_ref(report: Report) -> str:
    t = report.target
    resolved = str(getattr(t, "resolved", "") or "")
    kind = getattr(getattr(t, "kind", None), "value", "")
    if kind in ("github", "gist"):
        return resolved[:7]
    if kind == "remote_mcp":
        return "metadata " + resolved.removeprefix("sha256:")[:7]
    return resolved[:24]


def badge_text(report: Report) -> str:
    counts = {s: 0 for s in ("critical", "high")}
    for f in report.findings:
        if f.severity.value in counts:
            counts[f.severity.value] += 1
    parts = [f"{counts['critical']} critical"] if counts["critical"] else []
    parts.append(f"{counts['high']} high")
    ref = _short_ref(report)
    return " · ".join([*parts, ref] if ref else parts)


def badge_svg(report: Report) -> str:
    value = badge_text(report)
    lw = round(len(LABEL) * _CHAR_W + 2 * _PAD)
    vw = round(len(value) * _CHAR_W + 2 * _PAD)
    w = lw + vw
    label, text = escape(LABEL), escape(value)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{label}: {text}">'
        f"<title>{label}: {text}</title>"
        f'<rect width="{lw}" height="20" fill="#3a3f47"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="#5b6470"/>'
        f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
        f'<text x="{lw / 2:.1f}" y="14">{label}</text>'
        f'<text x="{lw + vw / 2:.1f}" y="14">{text}</text>'
        f"</g></svg>"
    )

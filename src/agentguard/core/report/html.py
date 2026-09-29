"""Single-file HTML report. No scripts at all; strict CSP; every scanned
string HTML-escaped. Works offline and with JavaScript disabled."""

from __future__ import annotations

import base64
import hashlib

from ..models import Report
from ..models.enums import Severity
from .render import html_escape as e

_CSS = """
:root{--bg:#fbfaf7;--fg:#1d1c1a;--muted:#6b6862;--line:#e4e1da;--card:#fff;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#0e7490;--info:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#161514;--fg:#ecebe7;--muted:#a19e96;--line:#2e2c29;--card:#1f1e1c;--crit:#f2b8b5;--high:#fdba74;--med:#fcd34d;--low:#67e8f9;--info:#9ca3af}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 64px}h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 8px}
.muted{color:var(--muted)}.counts{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}.pill{border:1px solid var(--line);border-radius:999px;padding:4px 12px;background:var(--card)}
.f{border:1px solid var(--line);border-left-width:4px;border-radius:8px;background:var(--card);padding:12px 14px;margin:10px 0}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}.f.info{border-left-color:var(--info)}
.f h3{font-size:1rem;margin:0 0 4px}code,pre{font:13px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;margin:8px 0;overflow-x:auto}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:6px 0}dt{color:var(--muted)}dd{margin:0}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.sev{font-weight:600;text-transform:uppercase;font-size:.75rem;letter-spacing:.04em}
"""


_CSS_HASH = "sha256-" + base64.b64encode(hashlib.sha256(_CSS.encode()).digest()).decode()


def render_html(report: Report) -> str:
    sev = report.stats.findings_by_severity
    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src '{_CSS_HASH}'; img-src 'none'; base-uri 'none'; form-action 'none'\">",
        "<title>Agent Guard report</title>",
        f"<style>{_CSS}</style></head><body><main>",
        "<h1>Agent Guard report</h1>",
        f"<p class=\"muted\">Engine {e(report.engine_version)} · rule pack {e(report.rule_pack.version)} "
        f"({e(report.rule_pack.digest[:12])}) · {report.stats.components} components · {report.stats.files_scanned} files</p>",
        f"<p><strong>{e(report.summary)}</strong></p>",
        "<p class=\"muted\">Findings are evidence for review, not verdicts. A clean result means no rule matched; it does not mean safe.</p>",
        "<div class=\"counts\">",
    ]
    for s in Severity:
        parts.append(f"<span class=\"pill\"><span class=\"sev\">{s.value}</span> {sev.get(s.value, 0)}</span>")
    parts.append("</div>")
    parts.append(f"<p class=\"muted\">Network features used: {e(', '.join(report.network_features_used) or 'none (offline scan)')}</p>")
    notes = [a for a in report.analyzers if a.status != "ran"]
    if notes:
        parts.append("<h2>Coverage notes</h2><ul>")
        parts += [f"<li><code>{e(a.id)}</code>: {e(a.status)} — {e(a.reason)}</li>" for a in notes]
        parts.append("</ul>")
    comps = {c.id: c for c in report.inventory}
    parts.append("<h2>Findings</h2>")
    if not report.findings:
        parts.append("<p>No findings.</p>")
    for f in report.findings:
        loc = f"{f.primary.path}:{f.primary.start_line}" if f.primary else ""
        comp = ", ".join(comps[c].name for c in f.component_ids if c in comps)
        parts.append(f"<section class=\"f {f.severity.value}\" id=\"{e(f.fingerprint)}\">")
        parts.append(f"<h3><span class=\"sev\">{f.severity.value}</span> · {e(f.title)} <code>{e(f.rule_id)}</code></h3>")
        parts.append(f"<p>{e(f.message)}</p><dl>")
        parts.append(f"<dt>Location</dt><dd><code>{e(loc)}</code></dd>")
        if comp:
            parts.append(f"<dt>Component</dt><dd>{e(comp)}</dd>")
        parts.append(f"<dt>Confidence</dt><dd>{e(f.confidence.value)}</dd>")
        if f.score:
            parts.append(f"<dt>AIVSS</dt><dd>{f.score.value} <span class=\"muted\">(scorer {e(f.score.scorer)} {e(f.score.scorer_version)})</span></dd>")
        maps = ", ".join(f"{m.id}" for m in f.mappings if m.id)
        if maps:
            parts.append(f"<dt>Standards</dt><dd>{e(maps)}</dd>")
        if f.tags:
            parts.append(f"<dt>Tags</dt><dd>{e(', '.join(f.tags))}</dd>")
        parts.append("</dl>")
        for ev in f.evidence[:3]:
            if str(ev.snippet):
                where = f"{ev.location.path}:{ev.location.start_line}" if ev.location else ""
                parts.append(f"<pre>{e(str(ev.snippet))}</pre><p class=\"muted\">{e(where)} {e(ev.detail)}</p>")
        if f.flow:
            parts.append(f"<p><strong>Flow:</strong> {e(f.flow.narrative)}</p>")
        parts.append(f"<p><strong>Why it matters:</strong> {e(f.explanation)}</p>")
        parts.append(f"<p><strong>Fix:</strong> {e(f.remediation)}</p></section>")
    parts.append("<h2>Inventory</h2><table><thead><tr><th>Kind</th><th>Name</th><th>Location</th></tr></thead><tbody>")
    for c in report.inventory:
        parts.append(f"<tr><td>{e(c.kind.value)}</td><td>{e(c.name)}</td><td><code>{e(c.root)}</code></td></tr>")
    parts.append("</tbody></table></main></body></html>\n")
    return "".join(parts)

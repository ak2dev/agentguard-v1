"""Single-file HTML report. No scripts at all; strict CSP; every scanned
string HTML-escaped. Works offline and with JavaScript disabled.

It uses the Agent Guard website's look: dark, orange-accented, Inter and
JetBrains Mono. The fonts (Latin subsets, SIL OFL 1.1, see ``fonts/``) are
embedded so the file needs nothing else; the CSP allows them only as data: URIs.
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache
from pathlib import Path

from ..models import ImmutableRef, Report
from ..models.enums import Severity
from .render import html_escape as e

_FONTS = Path(__file__).with_name("fonts")
_LATIN = (
    "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,"
    "U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD"
)

_CSS = """
:root{--bg:#0e0d0c;--surface:#161412;--surface-2:#1c1a17;--fg:#f4efe9;--fg-2:#d8d1c8;--muted:#a69e94;--line:#2a2724;--line-2:#3b3733;
--accent:#ff7a33;--orange:#cf4a0f;--code:#1f1c19;--crit:#ff8a80;--high:#ffb266;--med:#f5d565;--low:#7fdcf0;--info:#b5b0a8;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 "AG Inter",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased;font-feature-settings:"cv11"}
a{color:var(--accent);text-underline-offset:3px}
header{border-bottom:1px dashed var(--line-2)}
.bar{max-width:1080px;margin:0 auto;padding:18px 20px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.brand{display:inline-flex;align-items:center;gap:10px;font-weight:650;font-size:1.2rem;letter-spacing:-.02em}
.brand svg{width:28px;height:28px;color:var(--accent)}
.tag{border:1px solid var(--line-2);border-radius:999px;padding:4px 12px;font-size:.85rem;color:var(--fg-2)}
main{max-width:1080px;margin:0 auto;padding:28px 20px 64px}
h1,h2,h3{font-weight:600;letter-spacing:-.02em;line-height:1.1;text-wrap:balance}
h2{font-size:1.5rem;margin:40px 0 14px;padding-top:28px;border-top:1px dashed var(--line)}
h3{font-size:1.05rem;margin:0}
.hero{background:var(--orange);color:#fff;border-radius:20px;padding:34px 30px}
.hero h1{font-size:2.1rem;letter-spacing:-.028em;margin:0 0 10px;color:#fff}
.hero p{margin:0;color:#fff;max-width:70ch}
.hero .meta{margin-top:14px;font-size:.88rem}
.hero code{background:rgba(0,0,0,.25);border-color:rgba(255,255,255,.2);color:#fff}
.hero a{color:#fff;text-decoration:underline}
.note{color:var(--muted);margin:18px 0 0}
.counts{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin:18px 0 0}
.count{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.count b{display:block;font-size:1.8rem;font-weight:600;letter-spacing:-.02em;line-height:1.1}
.muted{color:var(--muted)}
.sev{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:2px 9px;border-radius:999px;border:1px solid currentColor}
.critical .sev,.sev.critical{color:var(--crit)}.high .sev,.sev.high{color:var(--high)}.medium .sev,.sev.medium{color:var(--med)}.low .sev,.sev.low{color:var(--low)}.info .sev,.sev.info{color:var(--info)}
.f{border:1px solid var(--line);border-left-width:4px;border-radius:14px;background:var(--surface);padding:16px 18px;margin:12px 0}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}.f.info{border-left-color:var(--info)}
.f header{border:0;display:flex;flex-wrap:wrap;align-items:center;gap:8px 10px;margin-bottom:8px}
.f p{margin:8px 0;max-width:80ch}
.f h4{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:14px 0 4px;font-weight:600}
.rule{color:var(--muted);font-family:"AG Mono",ui-monospace,monospace;font-size:.82rem}
code,pre{font:13px/1.5 "AG Mono",ui-monospace,SFMono-Regular,Consolas,monospace}
code{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:.1em .4em}
pre{white-space:pre-wrap;word-break:break-word;background:var(--code);border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0;overflow-x:auto}
pre code{background:none;border:0;padding:0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:6px 0}dt{color:var(--muted)}dd{margin:0}
.pill{display:inline-block;border:1px solid var(--line-2);border-radius:999px;padding:1px 9px;font-size:.8rem;color:var(--fg-2);margin:0 4px 4px 0}
.table{border:1px solid var(--line);border-radius:14px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{border-bottom:1px solid var(--line);padding:9px 12px;text-align:left;vertical-align:top}
th{background:var(--surface);color:var(--fg-2);font-weight:600}
tr:last-child td{border-bottom:0}
ul{padding-left:20px}li{margin:4px 0}
footer{max-width:1080px;margin:0 auto;padding:20px;border-top:1px dashed var(--line);color:var(--muted);font-size:.85rem}
@media (max-width:640px){.counts{grid-template-columns:repeat(3,1fr)}.hero{padding:26px 20px}.hero h1{font-size:1.6rem}}
@media print{
:root{--bg:#fff;--surface:#fff;--surface-2:#fff;--fg:#1d1a17;--fg-2:#3b3733;--muted:#5f5c55;--line:#ddd8d0;--line-2:#cfc9c0;--accent:#b33a0a;--code:#f5f2ee;--crit:#b3261e;--high:#b45309;--med:#8a6d00;--low:#0e7490;--info:#6b7280;color-scheme:light}
.hero{background:#fff;color:var(--fg);border:2px solid var(--orange)}.hero h1,.hero p{color:var(--fg)}.hero code{background:var(--code);color:var(--fg);border-color:var(--line)}
.f{break-inside:avoid}}
"""

_SHIELD = (
    '<svg viewBox="0 0 32 32" aria-hidden="true" focusable="false">'
    '<path d="M16 2 4 7v8c0 7.5 5.1 13.3 12 15 6.9-1.7 12-7.5 12-15V7L16 2z" fill="currentColor" opacity=".14"></path>'
    '<path d="M16 2 4 7v8c0 7.5 5.1 13.3 12 15 6.9-1.7 12-7.5 12-15V7L16 2z" fill="none" stroke="currentColor" stroke-width="2"></path>'
    '<path d="m10.5 16.2 3.6 3.6 7.4-7.6" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"></path>'
    "</svg>"
)

_FRAMEWORK = {
    "owasp-asi-2026": "OWASP Agentic", "owasp-mcp-2025-beta": "OWASP MCP", "owasp-ast-1.0": "OWASP Skills",
    "owasp-llm-2025": "OWASP LLM", "nsa-csi-mcp-2026-05": "NSA MCP CSI", "cwe": "CWE",
}


@lru_cache(maxsize=1)
def _style() -> tuple[str, str]:
    """The stylesheet (with embedded fonts, when available) and its CSP hash."""
    faces = []
    for family, name in (("AG Inter", "inter-latin-wght-normal.woff2"), ("AG Mono", "jetbrains-mono-latin-wght-normal.woff2")):
        try:
            data = base64.b64encode((_FONTS / name).read_bytes()).decode("ascii")
        except OSError:
            continue  # fall back to system fonts
        faces.append(
            f"@font-face{{font-family:\"{family}\";font-style:normal;font-weight:100 900;font-display:swap;"
            f"src:url(data:font/woff2;base64,{data}) format(\"woff2\");unicode-range:{_LATIN}}}"
        )
    css = "\n".join(faces) + _CSS
    return css, "sha256-" + base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()


def _target(report: Report) -> str:
    t = report.target
    if t is None:
        return ""
    if isinstance(t, ImmutableRef):
        label = f"{t.locator} @ {t.resolved[:12]}"
        if t.kind.value == "github":
            owner_repo = "/".join(t.locator.split("/")[:2])
            return f'<a href="{e("https://github.com/" + owner_repo + "/tree/" + t.resolved)}">{e(label)}</a>'
        return e(label)
    if t.kind.value == "local":
        # Only the folder or file name: a shared report should not reveal local paths.
        return e(t.locator.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1])
    return e(t.locator)


def _loc_link(report: Report, path: str, line: int) -> str:
    text = e(f"{path}:{line}")
    t = report.target
    if isinstance(t, ImmutableRef):
        url = t.url_for(path, line)
        if url and url.startswith("https://"):
            return f'<a href="{e(url)}"><code>{text}</code></a>'
    return f"<code>{text}</code>"


def render_html(report: Report) -> str:
    css, css_hash = _style()
    sev = report.stats.findings_by_severity
    target = _target(report)
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src '{css_hash}'; font-src data:; img-src 'none'; base-uri 'none'; form-action 'none'\">",
        '<meta name="referrer" content="no-referrer"><meta name="color-scheme" content="dark">',
        '<meta name="description" content="Agent Guard scan report: findings, evidence, fixes and standards mappings.">',
        "<title>Agent Guard report</title>",
        f"<style>{css}</style></head><body>",
        f'<header><div class="bar"><span class="brand">{_SHIELD}Agent Guard</span><span class="tag">Scan report</span></div></header><main>',
        '<section class="hero"><h1>Scan report</h1>',
        f"<p>{e(report.summary)}</p>",
        '<p class="meta">'
        + (f"Target {target} · " if target else "")
        + f"engine {e(report.engine_version)} · rule pack {e(report.rule_pack.version)} "
        f"(<code>{e(report.rule_pack.digest[:12])}</code>) · {report.stats.components} components · {report.stats.files_scanned} files</p></section>",
        '<div class="counts">',
    ]
    for s in Severity:
        parts.append(f'<div class="count {s.value}"><b>{sev.get(s.value, 0)}</b><span class="sev">{s.value}</span></div>')
    parts.append("</div>")
    parts.append(
        '<p class="note">Findings are evidence for review, not verdicts. A clean result means no rule matched; it does not mean safe. '
        f"Network features used: {e(', '.join(report.network_features_used) or 'none (offline scan)')}.</p>"
    )
    notes = [a for a in report.analyzers if a.status != "ran"]
    if notes:
        parts.append("<h2>Coverage notes</h2><ul>")
        parts += [f"<li><code>{e(a.id)}</code> {e(a.status)} — {e(a.reason)}</li>" for a in notes]
        parts.append("</ul>")
    comps = {c.id: c for c in report.inventory}
    parts.append("<h2>Findings</h2>")
    if not report.findings:
        parts.append("<p>No findings.</p>")
    for f in report.findings:
        comp = ", ".join(comps[c].name for c in f.component_ids if c in comps)
        parts.append(f'<section class="f {f.severity.value}" id="{e(f.fingerprint)}">')
        parts.append(f'<header><span class="sev">{f.severity.value}</span><h3>{e(f.title)}</h3><span class="rule">{e(f.rule_id)}</span></header>')
        parts.append(f"<p>{e(f.message)}</p><dl>")
        if f.primary:
            parts.append(f"<dt>Location</dt><dd>{_loc_link(report, f.primary.path, f.primary.start_line)}</dd>")
        if comp:
            parts.append(f"<dt>Component</dt><dd>{e(comp)}</dd>")
        parts.append(f"<dt>Confidence</dt><dd>{e(f.confidence.value)}</dd>")
        if f.score:
            parts.append(f'<dt>AIVSS</dt><dd>{f.score.value} <span class="muted">({e(f.score.scorer)} {e(f.score.scorer_version)})</span></dd>')
        maps = [m for m in f.mappings if m.id]
        if maps:
            pills = "".join(f'<span class="pill">{e(_FRAMEWORK.get(m.framework, m.framework))} {e(m.id or "")}</span>' for m in maps)
            parts.append(f"<dt>Standards</dt><dd>{pills}</dd>")
        if f.tags:
            parts.append(f"<dt>Tags</dt><dd>{e(', '.join(f.tags))}</dd>")
        parts.append("</dl>")
        shown = [ev for ev in f.evidence[:3] if str(ev.snippet)]
        if shown:
            parts.append("<h4>Evidence</h4>")
        for ev in shown:
            where = f"{ev.location.path}:{ev.location.start_line}" if ev.location else ""
            parts.append(f'<pre><code>{e(str(ev.snippet))}</code></pre><p class="muted">{e(where)} {e(ev.detail)}</p>')
        if f.flow:
            parts.append(f"<h4>Flow</h4><p>{e(f.flow.narrative)}</p>")
        parts.append(f"<h4>Why it matters</h4><p>{e(f.explanation)}</p>")
        parts.append(f"<h4>How to fix</h4><p>{e(f.remediation)}</p></section>")
    parts.append('<h2>Inventory</h2><div class="table"><table><thead><tr><th>Kind</th><th>Name</th><th>Location</th></tr></thead><tbody>')
    for c in report.inventory:
        parts.append(f"<tr><td>{e(c.kind.value)}</td><td>{e(c.name)}</td><td><code>{e(c.root)}</code></td></tr>")
    parts.append("</tbody></table></div></main>")
    parts.append("<footer>Generated by Agent Guard. Fonts: Inter and JetBrains Mono, SIL Open Font License 1.1.</footer></body></html>\n")
    return "".join(parts)

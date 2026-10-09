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
a:hover{color:#ffa06b}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
.bar,main,footer{max-width:1080px;margin:0 auto;padding-left:20px;padding-right:20px}
body>header{border-bottom:1px dashed var(--line-2)}
.bar{padding-top:18px;padding-bottom:18px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.brand{display:inline-flex;align-items:center;gap:10px;font-weight:650;font-size:1.2rem;letter-spacing:-.02em}
.brand svg{width:28px;height:28px;color:var(--accent)}
.bar .muted{font-size:.85rem}
main{padding-top:28px;padding-bottom:56px}
h1,h2,h3{font-weight:600;letter-spacing:-.02em;line-height:1.15;text-wrap:balance}
h2{font-size:1.45rem;margin:44px 0 16px;padding-top:28px;border-top:1px dashed var(--line);display:flex;align-items:baseline;gap:10px}
h2 .n{font-size:.9rem;font-weight:500;color:var(--muted);letter-spacing:0}
h3{font-size:1.08rem;margin:0}
.hero{background:var(--orange);color:#fff;border-radius:20px;padding:32px 30px 28px}
.hero h1{font-size:2.1rem;letter-spacing:-.028em;margin:0 0 8px;color:#fff}
.hero p{margin:0;color:#fff;max-width:70ch;font-size:1.02rem}
.hero a{color:#fff;text-decoration:underline}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:18px 0 0;padding:0;list-style:none}
.chips li{margin:0;background:rgba(0,0,0,.2);border:1px solid rgba(255,255,255,.18);border-radius:999px;padding:4px 12px;font-size:.84rem;color:#fff;overflow-wrap:anywhere}
.chips span{color:rgba(255,255,255,.72);margin-right:6px}
.chips code{background:none;border:0;padding:0;color:#fff;font-size:.8rem}
.counts{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0 0}
.count{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px 16px;display:flex;flex-direction:column;align-items:flex-start;gap:8px}
.count b{font-size:2rem;font-weight:600;letter-spacing:-.03em;line-height:1}
.count.critical b{color:var(--crit)}.count.high b{color:var(--high)}.count.medium b{color:var(--med)}.count.low b{color:var(--low)}.count.info b{color:var(--info)}
.count.zero{background:transparent;border-style:dashed}.count.zero b{color:var(--muted)}.count.zero .sev{opacity:.55}
.muted{color:var(--muted)}
.note{color:var(--muted);margin:16px 0 0;font-size:.93rem;max-width:90ch}
.sev{display:inline-block;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:2px 9px;border-radius:999px;border:1px solid currentColor;white-space:nowrap;line-height:1.5}
.critical .sev,.sev.critical{color:var(--crit)}.high .sev,.sev.high{color:var(--high)}.medium .sev,.sev.medium{color:var(--med)}.low .sev,.sev.low{color:var(--low)}.info .sev,.sev.info{color:var(--info)}
.rule{color:var(--muted);font-family:"AG Mono",ui-monospace,monospace;font-size:.8rem;white-space:nowrap}
code,pre{font:13px/1.55 "AG Mono",ui-monospace,SFMono-Regular,Consolas,monospace}
code{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:.1em .4em;overflow-wrap:anywhere}
a code{color:inherit}
pre{white-space:pre-wrap;word-break:break-word;background:var(--code);border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:0;overflow-x:auto}
pre code{background:none;border:0;padding:0}
.table{border:1px solid var(--line);border-radius:14px;overflow-x:auto;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:.92rem}
th,td{border-bottom:1px solid var(--line);padding:10px 14px;text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;background:var(--surface-2)}
tr:last-child td{border-bottom:0}
td a{color:var(--fg);text-decoration:none}td a:hover{color:var(--accent);text-decoration:underline}
.index td{vertical-align:middle}.index td:first-child{width:1%}
.f{border:1px solid var(--line);border-left-width:4px;border-radius:14px;background:var(--surface);padding:18px 20px;margin:14px 0;scroll-margin-top:16px}
.f:target{box-shadow:0 0 0 2px var(--accent)}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}.f.info{border-left-color:var(--info)}
.f>header{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px}
.f>header .rule{margin-left:auto}
.f>p{margin:10px 0 0;max-width:80ch;color:var(--fg-2)}
.facts{display:flex;flex-wrap:wrap;gap:6px 22px;margin:14px 0 0;padding:12px 0 0;border-top:1px solid var(--line)}
.facts div{display:flex;flex-direction:column;gap:2px;min-width:0}
.facts dt{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}
.facts dd{margin:0;font-size:.92rem;overflow-wrap:anywhere}
.pills{margin:12px 0 0;display:flex;flex-wrap:wrap;gap:6px}
.pill{display:inline-block;border:1px solid var(--line-2);border-radius:999px;padding:1px 10px;font-size:.78rem;color:var(--fg-2);background:var(--surface-2)}
.f h4{font-size:.74rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:18px 0 8px;font-weight:600}
.ev{margin:0 0 8px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.ev figcaption{display:flex;flex-wrap:wrap;gap:4px 10px;align-items:baseline;padding:6px 12px;background:var(--surface-2);border-bottom:1px solid var(--line);font-size:.82rem;color:var(--muted)}
.ev figcaption code{background:none;border:0;padding:0;color:var(--fg-2);font-size:.78rem}
.ev pre{border:0;border-radius:0}
.flow{margin:0;padding:10px 14px;border-radius:10px;background:var(--surface-2);border:1px solid var(--line)}
.advice{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:18px}
.advice section{border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:var(--bg)}
.advice section.fix{border-color:rgba(255,122,51,.45);background:rgba(255,122,51,.06)}
.advice h4{margin:0 0 6px}.advice section.fix h4{color:var(--accent)}
.advice p{margin:0;color:var(--fg-2)}
.empty{border:1px dashed var(--line-2);border-radius:14px;padding:20px;color:var(--fg-2)}
details.panel{border:1px solid var(--line);border-radius:14px;background:var(--surface);padding:0 18px}
details.panel summary{cursor:pointer;padding:14px 0;font-weight:600;list-style-position:inside}
details.panel summary .muted{font-weight:400}
details.panel ul{margin:0 0 14px;padding-left:20px;color:var(--fg-2)}
li{margin:5px 0}
footer{padding-top:20px;padding-bottom:28px;border-top:1px dashed var(--line);color:var(--muted);font-size:.85rem;display:flex;flex-wrap:wrap;gap:4px 16px;justify-content:space-between}
@media (max-width:720px){.advice{grid-template-columns:1fr}.f>header .rule{margin-left:0}}
@media (max-width:640px){.index th:nth-child(n+3),.index td:nth-child(n+3){display:none}.counts{grid-template-columns:repeat(3,1fr)}.hero{padding:26px 20px 22px}.hero h1{font-size:1.6rem}.f{padding:16px}}
@media print{
:root{--bg:#fff;--surface:#fff;--surface-2:#f7f5f2;--fg:#1d1a17;--fg-2:#3b3733;--muted:#5f5c55;--line:#ddd8d0;--line-2:#cfc9c0;--accent:#b33a0a;--code:#f5f2ee;--crit:#b3261e;--high:#b45309;--med:#8a6d00;--low:#0e7490;--info:#6b7280;color-scheme:light}
.hero{background:#fff;color:var(--fg);border:2px solid var(--orange)}.hero h1,.hero p,.chips li,.chips code{color:var(--fg)}.chips li{background:var(--code);border-color:var(--line)}.chips span{color:var(--muted)}
.advice section.fix{background:#fff}.f:target{box-shadow:none}
.f,.ev,.advice section{break-inside:avoid}}
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


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _same(a: str, b: str) -> bool:
    return a.strip().rstrip(".").casefold() == b.strip().rstrip(".").casefold()


def _finding(report: Report, f, comps: dict) -> list[str]:
    out = [f'<section class="f {f.severity.value}" id="{e(f.fingerprint)}">',
           f'<header><span class="sev">{f.severity.value}</span><h3>{e(f.title)}</h3><span class="rule">{e(f.rule_id)}</span></header>']
    if f.message and not _same(f.message, f.title):
        out.append(f"<p>{e(f.message)}</p>")
    facts = []
    if f.primary:
        facts.append(("Location", _loc_link(report, f.primary.path, f.primary.start_line)))
    comp = ", ".join(comps[c].name for c in f.component_ids if c in comps)
    if comp:
        facts.append(("Component", e(comp)))
    facts.append(("Confidence", e(f.confidence.value)))
    if f.score:
        facts.append(("AIVSS", f'{f.score.value} <span class="muted">{e(f.score.scorer)} {e(f.score.scorer_version)}</span>'))
    if f.tags:
        facts.append(("Tags", e(", ".join(f.tags))))
    out.append('<dl class="facts">' + "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in facts) + "</dl>")
    maps = [m for m in f.mappings if m.id]
    if maps:
        out.append('<p class="pills" aria-label="Standards">' + "".join(
            f'<span class="pill">{e(_FRAMEWORK.get(m.framework, m.framework))} {e(m.id or "")}</span>' for m in maps) + "</p>")
    narrative = f.flow.narrative if f.flow else ""
    shown = [ev for ev in f.evidence[:3] if str(ev.snippet) and not (narrative and _same(str(ev.snippet), narrative))]
    if shown:
        out.append("<h4>Evidence</h4>")
    for ev in shown:
        where = f"<code>{e(ev.location.path)}:{ev.location.start_line}</code>" if ev.location else ""
        caption = " ".join(x for x in (where, f"<span>{e(ev.detail)}</span>" if ev.detail else "") if x)
        out.append(f'<figure class="ev">{f"<figcaption>{caption}</figcaption>" if caption else ""}'
                   f"<pre><code>{e(str(ev.snippet))}</code></pre></figure>")
    if narrative and not _same(narrative, f.message or ""):
        out.append(f'<h4>Flow</h4><p class="flow">{e(narrative)}</p>')
    out.append(f'<div class="advice"><section><h4>Why it matters</h4><p>{e(f.explanation)}</p></section>'
               f'<section class="fix"><h4>How to fix</h4><p>{e(f.remediation)}</p></section></div></section>')
    return out


def render_html(report: Report) -> str:
    css, css_hash = _style()
    sev = report.stats.findings_by_severity
    target = _target(report)
    pack = f"{e(report.rule_pack.version)} · <code>{e(report.rule_pack.digest[:12])}</code>"
    chips = ([("Target", target)] if target else []) + [
        ("Engine", e(report.engine_version)),
        ("Rule pack", pack),
        ("Scanned", f"{_plural(report.stats.components, 'component')} · {_plural(report.stats.files_scanned, 'file')}"),
    ]
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src '{css_hash}'; font-src data:; img-src 'none'; base-uri 'none'; form-action 'none'\">",
        '<meta name="referrer" content="no-referrer"><meta name="color-scheme" content="dark">',
        '<meta name="description" content="Agent Guard scan report: findings, evidence, fixes and standards mappings.">',
        "<title>Agent Guard report</title>",
        f"<style>{css}</style></head><body>",
        f'<header><div class="bar"><span class="brand">{_SHIELD}Agent Guard</span><span class="muted">Scan report</span></div></header><main>',
        '<section class="hero"><h1>Scan report</h1>',
        f"<p>{e(report.summary)}</p>",
        '<ul class="chips">' + "".join(f"<li><span>{k}</span>{v}</li>" for k, v in chips) + "</ul></section>",
        '<div class="counts">',
    ]
    for s in Severity:
        n = sev.get(s.value, 0)
        parts.append(f'<div class="count {s.value}{"" if n else " zero"}"><b>{n}</b><span class="sev">{s.value}</span></div>')
    parts.append("</div>")
    parts.append(
        '<p class="note">Findings are evidence for review, not verdicts. A clean result means no rule matched; it does not mean safe. '
        f"Network features used: {e(', '.join(report.network_features_used) or 'none (offline scan)')}.</p>"
    )
    comps = {c.id: c for c in report.inventory}
    parts.append(f'<h2>Findings <span class="n">{len(report.findings)}</span></h2>')
    if not report.findings:
        parts.append(f'<p class="empty">{e(report.summary)}</p>')
    else:
        parts.append('<div class="table index"><table><thead><tr><th scope="col">Severity</th><th scope="col">Finding</th>'
                     '<th scope="col">Rule</th><th scope="col">Location</th></tr></thead><tbody>')
        for f in report.findings:
            loc = f"<code>{e(f.primary.path)}:{f.primary.start_line}</code>" if f.primary else ""
            parts.append(f'<tr class="{f.severity.value}"><td><span class="sev">{f.severity.value}</span></td>'
                         f'<td><a href="#{e(f.fingerprint)}">{e(f.title)}</a></td><td class="rule">{e(f.rule_id)}</td><td>{loc}</td></tr>')
        parts.append("</tbody></table></div>")
        for f in report.findings:
            parts += _finding(report, f, comps)
    notes = [a for a in report.analyzers if a.status != "ran"]
    if notes:
        parts.append(f'<h2>Coverage</h2><details class="panel" open><summary>What was not run '
                     f'<span class="muted">({_plural(len(notes), "analyzer")})</span></summary><ul>')
        parts += [f"<li><code>{e(a.id)}</code> {e(a.status)} — {e(a.reason)}</li>" for a in notes]
        parts.append("</ul></details>")
    parts.append(f'<h2>Inventory <span class="n">{len(report.inventory)}</span></h2><div class="table"><table><thead><tr>'
                 '<th scope="col">Kind</th><th scope="col">Name</th><th scope="col">Location</th></tr></thead><tbody>')
    for c in report.inventory:
        parts.append(f"<tr><td>{e(c.kind.value)}</td><td>{e(c.name)}</td><td><code>{e(c.root)}</code></td></tr>")
    parts.append("</tbody></table></div></main>")
    parts.append(f"<footer><span>Generated by Agent Guard {e(report.engine_version)} · rule pack {e(report.rule_pack.version)}</span>"
                 "<span>Fonts: Inter and JetBrains Mono, SIL Open Font License 1.1</span></footer></body></html>\n")
    return "".join(parts)

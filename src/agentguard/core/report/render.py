"""Pure renderers: Report → bytes/str. Identical output across CLI and web.

All scanned text reaching an output already went through ``redact_snippet``
(Evidence.snippet is a RedactedText). Renderers additionally neutralize
format-specific injection: Markdown control characters, @mentions, #refs,
remote images, and HTML.
"""

from __future__ import annotations

import html
import json
from typing import Any

import regex

from ..models import Finding, Report
from ..models.enums import Severity
from ..redact import redact_secrets

TOOL_NAME = "Agent Guard"
INFO_URI = "https://github.com/agentguard/agentguard"
SEVERITY_SCORE = {Severity.critical: "9.3", Severity.high: "7.7", Severity.medium: "5.3", Severity.low: "2.1"}
SARIF_LEVEL = {Severity.critical: "error", Severity.high: "error", Severity.medium: "warning", Severity.low: "note", Severity.info: "note"}


# ---------------------------------------------------------------- JSON ------
def render_json(report: Report) -> str:
    return report.model_dump_json(indent=2, exclude_none=True) + "\n"


# ---------------------------------------------------------------- SARIF -----
def _sarif_rule(f: Finding) -> dict[str, Any]:
    tags = ["security", "agent-guard"] + [m.id for m in f.mappings if m.id][:12]
    props: dict[str, Any] = {"tags": tags[:20], "precision": f.confidence.value}
    if f.severity != Severity.info:
        props["security-severity"] = SEVERITY_SCORE[f.severity]
    help_md = f"**{f.title}**\n\n{f.explanation}\n\n**Remediation:** {f.remediation}"
    return {
        "id": f.rule_id,
        "name": regex.sub(r"[^A-Za-z0-9]+", "", f.title.title())[:64] or f.rule_id,
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.explanation or f.title},
        "help": {"text": f"{f.explanation}\n\nRemediation: {f.remediation}", "markdown": help_md},
        "helpUri": f"{INFO_URI}/blob/main/docs/rules/{f.rule_id}.md",
        "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
        "properties": props,
    }


def render_sarif(report: Report, uri_base: str | None = None) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in report.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = _sarif_rule(f)
    rule_index = {rid: i for i, rid in enumerate(sorted(rules))}
    for f in report.findings:
        loc: dict[str, Any] = {}
        if f.primary:
            region: dict[str, Any] = {"startLine": max(1, f.primary.start_line), "startColumn": max(1, f.primary.start_col)}
            if f.primary.end_line and f.primary.end_line >= f.primary.start_line:
                region["endLine"] = f.primary.end_line
            if f.evidence and f.evidence[0].snippet:
                region["snippet"] = {"text": str(f.evidence[0].snippet)}
            art: dict[str, Any] = {"uri": f.primary.path}
            if uri_base:
                art["uriBaseId"] = uri_base
            loc = {"physicalLocation": {"artifactLocation": art, "region": region}}
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [loc] if loc else [],
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint, "agentguard/v1": f.fingerprint},
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                **({"aivss": f.score.value} if f.score else {}),
                "tags": f.tags,
            },
        }
        if f.related:
            result["relatedLocations"] = [
                {"id": i + 1, "physicalLocation": {"artifactLocation": {"uri": s.path}, "region": {"startLine": max(1, s.start_line)}}}
                for i, s in enumerate(f.related[:50])
            ]
        results.append(result)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": INFO_URI,
                        "semanticVersion": report.engine_version,
                        "version": report.engine_version,
                        "rules": [rules[r] for r in sorted(rules)],
                        "properties": {"rulePack": report.rule_pack.version, "rulePackDigest": report.rule_pack.digest},
                    }
                },
                "automationDetails": {"id": "agentguard/"},
                "invocations": [{"executionSuccessful": not any(a.status == "errored" for a in report.analyzers)}],
                "results": results,
                "properties": {"summary": report.summary, "networkFeaturesUsed": report.network_features_used},
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False) + "\n"


# ------------------------------------------------------------- Markdown -----
_MD_SPECIAL = regex.compile(r"([\\`*_{}\[\]()#+!|<>~])")


def md_escape(text: str) -> str:
    t = _MD_SPECIAL.sub(r"\\\1", text)
    t = regex.sub(r"@(?=\w)", "@​", t)          # neutralize @mentions
    t = regex.sub(r"(?<=\s|^)#(?=\d)", "#​", t)  # neutralize #123 refs
    return t.replace("\n", " ")


def render_markdown(report: Report, max_findings: int = 50) -> str:
    sev = report.stats.findings_by_severity
    lines = [
        "## Agent Guard scan",
        "",
        f"{md_escape(report.summary)}",
        "",
        "| critical | high | medium | low | info |",
        "|---:|---:|---:|---:|---:|",
        f"| {sev.get('critical', 0)} | {sev.get('high', 0)} | {sev.get('medium', 0)} | {sev.get('low', 0)} | {sev.get('info', 0)} |",
        "",
    ]
    if report.network_features_used:
        lines += [f"Network features used: {', '.join(report.network_features_used)}", ""]
    skipped = [a for a in report.analyzers if a.status != "ran"]
    if skipped:
        lines += ["<details><summary>Coverage notes</summary>", ""]
        lines += [f"- `{a.id}`: {a.status} — {md_escape(a.reason)}" for a in skipped]
        lines += ["", "</details>", ""]
    shown = [f for f in report.findings if f.severity != Severity.info][:max_findings]
    if shown:
        lines += ["| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
        for f in shown:
            loc = f"`{f.primary.path}:{f.primary.start_line}`" if f.primary else ""
            lines.append(f"| {f.severity.value} | `{f.rule_id}` | {loc} | {md_escape(f.message)[:300]} |")
        hidden = len([f for f in report.findings if f.severity != Severity.info]) - len(shown)
        if hidden > 0:
            lines += ["", f"…and {hidden} more. See the full report artifact."]
    lines += ["", f"<sub>Agent Guard {report.engine_version} · rule pack {report.rule_pack.version} · "
              "findings are not verdicts; review each one.</sub>", ""]
    return "\n".join(lines)


# ------------------------------------------------------------ CycloneDX -----
def render_cyclonedx(report: Report, serial: str | None = None) -> str:
    """CycloneDX 1.6 BOM of the discovered inventory (skills and MCP servers as
    components). Deterministic: no timestamp, serial derived from content."""
    comps = []
    for c in report.inventory:
        if c.kind.value not in ("skill", "mcp_server", "package", "instruction_file", "subagent", "command"):
            continue
        props = [{"name": "agentguard:kind", "value": c.kind.value}]
        if c.server:
            props += [
                {"name": "agentguard:transport", "value": c.server.transport.value},
                {"name": "agentguard:client", "value": c.server.client},
                {"name": "agentguard:scope", "value": c.server.scope},
                {"name": "agentguard:pinned", "value": str(c.server.pinned).lower()},
            ]
            if c.server.pin_detail:
                props.append({"name": "agentguard:pin_detail", "value": c.server.pin_detail})
            if c.server.command:
                props.append({"name": "agentguard:command", "value": c.server.command})
            if c.server.url:
                props.append({"name": "agentguard:url", "value": redact_secrets(c.server.url)})
            for n in c.server.env_names:
                props.append({"name": "agentguard:env_name", "value": n})
        entry: dict[str, Any] = {
            "type": "application" if c.kind.value in ("mcp_server", "package") else "data",
            "bom-ref": c.id,
            "name": c.name,
            "properties": props,
        }
        if c.version:
            entry["version"] = c.version
        if c.publisher:
            entry["publisher"] = c.publisher
        if c.content_hash:
            entry["hashes"] = [{"alg": "SHA-256", "content": c.content_hash}]
        if c.root:
            entry["properties"].append({"name": "agentguard:source", "value": c.root})
        comps.append(entry)
    import hashlib
    import uuid

    digest = hashlib.sha256(json.dumps(comps, sort_keys=True).encode()).digest()
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.UUID(bytes=digest[:16], version=5)}",
        "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": report.engine_version}]}},
        "components": comps,
    }
    return json.dumps(bom, indent=2, ensure_ascii=False) + "\n"


def html_escape(text: str) -> str:
    return html.escape(text, quote=True)

"""Toxic-flow analysis (AG-FLOW-*).

1. Label every component and tool with capabilities, from (in decreasing
   strength) code/regex evidence already gathered, tool annotations, tool
   names/descriptions, known server packages (rules/data/known-servers.yaml),
   and skill `allowed-tools`.
2. Group components that can be active in one agent session (same client;
   skills and instruction files join the session of the client they belong to,
   or every session when that is unknown).
3. Report dangerous combinations with a concrete path
   (source → agent → sink) and the evidence behind every label.

The agent's own built-in tools (e.g. a coding agent's file and web tools)
are out of scope: only installed skills and servers are labelled.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import ClassVar

import regex

from ..analyzers.base import Context
from ..mcp_config import docker_image, exe_name, package_arg, split_package_spec
from ..models import Component, Evidence, FlowPath, Span, ToolDef
from ..models.enums import CapLabel, ComponentKind, Confidence, EvidenceKind, Severity
from ..redact import RedactedText
from ..textutil import TIMEOUT

L = CapLabel
_TOOL_HINTS: tuple[tuple[CapLabel, regex.Pattern[str]], ...] = (
    (L.ingests_untrusted_content, regex.compile(
        r"(?i)(?:^|[_\-.])(?:fetch|browse|scrape|crawl|navigate|web_?search|search_web|read_(?:email|mail|inbox|message|messages)|"
        r"get_(?:issue|issues|pull_request|comments|messages|email|page|url)|list_(?:issues|comments|messages|emails)|rss|news)(?:$|[_\-.])")),
    (L.reads_private_data, regex.compile(
        r"(?i)(?:^|[_\-.])(?:read_file|read_text_file|get_file|get_file_contents|list_directory|list_files|search_files|read_multiple_files|"
        r"query|sql|select|get_secret|read_(?:email|mail|inbox|messages|calendar|notes)|search_(?:emails|messages|files|documents|drive)|"
        r"get_(?:document|record|customer|contacts|calendar))(?:$|[_\-.])")),
    (L.external_egress, regex.compile(
        r"(?i)(?:^|[_\-.])(?:send_(?:email|mail|message)|post_message|reply|create_(?:issue|comment|pull_request|gist|post|tweet)|"
        r"add_comment|upload|publish|webhook|http_request|fetch|share|tweet|post)(?:$|[_\-.])")),
    (L.destructive, regex.compile(
        r"(?i)(?:^|[_\-.])(?:delete|remove|drop|truncate|destroy|purge|wipe|overwrite|write_file|edit_file|move_file|update_record)(?:$|[_\-.])")),
    (L.code_exec, regex.compile(
        r"(?i)(?:^|[_\-.])(?:run_command|execute|exec|shell|bash|terminal|run_script|eval|python|run_code|start_process)(?:$|[_\-.])")),
)
_DESC_HINTS: tuple[tuple[CapLabel, regex.Pattern[str]], ...] = (
    (L.ingests_untrusted_content, regex.compile(r"(?i)\b(?:fetch(?:es)?\s+(?:a\s+)?(?:url|web\s*page)|web\s+pages?|search\s+the\s+web|browse|scrape|emails?|inbox|issues?|pull\s+requests?|comments?)\b")),
    (L.reads_private_data, regex.compile(r"(?i)\b(?:read(?:s)?\s+(?:a\s+)?files?|file\s+contents?|database|private\s+repositor|documents?|calendar|contacts|query)\b")),
    (L.external_egress, regex.compile(r"(?i)\b(?:send(?:s)?\s+(?:an?\s+)?(?:email|message)|post(?:s)?\s+(?:a\s+)?(?:message|comment)|create(?:s)?\s+(?:an?\s+)?(?:issue|comment|pull\s+request)|upload|publish)\b")),
    (L.code_exec, regex.compile(r"(?i)\b(?:run(?:s)?\s+(?:a\s+)?(?:shell\s+)?command|execute(?:s)?\s+(?:code|commands?|scripts?))\b")),
    (L.destructive, regex.compile(r"(?i)\b(?:delete(?:s)?|remove(?:s)?|overwrite(?:s)?|drop(?:s)?)\b")),
)
_NAME_HINTS: tuple[tuple[str, tuple[CapLabel, ...]], ...] = (
    ("github", (L.reads_private_data, L.ingests_untrusted_content, L.external_egress)),
    ("gitlab", (L.reads_private_data, L.ingests_untrusted_content, L.external_egress)),
    ("slack", (L.reads_private_data, L.ingests_untrusted_content, L.external_egress)),
    ("gmail", (L.reads_private_data, L.ingests_untrusted_content, L.external_egress)),
    ("email", (L.reads_private_data, L.ingests_untrusted_content, L.external_egress)),
    ("fetch", (L.ingests_untrusted_content, L.external_egress)),
    ("browser", (L.ingests_untrusted_content, L.external_egress)),
    ("playwright", (L.ingests_untrusted_content, L.external_egress)),
    ("puppeteer", (L.ingests_untrusted_content, L.external_egress)),
    ("search", (L.ingests_untrusted_content,)),
    ("filesystem", (L.reads_private_data, L.destructive)),
    ("postgres", (L.reads_private_data,)),
    ("database", (L.reads_private_data,)),
    ("shell", (L.code_exec,)),
)
_PROSE_KINDS = (ComponentKind.skill, ComponentKind.instruction_file, ComponentKind.command, ComponentKind.subagent)
FLOW_LABELS = (L.reads_private_data, L.ingests_untrusted_content, L.external_egress, L.destructive, L.code_exec, L.persistence)
LABEL_TEXT = {
    L.reads_private_data: "can read private data",
    L.ingests_untrusted_content: "can bring untrusted third-party content into the conversation",
    L.external_egress: "can send data outside",
    L.destructive: "can modify or delete data",
    L.code_exec: "can execute code or commands",
    L.persistence: "can write memory/instruction or startup files",
    L.auto_approved: "runs without per-call approval",
}


@dataclass
class Node:
    subject: str          # "cid" or "cid#tool"
    component: Component
    tool: str | None
    labels: dict[CapLabel, tuple[Confidence, list[Evidence]]]

    @property
    def display(self) -> str:
        return f"{self.component.name}.{self.tool}" if self.tool else self.component.name


def _known_server_labels(comp: Component, table: list[dict]) -> tuple[list[CapLabel], str]:
    if comp.server is None:
        keys = [comp.name]
    else:
        keys = [comp.name]
        runner, pkg = package_arg(comp.server.command, comp.server.args)
        if pkg:
            keys.append(split_package_spec(pkg)[0])
        if exe_name(comp.server.command) in ("docker", "podman"):
            img = docker_image(comp.server.args) or ""
            keys.append(img.split("@")[0].rsplit(":", 1)[0])
        if comp.server.url:
            keys.append(comp.server.url)
    keys = [k.lower() for k in keys if k]
    for entry in table:
        pats = [p.lower() for p in entry.get("match", [])]
        for k in keys:
            if any(fnmatch.fnmatch(k, p) for p in pats):
                return [CapLabel(x) for x in entry.get("labels", []) if x in CapLabel.__members__], k
    for word, labels in _NAME_HINTS:
        if any(word in k for k in keys):
            return list(labels), f"name contains '{word}'"
    return [], ""


def _ev(detail: str, span: Span | None = None, snippet: str = "") -> Evidence:
    return Evidence(kind=EvidenceKind.metadata, location=span, snippet=RedactedText.of(snippet), detail=detail)


def build_nodes(ctx: Context) -> list[Node]:
    table = (ctx.pack.data.get("known-servers") or {}).get("servers", [])
    nodes: dict[str, Node] = {}

    def node(comp: Component, tool: str | None) -> Node:
        key = f"{comp.id}#{tool}" if tool else comp.id
        if key not in nodes:
            nodes[key] = Node(key, comp, tool, {})
        return nodes[key]

    def put(n: Node, label: CapLabel, conf: Confidence, ev: list[Evidence]) -> None:
        cur = n.labels.get(label)
        if cur is None or conf.rank > cur[0].rank:
            n.labels[label] = (conf, ev[:2])

    for comp in sorted(ctx.inventory.components.values(), key=lambda c: c.id):
        if comp.kind == ComponentKind.mcp_client_config:
            continue
        # Evidence already gathered by analyzers (strongest).
        for cap in comp.capabilities:
            if cap.label not in FLOW_LABELS and cap.label != L.auto_approved:
                continue
            if not (cap.observed or cap.declared):
                continue
            tool = cap.subject.split("#", 1)[1] if "#" in cap.subject else None
            conf = cap.confidence if cap.observed else Confidence.low
            put(node(comp, tool), cap.label, conf, cap.evidence or [_ev(cap.reason)])
        # Tool metadata.
        for t in comp.tools:
            n = node(comp, t.name)
            ann = t.annotations or {}
            if ann.get("destructiveHint") is True:
                put(n, L.destructive, Confidence.high, [_ev("annotation destructiveHint=true", t.span)])
            if ann.get("openWorldHint") is True:
                put(n, L.ingests_untrusted_content, Confidence.medium, [_ev("annotation openWorldHint=true", t.span)])
            for label, rx in _TOOL_HINTS:
                if rx.search(t.name, timeout=TIMEOUT):
                    put(n, label, Confidence.medium, [_ev(f"tool name '{t.name}'", t.span)])
            for label, rx in _DESC_HINTS:
                if t.description and rx.search(t.description, timeout=TIMEOUT):
                    put(n, label, Confidence.medium, [_ev(f"tool description: {t.description[:100]}", t.span)])
            if ann.get("readOnlyHint") is True:
                n.labels.pop(L.destructive, None)
        # Config-only servers: known packages / names.
        if comp.kind in (ComponentKind.mcp_server, ComponentKind.package) and not comp.tools:
            labels, why = _known_server_labels(comp, table)
            span = comp.server.config_span if comp.server else None
            for label in labels:
                put(node(comp, None), label, Confidence.medium if "name contains" not in why else Confidence.low,
                    [_ev(f"known server ({why})", span)])
    # Tool-level nodes inherit the component's auto-approval.
    for n in nodes.values():
        if n.tool:
            parent = nodes.get(n.component.id)
            if parent and L.auto_approved in parent.labels:
                n.labels.setdefault(L.auto_approved, parent.labels[L.auto_approved])
    return [n for n in nodes.values() if any(lbl in n.labels for lbl in FLOW_LABELS)]


def session_of(comp: Component) -> set[str]:
    if comp.server is not None:
        return {comp.server.client}
    root = comp.root.replace("\\", "/")
    for marker, client in (("/.claude/", "claude-code"), (".claude/", "claude-code"), (".codex/", "codex"),
                           (".cursor/", "cursor"), (".gemini/", "gemini-cli"), (".openclaw/", "openclaw")):
        if marker in root or root.startswith(marker.strip("/")):
            return {client}
    return {"*"}


def _best(nodes: list[Node], label: CapLabel, exclude: set[str] = frozenset()) -> Node | None:
    cands = [n for n in nodes if label in n.labels and n.subject not in exclude]
    if not cands:
        return None
    return max(cands, key=lambda n: (n.labels[label][0].rank, n.tool is not None, n.subject))


class FlowAnalyzer:
    id: ClassVar[str] = "flows"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = tuple(f"AG-FLOW-00{i}" for i in range(1, 8))

    def run(self, ctx: Context) -> None:
        nodes = build_nodes(ctx)
        if not nodes:
            return
        clients = sorted({c for n in nodes for c in session_of(n.component)} - {"*"}) or ["*"]
        exfil_components = {cid for r in ctx.raw if r.rule_id in ("AG-SKL-EXF-001", "AG-CODE-022") and
                            (r.rule_id == "AG-SKL-EXF-001" or (r.severity == Severity.high)) for cid in r.component_ids}
        policy_sev = ctx.options.policy.trifecta_severity if ctx.options.policy else None
        for client in clients:
            group = [n for n in nodes if session_of(n.component) & {client, "*"}]
            self._group(ctx, client, group, exfil_components, policy_sev)

    # ------------------------------------------------------------------------
    def _group(self, ctx: Context, client: str, group: list[Node], exfil: set[str], policy_sev: Severity | None) -> None:
        agent = f"agent:{client}" if client != "*" else "agent"
        U, P, E = L.ingests_untrusted_content, L.reads_private_data, L.external_egress
        # FLOW-002: all three in one component.
        by_comp: dict[str, dict[CapLabel, tuple[Confidence, list[Evidence], Node]]] = {}
        for n in group:
            d = by_comp.setdefault(n.component.id, {})
            for lbl, (conf, ev) in n.labels.items():
                if lbl not in d or conf.rank > d[lbl][0].rank:
                    d[lbl] = (conf, ev, n)
        single_done = set()
        for cid, d in sorted(by_comp.items()):
            if all(x in d for x in (U, P, E)):
                comp = d[U][2].component
                if comp.kind in _PROSE_KINDS and not (d[P][0] == Confidence.high and d[E][0] == Confidence.high):
                    # A skill's untrusted-input label comes from its prose; the private-data
                    # read and the egress must be behaviour (code, a command, a fenced
                    # snippet), not words like "curl" or ".env" in documentation.
                    continue
                hops = [d[U][2], d[P][2], d[E][2]]
                conf = Confidence.min(d[U][0], d[P][0], d[E][0])
                self._emit(ctx, "AG-FLOW-002", client, agent, hops, (U, P, E), conf, policy_sev)
                single_done.add(cid)
        u, p, e = _best(group, U), _best(group, P), _best(group, E)
        if u and p and e and len({u.component.id, p.component.id, e.component.id}) > 1:
            conf = Confidence.min(u.labels[U][0], p.labels[P][0], e.labels[E][0])
            self._emit(ctx, "AG-FLOW-001", client, agent, [u, p, e], (U, P, E), conf, policy_sev)
            if all(L.auto_approved in n.labels for n in (u, p, e)):
                self._emit(ctx, "AG-FLOW-006", client, agent, [u, p, e], (U, P, E), conf, None)
        # FLOW-003: untrusted → code execution.
        x = _best(group, L.code_exec)
        if u and x:
            self._emit(ctx, "AG-FLOW-003", client, agent, [u, x], (U, L.code_exec),
                       Confidence.min(u.labels[U][0], x.labels[L.code_exec][0]), None)
        # FLOW-004: untrusted → auto-approved destructive tool.
        d_auto = [n for n in group if L.destructive in n.labels and L.auto_approved in n.labels]
        if u and d_auto:
            dn = max(d_auto, key=lambda n: (n.labels[L.destructive][0].rank, n.subject))
            self._emit(ctx, "AG-FLOW-004", client, agent, [u, dn], (U, L.destructive),
                       Confidence.min(u.labels[U][0], dn.labels[L.destructive][0]), None)
        # FLOW-005: private → egress to a known exfiltration sink.
        e_sink = [n for n in group if E in n.labels and n.component.id in exfil]
        if p and e_sink:
            en = max(e_sink, key=lambda n: (n.labels[E][0].rank, n.subject))
            self._emit(ctx, "AG-FLOW-005", client, agent, [p, en], (P, E),
                       Confidence.min(p.labels[P][0], en.labels[E][0]), None)
        # FLOW-007: untrusted → persistence (memory/instruction poisoning).
        per = _best(group, L.persistence)
        if u and per:
            self._emit(ctx, "AG-FLOW-007", client, agent, [u, per], (U, L.persistence),
                       Confidence.min(u.labels[U][0], per.labels[L.persistence][0]), None)

    def _emit(self, ctx: Context, rule_id: str, client: str, agent: str, hops: list[Node], labels: tuple[CapLabel, ...],
              conf: Confidence, severity: Severity | None) -> None:
        nodes = []
        edges = []
        prev = None
        for i, n in enumerate(hops):
            nodes.append(n.subject)
            if prev is not None:
                edges.append((prev, n.subject, agent))
            prev = n.subject
        label_map = {n.subject: [lbl for lbl in labels if lbl in n.labels] for n in hops}
        parts = [f"{h.display} {LABEL_TEXT[lbl]}" for h, lbl in zip(hops, labels, strict=False)]
        if rule_id in ("AG-FLOW-001", "AG-FLOW-002", "AG-FLOW-006"):
            narrative = (f"In one {client if client != '*' else 'agent'} session: {parts[0]}; {parts[1]}; {parts[2]}. "
                         f"Instructions hidden in that untrusted content could make the agent read private data with "
                         f"{hops[1].display} and send it out with {hops[2].display}.")
            if rule_id == "AG-FLOW-006":
                narrative += " None of these steps requires per-call approval."
        else:
            narrative = f"In one {client if client != '*' else 'agent'} session: " + "; then ".join(parts) + "."
        evidence: list[Evidence] = []
        for h, lbl in zip(hops, labels, strict=False):
            for ev in h.labels[lbl][1][:1]:
                evidence.append(Evidence(kind=EvidenceKind.metadata, location=ev.location, snippet=ev.snippet,
                                         detail=f"{h.display}: {lbl.value} ({ev.detail})"[:300]))
        primary = next((ev.location for ev in evidence if ev.location), Span(path=hops[0].component.root or "(inventory)"))
        ctx.emit(
            rule_id,
            component_ids=sorted({h.component.id for h in hops}),
            span=primary,
            snippet=narrative,
            match=f"{client}:" + "|".join(h.subject for h in hops),
            kind=EvidenceKind.metadata,
            confidence=conf,
            severity=severity if severity is not None else None,
            extra_evidence=evidence,
            flow=FlowPath(nodes=nodes, edges=edges, labels=label_map, narrative=narrative),
            message=narrative[:480],
        )


__all__ = ["FlowAnalyzer", "build_nodes", "session_of", "ToolDef"]

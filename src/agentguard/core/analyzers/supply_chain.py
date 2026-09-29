"""Supply-chain analyzers: lockfile drift / rug pulls (AG-SC-001..006), local
IOC feed matching (AG-SC-010..012), and offline registry checks (AG-SC-024/025)."""

from __future__ import annotations

import ipaddress
import urllib.parse
from typing import ClassVar

import regex

from ..lock import build_entries, lock_key, tool_diff
from ..mcp_config import package_arg, split_package_spec
from ..models import Evidence, LockEntry, Span
from ..models.enums import ComponentKind, EvidenceKind
from ..normalize.unicode import normalize
from ..redact import RedactedText
from ..textutil import TIMEOUT
from .base import Context
from .heuristics import damerau_levenshtein

_HOST = regex.compile(r"\b(?:https?|wss?|ftp)://([A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\])|\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b|\b(\d{1,3}(?:\.\d{1,3}){3})\b")


class DriftAnalyzer:
    id: ClassVar[str] = "supply.drift"
    requires: ClassVar[frozenset[str]] = frozenset({"lock"})
    rules: ClassVar[tuple[str, ...]] = ("AG-SC-001", "AG-SC-002", "AG-SC-003", "AG-SC-004", "AG-SC-005", "AG-SC-006")

    def run(self, ctx: Context) -> None:
        lock = ctx.options.lock
        assert lock is not None
        locked = {e.key: e for e in lock.entries}
        comps = {lock_key(c): c for c in ctx.inventory.components.values()}
        current = {e.key: e for e in build_entries(list(ctx.inventory.components.values()), list(ctx.inventory.artifacts.values()))}
        for key, cur in sorted(current.items()):
            comp = comps[key]
            span = comp.server.config_span if comp.server and comp.server.config_span else Span(path=comp.root or key)
            old = locked.get(key)
            if old is None:
                ctx.emit("AG-SC-006", component_ids=comp.id, span=span, snippet=key, match=key, kind=EvidenceKind.lock_diff,
                         message=f"'{comp.name}' is not in agentguard.lock (new or renamed component).")
                continue
            if old.content_hash == cur.content_hash and (old.tools or {}) == (cur.tools or {}):
                continue
            same_version = (old.version or "") == (cur.version or "")
            self._tools(ctx, comp.id, comp.name, span, old, cur, same_version)
            if (old.skill_files or {}) != (cur.skill_files or {}):
                changed = sorted(k for k in set(old.skill_files or {}) | set(cur.skill_files or {})
                                 if (old.skill_files or {}).get(k) != (cur.skill_files or {}).get(k))
                ctx.emit("AG-SC-002", component_ids=comp.id, span=span, snippet=", ".join(changed[:8]), match=f"{key}:files",
                         kind=EvidenceKind.lock_diff,
                         message=f"'{comp.name}' content changed since lock ({len(changed)} file(s): {', '.join(changed[:4])}).")
            if not same_version:
                ctx.emit("AG-SC-004", component_ids=comp.id, span=span, snippet=f"{old.version} → {cur.version}", match=f"{key}:ver",
                         kind=EvidenceKind.lock_diff,
                         message=f"'{comp.name}' version changed ({old.version} → {cur.version}) but the lockfile was not updated.")
            new_labels = sorted(set(cur.capability_labels) - set(old.capability_labels))
            if new_labels:
                ctx.emit("AG-SC-005", component_ids=comp.id, span=span, snippet=", ".join(l.value for l in new_labels),
                         match=f"{key}:labels", kind=EvidenceKind.lock_diff,
                         message=f"'{comp.name}' gained capabilities since lock: {', '.join(l.value for l in new_labels)}.")

    def _tools(self, ctx: Context, cid: str, name: str, span: Span, old: LockEntry, cur: LockEntry, same_version: bool) -> None:
        o, c = old.tools or {}, cur.tools or {}
        added, removed = sorted(set(c) - set(o)), sorted(set(o) - set(c))
        if added or removed:
            ctx.emit("AG-SC-003", component_ids=cid, span=span, snippet=f"added: {added} removed: {removed}",
                     match=f"{name}:{added}:{removed}", kind=EvidenceKind.lock_diff,
                     message=f"'{name}' tools changed since lock (added {added or 'none'}, removed {removed or 'none'}).")
        for t in sorted(set(o) & set(c)):
            if o[t].hash != c[t].hash:
                diff = tool_diff(o[t].definition, c[t].definition, t)
                ctx.emit("AG-SC-001" if same_version else "AG-SC-004", component_ids=cid, span=span,
                         snippet=f"tool '{t}' definition changed", match=f"{name}:{t}:{c[t].hash}", kind=EvidenceKind.lock_diff,
                         extra_evidence=[Evidence(kind=EvidenceKind.lock_diff, location=span,
                                                  snippet=RedactedText.of(diff, 4000), detail="definition diff (locked → current)")],
                         message=(f"Tool '{t}' of '{name}' changed without a version change (possible rug pull)." if same_version
                                  else f"Tool '{t}' of '{name}' changed with a version bump that is not in the lockfile."))


class IntelAnalyzer:
    id: ClassVar[str] = "supply.intel"
    requires: ClassVar[frozenset[str]] = frozenset({"intel"})
    rules: ClassVar[tuple[str, ...]] = ("AG-SC-010", "AG-SC-011", "AG-SC-012")

    def run(self, ctx: Context) -> None:
        feed = ctx.options.intel
        assert feed is not None
        hashes = {h.sha256: h.note for h in feed.entries.hashes}
        domains = {d.domain.lower().strip("."): d.note for d in feed.entries.domains}
        ips = {str(ipaddress.ip_address(i.ip)): i.note for i in feed.entries.ips}
        pubs = {p.handle.lower(): p.note for p in feed.entries.publishers}
        for art in sorted(ctx.inventory.artifacts.values(), key=lambda a: a.path):
            if art.sha256 in hashes:
                ctx.emit("AG-SC-010", component_ids=art.component_id, span=Span(path=art.path), snippet=f"sha256 {art.sha256}",
                         match=art.sha256, kind=EvidenceKind.intel, detail=hashes[art.sha256],
                         message=f"File matches IOC feed hash ({hashes[art.sha256] or 'no note'}; {feed.describe()}).")
        for comp in ctx.inventory.components.values():
            if comp.content_hash in hashes:
                ctx.emit("AG-SC-010", component_ids=comp.id, span=Span(path=comp.root), snippet=f"sha256 {comp.content_hash}",
                         match=comp.content_hash, kind=EvidenceKind.intel,
                         message=f"Component content hash matches IOC feed ({hashes[comp.content_hash] or 'no note'}).")
            for handle in _publisher_handles(comp):
                if handle in pubs:
                    ctx.emit("AG-SC-012", component_ids=comp.id, span=Span(path=comp.root), snippet=handle, match=handle,
                             kind=EvidenceKind.intel, message=f"Publisher '{handle}' is listed in the IOC feed ({pubs[handle] or 'no note'}).")
        if not domains and not ips:
            return
        for at in ctx.texts():
            seen: set[str] = set()
            for unit in at.units:
                for m in _HOST.finditer(unit.norm.text, timeout=TIMEOUT):
                    host = (m.group(1) or m.group(2) or m.group(3) or "").lower().strip("[]")
                    if not host or host in seen:
                        continue
                    hit = None
                    if host in ips:
                        hit = (host, ips[host])
                    else:
                        for dom, note in domains.items():
                            if host == dom or host.endswith("." + dom):
                                hit = (dom, note)
                                break
                    if hit:
                        seen.add(host)
                        ctx.emit("AG-SC-011", component_ids=at.artifact.component_id, span=ctx.unit_span(unit, m.start(), m.end()),
                                 snippet=at.line_text(ctx.unit_abs(unit, m.start()) or 0) if unit.base is not None else unit.text[:200],
                                 match=hit[0], kind=EvidenceKind.intel, hidden=unit.hidden, hidden_kind=unit.hidden_kind,
                                 decode_path=unit.decode_path,
                                 message=f"'{host}' matches IOC feed entry '{hit[0]}' ({hit[1] or 'no note'}).")
        for comp in ctx.inventory.components.values():
            if comp.server and comp.server.url:
                host = (urllib.parse.urlsplit(comp.server.url).hostname or "").lower()
                if host in ips or any(host == d or host.endswith("." + d) for d in domains):
                    ctx.emit("AG-SC-011", component_ids=comp.id, span=comp.server.config_span, snippet=comp.server.url,
                             match=f"url:{host}", kind=EvidenceKind.intel, message=f"Server URL host '{host}' matches the IOC feed.")


def _publisher_handles(comp) -> list[str]:
    out = []
    if comp.publisher:
        out.append(comp.publisher.lower())
    if comp.server:
        _, pkg = package_arg(comp.server.command, comp.server.args)
        if pkg:
            name = split_package_spec(pkg)[0].lower()
            if name.startswith("@") and "/" in name:
                out.append(f"npm:{name.split('/', 1)[0]}")
            out.append(f"pkg:{name}")
    if comp.name.startswith("io.github."):
        out.append(f"github:{comp.name.split('/', 1)[0][len('io.github.'):]}".lower())
    return out


class RegistryOfflineAnalyzer:
    """Offline checks on package names and MCP Registry server.json files."""

    id: ClassVar[str] = "supply.offline"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SC-024", "AG-SC-025")

    def run(self, ctx: Context) -> None:
        popular = [p.lower() for p in ctx.pack.list_data("popular-mcp-packages")]
        for comp in sorted(ctx.inventory.components.values(), key=lambda c: c.id):
            if comp.kind == ComponentKind.package and comp.metadata.get("registry_server_json"):
                self._namespace(ctx, comp)
            if comp.server and popular:
                _, pkg = package_arg(comp.server.command, comp.server.args)
                if not pkg:
                    continue
                name = split_package_spec(pkg)[0].lower()
                if name in popular:
                    continue
                folded = normalize(name).text
                for pop in popular:
                    if abs(len(pop) - len(name)) > 2 or len(pop) < 8:
                        continue
                    if folded == pop or 0 < damerau_levenshtein(folded, pop, cap=2) <= (1 if len(pop) < 16 else 2) \
                            or _scope_swap(name, pop):
                        ctx.emit("AG-SC-025", component_ids=comp.id, span=comp.server.config_span, snippet=name,
                                 match=f"{name}~{pop}", kind=EvidenceKind.config,
                                 message=f"Package '{name}' closely resembles the popular MCP package '{pop}'.")
                        break

    @staticmethod
    def _namespace(ctx: Context, comp) -> None:
        name = comp.name
        repo = comp.metadata.get("repository", "")
        m = regex.match(r"^io\.github\.([A-Za-z0-9-]+)/", name, timeout=TIMEOUT)
        if not m or not repo:
            return
        owner = m.group(1).lower()
        rm = regex.match(r"^https?://github\.com/([A-Za-z0-9-]+)/", repo, timeout=TIMEOUT)
        if rm and rm.group(1).lower() != owner:
            ctx.emit("AG-SC-024", component_ids=comp.id, span=Span(path=comp.root), snippet=f"{name} ← {repo}",
                     match=f"{owner}|{rm.group(1)}", kind=EvidenceKind.metadata,
                     message=f"Registry namespace owner '{owner}' does not match repository owner '{rm.group(1)}'.")


def _scope_swap(name: str, pop: str) -> bool:
    """@evil/server-github vs @modelcontextprotocol/server-github: same package part, different scope."""
    if not (name.startswith("@") and pop.startswith("@") and "/" in name and "/" in pop):
        return False
    return name.split("/", 1)[1] == pop.split("/", 1)[1] and name.split("/", 1)[0] != pop.split("/", 1)[0]

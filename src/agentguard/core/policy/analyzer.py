"""Built-in policy engine (allow/deny servers and publishers, pinning, PR
config-change guard). The Policy model reserves ``engine: rego|cel`` so an
OPA or CEL evaluator can be added behind the same analyzer interface."""

from __future__ import annotations

import fnmatch
from typing import ClassVar

from ..analyzers.base import Context
from ..models import Component, Span
from ..models.enums import ComponentKind, EvidenceKind, FindingSource

SECURITY_CONFIG_FILES = (".agentguard.yaml", ".agentguard.yml", "agentguard.lock", ".agentguard-baseline.json")


def _identities(c: Component) -> list[str]:
    ids = [c.name]
    if c.server:
        if c.server.command:
            ids.append(" ".join([c.server.command, *c.server.args]))
        if c.server.url:
            ids.append(c.server.url)
    return ids


class PolicyAnalyzer:
    id: ClassVar[str] = "policy"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-POL-001", "AG-POL-002", "AG-POL-003", "AG-POL-010")

    def run(self, ctx: Context) -> None:
        pol = ctx.options.policy
        if ctx.options.changed_paths:
            changed = sorted(p for p in ctx.options.changed_paths if p.rsplit("/", 1)[-1] in SECURITY_CONFIG_FILES)
            for p in changed:
                ctx.emit("AG-POL-010", component_ids=[], span=Span(path=p), snippet=p, match=p, kind=EvidenceKind.policy,
                         source=FindingSource.policy,
                         message=f"Security configuration '{p}' changed in this change set; PR mode used the base-ref version. Review the change.")
        if pol is None:
            return
        servers = sorted(ctx.inventory.of_kind(ComponentKind.mcp_server, ComponentKind.package), key=lambda c: c.id)
        for c in servers:
            span = c.server.config_span if c.server and c.server.config_span else Span(path=c.root)
            idents = _identities(c)
            denied = next((pat for pat in pol.deny_servers if any(fnmatch.fnmatch(i, pat) for i in idents)), None)
            if denied is None and c.publisher:
                denied = next((pat for pat in pol.deny_publishers if fnmatch.fnmatch(c.publisher, pat)), None)
            if denied:
                ctx.emit("AG-POL-001", component_ids=c.id, span=span, snippet=c.name, match=f"deny:{c.id}", kind=EvidenceKind.policy,
                         source=FindingSource.policy, message=f"'{c.name}' matches deny rule '{denied}'.")
                continue
            if pol.allow_servers is not None and not any(fnmatch.fnmatch(i, pat) for pat in pol.allow_servers for i in idents):
                ctx.emit("AG-POL-002", component_ids=c.id, span=span, snippet=c.name, match=f"allow:{c.id}", kind=EvidenceKind.policy,
                         source=FindingSource.policy, message=f"'{c.name}' is not on the server allowlist.")
            if pol.require_pinning and c.server and not c.server.pinned:
                ctx.emit("AG-POL-003", component_ids=c.id, span=span, snippet=c.server.pin_detail or c.name, match=f"pin:{c.id}",
                         kind=EvidenceKind.policy, source=FindingSource.policy,
                         message=f"Policy requires pinned versions; '{c.name}' is not pinned ({c.server.pin_detail}).")

"""Optional YARA analyzer (``yara``; install ``agentguard[yara]``).

Rules with ``match: {type: yara, rule_file: rules/yara/<name>.yar}`` are
compiled from the rule pack and matched against the raw bytes of every
artifact, so binary blobs the text analyzers never decode are covered. Any YARA
rule in a file reports that file's Agent Guard rule; ``applies_to`` limits it to
artifact roles.

The sources come from the rule pack, never from scanned input. They are
compiled with ``include`` directives disabled and no external variables, so a
rule cannot read files. yara-python is a native extension, so the analyzer is
skipped (and reported as skipped) where it is not installed, including the
browser build.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from ..models import Span, YaraMatch
from ..models.enums import EvidenceKind
from ..textutil import visible_escape
from .base import Context

if TYPE_CHECKING:
    from ..rules.pack import RulePack

MATCH_TIMEOUT_S = 10
MAX_STRINGS_IN_EVIDENCE = 4

_COMPILED: dict[str, Any] = {}


def namespace(rule_file: str) -> str:
    return "ns_" + "".join(c if c.isalnum() else "_" for c in rule_file)


def compile_pack(pack: RulePack) -> Any:
    """Compile every YARA source in the pack (cached per pack digest).
    Raises yara.SyntaxError for an invalid source: the analyzer then fails
    loudly (AG-SYS-002, exit 2) instead of silently matching nothing."""
    import yara  # native; only reached when installed

    compiled = _COMPILED.get(pack.digest)
    if compiled is None:
        sources = {namespace(path): text for path, text in sorted(pack.yara_sources.items())}
        compiled = yara.compile(sources=sources, includes=False)
        _COMPILED[pack.digest] = compiled
    return compiled


def _strings(match: Any) -> str:
    parts: list[str] = []
    for s in sorted(match.strings, key=lambda s: s.identifier):
        for inst in sorted(s.instances, key=lambda i: i.offset)[:1]:
            data = bytes(inst.matched_data[:48]).decode("latin-1")
            parts.append(f"{s.identifier}@{inst.offset:#x} {visible_escape(data)!r}")
        if len(parts) >= MAX_STRINGS_IN_EVIDENCE:
            break
    return ", ".join(parts)


class YaraAnalyzer:
    id: ClassVar[str] = "yara"
    requires: ClassVar[frozenset[str]] = frozenset({"native"})
    native_modules: ClassVar[tuple[str, ...]] = ("yara",)
    rules: ClassVar[tuple[str, ...]] = ()  # evaluates every rule with match.type == yara

    def run(self, ctx: Context) -> None:
        import yara

        by_ns: dict[str, list] = {}
        for rule in ctx.pack.rules.values():
            if rule.enabled and isinstance(rule.match, YaraMatch):
                by_ns.setdefault(namespace(rule.match.rule_file), []).append(rule)
        if not by_ns:
            return
        compiled = compile_pack(ctx.pack)
        tree = ctx.inventory.tree
        for art in sorted(ctx.inventory.artifacts.values(), key=lambda a: a.path):
            blob = tree.files.get(art.path) if tree else None
            if blob is None or not blob.data:
                continue
            try:
                matches = compiled.match(data=blob.data, timeout=MATCH_TIMEOUT_S)
            except yara.TimeoutError:
                ctx.emit("AG-SYS-001", component_ids=art.component_id, span=Span(path=art.path), snippet=art.path,
                         match=f"yara-timeout:{art.path}", kind=EvidenceKind.loader,
                         message=f"YARA matching timed out on '{art.path}'; it was not checked by YARA rules.")
                continue
            for m in sorted(matches, key=lambda m: (m.namespace, m.rule)):
                for rule in by_ns.get(m.namespace, []):
                    if rule.applies_to and art.role.value not in rule.applies_to:
                        continue
                    strings = _strings(m)
                    ctx.emit(rule.id, component_ids=art.component_id, span=Span(path=art.path),
                             snippet=f"{art.path}: YARA {m.rule}: {strings}"[:400], match=f"{art.sha256}:{m.rule}",
                             kind=EvidenceKind.yara, detail=f"YARA rule {m.rule} ({rule.match.rule_file})",
                             message=f"'{art.path}' matches YARA rule {m.rule}: {rule.title.lower()}.")

"""Skill analyzers: spec validation, execution surfaces, privilege,
description/behavior mismatch, typosquatting, bundled content."""

from __future__ import annotations

import posixpath
from typing import Any, ClassVar

import regex

from ..artifacts import EXECUTABLE_KINDS, ArtifactText, binary_kind
from ..models import Span
from ..models.enums import ArtifactRole, CapLabel, ComponentKind, Confidence, EvidenceKind, Severity
from ..normalize.unicode import normalize
from ..textutil import TIMEOUT
from .base import Context
from .heuristics import (
    CREDENTIAL_PATH,
    NETWORK_FETCH,
    READ_VERB,
    damerau_levenshtein,
    search,
)

SPEC_FIELDS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
# Known platform extensions (Claude Code; see docs/sources.md). Others → AG-SKL-SPEC-005.
PLATFORM_FIELDS = {
    "when_to_use", "argument-hint", "arguments", "disable-model-invocation", "user-invocable",
    "disallowed-tools", "model", "effort", "context", "agent", "background", "hooks", "paths", "shell",
    "version",
}
_NAME_RE = regex.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MARKUP = regex.compile(r"<\s*/?\s*[A-Za-z!][^>]{0,200}>|<\|[a-z_]+\|>|\[/?INST\]|<<SYS>>|\b(?:system|assistant|user)\s*:\s*$", regex.IGNORECASE | regex.MULTILINE)


def _skill_md(ctx: Context) -> list[ArtifactText]:
    return [t for t in ctx.texts("skill_md")]


def _fm_span(at: ArtifactText, key: str | None = None) -> Span:
    line = 1
    if at.fm and at.fm.has_frontmatter:
        line = 2
        if key:
            m = regex.search(rf"(?m)^\s*{regex.escape(key)}\s*:", at.fm.raw, timeout=TIMEOUT)
            if m:
                line = 2 + at.fm.raw.count("\n", 0, m.start())
    return Span(path=at.path, start_line=line)


def _fm_line(at: ArtifactText, key: str) -> str:
    if not (at.fm and at.fm.raw):
        return ""
    m = regex.search(rf"(?m)^\s*{regex.escape(key)}\s*:.*$", at.fm.raw, timeout=TIMEOUT)
    return m.group(0) if m else ""


class SkillSpecAnalyzer:
    id: ClassVar[str] = "skill.spec"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = tuple(f"AG-SKL-SPEC-00{i}" for i in range(1, 8))

    def run(self, ctx: Context) -> None:
        for at in _skill_md(ctx):
            cid = at.artifact.component_id
            comp = ctx.inventory.components[cid]
            fm = at.fm
            if fm is None or not fm.has_frontmatter:
                ctx.emit("AG-SKL-SPEC-001", component_ids=cid, span=Span(path=at.path), snippet=at.text[:120],
                         kind=EvidenceKind.schema, detail="SKILL.md has no YAML frontmatter",
                         message="SKILL.md has no YAML frontmatter, so required 'name' and 'description' are missing.")
                if fm and fm.error:
                    ctx.emit("AG-SKL-SPEC-007", component_ids=cid, span=Span(path=at.path), snippet="", match="unterminated",
                             kind=EvidenceKind.schema, detail=fm.error, message=f"Frontmatter anomaly: {fm.error}.")
                continue
            if fm.error:
                ctx.emit("AG-SKL-SPEC-007", component_ids=cid, span=_fm_span(at), snippet=fm.raw[:200], match=fm.error,
                         kind=EvidenceKind.schema, detail=fm.error, message=f"Frontmatter could not be loaded safely: {fm.error}.")
            for anomaly in fm.anomalies:
                ctx.emit("AG-SKL-SPEC-007", component_ids=cid, span=Span(path=at.path), snippet="", match=anomaly,
                         kind=EvidenceKind.schema, detail=anomaly, message=f"Frontmatter anomaly: {anomaly}.")
            for key, line in fm.duplicate_keys:
                ctx.emit("AG-SKL-SPEC-007", component_ids=cid, span=Span(path=at.path, start_line=line + 1),
                         snippet=f"{key}: …", match=f"dup:{key}", kind=EvidenceKind.schema,
                         detail=f"duplicate key '{key}'",
                         message=f"Frontmatter key '{key}' appears more than once; most loaders keep the last value, "
                                 "which can hide a value from reviewers.")
            data: dict[str, Any] = fm.data or {}
            for req in ("name", "description"):
                v = data.get(req)
                if not isinstance(v, str) or not v.strip():
                    ctx.emit("AG-SKL-SPEC-001", component_ids=cid, span=_fm_span(at, req), snippet=_fm_line(at, req),
                             match=req, kind=EvidenceKind.schema, detail=f"'{req}' missing or empty",
                             message=f"Required frontmatter field '{req}' is missing or empty.")
            name = data.get("name")
            if isinstance(name, str) and name:
                if len(name) > 64 or not _NAME_RE.match(name):
                    ctx.emit("AG-SKL-SPEC-002", component_ids=cid, span=_fm_span(at, "name"), snippet=_fm_line(at, "name"),
                             match=name, kind=EvidenceKind.schema,
                             detail="1-64 chars of a-z, 0-9 and single hyphens, not starting/ending with '-'",
                             message=f"Skill name '{name[:64]}' does not follow the Agent Skills naming rules.")
                parent = posixpath.basename(comp.root)
                if parent and parent != name:
                    ctx.emit("AG-SKL-SPEC-003", component_ids=cid, span=_fm_span(at, "name"), snippet=_fm_line(at, "name"),
                             match=f"{name}|{parent}", kind=EvidenceKind.schema,
                             message=f"Skill name '{name[:64]}' does not match its directory '{parent}'.")
            desc = data.get("description")
            if isinstance(desc, str) and len(desc) > 1024:
                ctx.emit("AG-SKL-SPEC-004", component_ids=cid, span=_fm_span(at, "description"), snippet=desc[:160],
                         match="description-length", kind=EvidenceKind.schema, detail=f"{len(desc)} characters (max 1024)",
                         message=f"Description is {len(desc)} characters; the spec allows at most 1024.")
            compat = data.get("compatibility")
            if isinstance(compat, str) and len(compat) > 500:
                ctx.emit("AG-SKL-SPEC-004", component_ids=cid, span=_fm_span(at, "compatibility"), snippet=compat[:160],
                         match="compatibility-length", kind=EvidenceKind.schema, detail=f"{len(compat)} characters (max 500)",
                         message=f"'compatibility' is {len(compat)} characters; the spec allows at most 500.")
            for key in sorted(data):
                if str(key) not in SPEC_FIELDS | PLATFORM_FIELDS:
                    ctx.emit("AG-SKL-SPEC-005", component_ids=cid, span=_fm_span(at, str(key)), snippet=_fm_line(at, str(key)),
                             match=str(key), kind=EvidenceKind.schema,
                             message=f"Unexpected frontmatter key '{str(key)[:64]}' (not in the Agent Skills spec or a known platform extension).")
            meta = data.get("metadata")
            if meta is not None and (not isinstance(meta, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in meta.items())):
                ctx.emit("AG-SKL-SPEC-007", component_ids=cid, span=_fm_span(at, "metadata"), snippet=_fm_line(at, "metadata"),
                         match="metadata-types", kind=EvidenceKind.schema,
                         message="'metadata' must map string keys to string values.")
            for key, value in data.items():
                for text in _strings(value):
                    m = search(_MARKUP, normalize(text).text)
                    if m:
                        ctx.emit("AG-SKL-SPEC-006", component_ids=cid, span=_fm_span(at, str(key)), snippet=text[:200],
                                 match=m.group(0).lower(), kind=EvidenceKind.schema,
                                 message=f"Frontmatter field '{str(key)[:40]}' contains markup or role/control tokens; "
                                         "frontmatter is loaded into every session.")
                        break


def _strings(value: Any, depth: int = 0) -> list[str]:
    if depth > 6:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v, depth + 1)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v, depth + 1)]
    return []


def hook_commands(data: dict[str, Any] | None) -> list[str]:
    """Collect every ``command`` string from a skill/agent ``hooks`` map."""
    if not data or "hooks" not in data:
        return []
    out: list[str] = []

    def walk(v: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(v, dict):
            for k, x in v.items():
                if k == "command" and isinstance(x, str):
                    out.append(x)
                else:
                    walk(x, depth + 1)
        elif isinstance(v, list):
            for x in v:
                walk(x, depth + 1)

    walk(data["hooks"])
    return out


# Local, read-only commands commonly used for dynamic context (no pipes, no
# redirection, no substitution). Anything else keeps the rule's severity.
_READONLY_CMD = regex.compile(
    r"^(?:git\s+(?:status|log|diff|show|branch|rev-parse|describe|remote\s+-v|ls-files|blame)|ls|pwd|date|whoami|uname|"
    r"cat\s+[\w./-]+|head\s+[\w./ -]+|wc\s+[\w./ -]+|node\s+--version|python3?\s+--version|npm\s+ls|gh\s+pr\s+(?:view|diff))"
    r"(?:\s+[^|;&<>`$()\n]*)?$"
)


class SkillExecAnalyzer:
    """Claude Code dynamic context injection and skill-scoped hooks."""

    id: ClassVar[str] = "skill.exec"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SKL-EXEC-001", "AG-SKL-EXEC-002", "AG-SKL-EXEC-003")

    def run(self, ctx: Context) -> None:
        from ..artifacts import TextUnit  # local import avoids a cycle

        extra: list[TextUnit] = ctx.data.setdefault("extra_units", [])  # type: ignore[assignment]
        for at in ctx.texts("skill_md", "instruction_md"):
            cid = at.artifact.component_id
            for b in at.bang:
                span = at.span(b.command_start, b.command_start + len(b.command))
                readonly = bool(_READONLY_CMD.match(b.command.strip()))
                ctx.emit("AG-SKL-EXEC-001", component_ids=cid, span=span, snippet=b.command, match=b.command,
                         kind=EvidenceKind.metadata, detail=f"{b.form} dynamic context injection",
                         severity=Severity.low if readonly else None,
                         message="Shell command runs when the skill is invoked, before the model sees the skill"
                                 + (" (read-only local command)." if readonly else "."))
                self._dangerous(ctx, cid, span, b.command)
                ctx.add_capability(cid, CapLabel.code_exec, confidence=Confidence.high, span=span, snippet=b.command,
                                   reason="dynamic context injection runs a shell command", kind=EvidenceKind.metadata)
            data = at.fm.data if at.fm else None
            for cmd in hook_commands(data):
                span = _fm_span(at, "hooks")
                ctx.emit("AG-SKL-EXEC-002", component_ids=cid, span=span, snippet=cmd, match=cmd,
                         kind=EvidenceKind.metadata, message="Skill registers a hook that runs a shell command for the rest of the session.")
                self._dangerous(ctx, cid, span, cmd)
                ctx.add_capability(cid, CapLabel.code_exec, confidence=Confidence.high, span=span, snippet=cmd,
                                   reason="hook runs a shell command", kind=EvidenceKind.metadata)
                norm = normalize(cmd)
                extra.append(TextUnit(path=at.path, component_id=cid, role=at.artifact.role.value, scope="command",
                                      text=cmd, norm=norm, base=None, anchor_span=span, label="skill-hook"))

    @staticmethod
    def _dangerous(ctx: Context, cid: str, span: Span, cmd: str) -> None:
        text = normalize(cmd).text
        fetch = search(NETWORK_FETCH, text)
        cred = search(CREDENTIAL_PATH, text)
        if fetch or cred:
            what = "fetches from the network" if fetch else "reads credential files"
            ctx.emit("AG-SKL-EXEC-003", component_ids=cid, span=span, snippet=cmd, match=cmd,
                     kind=EvidenceKind.metadata, message=f"Command that runs at invocation {what}.")


_UNRESTRICTED_TOOL = regex.compile(
    r"^(?:\*|Bash|PowerShell|Shell|Bash\(\s*\*?\s*(?::\s*\*)?\s*\)|Bash\(\s*\*\s+\*\s*\)|"
    r"Bash\(\s*(?:sh|bash|zsh|python3?|node|perl|ruby|pwsh|powershell|env|eval|sudo|xargs)\b[^)]*\))$",
    regex.IGNORECASE,
)
_SIDE_EFFECT_TOOL = regex.compile(r"^(?:Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell|WebFetch|Shell)\b", regex.IGNORECASE)
_READONLY_PURPOSE = regex.compile(
    r"\b(?:summari[sz]e|explain|review|analy[sz]e|read|search|look ?up|find|format|lint|check|inspect|document|convert|"
    r"translate|guide|reference|style|describe|answer|classif|extract|parse|validate|compare)", regex.IGNORECASE)
_ACTIVE_PURPOSE = regex.compile(
    r"\b(?:create|write|edit|modif|update|generat|build|deploy|install|run|execut|commit|push|send|post|upload|fetch|"
    r"download|delete|remove|refactor|fix|implement|scaffold|migrat|test|automat|manage|configur|set ?up|publish|release|"
    r"browse|crawl|scrape|call|query|sync)", regex.IGNORECASE)


_WEB_PURPOSE = regex.compile(r"\b(?:web|online|internet|urls?|websites?|sites?|research|sources|search)\b", regex.IGNORECASE)


def parse_allowed_tools(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if not isinstance(value, str):
        return []
    tokens: list[str] = []
    depth = 0
    cur = ""
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if depth == 0 and (ch.isspace() or ch == ","):
            if cur.strip():
                tokens.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        tokens.append(cur.strip())
    return tokens


class SkillPrivilegeAnalyzer:
    id: ClassVar[str] = "skill.privilege"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SKL-PRIV-001", "AG-SKL-PRIV-002")

    def run(self, ctx: Context) -> None:
        for at in ctx.texts("skill_md", "instruction_md"):
            data = at.fm.data if at.fm and at.fm.data else None
            if not data or "allowed-tools" not in data:
                continue
            cid = at.artifact.component_id
            tools = parse_allowed_tools(data.get("allowed-tools"))
            span = _fm_span(at, "allowed-tools")
            line = _fm_line(at, "allowed-tools")
            unrestricted = [t for t in tools if _UNRESTRICTED_TOOL.match(t)]
            if unrestricted:
                ctx.emit("AG-SKL-PRIV-001", component_ids=cid, span=span, snippet=line, match=",".join(unrestricted),
                         kind=EvidenceKind.metadata,
                         message=f"allowed-tools pre-approves unrestricted shell ({', '.join(unrestricted[:3])}); "
                                 "commands run without a permission prompt.")
                ctx.add_capability(cid, CapLabel.auto_approved, confidence=Confidence.high, span=span, snippet=line,
                                   reason="unrestricted shell pre-approved", kind=EvidenceKind.metadata)
                ctx.add_capability(cid, CapLabel.code_exec, confidence=Confidence.medium, span=span, snippet=line,
                                   reason="shell pre-approved", kind=EvidenceKind.metadata)
            desc = str(data.get("description") or "")
            web_purpose = bool(search(_WEB_PURPOSE, desc))
            side = [t for t in tools
                    if _SIDE_EFFECT_TOOL.match(t) and not (web_purpose and t.lower().startswith("webfetch"))]
            if side and search(_READONLY_PURPOSE, desc) and not search(_ACTIVE_PURPOSE, desc):
                ctx.emit("AG-SKL-PRIV-002", component_ids=cid, span=span, snippet=line, match=",".join(side),
                         kind=EvidenceKind.metadata,
                         message=f"The description reads as read-only, but allowed-tools pre-approves {', '.join(side[:4])}.")
            for t in tools:
                if t.lower().startswith("webfetch") or regex.match(r"(?i)bash\((?:curl|wget)", t, timeout=TIMEOUT):
                    ctx.add_capability(cid, CapLabel.external_egress, declared=True, observed=False,
                                       confidence=Confidence.medium, span=span, snippet=line,
                                       reason=f"pre-approved network tool {t}", kind=EvidenceKind.metadata)


class TyposquatAnalyzer:
    id: ClassVar[str] = "skill.typosquat"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SKL-TYP-001", "AG-SKL-TYP-002")

    def run(self, ctx: Context) -> None:
        popular: dict[str, str | None] = {}
        for entry in ctx.pack.list_data("popular-skills") + list(ctx.options.popular_skills):
            name, _, publisher = entry.partition(" ")
            popular[name.strip().lower()] = publisher.strip() or None
        if not popular:
            return
        for comp in ctx.inventory.of_kind(ComponentKind.skill):
            raw = comp.name.strip()
            if not raw:
                continue
            folded = normalize(raw).text.lower()
            at = next((t for t in ctx.texts("skill_md") if t.artifact.component_id == comp.id), None)
            span = _fm_span(at, "name") if at else Span(path=comp.root)
            snippet = _fm_line(at, "name") if at else raw
            if folded in popular:
                if folded != raw.lower():
                    ctx.emit("AG-SKL-TYP-001", component_ids=comp.id, span=span, snippet=snippet, match=raw,
                             kind=EvidenceKind.metadata, confidence=Confidence.high,
                             message=f"Skill name '{raw}' uses look-alike characters to imitate the popular skill '{folded}'.")
                    continue
                expected = popular[folded]
                if expected and comp.publisher and comp.publisher.lower() != expected.lower():
                    ctx.emit("AG-SKL-TYP-002", component_ids=comp.id, span=span, snippet=snippet, match=raw,
                             kind=EvidenceKind.metadata,
                             message=f"Skill uses the popular name '{raw}' but declares publisher '{comp.publisher}' "
                                     f"(expected '{expected}').")
                continue
            if len(folded) < 5:
                continue
            for name in sorted(popular):
                if len(name) < 5 or abs(len(name) - len(folded)) > 2:
                    continue
                limit = 1 if len(name) <= 8 else 2
                d = damerau_levenshtein(folded, name, cap=limit)
                if 0 < d <= limit:
                    ctx.emit("AG-SKL-TYP-001", component_ids=comp.id, span=span, snippet=snippet, match=raw,
                             kind=EvidenceKind.metadata,
                             message=f"Skill name '{raw}' is {d} edit(s) away from the popular skill '{name}'.")
                    break


class BundleAnalyzer:
    id: ClassVar[str] = "skill.bundle"
    requires: ClassVar[frozenset[str]] = frozenset()
    rules: ClassVar[tuple[str, ...]] = ("AG-SKL-BND-001", "AG-SKL-BND-002", "AG-SKL-BND-003")

    _NATIVE_EXT = (".so", ".dll", ".dylib", ".exe", ".pyc", ".pyd", ".jar", ".class", ".node", ".wasm", ".bin", ".msi", ".app", ".scr")

    def run(self, ctx: Context) -> None:
        tree = ctx.inventory.tree
        for art in sorted(ctx.inventory.artifacts.values(), key=lambda a: a.path):
            comp = ctx.inventory.components.get(art.component_id)
            if comp is None or comp.kind not in (ComponentKind.skill, ComponentKind.mcp_server):
                continue
            blob = tree.files.get(art.path) if tree else None
            data = blob.data if blob else b""
            kind = binary_kind(data)
            span = Span(path=art.path)
            if art.role == ArtifactRole.binary and (kind in EXECUTABLE_KINDS or art.path.lower().endswith(self._NATIVE_EXT)):
                ctx.emit("AG-SKL-BND-001", component_ids=comp.id, span=span, snippet=f"{art.path} ({kind or 'binary'}, {art.size} bytes)",
                         match=art.sha256, kind=EvidenceKind.metadata,
                         message=f"Bundle contains a compiled/native artifact ({kind or posixpath.splitext(art.path)[1]}) that cannot be reviewed as source.")
            elif art.role == ArtifactRole.archive:
                encrypted = kind == "zip" and len(data) > 8 and (data[6] & 0x1) == 1
                ctx.emit("AG-SKL-BND-002", component_ids=comp.id, span=span, snippet=f"{art.path} ({kind}, {art.size} bytes)",
                         match=art.sha256, kind=EvidenceKind.metadata,
                         severity=None if not encrypted else ctx.pack.rule("AG-SKL-BND-002").severity.bump(1),
                         message="Bundle contains a password-protected archive." if encrypted else "Bundle contains an archive; its contents are not scanned.")
        for comp in ctx.inventory.of_kind(ComponentKind.skill):
            md = next((t for t in ctx.texts("skill_md") if t.artifact.component_id == comp.id), None)
            if md is None:
                continue
            refs = md.text
            for at in ctx.texts("script"):
                if at.artifact.component_id != comp.id:
                    continue
                rel = at.path[len(comp.root) + 1 :] if comp.root else at.path
                base = posixpath.basename(rel)
                if base.startswith(".") or (rel not in refs and base not in refs):
                    ctx.emit("AG-SKL-BND-003", component_ids=comp.id, span=Span(path=at.path), snippet=rel, match=rel,
                             kind=EvidenceKind.metadata,
                             message=f"Script '{rel}' is {'a hidden dotfile' if base.startswith('.') else 'not referenced from SKILL.md'}.")


# Re-export for other modules.
__all__ = [
    "BundleAnalyzer", "SkillExecAnalyzer", "SkillPrivilegeAnalyzer", "SkillSpecAnalyzer", "TyposquatAnalyzer",
    "hook_commands", "parse_allowed_tools", "CREDENTIAL_PATH", "READ_VERB",
]

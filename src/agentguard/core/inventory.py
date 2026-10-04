"""Inventory: classify the files of an ArtifactTree into components.

Pure function of the tree (no filesystem, no network).
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any

import regex

from .artifacts import (
    ARCHIVE_KINDS,
    ArtifactText,
    binary_kind,
    is_markdown,
    language_for,
    prepare,
)
from .mcp_config import ClientConfig, looks_like_config, parse_config
from .models import (
    Artifact,
    Component,
    LoadLimits,
    PromptDef,
    ResourceDef,
    Span,
    ToolDef,
    component_id,
)
from .models.enums import ArtifactRole, ComponentKind
from .parsers import locate, parse_json, parse_toml
from .textutil import TIMEOUT, sha256_hex
from .tree import ArtifactTree

_INSTRUCTION_NAMES = {
    "agents.md", "agents.override.md", "agent.md", "claude.md", "claude.local.md", "gemini.md", ".cursorrules",
    ".windsurfrules", "copilot-instructions.md", "soul.md", "memory.md", "identity.md",
}
_INSTRUCTION_PATHS = (
    r"(^|/)\.cursor/rules/.+\.(mdc|md)$",
    r"(^|/)\.github/instructions/.+\.instructions\.md$",
    r"(^|/)\.copilot/instructions/.+\.md$",
    r"(^|/)\.claude/rules/.+\.md$",
    r"(^|/)\.windsurf/rules/.+\.md$",
    r"(^|/)\.clinerules(/.+\.md)?$",
)
_AGENT_PATH = r"(^|/)\.claude/agents/.+\.md$"
_COMMAND_PATH = r"(^|/)\.claude/commands/.+\.md$"
_MCP_SDK_DEPS = ("@modelcontextprotocol/sdk", "fastmcp", "mcp", "@modelcontextprotocol/server", "mcp-framework", "@mastra/mcp")


@dataclass
class Inventory:
    components: dict[str, Component] = field(default_factory=dict)
    artifacts: dict[str, Artifact] = field(default_factory=dict)       # by path
    texts: dict[str, ArtifactText] = field(default_factory=dict)       # by path
    configs: list[ClientConfig] = field(default_factory=list)
    server_components: dict[tuple[str, str, str], str] = field(default_factory=dict)  # (config, project, name) -> id
    manifests: dict[str, Any] = field(default_factory=dict)           # path -> parsed manifest value
    package_roots: dict[str, str] = field(default_factory=dict)       # root dir -> component id
    notes: list[str] = field(default_factory=list)
    tree: ArtifactTree | None = None

    def component_for(self, path: str) -> Component | None:
        art = self.artifacts.get(path)
        return self.components.get(art.component_id) if art else None

    def of_kind(self, *kinds: ComponentKind) -> list[Component]:
        return [c for c in self.components.values() if c.kind in kinds]


def _match(pattern: str, path: str) -> bool:
    return bool(regex.search(pattern, path, timeout=TIMEOUT))


def _dirname(path: str) -> str:
    return posixpath.dirname(path)


def _under(path: str, root: str) -> bool:
    return root == "" or path == root or path.startswith(root + "/")


def _skill_role(rel: str, data: bytes) -> ArtifactRole:
    kind = binary_kind(data)
    if kind in ARCHIVE_KINDS:
        return ArtifactRole.archive
    if kind:
        return ArtifactRole.binary
    top = rel.split("/", 1)[0] if "/" in rel else ""
    if language_for(rel, data):
        return ArtifactRole.script
    if top == "references" or is_markdown(rel):
        return ArtifactRole.reference
    return ArtifactRole.asset


def build_inventory(tree: ArtifactTree, limits: LoadLimits | None = None) -> Inventory:
    limits = limits or LoadLimits()
    inv = Inventory(tree=tree)
    paths = tree.paths()

    def add_artifact(path: str, comp: Component, role: ArtifactRole) -> Artifact:
        blob = tree.files[path]
        art = Artifact(
            id=sha256_hex(f"{comp.id}|{path}")[:16],
            component_id=comp.id,
            path=path,
            role=role,
            language=language_for(path, blob.data) if role in (ArtifactRole.script, ArtifactRole.source_code) else None,
            sha256=blob.sha256,
            size=blob.size,
        )
        inv.artifacts[path] = art
        comp.artifact_ids.append(art.id)
        if role not in (ArtifactRole.binary, ArtifactRole.archive):
            at = prepare(art, blob.data, max_decode_depth=limits.max_decode_depth, max_decoded=limits.max_decoded_bytes)
            if at is not None:
                inv.texts[path] = at
        return art

    def new_component(kind: ComponentKind, name: str, root: str, **kw: Any) -> Component:
        cid = component_id(kind, root, name, kw.pop("_key", ""))
        comp = Component(id=cid, kind=kind, name=name, root=root, source=tree.source, **kw)
        inv.components[cid] = comp
        return comp

    # 1. Skills (nearest SKILL.md owns the directory).
    skill_roots = sorted(
        {_dirname(p) for p in paths if posixpath.basename(p).lower() == "skill.md"}, key=lambda r: (-r.count("/"), r)
    )
    skill_comp_by_root: dict[str, Component] = {}
    for root in sorted(skill_roots):
        name = posixpath.basename(root) or "(root)"
        comp = new_component(ComponentKind.skill, name, root)
        skill_comp_by_root[root] = comp

    def owning_skill(path: str) -> str | None:
        for root in skill_roots:  # deepest first
            if _under(path, root):
                return root
        return None

    # 2. MCP server source packages.
    for p in paths:
        base = posixpath.basename(p)
        if owning_skill(p) is not None:
            continue
        if base == "package.json":
            parsed = parse_json(tree.files[p].data.decode("utf-8", "replace"))
            pkg = parsed.value if isinstance(parsed.value, dict) else {}
            deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {}), **(pkg.get("peerDependencies") or {})}
            name = str(pkg.get("name") or posixpath.basename(_dirname(p)) or "package")
            if any(d in deps for d in _MCP_SDK_DEPS) or "mcp" in name.lower():
                root = _dirname(p)
                comp = new_component(
                    ComponentKind.mcp_server, name, root, version=str(pkg.get("version") or "") or None,
                    publisher=_publisher_from_pkg(pkg), metadata={"ecosystem": "npm", "source_package": "true"},
                )
                inv.package_roots[root] = comp.id
                add_artifact(p, comp, ArtifactRole.package_manifest)
        elif base in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"):
            text = tree.files[p].data.decode("utf-8", "replace")
            root = _dirname(p)
            if root in inv.package_roots:
                comp = inv.components[inv.package_roots[root]]
                add_artifact(p, comp, ArtifactRole.package_manifest)
                continue
            name, version = posixpath.basename(root) or "package", None
            if base == "pyproject.toml":
                t = parse_toml(text).value or {}
                proj = t.get("project") or {}
                name = str(proj.get("name") or name)
                version = str(proj.get("version") or "") or None
                deps_text = " ".join(str(d) for d in (proj.get("dependencies") or []))
            else:
                deps_text = text
            if regex.search(r"(?im)(^|[\s\"'\[,])(mcp|fastmcp)\b", deps_text, timeout=TIMEOUT) or "mcp" in name.lower():
                comp = new_component(
                    ComponentKind.mcp_server, name, root, version=version, metadata={"ecosystem": "pypi", "source_package": "true"}
                )
                inv.package_roots[root] = comp.id
                add_artifact(p, comp, ArtifactRole.package_manifest)

    def owning_package(path: str) -> str | None:
        best = None
        for root in inv.package_roots:
            if _under(path, root) and (best is None or len(root) > len(best)):
                best = root
        return best

    # 3. Walk every file once.
    for p in paths:
        if p in inv.artifacts:
            continue
        data = tree.files[p].data
        base_lower = posixpath.basename(p).lower()
        sroot = owning_skill(p)
        if sroot is not None:
            comp = skill_comp_by_root[sroot]
            rel = p[len(sroot) + 1 :] if sroot else p
            role = ArtifactRole.skill_md if rel.lower() == "skill.md" else _skill_role(rel, data)
            add_artifact(p, comp, role)
            continue
        if _match(_AGENT_PATH, p) or _match(_COMMAND_PATH, p):
            kind = ComponentKind.subagent if _match(_AGENT_PATH, p) else ComponentKind.command
            comp = new_component(kind, posixpath.splitext(posixpath.basename(p))[0], p)
            add_artifact(p, comp, ArtifactRole.instruction_md)
            continue
        if base_lower in _INSTRUCTION_NAMES or any(_match(rx, p) for rx in _INSTRUCTION_PATHS):
            comp = new_component(ComponentKind.instruction_file, posixpath.basename(p), p)
            add_artifact(p, comp, ArtifactRole.instruction_md)
            continue
        if base_lower == "server.json":
            _add_server_json(inv, tree, p, new_component, add_artifact)
            continue
        if looks_like_config(p):
            text = data.decode("utf-8", "replace")
            cfg = parse_config(p, text)
            if cfg is not None:
                _add_client_config(inv, cfg, new_component, add_artifact, tree)
                continue
            manifest = _tool_manifest(text) if p.lower().endswith(".json") else None
            if manifest is not None:
                _add_manifest(inv, p, text, manifest, new_component, add_artifact, owning_package)
                continue
        proot = owning_package(p)
        if proot is not None:
            comp = inv.components[inv.package_roots[proot]]
            kind = binary_kind(data)
            if kind in ARCHIVE_KINDS:
                role = ArtifactRole.archive
            elif kind:
                role = ArtifactRole.binary
            elif language_for(p, data):
                role = ArtifactRole.source_code
            elif is_markdown(p):
                role = ArtifactRole.reference
            else:
                role = ArtifactRole.other
            add_artifact(p, comp, role)

    # Name skills from frontmatter where available; compute content hashes.
    for comp in inv.components.values():
        if comp.kind == ComponentKind.skill:
            md = next((t for t in inv.texts.values() if t.artifact.component_id == comp.id and t.artifact.role == ArtifactRole.skill_md), None)
            if md and md.fm and md.fm.data and isinstance(md.fm.data.get("name"), str):
                comp.name = md.fm.data["name"][:128]
            if md and md.fm and md.fm.data and isinstance(md.fm.data.get("metadata"), dict):
                meta = md.fm.data["metadata"]
                if isinstance(meta.get("version"), (str, int, float)):
                    comp.version = str(meta["version"])
                if isinstance(meta.get("author"), str):
                    comp.publisher = meta["author"][:128]
        arts = sorted((a for a in inv.artifacts.values() if a.component_id == comp.id), key=lambda a: a.path)
        if arts:
            root = comp.root if comp.kind in (ComponentKind.skill, ComponentKind.mcp_server) else ""
            comp.content_hash = sha256_hex(
                "\n".join(f"{a.path[len(root) + 1:] if root and a.path.startswith(root + '/') else a.path}\0{a.sha256}" for a in arts)
            )
        elif comp.server is not None:
            comp.content_hash = sha256_hex(repr(comp.server.model_dump(exclude={"config_path", "config_span"})))
    return inv


def _publisher_from_pkg(pkg: dict[str, Any]) -> str | None:
    author = pkg.get("author")
    if isinstance(author, dict):
        author = author.get("name")
    if isinstance(author, str) and author.strip():
        return author.strip()[:128]
    name = pkg.get("name")
    if isinstance(name, str) and name.startswith("@") and "/" in name:
        return name.split("/", 1)[0]
    return None


def _add_client_config(inv: Inventory, cfg: ClientConfig, new_component, add_artifact, tree: ArtifactTree) -> None:
    hint = tree.hints.get(cfg.path, {})
    if hint.get("client"):
        cfg.client = hint["client"]
    if hint.get("scope"):
        cfg.scope = hint["scope"]
    inv.configs.append(cfg)
    ccomp = new_component(ComponentKind.mcp_client_config, f"{cfg.client}:{cfg.path}", cfg.path, metadata={"client": cfg.client, "scope": cfg.scope})
    add_artifact(cfg.path, ccomp, ArtifactRole.client_config)
    for entry in cfg.servers:
        entry.spec.client = cfg.client
        if entry.project is None:
            entry.spec.scope = cfg.scope
        entry.spec.config_span = Span(path=cfg.path, start_line=entry.line)
        scomp = new_component(
            ComponentKind.mcp_server,
            entry.name,
            cfg.path,
            server=entry.spec,
            _key=f"{entry.project or ''}|{entry.name}",
            metadata={"client": cfg.client, "config": cfg.path, **({"project": entry.project} if entry.project else {})},
        )
        inv.server_components[(cfg.path, entry.project or "", entry.name)] = scomp.id


def _add_server_json(inv: Inventory, tree: ArtifactTree, path: str, new_component, add_artifact) -> None:
    text = tree.files[path].data.decode("utf-8", "replace")
    parsed = parse_json(text)
    v = parsed.value if isinstance(parsed.value, dict) else {}
    name = str(v.get("name") or posixpath.basename(_dirname(path)) or "server")
    version = v.get("version") or (v.get("version_detail") or {}).get("version")
    comp = new_component(
        ComponentKind.package, name, path, version=str(version) if version else None,
        publisher=name.split("/", 1)[0] if "/" in name else None,
        metadata={"registry_server_json": "true", "repository": str((v.get("repository") or {}).get("url") or "")},
    )
    add_artifact(path, comp, ArtifactRole.server_json)
    inv.manifests[path] = v


def _tool_manifest(text: str) -> dict[str, Any] | None:
    if '"tools"' not in text and '"prompts"' not in text and '"instructions"' not in text:
        return None
    parsed = parse_json(text)
    v = parsed.value
    if isinstance(v, dict) and isinstance(v.get("result"), dict):
        v = v["result"]
    if not isinstance(v, dict):
        return None
    tools = v.get("tools")
    if isinstance(tools, list) and tools and all(isinstance(t, dict) and "name" in t for t in tools):
        if any(k in tools[0] for k in ("inputSchema", "input_schema", "description")):
            return v
    if isinstance(v.get("prompts"), list) and all(isinstance(t, dict) and "name" in t for t in v["prompts"]):
        return v
    return None


def _add_manifest(inv: Inventory, path: str, text: str, v: dict[str, Any], new_component, add_artifact, owning_package) -> None:
    proot = owning_package(path)
    if proot is not None:
        comp = inv.components[inv.package_roots[proot]]
    else:
        info = v.get("serverInfo") if isinstance(v.get("serverInfo"), dict) else {}
        name = str(info.get("name") or v.get("name") or posixpath.splitext(posixpath.basename(path))[0])
        comp = new_component(ComponentKind.mcp_server, name, path, version=str(info.get("version") or "") or None,
                             metadata={"manifest": path})
    add_artifact(path, comp, ArtifactRole.tool_manifest)
    inv.manifests[path] = v
    for t in v.get("tools") or []:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str):
            continue
        comp.tools.append(
            ToolDef(
                name=t["name"],
                title=t.get("title") if isinstance(t.get("title"), str) else None,
                description=t.get("description") if isinstance(t.get("description"), str) else None,
                input_schema=t.get("inputSchema") or t.get("input_schema") or {},
                output_schema=t.get("outputSchema"),
                annotations=t.get("annotations") if isinstance(t.get("annotations"), dict) else {},
                origin="manifest",
                span=Span(path=path, start_line=locate(text, '"tools"', f'"{t["name"]}"')),
            )
        )
    for pr in v.get("prompts") or []:
        if isinstance(pr, dict) and isinstance(pr.get("name"), str):
            msgs = []
            for m in pr.get("messages") or []:
                content = m.get("content") if isinstance(m, dict) else None
                if isinstance(content, dict) and isinstance(content.get("text"), str):
                    msgs.append(content["text"])
                elif isinstance(content, str):
                    msgs.append(content)
            comp.prompts.append(
                PromptDef(name=pr["name"], title=pr.get("title"), description=pr.get("description"),
                          arguments=pr.get("arguments") or [], messages=msgs,
                          span=Span(path=path, start_line=locate(text, '"prompts"', f'"{pr["name"]}"')))
            )
    for rs in v.get("resources") or []:
        if isinstance(rs, dict) and isinstance(rs.get("uri"), str):
            comp.resources.append(
                ResourceDef(uri=rs["uri"], name=rs.get("name"), title=rs.get("title"), description=rs.get("description"),
                            mime_type=rs.get("mimeType"), text=rs.get("text") if isinstance(rs.get("text"), str) else None,
                            span=Span(path=path, start_line=locate(text, f'"{rs["uri"]}"')))
            )
    if isinstance(v.get("instructions"), str):
        comp.instructions = v["instructions"]

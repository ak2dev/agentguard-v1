"""Parsing of MCP client configuration files into server entries.

Supported shapes (verify each against client docs; see docs/sources.md):
* ``mcpServers`` map — Claude Desktop, Claude Code (``.mcp.json``, ``~/.claude.json``
  including ``projects.<path>.mcpServers``), Cursor, Windsurf, Gemini CLI, Cline.
* ``servers`` map (+ ``inputs``) — VS Code ``mcp.json``; ``mcp.servers`` in VS Code settings.
* ``context_servers`` map — Zed ``settings.json`` (legacy nested ``command.path`` form too).
* ``mcp_servers`` table — Codex ``config.toml``.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any

import regex

from .models import McpServerSpec
from .models.enums import Transport
from .parsers import locate, parse_json, parse_toml
from .textutil import TIMEOUT

SERVER_MAP_KEYS = ("mcpServers", "servers", "context_servers", "mcp_servers")

# Path → (client, default scope). Discovery passes exact client/scope hints;
# these patterns classify configs found inside a scanned repo or folder.
# Sources for each path: docs/sources.md ("MCP client config paths").
_CLIENT_BY_PATH = (
    (r"(^|/)claude_desktop_config\.json$", "claude-desktop", "user"),
    (r"(^|/)\.claude\.json$", "claude-code", "user"),
    (r"(^|/)\.mcp\.json$", "claude-code", "project"),
    (r"(^|/)\.claude/settings(\.local)?\.json$", "claude-code", "project"),
    (r"(^|/)managed-(?:settings|mcp)\.json$", "claude-code", "enterprise"),
    (r"(^|/)\.cursor/mcp\.json$", "cursor", "project"),
    (r"(^|/)\.vscode/mcp\.json$", "vscode", "workspace"),
    (r"(^|/)\.vscode/settings\.json$", "vscode", "workspace"),
    (r"(^|/)Code/User/(settings|mcp)\.json$", "vscode", "user"),
    (r"(^|/)(?:devin|windsurf)/mcp_config\.json$", "windsurf", "user"),
    (r"(^|/)\.gemini/settings\.json$", "gemini-cli", "project"),
    (r"(^|/)gemini-?cli/settings\.json$", "gemini-cli", "enterprise"),
    (r"(^|/)\.codex/config\.toml$", "codex", "user"),
    (r"(^|/)\.zed/settings\.json$", "zed", "project"),
    (r"(^|/)zed/settings\.json$", "zed", "user"),
    (r"(^|/)cline_mcp_settings\.json$", "cline", "user"),
    (r"(^|/)mcp\.json$", "generic", "project"),
)

_SEMVER_EXACT = regex.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
_RUNNERS_NPM = {"npx", "bunx", "pnpx"}
_RUNNERS_DLX = {"pnpm", "yarn", "bun"}
_RUNNERS_PY = {"uvx", "pipx"}


def client_for_path(path: str) -> tuple[str, str]:
    for pattern, client, scope in _CLIENT_BY_PATH:
        if regex.search(pattern, path, regex.IGNORECASE, timeout=TIMEOUT):
            return client, scope
    return "unknown", "unknown"


@dataclass
class ServerEntry:
    name: str
    raw: dict[str, Any]
    spec: McpServerSpec
    line: int
    map_key: str
    project: str | None = None  # for ~/.claude.json per-project entries


@dataclass
class ClientConfig:
    path: str
    client: str
    scope: str
    fmt: str
    value: Any
    servers: list[ServerEntry] = field(default_factory=list)
    error: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)  # non-server keys (auto-approve etc.)


def looks_like_config(path: str) -> bool:
    lower = path.lower()
    return lower.endswith((".json", ".jsonc", ".toml")) and not lower.endswith(("package.json", "package-lock.json", "tsconfig.json"))


def parse_config(path: str, text: str) -> ClientConfig | None:
    """Return a ClientConfig if ``text`` contains MCP server definitions."""
    if path.lower().endswith(".toml"):
        parsed = parse_toml(text)
    else:
        parsed = parse_json(text, jsonc=path.lower().endswith(".jsonc"))
    value = parsed.value
    client, scope = client_for_path(path)
    if parsed.error:
        if client != "unknown" and "mcp" in text.lower():
            return ClientConfig(path, client, scope, parsed.fmt, None, error=parsed.error)
        return None
    if not isinstance(value, dict):
        return None
    cfg = ClientConfig(path, client, scope, parsed.fmt, value)
    found = False

    def take(map_key: str, servers: Any, project: str | None = None, prefix: tuple[str, ...] = ()) -> None:
        nonlocal found
        if not isinstance(servers, dict):
            return
        for name, raw in servers.items():
            if not isinstance(raw, dict):
                continue
            found = True
            line = locate(text, *prefix, f'"{map_key}"' if cfg.fmt != "toml" else map_key, f'"{name}"' if cfg.fmt != "toml" else name)
            spec = build_spec(str(name), raw, client=client, scope=scope if project is None else "project", path=path)
            cfg.servers.append(ServerEntry(str(name), raw, spec, line, map_key, project))

    for key in SERVER_MAP_KEYS:
        if key == "servers" and client not in ("vscode", "generic", "unknown"):
            continue
        if key in value:
            if key == "servers" and not _looks_like_server_map(value[key]):
                continue
            take(key, value[key])
    mcp = value.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        take("servers", mcp["servers"], prefix=('"mcp"',))
    projects = value.get("projects")
    if isinstance(projects, dict):
        for proj, pval in projects.items():
            if isinstance(pval, dict) and isinstance(pval.get("mcpServers"), dict):
                take("mcpServers", pval["mcpServers"], project=str(proj), prefix=(f'"{proj}"',))
    for k in ("enableAllProjectMcpServers", "enabledMcpjsonServers", "chat.tools.autoApprove", "chat.mcp.autoStart"):
        if k in value:
            cfg.settings[k] = value[k]
    if not found and not cfg.settings:
        return None
    return cfg


def _looks_like_server_map(v: Any) -> bool:
    if not isinstance(v, dict) or not v:
        return False
    return all(isinstance(x, dict) and ({"command", "url", "type"} & set(x)) for x in v.values())


def build_spec(name: str, raw: dict[str, Any], *, client: str, scope: str, path: str) -> McpServerSpec:
    command = raw.get("command")
    args = raw.get("args") or []
    # Zed legacy: {"command": {"path": ..., "args": [...], "env": {...}}}
    if isinstance(command, dict):
        args = command.get("args") or []
        env = command.get("env") or {}
        command = command.get("path")
    else:
        env = raw.get("env") or {}
    if not isinstance(args, list):
        args = [str(args)]
    args = [str(a) for a in args]
    url = raw.get("httpUrl") or raw.get("url") or raw.get("serverUrl")
    kind = str(raw.get("type") or raw.get("transport") or "").lower()
    # Gemini CLI: `url` is an SSE endpoint, `httpUrl` is Streamable HTTP.
    gemini_sse = client == "gemini-cli" and not raw.get("httpUrl") and bool(raw.get("url"))
    if command:
        transport = Transport.stdio
    elif url:
        transport = Transport.sse_deprecated if kind == "sse" or gemini_sse else Transport.streamable_http
    else:
        transport = Transport.unknown
    headers = raw.get("headers") or raw.get("http_headers") or {}
    pinned, detail = pin_status(str(command) if command else None, args)
    if transport != Transport.stdio:
        pinned, detail = True, "remote server (version controlled by operator)"
    return McpServerSpec(
        transport=transport,
        command=str(command) if command else None,
        args=args,
        url=str(url) if url else None,
        env_names=sorted(str(k) for k in env) if isinstance(env, dict) else [],
        header_names=sorted(str(k) for k in headers) if isinstance(headers, dict) else [],
        pinned=pinned,
        pin_detail=detail,
        client=client,
        scope=scope,
        config_path=path,
    )


def exe_name(command: str | None) -> str:
    if not command:
        return ""
    base = posixpath.basename(command.replace("\\", "/")).lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def package_arg(command: str | None, args: list[str]) -> tuple[str | None, str | None]:
    """Return (runner, package spec) for package-runner invocations."""
    exe = exe_name(command)
    rest = list(args)
    if exe in ("cmd", "powershell", "pwsh") and rest:
        # e.g. cmd /c npx -y pkg — look through the wrapper
        joined = [a for a in rest if a.lower() not in ("/c", "/k", "-command", "-c")]
        if joined:
            return package_arg(joined[0], joined[1:])
    if exe in _RUNNERS_DLX:
        if rest and rest[0] == "dlx" or (exe == "bun" and rest and rest[0] == "x"):
            rest = rest[1:]
        else:
            return None, None
    elif exe == "pipx":
        if rest and rest[0] == "run":
            rest = rest[1:]
        else:
            return None, None
    elif exe == "uv":
        if len(rest) >= 2 and rest[0] == "tool" and rest[1] == "run":
            rest = rest[2:]
            exe = "uvx"
        else:
            return None, None
    elif exe not in _RUNNERS_NPM | _RUNNERS_PY:
        return None, None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("-p", "--package", "--from", "--spec"):
            if i + 1 < len(rest):
                return exe, rest[i + 1]
            return exe, None
        if a.startswith(("--package=", "--from=", "--spec=")):
            return exe, a.split("=", 1)[1]
        if a.startswith("-"):
            i += 1
            continue
        return exe, a
    return exe, None


def split_package_spec(spec: str) -> tuple[str, str | None]:
    s = spec.strip()
    if "==" in s:
        name, ver = s.split("==", 1)
        return name, ver
    if s.startswith("@"):
        at = s.find("@", 1)
        return (s, None) if at < 0 else (s[:at], s[at + 1 :])
    if "@" in s:
        name, ver = s.split("@", 1)
        return name, ver
    return s, None


def pin_status(command: str | None, args: list[str]) -> tuple[bool, str]:
    if not command:
        return False, "no command"
    exe = exe_name(command)
    if exe in ("docker", "podman", "nerdctl"):
        image = docker_image(args)
        if image is None:
            return False, "container image not identified"
        if "@sha256:" in image:
            return True, "image pinned by digest"
        tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else "latest"
        return False, f"image tag '{tag}' (not a digest)"
    runner, spec = package_arg(command, args)
    if runner:
        if not spec:
            return False, f"{runner}: package not identified"
        name, ver = split_package_spec(spec)
        if not ver or ver.lower() in ("latest", "next", "*"):
            return False, f"{runner} {name}: {'@' + ver if ver else 'no version'}"
        if _SEMVER_EXACT.match(ver):
            return True, f"{runner} {name}@{ver}"
        return False, f"{runner} {name}: version range '{ver}'"
    return True, "local or system command"


_DOCKER_FLAGS_WITH_VALUE = {
    "-v", "--volume", "-e", "--env", "--env-file", "-p", "--publish", "--name", "--network", "--net",
    "-w", "--workdir", "-u", "--user", "--mount", "--entrypoint", "--cap-add", "--cap-drop", "--pid",
    "--ipc", "--security-opt", "-l", "--label", "--platform", "--add-host", "--device", "-m", "--memory",
    "--cpus", "--restart", "--hostname", "-h", "--tmpfs", "--gpus", "--runtime", "--pull", "--init-path",
}


def docker_image(args: list[str]) -> str | None:
    if not args:
        return None
    rest = list(args)
    if rest[0] in ("run", "container"):
        rest = rest[1:] if rest[0] == "run" else rest[2:]
    else:
        return None
    i = 0
    while i < len(rest):
        a = rest[i]
        if a.startswith("-"):
            if "=" in a:
                i += 1
                continue
            if a in _DOCKER_FLAGS_WITH_VALUE:
                i += 2
                continue
            i += 1
            continue
        return a
    return None

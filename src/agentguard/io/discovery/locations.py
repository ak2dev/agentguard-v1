"""Known agent/MCP configuration locations per client and OS.

Every entry records whether the path was verified against the client's own
documentation (see docs/sources.md). Unverified entries are still scanned —
reading a file is harmless — but they are labelled in `agentguard discover`.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Location:
    client: str
    scope: str          # user | project | enterprise
    kind: str           # config | skills | instructions | agents | commands
    path: Path
    verified: bool
    note: str = ""


def _env_path(name: str) -> Path | None:
    v = os.environ.get(name)
    return Path(v) if v else None


def user_locations(home: Path | None = None, platform: str | None = None) -> list[Location]:
    home = home or Path.home()
    plat = platform or sys.platform
    appdata = _env_path("APPDATA") or home / "AppData" / "Roaming"
    localappdata = _env_path("LOCALAPPDATA") or home / "AppData" / "Local"
    xdg = _env_path("XDG_CONFIG_HOME") or home / ".config"
    L: list[Location] = []
    add = L.append

    # Claude Desktop (modelcontextprotocol.io "Connect to local MCP servers"; published for macOS and Windows only)
    if plat == "darwin":
        add(Location("claude-desktop", "user", "config", home / "Library/Application Support/Claude/claude_desktop_config.json", True))
    elif plat == "win32":
        add(Location("claude-desktop", "user", "config", appdata / "Claude" / "claude_desktop_config.json", True))
    else:
        add(Location("claude-desktop", "user", "config", xdg / "Claude" / "claude_desktop_config.json", False,
                     "Claude Desktop is published for macOS and Windows only; unofficial Linux builds"))
    # Claude Code (code.claude.com/docs: mcp, settings, skills, sub-agents, memory)
    add(Location("claude-code", "user", "config", home / ".claude.json", True))
    add(Location("claude-code", "user", "config", home / ".claude" / "settings.json", True))
    add(Location("claude-code", "user", "skills", home / ".claude" / "skills", True))
    add(Location("claude-code", "user", "agents", home / ".claude" / "agents", True))
    add(Location("claude-code", "user", "commands", home / ".claude" / "commands", True, "legacy command files"))
    add(Location("claude-code", "user", "instructions", home / ".claude" / "CLAUDE.md", True))
    add(Location("claude-code", "user", "instructions", home / ".claude" / "rules", True))
    add(Location("claude-code", "user", "skills", home / ".claude" / "plugins", False, "plugin install folder not stated; plugin skills live under <plugin>/skills/"))
    if plat == "darwin":
        add(Location("claude-code", "enterprise", "instructions", Path("/Library/Application Support/ClaudeCode/CLAUDE.md"), True))
    elif plat == "win32":
        add(Location("claude-code", "enterprise", "instructions", Path("C:/Program Files/ClaudeCode/CLAUDE.md"), True))
    else:
        add(Location("claude-code", "enterprise", "instructions", Path("/etc/claude-code/CLAUDE.md"), True))
    # Cursor (cursor.com/docs/context/mcp)
    add(Location("cursor", "user", "config", home / ".cursor" / "mcp.json", True))
    # VS Code: mcp.json lives in the user profile folder ("MCP: Open User Configuration"); the default
    # profile folder is Code/User and other profiles are Code/User/profiles/<id> (code.visualstudio.com
    # docs: mcp-servers, settings).
    if plat == "darwin":
        code_user = home / "Library/Application Support/Code/User"
    elif plat == "win32":
        code_user = appdata / "Code" / "User"
    else:
        code_user = xdg / "Code" / "User"
    add(Location("vscode", "user", "config", code_user / "mcp.json", True))
    add(Location("vscode", "user", "config", code_user / "settings.json", True))
    add(Location("vscode", "user", "config", code_user / "profiles", True, "non-default profiles"))
    # GitHub Copilot (VS Code docs: mcp-servers, custom-instructions); COPILOT_HOME overrides ~/.copilot
    copilot = _env_path("COPILOT_HOME") or home / ".copilot"
    add(Location("copilot", "user", "config", copilot / "mcp-config.json", True))
    add(Location("copilot", "user", "instructions", copilot / "copilot-instructions.md", True))
    add(Location("copilot", "user", "instructions", copilot / "instructions", True))
    # Windsurf / Devin Desktop (docs.devin.ai/desktop/cascade/mcp)
    if plat == "win32":
        add(Location("windsurf", "user", "config", appdata / "devin" / "mcp_config.json", True))
    else:
        add(Location("windsurf", "user", "config", xdg / "devin" / "mcp_config.json", True))
    add(Location("windsurf", "user", "config", home / ".codeium" / "windsurf" / "mcp_config.json", False,
                 "legacy Windsurf path; not in the current docs"))
    # Gemini CLI (geminicli.com/docs: reference/configuration, cli/gemini-md)
    add(Location("gemini-cli", "user", "config", home / ".gemini" / "settings.json", True))
    add(Location("gemini-cli", "user", "instructions", home / ".gemini" / "GEMINI.md", True,
                 "the file name is configurable (context.fileName)"))
    if plat == "darwin":
        add(Location("gemini-cli", "enterprise", "config", Path("/Library/Application Support/GeminiCli/settings.json"), True))
    elif plat == "win32":
        add(Location("gemini-cli", "enterprise", "config", Path("C:/ProgramData/gemini-cli/settings.json"), True))
    else:
        add(Location("gemini-cli", "enterprise", "config", Path("/etc/gemini-cli/settings.json"), True))
    # Codex (developers.openai.com/codex: mcp, AGENTS.md, skills); CODEX_HOME overrides ~/.codex
    codex = _env_path("CODEX_HOME") or home / ".codex"
    add(Location("codex", "user", "config", codex / "config.toml", True))
    add(Location("codex", "user", "instructions", codex / "AGENTS.md", True))
    add(Location("codex", "user", "instructions", codex / "AGENTS.override.md", True))
    add(Location("codex", "user", "skills", home / ".agents" / "skills", True, "also read by OpenClaw"))
    if plat != "win32":
        add(Location("codex", "enterprise", "skills", Path("/etc/codex/skills"), True))
    add(Location("codex", "user", "skills", codex / "skills", False,
                 "not in the current docs, but installed Codex keeps its bundled skills in skills/.system"))
    # Zed (zed.dev/docs/configuring-zed, as published in the zed-industries/zed repository)
    if plat == "win32":
        add(Location("zed", "user", "config", appdata / "Zed" / "settings.json", True))
    elif plat == "darwin":
        add(Location("zed", "user", "config", home / ".config" / "zed" / "settings.json", True))
    else:
        add(Location("zed", "user", "config", xdg / "zed" / "settings.json", True))
    # Cline CLI (docs.cline.bot/mcp/configuring-mcp-servers); the IDE extension keeps its file in editor storage
    add(Location("cline", "user", "config", home / ".cline" / "mcp.json", True))
    # OpenClaw (docs.openclaw.ai/skills); OPENCLAW_STATE_DIR / OPENCLAW_HOME override ~/.openclaw
    openclaw = _env_path("OPENCLAW_STATE_DIR") or _env_path("OPENCLAW_HOME") or home / ".openclaw"
    add(Location("openclaw", "user", "skills", openclaw / "skills", True))
    add(Location("openclaw", "user", "skills", openclaw / "workspace" / "skills", True, "default workspace"))
    return L


PROJECT_PATTERNS: tuple[tuple[str, str, str, bool], ...] = (
    # (relative path, client, kind, verified)
    (".mcp.json", "claude-code", "config", True),
    (".claude/settings.json", "claude-code", "config", True),
    (".claude/settings.local.json", "claude-code", "config", True),
    (".claude/skills", "claude-code", "skills", True),
    (".claude/agents", "claude-code", "agents", True),
    (".claude/commands", "claude-code", "commands", True),
    (".claude/rules", "claude-code", "instructions", True),
    (".claude/CLAUDE.md", "claude-code", "instructions", True),
    ("CLAUDE.md", "claude-code", "instructions", True),
    ("CLAUDE.local.md", "claude-code", "instructions", True),
    (".cursor/mcp.json", "cursor", "config", True),
    (".cursor/rules", "cursor", "instructions", True),
    (".vscode/mcp.json", "vscode", "config", True),
    (".github/copilot-instructions.md", "copilot", "instructions", True),
    (".github/instructions", "copilot", "instructions", True),
    (".gemini/settings.json", "gemini-cli", "config", True),
    ("GEMINI.md", "gemini-cli", "instructions", True),
    (".codex/config.toml", "codex", "config", True),
    (".agents/skills", "codex", "skills", True),
    ("AGENTS.md", "generic", "instructions", True),
    ("AGENTS.override.md", "codex", "instructions", True),
    (".zed/settings.json", "zed", "config", True),
)

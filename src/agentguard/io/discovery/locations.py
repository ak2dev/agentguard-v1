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

    # Claude Desktop (modelcontextprotocol.io "Connect to local MCP servers")
    if plat == "darwin":
        add(Location("claude-desktop", "user", "config", home / "Library/Application Support/Claude/claude_desktop_config.json", True))
    elif plat == "win32":
        add(Location("claude-desktop", "user", "config", appdata / "Claude" / "claude_desktop_config.json", True))
    else:
        add(Location("claude-desktop", "user", "config", xdg / "Claude" / "claude_desktop_config.json", False,
                     "Linux path not documented by vendor"))
    # Claude Code (code.claude.com/docs: mcp, settings, skills)
    add(Location("claude-code", "user", "config", home / ".claude.json", True))
    add(Location("claude-code", "user", "config", home / ".claude" / "settings.json", True))
    add(Location("claude-code", "user", "skills", home / ".claude" / "skills", True))
    add(Location("claude-code", "user", "agents", home / ".claude" / "agents", False))
    add(Location("claude-code", "user", "commands", home / ".claude" / "commands", False))
    add(Location("claude-code", "user", "instructions", home / ".claude" / "CLAUDE.md", False))
    add(Location("claude-code", "user", "skills", home / ".claude" / "plugins", False, "plugin skills live under <plugin>/skills/"))
    # Cursor (cursor.com/docs/context/mcp)
    add(Location("cursor", "user", "config", home / ".cursor" / "mcp.json", True))
    # VS Code user profile mcp.json (opened via "MCP: Open User Configuration")
    if plat == "darwin":
        code_user = home / "Library/Application Support/Code/User"
    elif plat == "win32":
        code_user = appdata / "Code" / "User"
    else:
        code_user = xdg / "Code" / "User"
    add(Location("vscode", "user", "config", code_user / "mcp.json", False, "profile folder location not stated in MCP docs"))
    add(Location("vscode", "user", "config", code_user / "settings.json", False))
    # Windsurf / Devin Desktop (docs.devin.ai/desktop/cascade/mcp)
    if plat == "win32":
        add(Location("windsurf", "user", "config", appdata / "devin" / "mcp_config.json", True))
    else:
        add(Location("windsurf", "user", "config", xdg / "devin" / "mcp_config.json", True))
    add(Location("windsurf", "user", "config", home / ".codeium" / "windsurf" / "mcp_config.json", False, "legacy Windsurf path"))
    # Gemini CLI (geminicli.com/docs/reference/configuration)
    add(Location("gemini-cli", "user", "config", home / ".gemini" / "settings.json", True))
    add(Location("gemini-cli", "user", "instructions", home / ".gemini" / "GEMINI.md", False))
    if plat == "darwin":
        add(Location("gemini-cli", "enterprise", "config", Path("/Library/Application Support/GeminiCli/settings.json"), True))
    elif plat == "win32":
        add(Location("gemini-cli", "enterprise", "config", Path("C:/ProgramData/gemini-cli/settings.json"), True))
    else:
        add(Location("gemini-cli", "enterprise", "config", Path("/etc/gemini-cli/settings.json"), True))
    # Codex (developers.openai.com/codex/mcp)
    add(Location("codex", "user", "config", home / ".codex" / "config.toml", True))
    add(Location("codex", "user", "instructions", home / ".codex" / "AGENTS.md", False))
    add(Location("codex", "user", "skills", home / ".codex" / "skills", False))
    # Zed (zed.dev/docs/configuring-zed)
    if plat == "darwin":
        add(Location("zed", "user", "config", home / "Library/Application Support/Zed/settings.json", True))
    elif plat == "win32":
        add(Location("zed", "user", "config", localappdata / "Zed" / "settings.json", True))
    else:
        add(Location("zed", "user", "config", home / ".local/share/zed/settings.json", True))
    add(Location("zed", "user", "config", xdg / "zed" / "settings.json", False, "older Zed location"))
    # OpenClaw / ClawHub skills (unverified)
    add(Location("openclaw", "user", "skills", home / ".openclaw" / "skills", False))
    add(Location("openclaw", "user", "skills", home / ".openclaw" / "workspace" / "skills", False))
    return L


PROJECT_PATTERNS: tuple[tuple[str, str, str, bool], ...] = (
    # (relative path, client, kind, verified)
    (".mcp.json", "claude-code", "config", True),
    (".claude/settings.json", "claude-code", "config", True),
    (".claude/settings.local.json", "claude-code", "config", True),
    (".claude/skills", "claude-code", "skills", True),
    (".claude/agents", "claude-code", "agents", False),
    (".claude/commands", "claude-code", "commands", False),
    (".cursor/mcp.json", "cursor", "config", True),
    (".cursor/rules", "cursor", "instructions", False),
    (".vscode/mcp.json", "vscode", "config", True),
    (".gemini/settings.json", "gemini-cli", "config", True),
    (".codex/config.toml", "codex", "config", True),
    (".zed/settings.json", "zed", "config", True),
    (".github/copilot-instructions.md", "copilot", "instructions", False),
    ("AGENTS.md", "generic", "instructions", False),
    ("CLAUDE.md", "claude-code", "instructions", False),
    ("GEMINI.md", "gemini-cli", "instructions", False),
)

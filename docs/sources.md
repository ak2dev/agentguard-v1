# Sources

Each entry records the claim it supports and when it was checked. Anything
marked TODO is unverified and must not be relied on without checking.

## Standards

| Topic | Claim relied on | Source | Checked |
|---|---|---|---|
| OWASP Agentic 2026 | ASI01–ASI10 IDs and titles | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | 2026-09-28 (search summary; re-verify against PDF) |
| OWASP MCP Top 10 | MCP01:2025–MCP10:2025 IDs/titles; beta status | https://owasp.org/www-project-mcp-top-10/ · https://github.com/OWASP/www-project-mcp-top-10 | 2026-09-28 (search summary; re-verify) |
| OWASP Agentic Skills Top 10 | AST01–AST10 IDs/titles, v1.0; AST01 sub-patterns (typosquatting, prerequisite lures, ClickFix, SOUL.md/MEMORY.md persistence) | https://owasp.github.io/www-project-agentic-skills-top-10/ · …/ast01.html | 2026-09-28 — **release date inconsistent** (site: "March 2026"; press: "v1.0 2026-08-17") |
| OWASP LLM Top 10 2025 | LLM01:2025–LLM10:2025 | https://genai.owasp.org/llm-top-10/ | 2026-09-28 |
| NSA AISC CSI (MCP) | Title; released 2026-05-20 | https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/ · https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF | **TODO — HTTP 403 to automated fetch; section IDs unverified; every rule maps to null + TODO** |
| OWASP AIVSS v0.8 | AARS = (10 − CVSS base) × (factor sum ÷ 10) × ThM; AIVSS = (CVSS base + AARS) × MF; ThM 1.00/0.97/0.50; MF 1.00/0.83/0.67; ten AARFs scored 0/0.5/1 | https://aivss.owasp.org/ | 2026-09-28 (search summary). **TODO: verify against the v0.8 PDF; AARF names not yet mapped — scorer uses a capability proxy and says so** |
| CWE | Titles of the CWE IDs used in mappings/cwe.yaml | https://cwe.mitre.org/ | TODO (titles from memory; re-check each) |

## Formats and protocols

| Topic | Claim relied on | Source | Checked |
|---|---|---|---|
| Agent Skills spec | name 1–64 `[a-z0-9-]`, no leading/trailing/double hyphen, must match dir; description 1–1024; compatibility 1–500; metadata string→string; allowed-tools experimental | https://agentskills.io/specification | 2026-09-28 |
| Claude Code skills | Frontmatter fields incl. `allowed-tools` (pre-approves for the turn, does not restrict), `disallowed-tools`, `hooks`, `shell`, `context`, `agent`; `` !`cmd` `` and ```` ```! ```` dynamic context injection runs before the model sees the skill; skill locations (personal, project, nested, enterprise, plugin) | https://code.claude.com/docs/en/skills | 2026-09-28 |
| MCP 2026-07-28 | Stateless; `server/discover`; `initialize` removed; DCR deprecated for Client ID Metadata Documents; RFC 9207 `iss` (AS SHOULD send, client MUST validate); HTTP+SSE deprecated; `CacheableResult` | https://modelcontextprotocol.io/specification/2026-07-28/changelog | 2026-09-28 |
| SARIF / GitHub code scanning | `security-severity` 0.1–10 (>9 critical, 7–8.9 high, 4–6.9 medium, <4 low); `precision`; ≤20 tags; `partialFingerprints.primaryLocationLineHash`; levels note/warning/error; 25k results/run; 10 MB gz; `semanticVersion` preferred; `help.markdown` | https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning | 2026-09-28 |
| CycloneDX 1.6 | Component schema | https://cyclonedx.org/docs/1.6/json/ | TODO |
| RFC 9728 / 8414 / 9207 / 8707 / 7636 / 9116 | Auth conformance and security.txt | rfc-editor.org | TODO (auth phase) |

## MCP client config paths (used by discovery)

| Client | Path(s) | Source | Checked |
|---|---|---|---|
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json` | https://modelcontextprotocol.io/docs/develop/connect-local-servers | 2026-09-28 (Linux path not documented → marked unverified) |
| Claude Code | user/local: `~/.claude.json` (`mcpServers`, `projects.<path>.mcpServers`); project: `.mcp.json`; settings: `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`; `bypassPermissions` no longer honored from project/local settings since v2.1.257 | https://code.claude.com/docs/en/mcp · https://code.claude.com/docs/en/settings | 2026-09-28 (managed-settings OS paths: TODO) |
| Cursor | `~/.cursor/mcp.json`, `.cursor/mcp.json` (`mcpServers`) | https://cursor.com/docs/context/mcp | 2026-09-28 |
| VS Code | `.vscode/mcp.json` (`servers`, `inputs`; type stdio/http/sse); `.mcp.json` portable format; user profile `mcp.json` via "MCP: Open User Configuration" | https://code.visualstudio.com/docs/copilot/customization/mcp-servers | 2026-09-28 (profile folder path: TODO; `chat.tools.autoApprove` not mentioned on that page: TODO verify) |
| Windsurf / Devin Desktop | `~/.config/devin/mcp_config.json` (or `$XDG_CONFIG_HOME/devin/`), Windows `%APPDATA%\devin\mcp_config.json`; keys `mcpServers`, `serverUrl`, `headers` | https://docs.devin.ai/desktop/cascade/mcp (redirected from docs.windsurf.com) | 2026-09-28 (legacy `~/.codeium/windsurf/mcp_config.json`: unverified) |
| Gemini CLI | `~/.gemini/settings.json`, `.gemini/settings.json`; system: Linux `/etc/gemini-cli/settings.json`, Windows `C:\ProgramData\gemini-cli\settings.json`, macOS `/Library/Application Support/GeminiCli/settings.json`; `url` = SSE, `httpUrl` = Streamable HTTP; `trust: true` bypasses all tool call confirmations | https://geminicli.com/docs/reference/configuration | 2026-09-28 |
| Codex | `~/.codex/config.toml`, project `.codex/config.toml` (trusted projects); `[mcp_servers.<name>]` | https://developers.openai.com/codex/mcp | 2026-09-28 (Codex skills dir: TODO) |
| Zed | macOS `~/Library/Application Support/Zed/settings.json`; Linux `~/.local/share/zed/settings.json`; Windows `%LOCALAPPDATA%\Zed\settings.json`; project `.zed/settings.json`; key `context_servers` | https://zed.dev/docs/configuring-zed · https://zed.dev/docs/ai/mcp | 2026-09-28 |
| Cline | `cline_mcp_settings.json`, `alwaysAllow` | — | TODO |
| OpenClaw / ClawHub | skill directories | — | TODO |

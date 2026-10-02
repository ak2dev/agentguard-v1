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
| NSA AISC CSI (MCP) | "Model Context Protocol (MCP): Security Design Considerations for AI-Driven Automation", U/OO/6030316-26, PP-26-1834, Ver. 1.0, May 2026 (released 2026-05-20). Its section headings (8 security concerns, 6 real-world examples, 9 recommendations) are the item ids in `mappings/nsa-csi-mcp-2026-05.yaml`; the CSI does not number its sections | https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf · press release https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/ | 2026-10-02: read in full (17 pages; SHA-256 `f9c0452acdf5f45603f61079eea66b67e19b372bee96a8bbb3981a74429add03`). nsa.gov and media.defense.gov refuse non-browser clients (HTTP 403); the PDF was saved through a browser. Every rule's NSA mapping reviewed against the text |
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

All rows re-checked 2026-10-02 unless noted. Paths not stated by the vendor stay unverified in
`agentguard discover`, with the reason.

| Client | Path(s) | Source | Checked |
|---|---|---|---|
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows `%APPDATA%\Claude\claude_desktop_config.json`. "Claude Desktop is available for macOS and Windows" | https://modelcontextprotocol.io/docs/develop/connect-local-servers | 2026-10-02 (no official Linux build → the Linux path stays unverified) |
| Claude Code (MCP, settings) | user/local: `~/.claude.json` (`mcpServers`, `projects.<path>.mcpServers`); project: `.mcp.json`; settings: `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`; `bypassPermissions` no longer honored from project/local settings since v2.1.257 | https://code.claude.com/docs/en/mcp · https://code.claude.com/docs/en/settings | 2026-09-28 (managed-settings OS paths: TODO) |
| Claude Code (skills, commands, subagents) | skills `~/.claude/skills/<name>/SKILL.md`, `.claude/skills/…`, nested `<subdir>/.claude/skills/…`, plugin `<plugin>/skills/…`; legacy commands `~/.claude/commands/<name>.md`, `.claude/commands/<name>.md`; subagents `~/.claude/agents/`, `.claude/agents/` (scanned recursively) | https://code.claude.com/docs/en/skills · https://code.claude.com/docs/en/sub-agents | 2026-10-02 (the plugin install folder is not stated → `~/.claude/plugins` stays unverified) |
| Claude Code (instructions) | managed: macOS `/Library/Application Support/ClaudeCode/CLAUDE.md`, Linux/WSL `/etc/claude-code/CLAUDE.md`, Windows `C:\Program Files\ClaudeCode\CLAUDE.md`; user `~/.claude/CLAUDE.md`, `~/.claude/rules/`; project `./CLAUDE.md` or `./.claude/CLAUDE.md`, `./CLAUDE.local.md`, `.claude/rules/**/*.md`; reads `AGENTS.md` (and `.claude/AGENTS.md`) when there is no CLAUDE.md | https://code.claude.com/docs/en/memory | 2026-10-02 |
| Cursor | MCP `~/.cursor/mcp.json`, `.cursor/mcp.json` (`mcpServers`); rules `.cursor/rules/*.mdc` (plain `.md` there is ignored); `AGENTS.md` in the project root and subdirectories | https://cursor.com/docs/context/mcp · https://cursor.com/docs/context/rules | 2026-10-02 (`.cursorrules` not mentioned; still scanned by name) |
| VS Code | `.vscode/mcp.json` (`servers`, `inputs`; type stdio/http/sse); user `mcp.json` in the user profile folder ("MCP: Open User Configuration"); profile folders: default `Code/User/` (Windows `%APPDATA%\Code\User`, macOS `~/Library/Application Support/Code/User`, Linux `~/.config/Code/User`), others `Code/User/profiles/<id>/` | https://code.visualstudio.com/docs/copilot/customization/mcp-servers · https://code.visualstudio.com/docs/configure/settings | 2026-10-02 (`chat.tools.autoApprove` is not on the MCP page: TODO verify) |
| GitHub Copilot | MCP `$COPILOT_HOME/mcp-config.json` or `~/.copilot/mcp-config.json`; instructions `.github/copilot-instructions.md`, `.github/instructions/**/*.instructions.md`, `AGENTS.md`, `~/.copilot/copilot-instructions.md`, `~/.copilot/instructions` | https://code.visualstudio.com/docs/copilot/customization/mcp-servers · https://code.visualstudio.com/docs/copilot/customization/custom-instructions | 2026-10-02 |
| Windsurf / Devin Desktop | `~/.config/devin/mcp_config.json` (or `$XDG_CONFIG_HOME/devin/`), Windows `%APPDATA%\devin\mcp_config.json`; keys `mcpServers`, `serverUrl`, `headers` | https://docs.devin.ai/desktop/cascade/mcp (redirected from docs.windsurf.com) | 2026-10-02 (legacy `~/.codeium/windsurf/mcp_config.json` is not in the current docs → unverified) |
| Gemini CLI | `~/.gemini/settings.json`, `.gemini/settings.json`; system: Linux `/etc/gemini-cli/settings.json`, Windows `C:\ProgramData\gemini-cli\settings.json`, macOS `/Library/Application Support/GeminiCli/settings.json`; `url` = SSE, `httpUrl` = Streamable HTTP; `trust: true` bypasses all tool call confirmations; context `~/.gemini/GEMINI.md` and `GEMINI.md` in workspace directories and their parents (name configurable with `context.fileName`) | https://geminicli.com/docs/reference/configuration · https://geminicli.com/docs/cli/gemini-md | 2026-10-02 |
| Codex | `~/.codex/config.toml` (`CODEX_HOME`), project `.codex/config.toml` (trusted projects), `[mcp_servers.<name>]`; instructions `~/.codex/AGENTS.override.md` else `~/.codex/AGENTS.md`, then `AGENTS.override.md` / `AGENTS.md` from the repository root down; skills `.agents/skills` from the working directory up to the repository root, `$HOME/.agents/skills`, `/etc/codex/skills` | https://developers.openai.com/codex/mcp · https://learn.chatgpt.com/docs/agent-configuration/agents-md · https://learn.chatgpt.com/docs/build-skills (developers.openai.com/codex/* redirects there) | 2026-10-02 (`~/.codex/skills` is not in the current docs → unverified) |
| Zed | user `~/.config/zed/settings.json` on macOS and Linux (`$XDG_CONFIG_HOME/zed/` on Linux), `%APPDATA%\Zed\settings.json` on Windows; project `.zed/settings.json`; key `context_servers` | https://zed.dev/docs/configuring-zed (text checked in the zed-industries/zed repository, `docs/src/configuring-zed.md`) · https://zed.dev/docs/ai/mcp | 2026-10-02. **Corrected**: discovery previously used `~/Library/Application Support/Zed`, `~/.local/share/zed` and `%LOCALAPPDATA%\Zed`, which are Zed's data directories, not its settings |
| Cline | CLI: `~/.cline/mcp.json`; the IDE extension edits its settings through the Cline panel (no fixed path documented); `autoApprove` lists tools that run without confirmation | https://docs.cline.bot/mcp/configuring-mcp-servers | 2026-10-02 (`cline_mcp_settings.json` in editor storage: path not documented; matched by name) |
| OpenClaw / ClawHub | skills, highest precedence first: `<workspace>/skills` (default workspace `~/.openclaw/workspace`), `<workspace>/.agents/skills`, `~/.agents/skills`, `<state-dir>/skills` (default state dir `~/.openclaw`; `OPENCLAW_STATE_DIR` / `OPENCLAW_HOME`), bundled, `skills.load.extraDirs`; `openclaw skills install` writes to `~/.openclaw/skills` | https://docs.openclaw.ai/skills | 2026-10-02 (state-dir default and env vars from the docs site's search summary) |

## Agent Guard Web (browser scanner) and hosting

| Topic | Claim relied on | Source | Checked |
|---|---|---|---|
| GitHub REST rate limits | Unauthenticated: 60 requests/hour per IP; `x-ratelimit-limit/remaining/used/reset/resource` headers; exceeding returns 403 or 429 | https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api | 2026-09-29 |
| GitHub "Get a tree" | `GET /repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1`; entries `path`, `mode`, `type`, `sha`, `size`; `truncated` when over 100,000 entries or 7 MB | https://docs.github.com/en/rest/git/trees | 2026-09-29 |
| GitHub "Get a commit" | `ref` may be a SHA, branch or tag; `Accept: application/vnd.github.sha` returns only the SHA | https://docs.github.com/en/rest/commits/commits#get-a-commit | 2026-09-29 |
| CORS for api.github.com / raw.githubusercontent.com | Browser `fetch` without credentials works for public data | Verified empirically from the scanner (2026-09-29): repo, commit, tree and 429 raw files fetched | 2026-09-29 (TODO: find a documented statement) |
| Vercel `vercel.json` | `framework: null` = "Other"; `installCommand`, `buildCommand`, `outputDirectory`; `headers[].source` pattern + `headers`; `trailingSlash: true` 308-redirects paths without an extension | https://vercel.com/docs/project-configuration/vercel-json | 2026-09-29 (precedence when several header rules set the same key is not documented, so the config avoids overlapping keys) |
| CSP `'wasm-unsafe-eval'` | Allows WebAssembly compilation without allowing JavaScript `eval`; Chrome 97+ | https://github.com/WebAssembly/content-security-policy/blob/main/proposals/CSP.md | 2026-09-29 (Pyodide 0.28.3 verified to run with it and without `'unsafe-eval'`) |
| Pyodide 0.28.3 | npm package ships the runtime and `pyodide-lock.json` (with sha256 per wheel) but not the wheels; wheels at `https://cdn.jsdelivr.net/pyodide/v0.28.3/full/` (build time only) | `site/node_modules/pyodide/pyodide-lock.json` | 2026-09-29 |

## Agent Guard Web server (fetcher and resolver)

| Topic | Claim relied on | Source | Checked |
|---|---|---|---|
| GitHub "Download a repository archive (tar)" | `GET /repos/{owner}/{repo}/tarball/{ref}`; `ref` = commit, branch or tag; responds with a 302 redirect (to codeload.github.com in practice) | https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-tar | 2026-10-01 (redirect host and `Accept: application/vnd.github+json` requirement verified against the live API: `application/octet-stream` gets HTTP 415) |
| npm registry metadata | `GET /<name>` (scoped names as `@scope%2fname`); `dist-tags.latest`; `versions[v].dist.tarball` and `dist.integrity` (`sha512-<base64>`); abbreviated form with `Accept: application/vnd.npm.install-v1+json` | https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md (does not document `integrity` or scoped encoding) | 2026-10-01 (verified against the live registry) |
| PyPI JSON API | `GET /pypi/<project>/<version>/json` → `urls[]` with `packagetype` (`sdist`, `bdist_wheel`), `url` on files.pythonhosted.org, `digests.sha256`, `yanked`; `GET /pypi/<project>/json` → `info.version` | https://docs.pypi.org/api/json/ | 2026-10-01 |
| MCP Registry API | `GET /v0.1/servers/{url-encoded name}/versions/{version|latest}` → `{"server": <server.json>, "_meta": …}`; `server.json` has `packages[]` (`registryType`, `identifier`, `version`), `remotes[]`, `repository` (`url`, `subfolder`) | https://registry.modelcontextprotocol.io (docs page did not render; endpoint and shape verified against the live API) | 2026-10-01 |
| Docker run hardening flags | `--network none`, `--read-only`, `--tmpfs`, `--user`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit`, `--memory`/`--memory-swap`, `--cpus`, `--ulimit`, `--runtime` | https://docs.docker.com/reference/cli/docker/container/run/ | 2026-10-01 (behaviour verified by the Docker tests, incl. no egress) |

## Site navigation

| Topic | Claim relied on | Source | Checked |
|---|---|---|---|
| Cross-document view transitions | `@view-transition { navigation: auto; }` opts same-origin navigations in; `navigation: none` opts out; not Baseline (progressive enhancement) | https://developer.mozilla.org/en-US/docs/Web/CSS/@view-transition | 2026-10-01 (verified in Chromium/Edge 152 via `pageswap` `viewTransition`) |
| Speculation rules via HTTP header | `Speculation-Rules: "<url>"`; the rules file must be served as `application/speculationrules+json`; same JSON as inline rules | https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Speculation-Rules | 2026-10-01 (an invalid `href_matches` pattern disables the whole rule set; verified `deliveryType: navigational-prefetch` in Edge) |

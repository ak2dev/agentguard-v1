# Agent Guard v1 — Design Proposal (for approval)

Status: **DRAFT, awaiting approval** · 2026-09-28 · Engine 0.1.0-dev · Rule pack 0.1.0-dev

This document covers (a) threat model, (b) rule catalog, (c) data model, (d) repo layout,
(e) website structure and generator choice, (f) Agent Guard Web architecture and the v1
interfaces it depends on. Nothing is built yet beyond this document and `docs/sources.md`.

## 0. Findings from verification that change the brief

I checked the sources listed in `docs/sources.md` before writing this. Five things change the brief:

1. **Claude Code skills can execute shell at invocation time.** SKILL.md supports
   dynamic context injection (`` !`cmd` `` and ```` ```! ```` blocks), which runs *before the
   model sees the skill*. It also supports a `hooks:` frontmatter map that registers hooks
   for the rest of the session. Neither needs a `scripts/` directory. I added the
   `AG-SKL-EXEC-*` rules, and both surfaces are sent to the shell analyzer.
2. **`allowed-tools` pre-approves tools for the invoking turn. `disallowed-tools` is the
   one that removes tools.** The over-privilege rules follow those semantics.
3. **MCP 2026-07-28 is stateless.** `initialize` is gone and servers MUST implement
   `server/discover`. List results now carry `ttlMs`/`cacheScope`. DCR is deprecated in
   favour of Client ID Metadata Documents. RFC 9207 `iss` is SHOULD for the AS and MUST for
   the client to validate. The opt-in metadata client therefore has two handshakes:
   `server/discover` for 2026-07-28, and `initialize` for 2025-11-25 and 2025-06-18.
4. **Agent Skills spec limits:** `name` is 1–64 chars from `[a-z0-9-]`, with no
   leading/trailing/double hyphen, and must match the parent directory. `description` is
   1–1024 chars. `compatibility` is 1–500 chars. `metadata` is string→string. The spec
   marks `allowed-tools` experimental.
5. **I could not retrieve the NSA CSI PDF.** Both nsa.gov and media.defense.gov returned
   403 to my fetcher. All NSA mappings stay `null` + `TODO` until someone reads the
   document; I'd appreciate a copy. OWASP AST10 sources disagree on the release date
   (March 2026 vs. "v1.0 on 2026-08-17"). The IDs and titles agree, so I'll pin to the
   project page's version at implementation time.

---

## (a) Threat model — Agent Guard CLI / engine

**System.** A Python CLI and library that reads untrusted artifacts (skills, instruction
files, MCP configs, server source, package metadata) on a developer laptop or CI runner.
It writes reports to a terminal, to files, to GitHub code scanning (SARIF) and to PR
comments. It can optionally use the network (remote MCP list calls, auth probes, OSV,
provenance, registry) and an optional LLM judge.

**Assets.** A1: integrity of the host and CI runner, including their secrets
(`GITHUB_TOKEN`, cloud creds). A2: correctness of results (no silent evasion, no fail-open).
A3: secrets present *in* scanned targets. A4: user privacy (what they have installed).
A5: Agent Guard's own supply chain (releases, rule pack, IOC feed). A6: CI availability.

**Adversaries.** T1: author of a malicious skill or server, who controls every scanned
byte. T2: malicious PR contributor, who controls the repo *including* `.agentguard.yaml`,
the lockfile and the baseline. T3: a hostile remote MCP server or network attacker.
T4: an attacker targeting Agent Guard's dependencies, rule pack or intel feed.
T5: a third party reading public SARIF alerts or PR comments.

| # | Threat | Mitigation (v1) |
|---|---|---|
| TM-01 | **Scanner executes target code.** Paths: lifecycle scripts, `setup.py`, importing target modules, git hooks, `core.fsmonitor`, diff/textconv drivers, spawning STDIO servers. | Parse-only design: no import of target code and no package managers. A **process-level `sys.addaudithook` guard** raises on `subprocess.Popen`, `os.system`, `os.exec*`, `os.posix_spawn` and `os.startfile`. The only exception is the hardened git call in PR mode: `git -c core.fsmonitor=false -c core.hooksPath=<empty> --no-pager diff --no-ext-diff --no-textconv --name-only`, with `GIT_CONFIG_NOSYSTEM=1`. The `tests/safety/` suite asserts that no process spawns across the whole fixture corpus. |
| TM-02 | **Parser/resource attacks.** YAML alias bombs and custom tags, deep JSON, huge files, zip bombs, ReDoS, tree-sitter pathologies, FIFOs and device files that block reads. | A central `LoadLimits` object (bytes/file, total bytes, file count, depth, decompression ratio, decode depth, AST node budget). YAML goes through a safe loader with **aliases and non-core tags rejected**. The `regex` module runs with per-match timeouts; rule regexes get a ReDoS lint in CI. Only regular files are read (`lstat`). A per-artifact time budget applies. Anything skipped raises `AG-SYS-001` and is listed in the report's coverage section. |
| TM-03 | **Path escape.** Symlinks, hardlinks, Windows junctions/reparse points, ADS (`file:stream`), `..`/absolute/UNC entries in archives, case-fold collisions, reserved names (`CON`, `NUL`). | Every path is resolved against the scan root and rejected on escape. Symlinks and junctions are never followed; they are recorded (`AG-SYS-003`). Archive members are normalized with `PurePosixPath`, and links and absolute paths are dropped. Windows-specific checks run on all OSes because they matter for archives. |
| TM-04 | **Prompt injection against the LLM judge.** | Content is placed only inside nonce-delimited data blocks with the delimiter escaped from the content. The judge has no tools. Output must validate against `judge-output.v1.json` or it is discarded. The judge can *annotate* but never create a CRITICAL finding and never lower a deterministic finding's severity. Results are cached by content hash. Injection detectors run first, and flagged content goes to the judge with a warning banner. |
| TM-05 | **Evasion.** Unicode tricks, nested encodings, payload split across files, paraphrase. | NFKC plus confusable folding with original offsets preserved. Encoded blobs are decoded up to depth 3 and rescanned. Correlation runs at *component* level, so split payloads recombine. An adversarial held-out bench split is maintained, and per-category recall is published even where it is weak. |
| TM-06 | **Fail-open.** An analyzer crashes and the scan exits 0. | Analyzers run isolated. An exception produces `AG-SYS-002` and exit code **2**. Exit code 0 is impossible if any analyzer errored, unless the user passes `--allow-partial`, which the report header records. |
| TM-07 | **Malicious PR edits the security config.** Adds suppressions, a baseline, lock entries, or loosens policy. | PR mode loads policy, suppressions and the baseline from the **base ref**. A PR that changes `.agentguard.yaml`, the lock or the baseline triggers `AG-POL-010` ("security configuration changed in this change set"). Suppressions require `reason` and `expires`; expired ones resurface. |
| TM-08 | **PR-mode blind spot.** The payload sits in an unchanged file referenced by a changed one. | `--changed-since` scans every *component* touching a changed file, plus components that reference it. Cross-component flow analysis always runs on the full inventory. |
| TM-09 | **Secret leakage via reports.** SARIF lands in GitHub, and PR comments are public. | Redaction at a single choke point: `Evidence.snippet` is a `RedactedText` type that can only be built through `redact()`, which keeps the first 4 chars plus an 8-hex hash. Golden tests assert that no fixture secret appears in any output format. |
| TM-10 | **Output injection.** ANSI escapes in the terminal, Markdown/HTML injection, @mentions, tracking images, SARIF Markdown. | Control characters and ANSI are stripped for terminal output. Markdown is escaped, `@` and `#` references are neutralized, and remote images are never emitted. The HTML report uses autoescaping and a strict CSP meta tag with no inline script. SARIF uses `text` messages with minimal `markdown`. |
| TM-11 | **SSRF / hostile remote server** (opt-in network). | `SafeHttpClient` resolves DNS first and blocks private, loopback, link-local, CGNAT, metadata and multicast ranges. It pins the resolved IP, re-validates every redirect, requires HTTPS (except explicit `--allow-http-localhost`), and enforces a timeout and response-size cap. Only read-only list and discovery methods are allowed, and `tools/call` is refused at the client layer. |
| TM-12 | **Privacy leakage** through network features. | Every network feature is off by default. Enabled features are listed in the report header with the hosts contacted. There is no telemetry, and CI tests assert zero sockets in default mode. |
| TM-13 | **Agent Guard supply chain.** | `uv.lock` with hashes and a minimal dependency set. Releases are Sigstore-signed, with a CycloneDX SBOM and SLSA provenance. The rule pack and IOC feed are signed bundles verified before load, with a monotonic version to prevent rollback. `SECURITY.md` is included. |
| TM-14 | **False assurance.** | The tool never says "safe". A clean scan reads "No findings from N rules (rule pack vX)". Every report lists analyzers not run (e.g., "YARA unavailable", "code analysis: 3 files unparsed"), and the README has a Limitations section. |
| TM-15 | **TOCTOU** between scan and install/update (rug pull). | `agentguard lock` / `verify` hash normalized tool definitions and skill files. Phase 4 gateway enforcement is designed but not built. |

**Out of scope for v1:** a compromised host or Python interpreter, runtime behaviour of
servers (Phase 3), and attacks on the agent runtime itself.

---

## (b) Rule catalog — rule pack 0.1.0

**Legend.** Severity: crit / high / med / low / info. Confidence: H / M / L.
The mapping columns carry proposed crosswalk IDs. ASI = OWASP Agentic 2026. MCP = OWASP
MCP Top 10 2025 (beta; `MCP03` means `MCP03:2025`). AST = OWASP Agentic Skills Top 10 v1.0.
LLM = OWASP LLM Top 10 2025. `—` means no applicable ID. The **NSA CSI column is `null`/TODO
for every rule** until the document is retrieved (§0.5), so it is omitted here.

**Invariants the engine enforces (not per-rule):**
- **CRITICAL requires confidence H and at least one deterministic evidence item.** If a
  CRITICAL rule matches with confidence below H, severity is capped at high.
- An LLM-sourced finding caps at high.
- **Hidden-context escalation:** an instruction-layer, social-engineering, credential or
  exfil match found *inside* hidden content (HTML comment, tag characters, decoded blob,
  post-whitespace text) is raised one severity level and gains the tag `hidden`.
- Instruction files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursor/rules/*.mdc`,
  `copilot-instructions.md`, agents, commands) run all `AG-SKL-*` content rules. `SPEC`
  rules apply only to `SKILL.md`.

### Skill analyzer — spec validation
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-SKL-SPEC-001 | Missing or empty required `name`/`description` | low | H | — | — | AST04 | — | — |
| AG-SKL-SPEC-002 | `name` violates format (charset, hyphens, 1–64) | low | H | — | — | AST04 | — | — |
| AG-SKL-SPEC-003 | `name` does not match parent directory | low | H | — | — | AST04 | — | — |
| AG-SKL-SPEC-004 | `description` > 1024 or `compatibility` > 500 chars | low | H | — | — | AST04 | — | — |
| AG-SKL-SPEC-005 | Unexpected frontmatter key (not spec or known platform extension) | info | M | — | — | AST04 | — | — |
| AG-SKL-SPEC-006 | Angle brackets / markup / role tags in frontmatter values (loaded into every session) | med | M | ASI01 | — | AST04 | LLM01 | — |
| AG-SKL-SPEC-007 | Frontmatter anomalies: duplicate keys, YAML aliases/tags, non-string `metadata` values | med | H | — | — | AST04 | — | CWE-20 |

### Skill analyzer — hidden content
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-SKL-HID-001 | Unicode tag characters (U+E0000–E007F) | high | H | ASI01 | — | AST01 | LLM01 | CWE-451 |
| AG-SKL-HID-002 | Bidi override/isolate controls (Trojan Source) | high | H | ASI01 | — | AST01 | LLM01 | CWE-451 |
| AG-SKL-HID-003 | Zero-width characters inside words/instructions (emoji ZWJ sequences excluded) | med | M | ASI01 | — | AST04 | LLM01 | CWE-451 |
| AG-SKL-HID-004 | Mixed-script homoglyph tokens (UTS #39 confusables) | med | M | ASI01 | — | AST01 | LLM01 | CWE-1007 |
| AG-SKL-HID-005 | HTML comment with agent-directed text (not rendered to users) | med | M | ASI01 | — | AST04 | LLM01 | CWE-451 |
| AG-SKL-HID-006 | Content hidden after a long whitespace run or off-screen padding | med | M | ASI01 | — | AST04 | LLM01 | CWE-451 |
| AG-SKL-HID-007 | Text in link-reference definitions / image alt / title attributes | low | M | ASI01 | — | AST04 | LLM01 | — |
| AG-SKL-HID-008 | Encoded blob (base64/hex/percent/QP/gzip+b64) decoded and rescanned | low | H | — | — | AST04 | — | — |
| AG-SKL-HID-009 | Decoded blob contains instructions or executable content | high | H | ASI01 | — | AST01 | LLM01 | CWE-506 |
| AG-SKL-HID-010 | CSS/HTML hiding in Markdown (`display:none`, zero font, same-color text) | med | M | ASI01 | — | AST04 | LLM01 | CWE-451 |

### Skill analyzer — instruction-layer threats
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-SKL-INJ-001 | Override / ignore-previous-instructions directive | high | M | ASI01 | — | AST01 | LLM01 | — |
| AG-SKL-INJ-002 | Forged role or context delimiters (`</system>`, chat-template tokens, fake tool results) | high | H | ASI01 | — | AST01 | LLM01 | CWE-74 |
| AG-SKL-INJ-003 | Instruction to conceal actions from the user | high | M | ASI09 | — | AST01 | LLM01 | — |
| AG-SKL-INJ-004 | Disables approvals/safety (skip-permissions flags, bypass modes, auto-approve settings) | high | H | ASI03 | — | AST03 | LLM06 | — |
| AG-SKL-INJ-005 | Self-modification (edits own/other skills, installs skills) | high | M | ASI10 | — | AST01 | LLM06 | — |
| AG-SKL-INJ-006 | Persistence: writes to memory/identity files, AGENTS/CLAUDE.md, shell rc, cron, launchd, systemd user units, Run keys, Startup | high | M | ASI06 | — | AST01 | — | — |
| AG-SKL-INJ-007 | Tampers with agent/IDE settings or MCP configs (adds servers or hooks) | high | M | ASI03 | MCP09 | AST01 | LLM06 | — |
| AG-SKL-INJ-008 | Loads remote instructions ("fetch URL and follow it") | high | M | ASI01 | — | AST05 | LLM01 | — |
| AG-SKL-INJ-009 | Authority/urgency impersonation aimed at agent or user | med | L | ASI09 | — | AST01 | LLM01 | — |

### Skill analyzer — platform execution surfaces (new, see §0.1)
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-SKL-EXEC-001 | Dynamic context injection (`` !`cmd` `` / ```` ```! ````) — runs at invocation; command sent to shell analyzer | med | H | ASI05 | — | AST06 | — | CWE-78 |
| AG-SKL-EXEC-002 | Skill-scoped `hooks:` in frontmatter — commands sent to shell analyzer | med | H | ASI05 | — | AST06 | — | — |
| AG-SKL-EXEC-003 | Injected/hook command fetches from network or reads credentials | crit | H | ASI05 | — | AST01 | — | CWE-494 |

### Skill analyzer — social-engineering install steps
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-SKL-SE-001 | "Prerequisites/Setup" tells user or agent to download and run a binary | high | H | ASI09 | — | AST01 | LLM03 | CWE-494 |
| AG-SKL-SE-002 | Pipe-to-shell (`curl … \| sh`, `iwr … \| iex`) from a host **not** on the vendor-installer allowlist | crit | H | ASI05 | — | AST01 | LLM03 | CWE-494 |
| AG-SKL-SE-003 | Password-protected archive with the password given in text | crit | H | ASI09 | — | AST01 | — | CWE-506 |
| AG-SKL-SE-004 | "Paste this into your terminal" (ClickFix-style) instruction | high | H | ASI09 | — | AST01 | — | — |
| AG-SKL-SE-005 | Encoded command execution (`-EncodedCommand`, `base64 -d \| sh`, `xxd -r \| bash`) | crit | H | ASI05 | — | AST01 | — | CWE-506 |
| AG-SKL-SE-006 | Fake credential prompt (password, sudo, keychain, seed phrase) | high | M | ASI09 | — | AST01 | LLM02 | — |
| AG-SKL-SE-007 | OS protection bypass (quarantine xattr removal, `spctl` disable, Defender exclusion) | crit | H | ASI05 | — | AST01 | — | — |
| AG-SKL-SE-008 | Pipe-to-shell from an allowlisted vendor installer (e.g., official language toolchains) | low | H | — | — | AST02 | LLM03 | CWE-494 |

### Skill analyzer — credentials, exfiltration, privilege, mismatch, typosquat, bundle
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-SKL-CRED-001 | References credential stores (SSH, cloud CLI creds, kube, docker, `.npmrc`/`.pypirc`/`.netrc`, `.env`, keychain, browser profiles, wallets) | med | M | ASI03 | — | AST03 | LLM02 | — |
| AG-SKL-CRED-002 | Harvests token env vars or dumps the full environment | med | M | ASI03 | — | AST03 | LLM02 | — |
| AG-SKL-CRED-010 | Credential access **and** network egress in the same skill | crit | H | ASI03 | — | AST01 | LLM02 | — |
| AG-SKL-EXF-001 | Known exfil sink (webhook catchers, paste sites, chat-bot APIs, tunnels, OAST) | high | M | ASI02 | — | AST01 | LLM02 | — |
| AG-SKL-EXF-002 | URL to a raw IP address | med | H | ASI02 | — | AST01 | — | — |
| AG-SKL-EXF-003 | URL shortener | med | H | ASI02 | — | AST01 | — | — |
| AG-SKL-EXF-004 | DNS-exfil pattern (variable subdomain lookups) | high | M | ASI02 | — | AST01 | LLM02 | — |
| AG-SKL-EXF-005 | Data-in-URL rendering (Markdown image/link carrying secrets or context) | high | M | ASI01 | — | AST01 | LLM02 | — |
| AG-SKL-PRIV-001 | `allowed-tools` pre-approves unrestricted shell (`Bash`, `Bash(*)`, PowerShell) | med | H | ASI03 | — | AST03 | LLM06 | CWE-250 |
| AG-SKL-PRIV-002 | Pre-approved tools exceed the purpose the description states | med | M | ASI03 | — | AST03 | LLM06 | CWE-250 |
| AG-SKL-MIS-001 | Description/behavior mismatch (deterministic purpose-vs-capability diff) | med | L | ASI02 | — | AST04 | — | — |
| AG-SKL-TYP-001 | Near-duplicate of a popular skill name (Damerau-Levenshtein + homoglyph fold) | med | M | ASI04 | — | AST01 | LLM03 | — |
| AG-SKL-TYP-002 | Exact popular-skill name from a different publisher/source | med | M | ASI04 | — | AST02 | LLM03 | — |
| AG-SKL-BND-001 | Bundled native binary / compiled artifact (ELF/PE/Mach-O, .so/.dll, .pyc, .jar, .wasm) | high | M | ASI04 | — | AST01 | LLM03 | CWE-506 |
| AG-SKL-BND-002 | Bundled archive (password-protected escalates to high) | med | H | ASI04 | — | AST01 | — | — |
| AG-SKL-BND-003 | Script not referenced from SKILL.md, or hidden dotfile script | low | M | — | — | AST04 | — | — |

### MCP config (`AG-MCP-CFG-*`)
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-MCP-CFG-001 | Shell interpreter as command with `-c` / `/c` / `-Command` | high | H | ASI05 | MCP05 | — | — | CWE-78 |
| AG-MCP-CFG-002 | Inline code as command (`python -c`, `node -e`, `perl -e`, …) | high | H | ASI05 | MCP05 | — | — | CWE-94 |
| AG-MCP-CFG-003 | Command/args built from variable expansion or command substitution | med | M | ASI05 | MCP05 | — | — | CWE-78 |
| AG-MCP-CFG-004 | Unpinned package runner (`npx`/`bunx`/`pnpm dlx`/`uvx`/`pipx run`, `@latest`, `-y`) | med | H | ASI04 | MCP04 | AST07 | LLM03 | CWE-829 |
| AG-MCP-CFG-006 | Remote script fetch in command (pipe-to-shell, non-allowlisted host) | crit | H | ASI05 | MCP05 | — | LLM03 | CWE-494 |
| AG-MCP-CFG-007 | Docker `--privileged`, `--cap-add=ALL`, `--pid=host`, `--network=host` | high | H | ASI03 | MCP02 | — | — | CWE-250 |
| AG-MCP-CFG-008 | Docker mounts `docker.sock` or host `/` | crit | H | ASI03 | MCP02 | — | — | CWE-250 |
| AG-MCP-CFG-009 | Docker mounts `$HOME` or credential directories | high | H | ASI03 | MCP02 | — | LLM02 | CWE-250 |
| AG-MCP-CFG-010 | Container image not pinned by digest / `:latest` | med | H | ASI04 | MCP04 | — | LLM03 | CWE-829 |
| AG-MCP-CFG-011 | Literal secret in env/args/headers (provider pattern) | high | H | — | MCP01 | — | LLM02 | CWE-798 |
| AG-MCP-CFG-012 | High-entropy literal in a secret-named field | med | M | — | MCP01 | — | LLM02 | CWE-798 |
| AG-MCP-CFG-013 | Remote server over plain `http://` (non-loopback) | high | H | — | MCP07 | — | — | CWE-319 |
| AG-MCP-CFG-014 | Remote server at a raw IP | med | H | — | MCP09 | — | — | — |
| AG-MCP-CFG-015 | Cloud-metadata / link-local / private-range target | high | H | — | MCP07 | — | — | CWE-918 |
| AG-MCP-CFG-016 | Server bound to `0.0.0.0` / all interfaces | med | M | — | MCP07 | — | — | CWE-1327 |
| AG-MCP-CFG-017 | Near-duplicate server names across configs (shadowing) | med | M | ASI04 | MCP09 | — | — | — |
| AG-MCP-CFG-018 | Same server name → different command/URL in different configs | high | H | ASI04 | MCP09 | — | — | — |
| AG-MCP-CFG-019 | Token/API key in URL query string | high | H | — | MCP01 | — | LLM02 | CWE-598 |
| AG-MCP-CFG-020 | Sensitive env var passed to a server (inventory signal) | low | L | ASI03 | MCP02 | — | — | — |
| AG-MCP-CFG-021 | Client auto-approve/trust setting for server tools (per-client keys; verify each in sources.md) | high | H | ASI03 | MCP02 | — | LLM06 | — |
| AG-MCP-CFG-022 | Repo-shipped project config adds a STDIO server (runs on open/trust) | med | H | ASI04 | MCP09 | — | LLM03 | CWE-829 |
| AG-MCP-CFG-023 | Deprecated HTTP+SSE transport | low | H | — | MCP07 | — | — | — |

*(CFG-005 was merged into CFG-004 and the ID retired.)*

### MCP tool/prompt/resource metadata (`AG-MCP-META-*`)
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-MCP-META-001 | Hidden Unicode in tool/param/prompt/resource metadata | high | H | ASI01 | MCP03 | — | LLM01 | CWE-451 |
| AG-MCP-META-002 | Instruction-layer directives in tool or param descriptions | high | M | ASI01 | MCP03 | — | LLM01 | — |
| AG-MCP-META-003 | Description directs reading sensitive files/secrets into tool arguments | crit | H | ASI02 | MCP03 | — | LLM02 | — |
| AG-MCP-META-004 | Side-channel parameter (e.g., "notes" asking for conversation or file content) | high | M | ASI02 | MCP10 | — | LLM02 | — |
| AG-MCP-META-005 | Injection in enum values, defaults, titles, examples, annotations | high | M | ASI01 | MCP03 | — | LLM01 | — |
| AG-MCP-META-006 | Tool shadowing: description references or redefines other servers' tools | high | M | ASI02 | MCP03 | — | LLM01 | — |
| AG-MCP-META-007 | Exact tool-name collision across servers | med | H | ASI02 | MCP09 | — | — | — |
| AG-MCP-META-008 | Near-collision tool names (edit distance / homoglyph) | med | M | ASI02 | MCP09 | — | — | CWE-1007 |
| AG-MCP-META-009 | Unconstrained dangerous string param (`command`, `code`, `path`, `url`, `sql`, `query`, …) | med | M | ASI02 | MCP05 | — | LLM06 | CWE-20 |
| AG-MCP-META-010 | `additionalProperties: true` on a dangerous tool | low | M | ASI02 | MCP05 | — | — | CWE-20 |
| AG-MCP-META-011 | `readOnlyHint: true` contradicted by code evidence | high | M | ASI09 | MCP02 | — | LLM06 | — |
| AG-MCP-META-012 | `destructiveHint: false` / `openWorldHint: false` contradicted by code | med | M | ASI09 | MCP02 | — | LLM06 | — |
| AG-MCP-META-013 | Injection in server `instructions` | high | M | ASI01 | MCP06 | — | LLM01 | — |
| AG-MCP-META-014 | Injection in prompt templates | high | M | ASI01 | MCP06 | — | LLM01 | — |
| AG-MCP-META-015 | Injection in resource metadata / templates | med | M | ASI01 | MCP10 | — | LLM01 | — |
| AG-MCP-META-016 | MCP Apps UI resource: script calls undeclared network origins | med | M | ASI02 | MCP10 | — | LLM02 | CWE-829 |
| AG-MCP-META-017 | MCP Apps UI resource: credential-style form fields | high | M | ASI09 | MCP01 | — | LLM02 | — |
| AG-MCP-META-018 | MCP Apps UI resource: external frames | med | M | ASI09 | MCP10 | — | — | — |
| AG-MCP-META-019 | Description stuffing (excessive length, padding) | low | M | ASI01 | MCP03 | — | LLM01 | — |
| AG-MCP-META-020 | Tool definitions vary by client identity or are fetched remotely at runtime (rug-pull enabler) | med | L | ASI04 | MCP03 | AST07 | — | — |

### Code (`AG-CODE-*`) — JS/TS, Python, shell
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-CODE-001 | Tool param → shell execution (`exec`, `shell=True`, `os.system`, …) | crit | H | ASI05 | MCP05 | AST06 | LLM05 | CWE-78 |
| AG-CODE-002 | Tool param → argv of spawned process (argument injection) | med | M | ASI05 | MCP05 | — | LLM05 | CWE-88 |
| AG-CODE-003 | Tool param → `eval` / `new Function` / `exec` / `vm` | crit | H | ASI05 | MCP05 | AST06 | LLM05 | CWE-95 |
| AG-CODE-004 | Unsafe deserialization of tool input (pickle, unsafe YAML, marshal, node-serialize) | high | H | ASI05 | MCP05 | — | LLM05 | CWE-502 |
| AG-CODE-005 | Tool param → filesystem path without containment (traversal) | high | M | ASI02 | MCP02 | — | LLM05 | CWE-22 |
| AG-CODE-006 | Tool param → outbound URL without allowlist (SSRF) | high | M | ASI02 | MCP05 | — | LLM05 | CWE-918 |
| AG-CODE-007 | Tool param → SQL string construction | high | M | ASI02 | MCP05 | — | LLM05 | CWE-89 |
| AG-CODE-008 | Tool param → template engine source (SSTI) | high | M | ASI05 | MCP05 | — | LLM05 | CWE-1336 |
| AG-CODE-020 | Reads credential paths | med | H | ASI03 | MCP01 | AST03 | LLM02 | — |
| AG-CODE-021 | Dumps environment | med | H | ASI03 | MCP01 | AST03 | LLM02 | — |
| AG-CODE-022 | Hardcoded outbound host (known exfil sink escalates to high) | low | H | ASI02 | MCP10 | — | LLM02 | — |
| AG-CODE-023 | Obfuscated execution (eval/exec of decoded, char-code or decompressed strings) | high | H | ASI05 | MCP04 | AST01 | — | CWE-506 |
| AG-CODE-024 | Install-time hook (`preinstall`/`postinstall`/`prepare`, custom `setup.py` commands) | med | H | ASI04 | MCP04 | AST02 | LLM03 | CWE-829 |
| AG-CODE-025 | Runtime fetch of remote code / runtime package install | high | H | ASI04 | MCP04 | AST02 | LLM03 | CWE-494 |
| AG-CODE-026 | Persistence writes (rc files, crontab, LaunchAgents, systemd user, Run keys, schtasks) | high | H | ASI06 | — | AST01 | — | — |
| AG-CODE-027 | Anti-analysis gating (CI/sandbox detection, delayed execution around sensitive sinks) | med | L | ASI10 | MCP04 | AST01 | — | — |
| AG-CODE-028 | Native binary shipped or downloaded at runtime | high | M | ASI04 | MCP04 | AST01 | LLM03 | CWE-494 |
| AG-CODE-029 | Token passthrough: inbound `Authorization` forwarded upstream | high | M | ASI03 | MCP07 | — | — | — |
| AG-CODE-040 | Undeclared capability: code shows egress/exec/write/credential read that tool text/annotations omit | med | M | ASI02 | MCP02 | AST04 | LLM06 | — |

### Remote auth conformance (`AG-AUTH-*`, opt-in network)
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-AUTH-001 | Server serves list/discover without authentication (reported, not judged) | info | H | — | MCP07 | — | — | — |
| AG-AUTH-002 | 401 without RFC 9728 Protected Resource Metadata, or PRM missing | med | H | ASI03 | MCP07 | — | — | — |
| AG-AUTH-003 | PRM `resource` inconsistent with server URL | high | H | ASI03 | MCP07 | — | — | — |
| AG-AUTH-004 | Authorization-server metadata missing or issuer inconsistent | med | H | ASI03 | MCP07 | — | — | — |
| AG-AUTH-005 | PKCE S256 not advertised | high | H | ASI03 | MCP07 | — | — | — |
| AG-AUTH-006 | RFC 9207 `iss` response parameter not advertised | low | H | ASI03 | MCP07 | — | — | — |
| AG-AUTH-007 | DCR only; no Client ID Metadata Document support (DCR deprecated 2026-07-28) | low | H | — | MCP07 | — | — | — |
| AG-AUTH-008 | No evidence of RFC 8707 resource indicators / audience binding | med | L | ASI03 | MCP07 | — | — | — |
| AG-AUTH-009 | TLS weaknesses (invalid chain, < TLS 1.2); plain HTTP is covered by CFG-013 | high | H | — | MCP07 | — | — | CWE-295 |
| AG-AUTH-010 | Advertised protocol version is old or unsupported (version always reported) | info | H | — | — | — | — | — |
| AG-AUTH-011 | Metadata endpoint redirects cross-origin or to insecure scheme | med | H | — | MCP07 | — | — | — |

### Toxic flows (`AG-FLOW-*`) — correlation stage
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-FLOW-001 | Lethal trifecta reachable across components in one session | high | M* | ASI01 | MCP10 | AST06 | LLM01 | — |
| AG-FLOW-002 | Lethal trifecta inside a single component | high | H* | ASI01 | MCP10 | AST03 | LLM01 | — |
| AG-FLOW-003 | Untrusted content → code-exec tool | high | M* | ASI05 | MCP06 | AST06 | LLM01 | — |
| AG-FLOW-004 | Untrusted content → destructive tool that is auto-approved | high | M* | ASI02 | MCP02 | AST03 | LLM06 | — |
| AG-FLOW-005 | Private data → egress to a known exfil sink or suspicious host | crit | H | ASI02 | MCP10 | AST01 | LLM02 | — |
| AG-FLOW-006 | Trifecta path with **no human approval on any hop** | crit | H* | ASI01 | MCP02 | AST03 | LLM06 | — |
| AG-FLOW-007 | Untrusted content → write to memory/instruction files (memory poisoning) | high | M* | ASI06 | MCP10 | AST05 | LLM01 | — |

\* Flow confidence = min(label confidences). FLOW-006 is CRITICAL only when every label has confidence H.
Otherwise the invariant caps it at high.

### Supply chain and drift (`AG-SC-*`)
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-SC-001 | Tool definition changed vs. lock at the same version (rug pull) | high | H | ASI04 | MCP03 | AST07 | LLM03 | — |
| AG-SC-002 | Skill content changed vs. lock | med | H | ASI04 | — | AST07 | LLM03 | — |
| AG-SC-003 | Tool added or removed vs. lock | med | H | ASI04 | MCP03 | AST07 | — | — |
| AG-SC-004 | Version changed without lock update | low | H | ASI04 | MCP04 | AST07 | — | — |
| AG-SC-005 | Drift introduces new capability labels (e.g., now has egress) | high | H | ASI04 | MCP03 | AST07 | LLM03 | — |
| AG-SC-006 | Component not present in lockfile | low | H | ASI04 | MCP09 | AST09 | — | — |
| AG-SC-010 | Content hash matches IOC feed entry | crit | H | ASI04 | MCP04 | AST01 | LLM03 | — |
| AG-SC-011 | Domain/IP matches IOC feed entry | high | H | ASI04 | MCP04 | AST01 | — | — |
| AG-SC-012 | Publisher handle matches IOC feed entry | high | M | ASI04 | MCP04 | AST02 | LLM03 | — |
| AG-SC-020 | No provenance attestation (opt-in) | low | H | ASI04 | MCP04 | AST02 | LLM03 | — |
| AG-SC-021 | Provenance/signature present but fails verification (opt-in) | high | H | ASI04 | MCP04 | AST02 | LLM03 | — |
| AG-SC-022 | Dependency with known vulnerability (OSV, opt-in; severity from advisory) | var | H | ASI04 | MCP04 | AST02 | LLM03 | per advisory |
| AG-SC-023 | Package or publisher younger than threshold (opt-in) | low | M | ASI04 | MCP04 | AST02 | LLM03 | — |
| AG-SC-024 | MCP Registry namespace does not match package/repo owner (opt-in) | med | M | ASI04 | MCP09 | AST02 | LLM03 | — |
| AG-SC-025 | Package name typosquats a popular MCP server | med | M | ASI04 | MCP04 | AST01 | LLM03 | — |

### Policy, system, judge
| ID | Title | Sev | Conf | ASI | MCP | AST | LLM | CWE |
|---|---|---|---|---|---|---|---|---|
| AG-POL-001 | Denied server/publisher present | policy (def. high) | H | — | MCP09 | AST09 | — | — |
| AG-POL-002 | Server/skill not on allowlist | policy (def. med) | H | — | MCP09 | AST09 | — | — |
| AG-POL-003 | Version not pinned (policy requires pinning) | policy (def. med) | H | ASI04 | MCP04 | AST07 | — | — |
| AG-POL-005 | Suppression expired — original finding resurfaced | info | H | — | — | AST09 | — | — |
| AG-POL-006 | Suppression missing `reason` or `expires` (ignored) | med | H | — | — | AST09 | — | — |
| AG-POL-010 | Security configuration changed in this change set (PR mode) | med | H | — | — | AST09 | — | — |
| AG-SYS-001 | Content skipped by safety limits (coverage reduced) | info | H | — | — | AST08 | — | CWE-409 |
| AG-SYS-002 | Analyzer error / unparseable file (coverage reduced) | info | H | — | — | AST08 | — | — |
| AG-SYS-003 | Symlink/hardlink/path escape blocked | med | H | — | — | AST06 | — | CWE-59 |
| AG-SYS-004 | Archive bomb detected | high | H | — | — | — | LLM10 | CWE-409 |
| AG-LLM-001 | Judge: description/behavior mismatch (max high, conf ≤ M) | ≤high | ≤M | ASI02 | MCP03 | AST04 | — | — |
| AG-LLM-002 | Judge: subtle instruction-layer manipulation (max high, conf ≤ M) | ≤high | ≤M | ASI01 | MCP03 | AST01 | LLM01 | — |

**Totals:** 159 rules, 14 of them CRITICAL. The CRITICAL rules are all conjunctions or high-specificity signatures (SE-002/003/005/007, EXEC-003, CRED-010,
CFG-006/008, META-003, CODE-001/003, FLOW-005/006, SC-010). That set is how the ≥95% CRITICAL precision target is met.
The cross-component trifecta (FLOW-001) defaults to **HIGH**, because almost every developer
setup has *some* trifecta (filesystem + fetch). Policy can raise it.

---

## (c) Data model (Pydantic v2; JSON Schemas generated into `schemas/`)

```python
# ---- sources & inputs ---------------------------------------------------
class SourceKind(StrEnum): local, npm, pypi, oci, github, gist, raw_url, mcp_registry, marketplace, remote_mcp
class SourceRef(BaseModel):                 # what the user gave us
    kind: SourceKind; locator: str; subpath: str | None
class ImmutableRef(BaseModel):              # what we actually scanned (M2 cache key part)
    kind: SourceKind; locator: str; resolved: str   # commit SHA | exact version | image digest
    integrity: str | None                           # sha512 tarball / sha256 archive
    source_url_template: str | None                 # "https://github.com/o/r/blob/{sha}/{path}#L{line}"

# ---- virtual filesystem (engine never touches real FS) ------------------
class FileBlob(BaseModel):
    path: PurePosixPath; size: int; sha256: str; data: bytes (excluded from JSON)
    kind: Literal["regular"]; skipped: SkipReason | None
class ArtifactTree(BaseModel):              # built by io.fs_loader / io.archive / from_mapping()
    root_ref: ImmutableRef | SourceRef; files: dict[str, FileBlob]; limit_events: list[LimitEvent]

# ---- inventory ----------------------------------------------------------
class ComponentKind(StrEnum): agent_host, skill, instruction_file, subagent, command, mcp_server, mcp_client_config, package
class Transport(StrEnum): stdio, streamable_http, sse_deprecated, unknown
class McpServerSpec(BaseModel):
    transport: Transport; command: str | None; args: list[str]; url: str | None
    env_names: list[str]; header_names: list[str]      # names only, never values
    pinned: bool; pin_detail: str | None; client: str; scope: Literal["user","project","enterprise","workspace"]
    config_path: str; config_span: Span
class Component(BaseModel):
    id: str                                  # stable: sha256(kind|source|name|config_path)[:16]
    kind: ComponentKind; name: str; version: str | None; publisher: str | None
    source: SourceRef; content_hash: str     # merkle over its artifacts
    server: McpServerSpec | None; artifact_ids: list[str]; tools: list[ToolDef]
    prompts: list[PromptDef]; resources: list[ResourceDef]; instructions: str | None
    capabilities: list[Capability]

# ---- artifacts & normalized text ----------------------------------------
class ArtifactRole(StrEnum): skill_md, instruction_md, script, reference, asset, client_config, server_json,
                             tool_manifest, source_code, package_manifest, lockfile, ui_resource, binary
class Artifact(BaseModel):
    id: str; component_id: str; path: str; role: ArtifactRole; language: str | None
    sha256: str; size: int
    text: NormalizedText | None             # NFKC+confusable-folded view with offset map to original
    decode_layers: list[DecodedLayer]       # (encoding, span, depth, child NormalizedText)
    frontmatter: dict | None                # safe-loaded, aliases rejected

class ToolDef(BaseModel):                   # normalized; hashing input for lock
    name: str; title: str | None; description: str | None
    input_schema: dict; output_schema: dict | None; annotations: dict[str, bool | str]
    origin: Literal["manifest","server_json","source_extraction","live_list"]; span: Span | None
    def normalized_hash(self) -> str: ...   # canonical JSON (RFC 8785 JCS) → sha256

# ---- capability graph ---------------------------------------------------
class CapLabel(StrEnum): reads_private_data, ingests_untrusted_content, external_egress, destructive, code_exec,
                         # sublabels used in explanations / escalation:
                         credential_access, persistence, auto_approved
class Capability(BaseModel):
    label: CapLabel; subject: str            # component id or "component_id#tool_name"
    declared: bool                           # stated by description/annotations
    observed: bool                           # evidenced by code/config
    confidence: Confidence; evidence: list[Evidence]

# ---- findings -----------------------------------------------------------
class Severity(StrEnum): critical, high, medium, low, info
class Confidence(StrEnum): high, medium, low
class Span(BaseModel): path: str; start_line: int; start_col: int; end_line: int; end_col: int
class Evidence(BaseModel):
    kind: Literal["regex","yara","ast","taint","schema","config","metadata","intel","lock_diff","llm","policy"]
    location: Span | None; snippet: RedactedText   # only constructible via redact()
    detail: str; hidden: bool = False; decode_path: list[str] = []   # e.g. ["html-comment","base64"]
    taint_path: list[Span] | None = None
class Mapping(BaseModel):
    framework: Literal["owasp-asi-2026","owasp-mcp-2025-beta","owasp-ast-1.0","owasp-llm-2025",
                       "nsa-csi-mcp-2026-05","cwe"]
    id: str | None; title: str | None; todo: str | None     # id=None ⇒ todo required
class Score(BaseModel):
    scorer: str; scorer_version: str         # "aivss", "0.8"
    value: float; vector: str; components: dict[str, float]  # cvss_base, aars, factor_sum, thm, mitigation
class FlowPath(BaseModel):
    nodes: list[str]; edges: list[tuple[str, str, str]]      # (from, to, via: "agent-session")
    labels: dict[str, list[CapLabel]]; narrative: str        # plain-English, templated (deterministic)
class Finding(BaseModel):
    fingerprint: str                         # sha256(rule_id|component.id|normalized primary span|matched-content-hash)
    rule_id: str; rule_version: int; title: str
    severity: Severity; confidence: Confidence; score: Score
    source: Literal["deterministic","llm","intel","policy"]
    component_ids: list[str]; primary: Span | None; related: list[Span]
    message: str; explanation: str; remediation: str
    evidence: list[Evidence]; mappings: list[Mapping]; references: list[HttpUrl]
    tags: list[str]; flow: FlowPath | None
    suppression: SuppressionState | None     # active | expired (then finding is emitted normally + tag)
    baseline_state: Literal["new","unchanged"] | None

# ---- config, policy, lock -----------------------------------------------
class Suppression(BaseModel):
    rule_id: str | None; fingerprint: str | None; path_glob: str | None   # ≥1 selector
    reason: constr(min_length=10); expires: date                           # both required
class Policy(BaseModel):
    version: Literal[1]; deny_servers: list[Pattern]; deny_publishers: list[str]
    allow_servers: list[Pattern] | None; require_pinning: bool; max_severity: Severity | None
    severity_overrides: dict[str, Severity]; engine: Literal["builtin"] = "builtin"   # "rego"/"cel" later
class LockEntry(BaseModel):
    key: str                                 # kind:name@source
    version: str | None; content_hash: str
    skill_files: dict[str, str] | None       # path → sha256
    tools: dict[str, ToolSnapshot] | None    # name → {hash, canonical def} (kept for readable diffs)
    capability_labels: list[CapLabel]
class Lockfile(BaseModel): lock_version: Literal[1]; entries: list[LockEntry]   # sorted by key

# ---- engine I/O ---------------------------------------------------------
class ScanOptions(BaseModel):
    fail_on: Severity = high; limits: LoadLimits; analyzers: set[str] | None
    network: NetworkOptions = NetworkOptions()          # all False by default
    judge: JudgeOptions | None = None; policy: Policy | None; suppressions: list[Suppression]
    baseline: set[str] | None; changed_paths: set[str] | None; lock: Lockfile | None
    intel: IntelFeed | None; include_timestamps: bool = False     # determinism
    deadline_s: float | None; on_progress: Callable[[ProgressEvent], None] | None (excluded)
class Report(BaseModel):
    schema_version: Literal["1.0"]; engine_version: str
    rule_pack: RulePackInfo                  # version, digest, rule_count
    target: SourceRef | ImmutableRef; network_features_used: list[NetworkUse]  # [] in default mode
    analyzers: list[AnalyzerRun]             # ran/skipped/errored + reason → honest coverage
    inventory: list[Component]; findings: list[Finding]   # sorted: severity, rule_id, path, line, fingerprint
    flows: list[FlowPath]; stats: ReportStats; summary: str  # "No findings from 159 rules (rule pack 0.1.0)"
    generated_at: datetime | None            # only when include_timestamps

# ---- rule definition (YAML, validated by schemas/rule.v1.json) ----------
class RuleDef(BaseModel):
    id: str; version: int; title: str; description: str; severity: Severity; confidence: Confidence
    applies_to: list[ArtifactRole | ComponentKind]
    match: RegexMatch | KeywordSetMatch | YaraMatch | JsonPathMatch | AnalyzerRef | CorrelationMatch
    escalate: list[EscalationRule] = []; mappings: list[Mapping]; cvss4_vector: str
    aivss_defaults: AivssDefaults; remediation: str; references: list[HttpUrl]
    fixtures: RuleFixtures                   # ≥1 positive, ≥1 negative (paths under fixtures/rules/<id>/)
```

**Plugin interfaces.**
- `Analyzer`: `id`, `requires: set[Literal["native","network"]]`, and
  `analyze(unit, ctx) -> Iterable[Finding | Capability]`. It is pure: no I/O, and the
  context is read-only.
- `Scorer`: `score(finding, ctx) -> Score`. The AIVSS v0.8 formula uses a CVSS v4 base from
  the rule's vector, Agentic Risk Amplification Factors derived from component context, and
  the threat and mitigation multipliers. It is swappable for v1.0.
- `PolicyEngine`: `evaluate(report, policy) -> list[Finding]`. Only `builtin` ships in v1;
  Rego and CEL adapters come later.
- `JudgeProvider`: `judge(request: JudgeRequest) -> JudgeResult` (schema-validated).

---

## (d) Repo layout

```
agentguard/
├── pyproject.toml  uv.lock  README.md  LICENSE  SECURITY.md  CHANGELOG.md  CONTRIBUTING.md
├── action.yml                        # GitHub Action (composite; pinned uv + agentguard by hash)
├── .pre-commit-hooks.yaml
├── .agentguard.yaml                  # dogfooding config
├── src/agentguard/
│   ├── __init__.py                   # public API: scan, ScanOptions, Report, ArtifactTree, render_*
│   ├── core/                         # PURE PYTHON — no native deps, no FS, no network (Pyodide CI job)
│   │   ├── models/                   # component, artifact, finding, capability, mapping, lock, report, options
│   │   ├── tree.py  limits.py  redact.py  inputs.py (M2 input parser; pure)
│   │   ├── normalize/                # unicode.py (NFKC+confusables w/ offset map), decode.py, markdown.py
│   │   ├── parsers/                  # frontmatter.py, safe_yaml.py, jsonc.py, toml.py, package_json.py, server_json.py
│   │   ├── rules/                    # loader.py (signed pack), schema.py, matchers.py, engine.py
│   │   ├── analyzers/                # skill/, instructions/, mcp_config/, mcp_meta/, code_lite/ (regex fallback),
│   │   │                             # supply_chain/, capability_labels.py
│   │   ├── correlate/                # dedupe.py, graph.py, flows.py, escalate.py, narrative.py
│   │   ├── scoring/                  # base.py, aivss_v0_8.py
│   │   ├── policy/                   # model.py, builtin.py, suppressions.py, baseline.py
│   │   ├── lock/                     # canonical.py (JCS), lockfile.py, diff.py
│   │   ├── report/                   # json.py, sarif.py, markdown.py, html.py (+templates/), cyclonedx.py, terminal_safe.py
│   │   └── engine.py                 # scan(tree, options) -> Report
│   ├── native/                       # OPTIONAL extras: agentguard[code], agentguard[yara]
│   │   ├── treesitter/               # parse.py, js_ts.py, python.py, bash.py, taint.py, tool_extract.py
│   │   └── yara/                     # compile.py (limits), scan.py
│   ├── io/                           # host-only
│   │   ├── guard.py                  # sys.addaudithook no-exec guard
│   │   ├── fs_loader.py  archive.py  git.py (hardened diff only)
│   │   └── discovery/                # platform.py (mac/linux/win paths), clients/{claude_desktop,claude_code,cursor,
│   │                                 #   vscode,windsurf,gemini_cli,codex,zed}.py, skills.py, instructions.py
│   ├── net/                          # opt-in only
│   │   ├── safe_http.py              # SSRF-hardened client (reused by M2)
│   │   ├── mcp_list.py               # server/discover | initialize → */list only
│   │   ├── auth_probe.py  osv.py  provenance.py  registry.py
│   ├── judge/                        # base.py, prompt.py (nonce blocks), schema.py, cache.py,
│   │                                 # anthropic.py, openai_compat.py, ollama.py
│   ├── intel/                        # feed.py, verify.py (signature + monotonic version)
│   ├── bench/                        # runner.py, metrics.py, splits.py
│   └── cli/                          # app.py (Typer): scan, discover, lock, verify, rules, bench, intel, report, export
├── rules/                            # RULE PACK (versioned separately; signed on release)
│   ├── pack.yaml                     # version, min_engine, digest
│   ├── skill/ instructions/ mcp-config/ mcp-meta/ code/ flow/ supply-chain/ auth/ policy/ sys/ *.yaml
│   ├── yara/*.yar
│   └── data/                         # credential-paths.yaml, exfil-hosts.yaml, vendor-installers.yaml,
│                                     # secret-patterns.yaml, popular-skills.txt, popular-mcp-packages.txt, confusables.txt
├── mappings/                         # owasp-asi-2026.yaml, owasp-mcp-2025-beta.yaml, owasp-ast-1.0.yaml,
│                                     # owasp-llm-2025.yaml, nsa-csi-mcp-2026-05.yaml, cwe.yaml, crosswalk.yaml
├── schemas/                          # report.v1.json, rule.v1.json, lock.v1.json, policy.v1.json, config.v1.json,
│                                     # judge-output.v1.json (generated; CI stale check)
├── intel/                            # sample-feed.json + sample-feed.sigstore.json
├── fixtures/
│   ├── rules/<RULE-ID>/{positive,negative}/…     # inert; example.invalid only
│   ├── loaders/                      # zip bomb, symlink escape, junction, ADS name, alias bomb, deep JSON, FIFO spec
│   └── clients/<client>/<os>/…       # sample configs per client/OS
├── bench/
│   ├── manifest.yaml                 # every corpus item: source, license, pinned hash, split, category, author/template id
│   ├── corpus/{benign,malicious,adversarial}/
│   ├── fetch.py                      # dev-only: fetches pinned benign items that can't be vendored
│   └── results/latest.json
├── tests/  unit/ integration/ safety/ determinism/ pyodide/ golden/
├── docs/   sources.md  threat-model.md  limitations.md  design/
├── site/                             # Astro static site (see e)
├── web/                              # Milestone 2 placeholder: README.md, threat-model.md (stub), api.openapi.yaml (draft)
├── scripts/                          # gen_site_data.py, check_stale.py, check_csp.mjs, lint_regex.py
└── .github/workflows/                # ci.yml, pyodide.yml, bench.yml, site.yml, release.yml (sigstore, SBOM, SLSA)
```

---

## (e) Website — Astro, not MkDocs Material

**Choice: Astro (static output), with no Starlight theme.** Reasons:
1. **Strict CSP with no inline scripts is achievable.** Astro emits zero JS by default, and
   islands compile to external module files. MkDocs Material injects inline configuration
   scripts, so it would need `'unsafe-inline'` or a post-build rewrite. A post-build check
   (`scripts/check_csp.mjs`) fails CI on any inline `<script>`, `on*=` attribute or
   `style=` attribute, and adds SRI hashes to every script and stylesheet.
2. **Readable with JS disabled** by construction, because every page is static HTML.
   Search (self-hosted Pagefind) is an enhancement only. The rule catalog index is a plain
   static table.
3. **Milestone 2 fit.** The `/scan` page needs a Pyodide web worker and a flow-graph
   visualization. Astro islands handle this without changing generators later.
4. **Data-driven pages.** Astro content collections with schemas consume the generated JSON
   (rules, mappings, bench, CLI reference) and fail the build on schema mismatch.
5. **Maintenance.** Material for MkDocs announced maintenance mode in favour of a successor
   project, which is a poor bet for a new site.

The cost is a Node toolchain *for the site only*. It is pinned with a lockfile and never
bundled into the CLI.

**GitHub Pages limitation.** Pages cannot set response headers. CSP ships as a `<meta>` tag
(`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests`).
`frame-ancestors` cannot be set via meta; the docs say so honestly. HTTPS is enforced in the
Pages settings. Fonts are self-hosted system stacks, with no CDN.

**Pages**
```
/                         landing: what it catches, 30-second install, sample-report link, "Scan a link" (flag AG_FEATURE_SCAN, off)
/docs/install  /docs/quickstart  /docs/cli (generated from Typer)  /docs/config  /docs/policy
/docs/suppressions  /docs/ci (Action, pre-commit, SARIF)  /docs/output (report schema)  /docs/library-api
/docs/how-it-works (pipeline, toxic flows)  /docs/limitations
/rules/                   static table (id, title, sev, conf, category); JS filter enhancement
/rules/<id>/              id, severity, confidence, detects, why it matters, unsafe/safe examples (from inert fixtures),
                          remediation, mappings, rule version
/coverage/                matrix: rows = ASI/MCP/AST/LLM/NSA ids, cols = rules; empty rows shown as gaps
/benchmarks/              precision/recall/F1/FPR per category & severity, corpus composition, held-out results, date+commit
/sample-report/           real HTML report from bench/corpus/malicious synthetic fixture
/security/                verifying releases (cosign/sigstore), SBOM, disclosure policy
/changelog/  /privacy/  /404
/.well-known/security.txt (RFC 9116, with Expires)
/scan/                    (M2; excluded from build until flag on)
```

**Generation.** `scripts/gen_site_data.py` produces the site data from four sources:
`agentguard rules export --format json`, the Typer app introspected into Markdown,
`mappings/*.yaml` for the coverage matrix, and `bench/results/latest.json`. It writes
`site/src/data/generated/`, and CI regenerates and runs `git diff --exit-code`.
Lighthouse CI (≥ 95) and pa11y/axe (WCAG 2.2 AA) run on each site build. The wordmark is
an original SVG kept at `site/src/brand/` behind a single component, so it is easy to swap.

---

## (f) Agent Guard Web — architecture sketch (design only)

```
                 ┌──────────────── static site (same Astro build) ────────────────┐
  paste / drop ─▶│ /scan  → Web Worker: Pyodide + agentguard-core wheel + rule pack│─▶ Report JSON → client renderer
                 │          (CSP connect-src 'self'; zero requests after load,      │    (flow graph, findings)
                 │           asserted by Playwright network-idle test)              │
  link ─────────▶│  POST /api/scans {input}                                         │
                 └──────────────┬───────────────────────────────────────────────────┘
                                ▼
   API (FastAPI) ── core.inputs.parse(input) → SourceRef | Rejection(list of supported inputs)
      │  rate limit (IP + session), bot check, queue cap
      ▼
   Resolver (egress: GitHub/npm/PyPI/MCP Registry/allowlisted marketplaces; holds GitHub App token)
      SourceRef → ImmutableRef (commit SHA | exact version + tarball hash | server.json → package)
      │ cache lookup: key = (ImmutableRef, rule_pack.digest, engine_version) ─── hit ─▶ return report
      ▼ miss
   Queue (Redis) ─▶ Fetcher (same egress allowlist; archive API/tarballs only, no git clone/install)
                       │ bytes → ephemeral object store (TTL, deleted after scan)
                       ▼
                    Scanner worker (gVisor/microVM, non-root, RO rootfs, NO network, no creds, CPU/mem/wall limits)
                       ArtifactTree.from_archive(bytes, LoadLimits.web()) → engine.scan(tree, opts) → Report
   Remote MCP URL ─▶ Probe worker (net.safe_http only; public IPs only; */list + discover + auth metadata)
                       → Component metadata → Scanner worker (as a pre-built tree)
      ▼
   Postgres (report JSON, redacted) + object store (HTML/SARIF/CycloneDX renders)
   progress: engine on_progress → worker → Redis pub/sub → SSE /api/scans/{id}/events
   permalink: /r/{kind}/{locator}@{resolved}/{rulepack}   (unlisted; no index, no leaderboard)
```

**Interfaces v1 must expose. These are stable, versioned, and used by the CLI too.**
1. `agentguard.scan(tree: ArtifactTree, options: ScanOptions) -> Report`. It is pure: no
   FS, no network, no clock unless `include_timestamps`. It supports a deadline and
   cancellation through `options.deadline_s`, and emits progress through
   `options.on_progress(ProgressEvent(stage, done, total))`.
2. `ArtifactTree.from_directory(path, limits)`, `.from_archive(bytes, fmt, limits)`
   (zip/tar/tgz, with ratio cap, link dropping and escape rejection), and
   `.from_mapping({path: bytes}, limits)` for pasted text in the browser.
   `LoadLimits` has named presets: `cli()`, `ci()`, `web()`.
3. `core.inputs.parse(str) -> SourceRef | Rejection` for every M2 input form (GitHub
   tree/blob/gist/raw, `npm:name@ver`, `pypi:name==ver`, registry name, marketplace URL
   via adapter registry, remote MCP URL). Resolution itself is **not** in the core: it is
   the `Resolver` protocol `resolve(SourceRef) -> ImmutableRef`, with only a local
   implementation in v1.
4. `ImmutableRef.source_url_template`, so every `Span` can link to file:line at the commit.
5. `net.safe_http.SafeHttpClient`, built and tested in v1 because the opt-in live metadata
   and auth checks need it. It has an SSRF test suite (private ranges, IPv6-mapped
   addresses, DNS rebinding via pinned IP, redirect revalidation, size and time caps).
6. `net.mcp_list.fetch_metadata(url, client) -> Component` (read-only, version-aware
   handshake). It refuses `tools/call` by construction.
7. Renderers are pure functions of `Report`: `render_json`, `render_sarif`,
   `render_markdown`, `render_html`, `render_cyclonedx` → `bytes`, identical across CLI and web.
8. `schemas/report.v1.json` is the only engine↔UI contract. It uses semver with additive
   minor changes, and the golden tests pin it.
9. `report_cache_key(ImmutableRef, RulePackInfo, engine_version) -> str`, plus a
   determinism test (same input → byte-identical JSON).
10. `diff_reports(old, new) -> DriftDiff`, which shares `lock.diff` for the "drift since
    previous scan" view.
11. `RulePack.load(bundle_bytes, verify=True)`, so web workers can pin a signed pack by digest.
12. `redact()` / `RedactedText`. The web service stores only redacted findings JSON.
13. A **pure-Python `agentguard-core` wheel** that runs under Pyodide. Code taint and YARA
    are absent there and reported in `Report.analyzers` as skipped. The `code_lite`
    regex analyzer gives partial coverage in the browser.

**Separate service threat model (to be written in `web/threat-model.md` in M2).** It will cover:
- hostile archives against the extractor;
- worker escape and the no-egress requirement;
- fetcher credential theft;
- SSRF through the probe;
- cache poisoning (the key includes the immutable ref, and only the resolver sets it);
- stored XSS via findings in the report UI;
- abuse and cost (rate limits, queue caps);
- defamation risk (factual wording, no "malicious" or "safe" labels, maintainer response);
- data retention.

---

## Open questions (need your call before build)

1. **Site generator: Astro** (adds a pinned Node toolchain for `site/` only). OK?
2. **Cross-component lethal trifecta defaults to HIGH**, with CRITICAL only for FLOW-005 and
   FLOW-006. This protects the CRITICAL precision target. OK?
3. **NSA CSI:** I could not fetch the PDF (403). Can you drop a copy into `docs/refs/`?
   Until then, the NSA mappings stay `null` + TODO.
4. **Benign corpus licensing:** vendor only permissively licensed items (with NOTICE), and
   fetch the rest by pinned hash in a dev-only step with a CI cache. Or vendor nothing?
5. **License and name:** Apache-2.0? Is the `agentguard` package name on PyPI/npm cleared,
   or should I use a placeholder (`agent-guard-scanner`) until it is?

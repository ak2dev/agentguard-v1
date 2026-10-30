# Agent Guard

**Is it safe to give this skill or MCP server to my agent — and if not, exactly why, and how do I fix it?**

Agent Guard is an open-source, offline-first security scanner for AI agent skills (`SKILL.md` bundles), agent instruction files (`AGENTS.md`, `CLAUDE.md`, Cursor rules, …) and Model Context Protocol (MCP) servers and client configs. Run it before anything is installed, enabled or merged.

- **Never executes what it scans.** No `npx`, `uvx`, `pip install`, `docker run`, no STDIO servers, no bundled scripts. A process-wide audit hook blocks process creation; the only exception is a hardened, read-only `git` call in PR mode.
- **Offline, no account, no telemetry.** Network features are opt-in flags and every report lists the ones used.
- **Honest results.** A clean scan says "No findings from N rules (rule pack vX)", never "safe". Anything not scanned is reported.
- **Deterministic.** Same input + same rule pack → byte-identical report.

## Install

```bash
uvx agentguard scan            # this machine's agent configuration + the current project
pipx install agentguard        # or install it
```

Python 3.12+. Optional extras: `agentguard[code]` (tree-sitter taint for JS/TS tool handlers and shell scripts), `agentguard[yara]` (YARA rules over bundled binaries; wheels up to Python 3.13), `agentguard[judge]` (Anthropic provider for the LLM judge). Without an extra, its analyzer is reported as skipped and its rules are not counted.

## Use

```bash
agentguard scan ./skills/my-skill          # a skill folder, a repo, or an MCP config file
agentguard scan . -v                       # evidence, remediation and standards per finding
agentguard scan . -f sarif -o ag.sarif     # also: json, markdown, html
agentguard report -i ag.json -f html       # re-render a saved JSON report (no rescan)
agentguard discover -f cyclonedx           # inventory as a CycloneDX 1.6 BOM
agentguard lock && agentguard verify       # pin skills/tool definitions, then detect rug pulls with a diff
agentguard rules explain AG-SKL-SE-002     # what a rule detects, why, and how to fix it
```

Exit codes: `0` no findings at or above `--fail-on` (default `high`), `1` findings at or above it, `2` scanner error (including any analyzer failure — never a silent pass).

The HTML report is one self-contained file you can attach or archive. It has no scripts, loads nothing from anywhere else (the fonts are embedded and a strict Content-Security-Policy is set) and works offline. It looks like the website's report: a verdict and severity counts, a finding index, and for each finding the evidence, why it matters, the fix and the standards it maps to. It prints in a light theme. The website's sample report is one, generated from an inert malicious skill in the benchmark corpus.

## What it catches

| Area | Examples |
|---|---|
| Malicious skills | "Prerequisites" download-and-run lures (also in plain words, without command syntax), pipe-to-shell, downloads executed from another script, Windows binaries that run remote code (`mshta`, `regsvr32`), reverse shells, password-protected archives, scripts hidden inside Office documents, Python bytecode that does not match its source, package-manager registry redirection, ClickFix, encoded commands, Gatekeeper/Defender bypass, credential theft + exfiltration, typosquatting |
| Hidden instructions | Unicode tag characters, bidi and zero-width tricks, homoglyphs, HTML comments, off-screen and CSS-hidden text, encoded blobs (decoded and rescanned) |
| Instruction layer | Override directives (including paraphrased ones), forged role delimiters, concealment, approval bypass, self-modification, persistence into memory/instruction files, Claude Code `!` injections and skill hooks |
| MCP configuration | Shell-string commands, inline code, encoded commands, reverse shells, unpinned `npx -y`/`uvx`, Docker socket and home mounts, literal secrets, plain-HTTP and metadata targets, auto-approval, shadowed server names |
| MCP metadata | Tool poisoning, side-channel parameters, tool shadowing, name collisions, unsafe schemas, annotation lies, MCP Apps UI risks |
| Code | Taint from tool parameters to shell, eval, deserialization, paths, URLs, SQL and templates; obfuscation, install hooks, runtime code fetch, token passthrough |
| Toxic flows | The lethal trifecta (untrusted content + private data + egress) across all components in one agent session, shown as a concrete path |
| Supply chain | Lockfile drift and rug pulls, signed IOC feed, registry namespace and package typosquats; opt-in provenance, OSV and package-age checks, and `--check-hijackable` (SkillJacking: referenced GitHub owners that no longer exist, unregistered npm/PyPI names, unregistered or expired download domains, freed cloud-app hostnames) |
| Remote auth | Opt-in RFC 9728/8414/9207/8707 and PKCE conformance for remote MCP servers (unauthenticated probes only) |

173 rules in rule pack 0.1.0, each with an unsafe and a safe fixture, mapped to the OWASP Top 10 for Agentic Applications (ASI), OWASP MCP Top 10, OWASP Agentic Skills Top 10 (AST), OWASP LLM Top 10, the NSA MCP security guidance (May 2026) and CWE, with an AIVSS score. The website shows the full catalog and a coverage matrix that lists gaps.

## In the browser

The website's `/scan` page runs the same engine in your browser (Pyodide). You can paste a `SKILL.md` or MCP config, or drop a folder or `.zip`; pasted and dropped input never leaves your device (a CI test asserts zero network requests).

Links go to the Agent Guard Web server (`web/`). That covers a public GitHub repository, folder, file or gist, an npm or PyPI package, an MCP Registry name, or a remote MCP server. Each is pinned to an exact commit or version, fetched through an allowlist (or probed read-only, for a remote server) and scanned in a throwaway container with no network. If the server is unavailable, GitHub links are scanned in your browser instead, with the files fetched straight from GitHub.

Server reports have unlisted permalinks, rescans with current rules, factual README badges and maintainer responses. Every report downloads as JSON, SARIF, HTML, Markdown or CycloneDX. See `site/src/pages/docs/web-scanner.md` and `web/README.md`.

## CI

```yaml
- uses: actions/checkout@<sha>
  with: { fetch-depth: 0, persist-credentials: false }
- uses: ak2dev/agentguard-v1@<release-sha>
  with: { path: ., fail-on: high }
```

Pull requests run in PR mode (only components touched by the change; configuration read from the base commit) and upload SARIF to GitHub code scanning. A pre-commit hook is included (`.pre-commit-hooks.yaml`).

The action is offline by default. `check-hijackable: true` adds the `--check-hijackable` network check (SkillJacking); the workflow token is then passed to the scan and sent to `api.github.com`, and nowhere else, so GitHub owner lookups are not limited to 50 per scan. On the CLI, set `AGENTGUARD_GITHUB_TOKEN` (or `GITHUB_TOKEN`) for the same effect; the log names the variable it used, never the token.

## Benchmark

`agentguard bench` reports precision, recall, F1 and false-positive rate per category and severity on `bench/`. The corpus has 123 synthetic items (76 attacks, 47 benign, many of them look-alikes of the attacks) and 163 real benign skills and MCP servers from eight vendor-maintained repositories at pinned commits. Latest committed results (`bench/results/latest.json`): precision 1.0 at CRITICAL and 0.95 at HIGH, recall 0.97 at HIGH, benign false-positive rate 0.019 at HIGH (target: at most 0.02), 100 skills + 20 server configs scanned in about 2 seconds (target: under 10). Each attack records the severity it warrants: 73 of 76 reach it, and 52 of the 54 that warrant CRITICAL are reported at CRITICAL (raw recall at CRITICAL is 0.68 because it also counts the attacks that warrant HIGH). CI fails if the committed results are stale or a pull request makes any item worse. [docs/benchmark.md](docs/benchmark.md) records every tuning round, its held-out result before tuning, the attacks still below their expected severity, and the benign items still flagged.

## Limitations

- **Static only.** Behavior that appears only at run time (code downloaded later, a server changing its tools after connection) is out of reach; `lock`/`verify` catches changes between scans. Sandboxed dynamic analysis is planned, not built.
- **Pattern rules can be evaded.** Paraphrased lures and overrides are matched by verb and noun lists, so wording outside them gets through. Payloads split across the files of a skill are linked through a file one writes and another reads, one script running another, or an import (up to three links); the link is between files, not values, so a script that reads a relay file and separately makes an unrelated request is still reported. A credential path built with `path.join` is still missed (see the benchmark). The optional LLM judge (`--llm-judge`) helps with paraphrase but is never the sole basis for a CRITICAL finding.
- **The benchmark's malicious set is synthetic** and written by the same person as the rules (the round-4 held-out items before the round-4 rules existed, but knowing their targets), and more than half of the real benign items were used to tune rules. Before each tuning round the next vendor repositories were scanned once: 16 of 43, then 7 of 28, then 1 of 79 benign items flagged at HIGH. Expect false positives on real skills that look unlike those repositories, and treat MEDIUM (FPR 0.14 on real code) as review material.
- **Taint analysis follows helpers only within the server.** Python uses the standard `ast` module and follows a tool parameter into helper functions of the same file, relative, sibling or package imports, and `self.` methods. JavaScript/TypeScript is pattern-based and follows same-file functions and relative named, namespace and `require` imports; default exports, re-exports, class methods and functions passed as values are not followed. Both stop three helpers deep and never follow installed packages. With `agentguard[code]`, the tree-sitter analyzer also follows destructuring, reassignment, handlers passed by name and `promisify`/import aliases, within one function only, and adds shell-script taint (`$1` → `eval`, `sh -c`). It only adds findings; it does not remove pattern-analyzer false positives.
- **YARA rules need `agentguard[yara]`,** which has no Python 3.14 wheels yet. The browser scanner runs neither native analyzer.
- **Flow labels are inferred** (medium or low confidence) when only a config names a server and its code or tools are unavailable.
- **`--check-hijackable` (network, opt-in):** GitHub cannot tell a deleted or renamed account (name claimable) from a suspended one (not claimable); npm and PyPI may still reserve a missing name; registrable domains use a small second-level list instead of the Public Suffix List, and only domains that fail to resolve are checked with RDAP; at most 50 GitHub lookups per scan without a token (unauthenticated API limit), 500 with one; freed cloud-app slots are checked only on platforms where a free app name stops resolving (Azure App Service, Traffic Manager, Blob Storage and cloudapp.azure.com, Cloudflare Pages and Workers, Fly.io, Elastic Beanstalk), not on wildcard-DNS platforms (Heroku, Vercel, Netlify, GitHub Pages), and a name the platform still reserves is reported anyway. Only references in install, download, clone or config context count, plus GitHub links (reported at medium).
- **Provenance:** missing attestations and subject-digest mismatches are detected; full Sigstore chain verification is not.
- **AIVSS scores are approximate:** severity-default CVSS bases and a capability proxy for the amplification factors; each score records this.
- **NSA MCP guidance mappings use section names:** the CSI does not number its sections, so rules map to its own headings; it covers MCP only, so skill rules have none.
- **Four client config paths are unverified** because the vendor does not document them (Claude Desktop on Linux, Claude Code's plugin folder, legacy Windsurf and `~/.codex/skills`); `agentguard discover` labels them and says why.

## Project layout

`src/agentguard/core` is the pure engine (runs under Pyodide) and `webscan.py` its browser entry points; `io`, `net`, `judge` and `cli` are host-side. Rules are data in `rules/`, standards crosswalk in `mappings/`, fixtures in `fixtures/rules/`, benchmark in `bench/`, website and browser scanner in `site/` (deployed to Vercel with `vercel.json`), and the Agent Guard Web server in `web/` (connecting the site takes an `/api/*` rewrite, described in `web/README.md`). Design and threat model: `docs/`.

## License

Apache-2.0. Security issues: see [SECURITY.md](SECURITY.md).

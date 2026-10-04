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
agentguard discover -f cyclonedx           # inventory as a CycloneDX 1.6 BOM
agentguard lock && agentguard verify       # pin skills/tool definitions, then detect rug pulls with a diff
agentguard rules explain AG-SKL-SE-002     # what a rule detects, why, and how to fix it
```

Exit codes: `0` no findings at or above `--fail-on` (default `high`), `1` findings at or above it, `2` scanner error (including any analyzer failure — never a silent pass).

## What it catches

| Area | Examples |
|---|---|
| Malicious skills | "Prerequisites" download-and-run lures, pipe-to-shell, password-protected archives, ClickFix, encoded commands, Gatekeeper/Defender bypass, credential theft + exfiltration, typosquatting |
| Hidden instructions | Unicode tag characters, bidi and zero-width tricks, homoglyphs, HTML comments, off-screen and CSS-hidden text, encoded blobs (decoded and rescanned) |
| Instruction layer | Override directives, forged role delimiters, concealment, approval bypass, self-modification, persistence into memory/instruction files, Claude Code `!` injections and skill hooks |
| MCP configuration | Shell-string commands, inline code, unpinned `npx -y`/`uvx`, Docker socket and home mounts, literal secrets, plain-HTTP and metadata targets, auto-approval, shadowed server names |
| MCP metadata | Tool poisoning, side-channel parameters, tool shadowing, name collisions, unsafe schemas, annotation lies, MCP Apps UI risks |
| Code | Taint from tool parameters to shell, eval, deserialization, paths, URLs, SQL and templates; obfuscation, install hooks, runtime code fetch, token passthrough |
| Toxic flows | The lethal trifecta (untrusted content + private data + egress) across all components in one agent session, shown as a concrete path |
| Supply chain | Lockfile drift and rug pulls, signed IOC feed, registry namespace and package typosquats; opt-in provenance, OSV and package-age checks |
| Remote auth | Opt-in RFC 9728/8414/9207/8707 and PKCE conformance for remote MCP servers (unauthenticated probes only) |

161 rules in rule pack 0.1.0, each with an unsafe and a safe fixture, mapped to the OWASP Top 10 for Agentic Applications (ASI), OWASP MCP Top 10, OWASP Agentic Skills Top 10 (AST), OWASP LLM Top 10 and CWE, with an AIVSS score. The website shows the full catalog and a coverage matrix that lists gaps.

## In the browser

The website's `/scan` page runs the same engine in your browser (Pyodide): paste a `SKILL.md` or MCP config, drop a folder or `.zip`, or give a public GitHub repository, folder, file or gist link. Pasted and dropped input never leaves your device (a CI test asserts zero network requests); for GitHub links your browser fetches the files straight from GitHub, pinned to a commit. npm, PyPI, MCP Registry and remote MCP server links go to the Agent Guard Web server (`web/`): pinned to an exact version, fetched through an allowlist (or probed read-only, for a remote server) and scanned in a throwaway container with no network. Reports have unlisted permalinks, rescans with current rules, factual README badges and maintainer responses. See `site/src/pages/docs/web-scanner.md` and `web/README.md`.

## CI

```yaml
- uses: actions/checkout@<sha>
  with: { fetch-depth: 0, persist-credentials: false }
- uses: agentguard/agentguard@<release-sha>
  with: { path: ., fail-on: high }
```

Pull requests run in PR mode (only components touched by the change; configuration read from the base commit) and upload SARIF to GitHub code scanning. A pre-commit hook is included (`.pre-commit-hooks.yaml`).

## Benchmark

`agentguard bench` reports precision, recall, F1 and false-positive rate per category and severity on `bench/`. The corpus has 61 synthetic items and 163 real benign skills and MCP servers from eight vendor-maintained repositories at pinned commits. Latest committed results (`bench/results/latest.json`): precision 1.0 at CRITICAL and 0.91 at HIGH, recall 0.89 at HIGH, benign false-positive rate 0.016 at HIGH (1 of 79 real held-out items flagged), 100 skills + 20 server configs scanned in about 1 second (target: under 10). Rules were tuned against the `dev` real sources; [docs/benchmark.md](docs/benchmark.md) records every tuning round, its held-out result before tuning, and the benign items still flagged.

## Limitations

- **Static only.** Behavior that appears only at run time (code downloaded later, a server changing its tools after connection) is out of reach; `lock`/`verify` catches changes between scans. Sandboxed dynamic analysis is planned, not built.
- **Pattern rules can be evaded.** Paraphrased lures and payloads split across files are known misses and are reported as such by the benchmark. The optional LLM judge (`--llm-judge`) helps with paraphrase but is never the sole basis for a CRITICAL finding.
- **The benchmark's malicious set is synthetic**, and more than half of the real benign items were used to tune rules. Before each tuning round the next vendor repositories were scanned once: 16 of 43, then 7 of 28, then 1 of 79 benign items flagged at HIGH. Expect false positives on real skills that look unlike those repositories, and treat MEDIUM (FPR 0.14 on real code) as review material.
- **Taint analysis is intra-procedural.** Python uses the standard `ast` module. JavaScript/TypeScript is pattern-based within a tool handler unless `agentguard[code]` is installed; its tree-sitter analyzer follows destructuring, reassignment, handlers passed by name and `promisify`/import aliases, still within one function, and adds shell-script taint (`$1` → `eval`, `sh -c`). It only adds findings; it does not remove pattern-analyzer false positives.
- **YARA rules need `agentguard[yara]`,** which has no Python 3.14 wheels yet. The browser scanner runs neither native analyzer.
- **Flow labels are inferred** (medium or low confidence) when only a config names a server and its code or tools are unavailable.
- **Provenance:** missing attestations and subject-digest mismatches are detected; full Sigstore chain verification is not.
- **AIVSS scores are approximate:** severity-default CVSS bases and a capability proxy for the amplification factors; each score records this.
- **Standards mappings to the NSA MCP guidance are pending** (the document could not be retrieved automatically).
- **Some client config paths are unverified;** `agentguard discover` labels them.

## Project layout

`src/agentguard/core` is the pure engine (runs under Pyodide) and `webscan.py` its browser entry points; `io`, `net`, `judge` and `cli` are host-side. Rules are data in `rules/`, standards crosswalk in `mappings/`, fixtures in `fixtures/rules/`, benchmark in `bench/`, website and browser scanner in `site/` (deployed with `vercel.json`), Milestone 2 server design in `web/`. Design and threat model: `docs/`.

## License

Apache-2.0. Security issues: see [SECURITY.md](SECURITY.md).

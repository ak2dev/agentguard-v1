# Threat model — Agent Guard CLI and engine (v1)

Scope: the CLI and library that read untrusted skills, instruction files, MCP configs, server source and package metadata on a developer machine or CI runner, and write reports to the terminal, files, GitHub code scanning (SARIF) and PR comments. The hosted service (Milestone 2) has its own threat model in `web/threat-model.md`.

## Assets

- **A1** Integrity of the host and CI runner, including its secrets (`GITHUB_TOKEN`, cloud credentials).
- **A2** Correctness of results: no silent evasion, no fail-open.
- **A3** Secrets present *in* scanned targets.
- **A4** User privacy: what the user has installed.
- **A5** Agent Guard's supply chain: releases, rule pack, IOC feed.
- **A6** CI availability.

## Adversaries

- **T1** Author of a malicious skill or server, who controls every scanned byte.
- **T2** Malicious PR contributor, who controls the repo including `.agentguard.yaml`, the lockfile and the baseline.
- **T3** Hostile remote MCP server or network attacker (opt-in network features only).
- **T4** Attacker on Agent Guard's dependencies, rule pack or intel feed.
- **T5** Third party reading public SARIF alerts or PR comments.

## Threats and mitigations (as implemented)

| # | Threat | Mitigation | Where |
|---|---|---|---|
| TM-01 | Scanner executes target code | Parse-only design; audit hook raises on every process-creation event; the only exception is an exact-argv, hardened `git` for PR mode (`core.fsmonitor=false`, hooks path set to null device, no external diff/textconv, `GIT_CONFIG_NOSYSTEM=1`) | `io/guard.py`, `io/git.py`, `tests/safety/test_no_exec.py` |
| TM-02 | Parser and resource attacks | `LoadLimits` (file size, total bytes, file count, depth, decompression ratio, decode depth); YAML aliases/anchors/custom tags rejected; regex per-call timeouts; only regular files read; optional native parsers (tree-sitter, YARA) only see input under the same limits, tree-sitter is skipped above 1 MB per file, YARA matches time out per file (AG-SYS-001) and its rules come from the rule pack, compiled with includes disabled | `core/models/config.py`, `core/parsers/safe_yaml.py`, `core/archive.py`, `io/fs_loader.py` |
| TM-03 | Path escape | Scan-root confinement; symlinks, junctions and reparse points never followed and reported (`AG-SYS-003`); archive members with `..`, absolute, drive-letter, UNC or ADS names rejected | `core/tree.py`, `core/archive.py`, `io/fs_loader.py` |
| TM-04 | Prompt injection against the LLM judge | Material only inside nonce-id data blocks with delimiter text neutralized; no tools; JSON-schema output validated with Pydantic, invalid output discarded; judge findings capped at HIGH and at medium confidence; never alters deterministic findings; cached by content hash | `judge/`, `core/analyzers/judge_rules.py`, `tests/unit/test_judge.py` |
| TM-05 | Evasion (Unicode, encodings, splitting, paraphrase) | NFKC + confusable folding with offset maps; invisible characters stripped; blobs decoded to depth 3 and rescanned; component-level correlation; adversarial benchmark split; misses reported | `core/normalize/`, `bench/` |
| TM-06 | Fail-open on crash | Analyzers isolated; an exception yields `AG-SYS-002` and exit code 2 unless `--allow-partial` (recorded in the report) | `core/engine.py` |
| TM-07 | PR edits its own security config | PR mode reads config and suppressions from the base ref; `AG-POL-010` when `.agentguard.yaml`, the lock or the baseline change; suppressions need a reason and an expiry | `cli/app.py`, `core/policy/` |
| TM-08 | PR-mode blind spot | Whole components touched by a change are reported, not just changed files | `core/engine.py` (`_pr_filter`) |
| TM-09 | Secret leakage via reports | `RedactedText` is the only snippet type and always redacts (first 4 characters + short hash); tested across all output formats | `core/redact.py`, `tests/unit/test_reporting_cli.py` |
| TM-10 | Output injection | Control characters rendered visibly; Rich markup escaped; Markdown escaped with @mentions and #refs neutralized; HTML escaped with hash-based CSP and no scripts | `core/textutil.py`, `cli/terminal.py`, `core/report/` |
| TM-11 | SSRF and hostile remote servers | DNS resolved first; only globally routable addresses; IP pinned for the connection; redirects re-validated; HTTPS only; size and time caps; read-only MCP methods allowlist (`tools/call` impossible); no credentials sent | `net/safe_http.py`, `net/remote.py`, `tests/unit/test_network.py` |
| TM-12 | Privacy leakage via network features | All network features opt-in; features and contacted hosts listed in every report; no telemetry | `core/models/config.py`, `core/engine.py` |
| TM-13 | Agent Guard supply chain | Pinned dependencies; SHA-pinned GitHub Actions; Sigstore-signed releases with SBOM; Ed25519-signed IOC feed with rollback protection | `.github/workflows/`, `core/intel/`, `io/intel_store.py` |
| TM-14 | False assurance | Clean scans never say "safe"; analyzers not run are listed; Limitations documented | `core/engine.py`, `README.md` |
| TM-15 | TOCTOU between scan and install (rug pull) | `agentguard lock` / `verify` over skill-file hashes and normalized tool definitions | `core/lock.py`, `core/analyzers/supply_chain.py` |

## Out of scope for v1

A compromised host or Python interpreter; runtime behavior of servers (planned sandboxed dynamic mode); attacks on the agent runtime itself.

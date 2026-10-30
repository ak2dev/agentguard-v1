---
layout: ../../layouts/Doc.astro
title: Limitations
description: What Agent Guard does not do yet, stated plainly, and what comes next.
---

# Limitations

- **Static only.** Agent Guard never runs what it scans. Behavior that only appears at run time is out of reach until the planned sandboxed dynamic mode — for example, code downloaded later, or a server that changes its tools after connection. `lock` / `verify` catches changes between scans.
- **Pattern rules can be evaded.** Paraphrased lures ("hand the script to your shell") are a known weak spot. Payloads split across the files of a skill are linked through a file one writes and another reads, one script running another, or an import (up to three links); the link is between files, not values, so a script that reads a relay file and separately makes an unrelated request is still reported. The benchmark reports misses rather than hiding them.
- **Taint follows helpers only within the server.** Python uses the standard `ast` module and follows a tool parameter into helper functions of the same file, relative, sibling or package imports, and `self.` methods. JavaScript/TypeScript taint is pattern-based and follows same-file functions and relative named, namespace and `require` imports; default exports, re-exports, class methods and functions passed as values are not followed. Both stop three helpers deep and never follow installed packages. The `agentguard[code]` extra's tree-sitter analyzer follows destructuring, reassignment, handlers passed by name and `promisify`/import aliases, and adds shell-script taint, but it does not follow calls into other functions or files. It only adds findings; it does not remove pattern-analyzer false positives.
- **YARA rules need the `agentguard[yara]` extra** (wheels for Python 3.12–3.13 only). The browser scanner runs neither native analyzer; reports list them as skipped.
- **Toxic flows use inferred labels** when a server's code or tools are not available (for example, a config that only names a package). Those labels have medium or low confidence and are marked as inferred.
- **Provenance** checks detect a missing attestation and a subject-digest mismatch. Full Sigstore certificate-chain verification is not performed yet.
- **Auth checks are unauthenticated.** Agent Guard never logs in to, or sends tokens to, remote servers.
- **NSA MCP guidance mappings use section names.** The NSA CSI (May 2026) does not number its sections, so rules map to its own headings (a concern, a real-world example, or a recommendation). It covers MCP only, so skill rules have no NSA mapping.
- **AIVSS scores are approximate.** CVSS base scores default to per-severity values unless a rule carries a calculator-computed score, and capability labels stand in for the ten amplification factors. Every score records this.
- **Benchmark caveats.** Malicious and adversarial items are synthetic, written by the same person as the rules; the round-4 held-out items were scanned before the round-4 rules existed, but their author knew what the rules would target. The 163 real benign skills and servers come from eight vendor repositories, and rules were tuned against all of them except microsoft/skills. Before each tuning round, the next repositories were scanned once: 16 of 43, then 7 of 28, then 1 of 79 benign items were flagged at HIGH. Real skills unlike those repositories will produce more false positives. MEDIUM is noisy on real code (about 15% of benign items).
- **Some findings are downgraded rather than removed.** A quoted prompt pattern in a reference document, a chat-template token in a code span, a CLI reference that documents an approval flag, or quarantine removal on a Homebrew-installed binary is reported at MEDIUM instead of HIGH or CRITICAL. A payload written to look like such a mention is still reported, but at MEDIUM.
- **A few client config paths are unverified** because the vendor does not document them: Claude Desktop on Linux (no official build), Claude Code's plugin folder, and the legacy Windsurf and `~/.codex/skills` folders. `agentguard discover` labels them and says why; everything else was checked against vendor documentation (see `docs/sources.md`).

## Next mile

What comes after the first version, roughly in order. Each item closes a limitation above or a gap that real use will expose.

1. **Host the scan server.** The site runs on Vercel; the Agent Guard Web server still needs a public host that can run Docker containers with `--network none` (ideally gVisor). Until then it runs locally with `docker compose up`, and the public site scans GitHub links in the browser instead.
2. **First release.** Publish 0.1.0 to PyPI and tag the GitHub Action, with Sigstore-signed artifacts and a CycloneDX SBOM (the release workflow is in place).
3. **Sandboxed dynamic analysis.** Run servers and skill scripts in an isolated, credential-free sandbox and record what they actually do: processes, files touched, connections attempted. This reaches behavior a static scan cannot see, such as code downloaded at run time.
4. **Runtime enforcement.** A gateway between the agent and its MCP servers that checks tool definitions against `agentguard.lock` on every connection, so a rug pull is blocked rather than found at the next scan.
5. **Independent malicious samples.** Measure against real malicious skills and attacks written by other people, not only the author's synthetic set, and bring MEDIUM noise on real code down.
6. **Close known detection gaps.** Credential paths built with `path.join`, byte transforms without a recognizable decoder, JS/TS taint through default exports, re-exports and class methods, and tree-sitter taint across functions and files.
7. **Supply-chain depth.** Full Sigstore certificate-chain verification for provenance, and CycloneDX 1.7 output.
8. **Standards updates.** AIVSS v1.0 scoring when it is published, and rules for the NSA MCP guidance items that have none yet (audit logs, denial of service, logging and detection).
9. **Policy as code.** Rego and CEL adapters next to the built-in policy engine.

---
layout: ../../layouts/Doc.astro
title: Limitations
description: What Agent Guard does not do, stated plainly.
---

# Limitations

- **Static only.** Agent Guard never runs what it scans. Behavior that only appears at run time is out of reach until the planned sandboxed dynamic mode — for example, code downloaded later, or a server that changes its tools after connection. `lock` / `verify` catches changes between scans.
- **Pattern rules can be evaded.** Paraphrased lures ("hand the script to your shell") and payloads split across files are known weak spots. The benchmark reports them as misses rather than hiding them.
- **JavaScript/TypeScript taint** is intra-handler and pattern-based unless the optional tree-sitter extra is installed. Python taint is intra-procedural (no cross-function flow).
- **Toxic flows use inferred labels** when a server's code or tools are not available (for example, a config that only names a package). Those labels have medium or low confidence and are marked as inferred.
- **Provenance** checks detect a missing attestation and a subject-digest mismatch. Full Sigstore certificate-chain verification is not performed yet.
- **Auth checks are unauthenticated.** Agent Guard never logs in to, or sends tokens to, remote servers.
- **NSA MCP guidance mappings use section names.** The NSA CSI (May 2026) does not number its sections, so rules map to its own headings (a concern, a real-world example, or a recommendation). It covers MCP only, so skill rules have no NSA mapping.
- **AIVSS scores are approximate.** CVSS base scores default to per-severity values unless a rule carries a calculator-computed score, and capability labels stand in for the ten amplification factors. Every score records this.
- **Benchmark caveats.** Malicious and adversarial items are synthetic. The 163 real benign skills and servers come from eight vendor repositories, and rules were tuned against five of them. Before each tuning round, the next repositories were scanned once: 16 of 43, then 7 of 28, then 1 of 79 benign items were flagged at HIGH. Real skills unlike those repositories will produce more false positives. MEDIUM is noisy on real code (about 14% of benign items).
- **Some findings are downgraded rather than removed.** A quoted prompt pattern in a reference document, a chat-template token in a code span, a CLI reference that documents an approval flag, or quarantine removal on a Homebrew-installed binary is reported at MEDIUM instead of HIGH or CRITICAL. A payload written to look like such a mention is still reported, but at MEDIUM.
- **A few client config paths are unverified** because the vendor does not document them: Claude Desktop on Linux (no official build), Claude Code's plugin folder, and the legacy Windsurf and `~/.codex/skills` folders. `agentguard discover` labels them and says why; everything else was checked against vendor documentation (see `docs/sources.md`).

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
- **NSA MCP guidance mappings are pending** because the document could not be retrieved automatically; those mappings are empty with a TODO.
- **AIVSS scores are approximate.** CVSS base scores default to per-severity values unless a rule carries a calculator-computed score, and capability labels stand in for the ten amplification factors. Every score records this.
- **The benign benchmark set is currently synthetic.** Real-world benign corpora are added by `bench/fetch_real.py`.
- **Client config paths** marked "unverified" in `agentguard discover` have not been confirmed against vendor documentation.

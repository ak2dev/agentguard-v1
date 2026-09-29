---
layout: ../../layouts/Doc.astro
title: How it works
description: The scan pipeline, capability labels and toxic flows.
---

# How it works

1. **Discover** agent configuration, skills and instruction files (or load the path you give).
2. **Load safely:** size, count and depth limits; archive-bomb caps; symlinks, junctions and path escapes are refused and reported; YAML is safe-loaded with anchors, aliases and custom tags rejected.
3. **Normalize:** Unicode is NFKC-normalized and look-alike characters are folded, with offsets mapped back to the original; invisible characters are removed; encoded blobs (base64, hex, percent, gzip) are decoded to depth 3 and rescanned; hidden Markdown (comments, off-screen text, alt text, CSS-hidden elements) is extracted.
4. **Analyze** with independent analyzers: skill spec and structure, hidden content, data-defined pattern rules, MCP configuration, MCP metadata, code (Python taint via the standard `ast` module; JS/TS handler analysis), supply chain and policy.
5. **Correlate:** deduplicate, escalate findings found inside hidden content by one severity, combine credential access with egress, and build the **capability graph** for toxic flows.
6. **Score** each finding (AIVSS v0.8, pluggable) and apply suppressions, baselines and policy.
7. **Report** as terminal output, JSON, SARIF 2.1.0, Markdown or a single-file HTML report.

The engine is a pure function of its inputs: `scan(tree, options) → report`. It never touches the filesystem or network itself, so the same input and rule pack always produce the same report, and the same engine runs in the browser under Pyodide.

## Severity rules

- **CRITICAL requires high confidence** and deterministic evidence; a lower-confidence critical match is reported as high (tagged `capped-by-confidence`).
- Matches inside hidden or encoded content are escalated one level (tagged `hidden`).
- Results from the optional LLM judge can never be critical.

## Toxic flows

Every skill, server and tool gets capability labels: `reads_private_data`, `ingests_untrusted_content`, `external_egress`, `destructive` and `code_exec`. The labels come from code and config evidence, tool annotations and descriptions, and a list of well-known servers. Components that can be active in the same agent session are grouped, and dangerous combinations are reported as a path, for example:

> In one claude-desktop session: fetch can bring untrusted third-party content into the conversation; filesystem can read private data; fetch can send data outside. Instructions hidden in that untrusted content could make the agent read private data with filesystem and send it out with fetch.

The cross-component lethal trifecta is HIGH by default, because almost every multi-server setup has one. It becomes CRITICAL when data can reach a known exfiltration sink, or when no hop requires approval.

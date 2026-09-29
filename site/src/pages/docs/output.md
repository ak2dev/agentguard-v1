---
layout: ../../layouts/Doc.astro
title: Output formats
description: JSON, SARIF, Markdown, HTML and CycloneDX.
---

# Output formats

| Format | Flag | Use |
|---|---|---|
| Terminal | default | Grouped by severity; `-v` adds evidence, fixes and mappings |
| JSON | `-f json` | The versioned report schema — the only contract between the engine and any UI |
| SARIF 2.1.0 | `-f sarif` | GitHub code scanning (`security-severity`, `precision`, stable fingerprints) |
| Markdown | `-f markdown` | Pull-request comments; mentions, links and HTML are neutralized |
| HTML | `-f html` | A single self-contained file with no scripts and a strict CSP |
| CycloneDX 1.6 | `agentguard discover -f cyclonedx` | Inventory of skills and MCP servers as components |

Convert without rescanning: `agentguard report --input report.json --format sarif`.

## Every finding carries

- rule ID and version, title, severity and confidence;
- an AIVSS score, with how it was computed;
- a file:line location with a **redacted** snippet;
- explanation, remediation, standards mappings and references;
- tags and a stable fingerprint.

Secrets are always shown as the first four characters plus a short hash (for example `ghp_…[1a2b3c4d]`), in every format.

## Determinism

With the same input and rule pack, reports are byte-for-byte identical. Timestamps are omitted unless you pass `--timestamps`.

Schemas: `agentguard schema report` (also `rule`, `lock`, `policy`, `config`).

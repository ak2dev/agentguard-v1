---
layout: ../../layouts/Doc.astro
title: Quickstart
description: Scan your machine, a skill, a repository or an MCP config.
---

# Quickstart

```bash
# Everything this machine's agents can use, plus the current project
agentguard scan

# One skill folder, a repository, or a single MCP config file
agentguard scan ./skills/pdf-helper
agentguard scan ~/.cursor/mcp.json

# Show evidence, remediation and standards for each finding
agentguard scan ./skills -v

# Inventory only (no findings): agents, MCP servers, skills, instruction files
agentguard discover
agentguard discover --format cyclonedx -o agents.cdx.json
```

## Reading the output

Findings are grouped by severity (critical, high, medium, low, info). Each has a confidence (high, medium, low), a location and a rule ID. With `-v` you also get a redacted evidence snippet, the fix and the standards mappings. `agentguard rules explain AG-SKL-SE-002` explains any rule.

A clean result reads **"No findings from N rules (rule pack vX)"**. It never says "safe": it means no rule matched, and the report lists any analyzers that did not run.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings at or above `--fail-on` (default: high) |
| 1 | Findings at or above the threshold |
| 2 | Scanner error, including any analyzer failure (never a silent pass) |

## Pin what you reviewed

```bash
agentguard lock            # writes agentguard.lock
agentguard verify          # later: shows drift and rug pulls with a diff
```

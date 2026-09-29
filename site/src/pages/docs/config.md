---
layout: ../../layouts/Doc.astro
title: Configuration
description: The .agentguard.yaml file.
---

# Configuration

Agent Guard reads `.agentguard.yaml` next to the scanned target (or `--config PATH`). In PR mode (`--changed-since REF`) it is read **from the base ref**, so a pull request cannot relax its own checks.

```yaml
version: 1
fail_on: high            # critical | high | medium | low | info
exclude:                 # directory names to skip
  - fixtures
popular_skills:          # extra names for typosquat checks ("name [publisher]")
  - internal-deploy acme
suppressions:            # see Suppressions
  - rule_id: AG-MCP-CFG-004
    path_glob: "sandbox/*"
    reason: Sandbox configs are rebuilt nightly from pinned images.
    expires: 2026-12-31
policy:                  # see Policy
  require_pinning: true
```

The JSON Schema is available with `agentguard schema config`.

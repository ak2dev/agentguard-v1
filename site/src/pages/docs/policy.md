---
layout: ../../layouts/Doc.astro
title: Policy
description: Allow and deny servers and publishers, require pinning, set a maximum severity.
---

# Policy

A policy can live under `policy:` in `.agentguard.yaml`, or in its own file passed with `--policy`.

```yaml
version: 1
engine: builtin              # "rego" and "cel" are reserved for future evaluators
deny_servers:                # glob against name, full command line, or URL
  - "*@attacker-example/*"
deny_publishers: ["npm:@untrusted"]
allow_servers:               # if set, anything else is reported (AG-POL-002)
  - "npx -y @modelcontextprotocol/*"
require_pinning: true        # AG-POL-003 for unpinned package runners and images
max_severity: medium         # fail when anything above medium is found
severity_overrides:
  AG-SKL-EXEC-001: low
trifecta_severity: high      # severity for cross-component lethal trifecta flows
```

Policy findings (`AG-POL-*`) are ordinary findings: they appear in every output format and count toward the exit code.

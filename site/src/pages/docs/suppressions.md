---
layout: ../../layouts/Doc.astro
title: Suppressions
description: Accepting a finding, with a reason and an expiry date.
---

# Suppressions

Every suppression needs a **reason** (at least 10 characters) and an **expiry date**. Select findings by rule, by fingerprint, by path glob, or a combination.

```yaml
suppressions:
  - rule_id: AG-SKL-SE-008
    reason: The uv installer is reviewed and pinned by checksum in our setup docs.
    expires: 2027-03-31
  - fingerprint: 3f9a0c1d2e4b5a6978c0d1e2f3a4b5c6
    reason: Reviewed with the security team (ticket SEC-142).
    expires: 2026-12-01
```

- Suppressed findings are left out of the result but kept in the JSON report under `suppressed_findings`.
- An **expired** suppression no longer hides anything: the finding comes back tagged `suppression-expired`, together with an `AG-POL-005` notice.
- A suppression without a reason or expiry is ignored and reported as `AG-POL-006`.
- In PR mode, suppressions come from the base ref, and a PR that edits `.agentguard.yaml` gets `AG-POL-010`.

To report only new findings, use a baseline instead: `agentguard scan --baseline previous-report.json`.

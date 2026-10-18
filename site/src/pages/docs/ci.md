---
layout: ../../layouts/Doc.astro
title: CI integration
description: GitHub Action with SARIF alerts, pull-request mode, and pre-commit.
---

# CI integration

## GitHub Action

```yaml
jobs:
  agentguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@<commit-sha>   # pin by SHA
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: ak2dev/agentguard-v1@<release-sha>
        with:
          path: .
          fail-on: high
```

On pull requests the action runs in **PR mode**. It:

- reports only components touched by the change (whole components, so a payload split into unchanged files is still seen);
- reads configuration from the base commit;
- uploads SARIF to GitHub code scanning;
- writes a Markdown summary to the job page.

### Hijackable dependencies (opt-in network check)

```yaml
      - uses: ak2dev/agentguard-v1@<release-sha>
        with:
          path: .
          check-hijackable: true
```

`check-hijackable: true` runs `--check-hijackable` (SkillJacking): referenced GitHub owners, npm and PyPI packages, download domains and cloud-app hostnames are looked up to see whether anyone could claim them (rules AG-SC-026, AG-SC-027, AG-SC-028). It is off by default, so the action makes no network requests for the scan unless you turn it on, and the report lists the feature and every host contacted.

When it is on, the action passes the workflow's `GITHUB_TOKEN` to the scan. Agent Guard sends it to `api.github.com` only, for the owner lookups, which raises the cap from 50 lookups per scan (anonymous limit) to 500; the token is never sent to any other host and never printed. When the input is off, the token is not passed at all.

The only process Agent Guard ever starts is a hardened, read-only `git diff` / `git cat-file` for PR mode, with repository hooks, fsmonitor, external diff and textconv disabled.

## pre-commit

```yaml
repos:
  - repo: https://github.com/ak2dev/agentguard-v1
    rev: <release-tag>
    hooks:
      - id: agentguard
```

## Other CI systems

```bash
agentguard scan . --format json --output agentguard-report.json --changed-since "$BASE_SHA"
agentguard report --input agentguard-report.json --format sarif --output agentguard.sarif
agentguard report --input agentguard-report.json --format markdown   # PR comment body
# Optional network check; a token raises the GitHub lookup cap and goes to api.github.com only:
AGENTGUARD_GITHUB_TOKEN="$TOKEN" agentguard scan . --check-hijackable --format json --output agentguard-report.json
```

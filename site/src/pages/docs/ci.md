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
      - uses: agentguard/agentguard@<release-sha>
        with:
          path: .
          fail-on: high
```

On pull requests the action runs in **PR mode**. It:

- reports only components touched by the change (whole components, so a payload split into unchanged files is still seen);
- reads configuration from the base commit;
- uploads SARIF to GitHub code scanning;
- writes a Markdown summary to the job page.

The only process Agent Guard ever starts is a hardened, read-only `git diff` / `git cat-file` for PR mode, with repository hooks, fsmonitor, external diff and textconv disabled.

## pre-commit

```yaml
repos:
  - repo: https://github.com/agentguard/agentguard
    rev: <release-tag>
    hooks:
      - id: agentguard
```

## Other CI systems

```bash
agentguard scan . --format json --output agentguard-report.json --changed-since "$BASE_SHA"
agentguard report --input agentguard-report.json --format sarif --output agentguard.sarif
agentguard report --input agentguard-report.json --format markdown   # PR comment body
```

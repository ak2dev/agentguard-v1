---
layout: ../../layouts/Doc.astro
title: Install
description: Install Agent Guard with uv or pipx.
---

# Install

Agent Guard needs Python 3.12 or newer. It has no account, no API key and no telemetry.

```bash
uvx agentguard --version          # run without installing
pipx install agentguard           # or install it
pip install "agentguard[code]"    # optional: tree-sitter parsers for deeper JS/TS analysis
```

## Verify a release

Every release is signed with Sigstore and ships a CycloneDX SBOM. See [Security](../../security/) for the verification commands.

## What it needs

- **Filesystem:** read access to the paths you scan (and, for `agentguard scan` with no path, your agent configuration in your home directory).
- **Network:** none by default. Network features are opt-in flags (`--live-metadata`, `--auth-checks`, `--osv`, `--provenance`, `--registry`) and every report lists the ones that were used.
- **Processes:** none. Agent Guard installs an audit hook that blocks process creation, so nothing it scans can run — not even by accident.

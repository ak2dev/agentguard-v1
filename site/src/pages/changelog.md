---
layout: ../layouts/Doc.astro
title: Changelog
description: Release history.
---

# Changelog

## 0.1.0 (unreleased)

First public version.

- `agentguard scan`, `discover`, `lock`, `verify`, `rules`, `report`, `bench`, `intel`, `schema`.
- Rule pack 0.1.0 with 167 rules across skills, instruction files, MCP configuration, MCP metadata, code, toxic flows, supply chain, remote auth conformance, policy, coverage and the optional LLM judge.
- Outputs: terminal, JSON (schema v1), SARIF 2.1.0, Markdown, single-file HTML, CycloneDX 1.6 inventory.
- GitHub Action with PR mode and SARIF upload; pre-commit hook.
- Pure-Python engine that runs under Pyodide.
- Agent Guard Web: GitHub, npm, PyPI, MCP Registry and remote MCP server links scanned on the server in an isolated sandbox; rescans with current rules, maintainer responses, factual README badges, a self-hosted bot check, and toxic flows drawn as diagrams.
- Optional native analyzers: tree-sitter taint for JS/TS tool handlers and shell scripts (`agentguard[code]`), and YARA rules over bundled binaries (`agentguard[yara]`).
- Benchmark with 163 real benign skills and MCP servers from vendor repositories, plus false-positive tuning. Some documentary matches are now reported at MEDIUM instead of HIGH (see Limitations).

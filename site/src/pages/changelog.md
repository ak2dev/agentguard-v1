---
layout: ../layouts/Doc.astro
title: Changelog
description: Release history.
---

# Changelog

## 0.1.0 (unreleased)

First public version.

- `agentguard scan`, `discover`, `lock`, `verify`, `rules`, `report`, `bench`, `intel`, `schema`.
- Rule pack 0.1.0 with 159 rules across skills, instruction files, MCP configuration, MCP metadata, code, toxic flows, supply chain, remote auth conformance, policy, coverage and the optional LLM judge.
- Outputs: terminal, JSON (schema v1), SARIF 2.1.0, Markdown, single-file HTML, CycloneDX 1.6 inventory.
- GitHub Action with PR mode and SARIF upload; pre-commit hook.
- Pure-Python engine that runs under Pyodide.

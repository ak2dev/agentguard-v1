# Changelog

## 0.1.0 (unreleased)

First public version.

- Commands: `scan`, `discover`, `lock`, `verify`, `rules` (`list`, `explain`, `export`), `report`, `bench`, `intel` (`status`, `update`), `schema`.
- Rule pack 0.1.0 with 159 rules across skills and instruction files, MCP client configuration, MCP metadata, code, toxic flows, supply chain and drift, remote auth conformance, policy, coverage, and the optional LLM judge. Every rule has an unsafe and a safe fixture.
- Outputs: terminal, JSON (schema v1), SARIF 2.1.0, Markdown, single-file HTML, CycloneDX 1.6 inventory.
- Opt-in network features: read-only remote MCP metadata, OAuth/TLS conformance, npm provenance, OSV, package age, LLM judge (Anthropic, OpenAI-compatible, Ollama).
- GitHub Action with PR mode and SARIF upload; pre-commit hook.
- Pure-Python engine that runs under Pyodide.

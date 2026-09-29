# Agent Guard Web (Milestone 2) — placeholder

"Paste a link, get a report." Designed during v1, **not built yet**. The full architecture is in `docs/design/v1-design.md` § (f).

## Shape

- **Pasted text and dropped files** are scanned in the browser: a Web Worker runs Pyodide with the pure `agentguard.core` engine and the signed rule pack. No upload, zero network requests after page load (to be verified by an automated test).
- **Links** (GitHub repo/subfolder/gist/raw, `npm:name@version`, `pypi:name==version`, MCP Registry names, allowed marketplace URLs, remote MCP URLs) are normalized to an immutable reference, then fetched and scanned server-side:
  - **API** (FastAPI): input validation (`agentguard.core.inputs`, to be added), rate limits, cache lookup keyed by `(immutable ref, rule-pack digest, engine version)`.
  - **Fetcher**: the only component with egress (allowlist: GitHub, npm, PyPI, MCP Registry, configured marketplaces); archive APIs and registry tarballs only — never `git clone`, never install.
  - **Scanner worker**: the same engine in an ephemeral, non-root, read-only, no-network gVisor/microVM container with CPU/memory/time limits, destroyed after each job. `ArtifactTree.from_archive(bytes, LoadLimits.web())` → `scan()`.
  - **Probe worker** for remote MCP URLs: `agentguard.net.safe_http.SafeHttpClient` + `agentguard.net.remote.probe_server` (read-only; `tools/call` impossible).
- **Results**: report page rendered from the findings JSON (the only engine↔UI contract, `schemas/report.v1.json`); permalinks keyed to commit/version + rule pack; downloads in JSON, SARIF, HTML, CycloneDX; unlisted by default; factual badges only ("0 high · a1b2c3d"), never "verified safe".

## v1 interfaces this relies on (already in the engine)

`scan(tree, options)` (pure, deterministic, `on_progress`, `deadline_s`); `ArtifactTree.from_mapping` / `from_archive`; `LoadLimits.web()`; `SafeHttpClient`; `probe_server`; `render_json/sarif/markdown/html/cyclonedx`; `RulePack.from_files` (+ digest); `redact()` / `RedactedText`; `lock.tool_diff` for drift views.

Still to add in M2: `core.inputs.parse()` for link normalization, `report_cache_key()`, `diff_reports()`.

Local development will be one `docker compose up`.

# Agent Guard Web (Milestone 2)

"Paste a link, get a report." The full architecture is in `docs/design/v1-design.md` § (f).

## Built: the browser-only part

The website's `/scan` page (`site/src/pages/[scan].astro`, `site/public/js/scan-page.js`, `site/public/js/scan-worker.js`) scans in the browser with the pure engine under Pyodide, served by the site itself:

- **Pasted text, dropped files, folders and archives**: scanned on the device, zero network requests after the engine has loaded (asserted by `site/tests/e2e/scan.spec.mjs` in CI).
- **Public GitHub repository / folder / file / raw file / gist links**: parsed by `agentguard.core.inputs.parse`, resolved in the browser to a commit SHA via `api.github.com`, file list reduced by `agentguard.core.fetchplan.plan_fetch`, contents fetched from `raw.githubusercontent.com`, then scanned locally. Findings link to the file and line at that commit.
- **Report**: rendered from the findings JSON (`schemas/report.v1.json`) as text nodes only; downloads in JSON, SARIF, HTML, Markdown and CycloneDX, rendered by the engine in the worker.
- **Hosting**: static, on Vercel (`vercel.json`: build, security headers, trailing slashes). No server code.

The scanned project's own `.agentguard.yaml` is ignored so it cannot suppress its own findings.

## Still to build: the server part

For inputs a browser cannot fetch safely or at all — npm and PyPI packages, MCP Registry names, marketplace listings, remote MCP server URLs — and for permalinks, caching and rescans:

- **API** (FastAPI): `core.inputs.parse` already recognizes these inputs and returns the "server needed" note; add rate limits, bot protection, cache lookup keyed by `(immutable ref, rule-pack digest, engine version)`.
- **Fetcher**: the only component with egress (allowlist: GitHub, npm, PyPI, MCP Registry, configured marketplaces); archive APIs and registry tarballs only — never `git clone`, never install. It can reuse `core.fetchplan.plan_fetch`.
- **Scanner worker**: the same engine in an ephemeral, non-root, read-only, no-network gVisor/microVM container with CPU/memory/time limits, destroyed after each job: `from_archive(bytes, limits=LoadLimits.web())` → `scan()`. Vercel Functions cannot provide this isolation, so workers run on a platform that can (e.g. Cloud Run or Fly Machines); the site and API can stay on Vercel.
- **Probe worker** for remote MCP URLs: `agentguard.net.safe_http.SafeHttpClient` + `agentguard.net.remote.probe_server` (read-only; `tools/call` impossible).
- **Results**: permalinks keyed to commit/version + rule pack; drift diff against the previous scan; unlisted by default; factual badges only ("0 high · a1b2c3d"), never "verified safe".
- Still to add to the engine: `report_cache_key()`, `diff_reports()`.

The service's own threat model is in `web/threat-model.md`. Local development will be one `docker compose up`.

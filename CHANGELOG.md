# Changelog

## 0.1.0 (unreleased)

First public version.

- Agent Guard Web server (`web/`, `agentguard-web`): paste a GitHub, npm, PyPI or MCP Registry link; it is pinned to an exact commit or version (registry digests verified), fetched through an allowlisted SSRF-hardened fetcher, scanned in a throwaway container with no network, and stored as an unlisted report with a permalink, downloads and drift against the previous scan. `docker compose up` runs it locally; CI tests the isolation against real containers.
- Web scanner (`/scan`): paste text, drop files or a .zip, or give a public GitHub repository, folder, file or gist link; scanned in the browser by the same engine under Pyodide, with zero network requests for pasted and dropped input (tested in CI). GitHub links are pinned to a commit and findings link to the exact file and line. Deployable to Vercel with `vercel.json` security headers.
- Commands: `scan`, `discover`, `lock`, `verify`, `rules` (`list`, `explain`, `export`), `report`, `bench`, `intel` (`status`, `update`), `schema`.
- Rule pack 0.1.0 with 159 rules across skills and instruction files, MCP client configuration, MCP metadata, code, toxic flows, supply chain and drift, remote auth conformance, policy, coverage, and the optional LLM judge. Every rule has an unsafe and a safe fixture.
- Outputs: terminal, JSON (schema v1), SARIF 2.1.0, Markdown, single-file HTML, CycloneDX 1.6 inventory.
- Opt-in network features: read-only remote MCP metadata, OAuth/TLS conformance, npm provenance, OSV, package age, LLM judge (Anthropic, OpenAI-compatible, Ollama).
- GitHub Action with PR mode and SARIF upload; pre-commit hook.
- Pure-Python engine that runs under Pyodide.

### Real-world benchmark and false-positive tuning

- Benchmark: 163 real benign skills and MCP servers from anthropics/skills, openai/skills, modelcontextprotocol/servers, microsoft/playwright-mcp, huggingface/skills, supabase-mcp (dev) and microsoft/skills, cloudflare/mcp-server-cloudflare (held out), vendored at pinned commits with per-directory license checks (`bench/fetch_real.py`, `bench/NOTICE`). History and caveats: `docs/benchmark.md`.
- Rules can now report a match at lower severity instead of dropping it (`downgrade`: quoted mention in a reference doc, context pattern, or the skill's declared purpose). Negative fixtures can assert a ceiling (`max_severity` in `_case.yaml`).
- Environment copies handed only to a child process (`subprocess` `env=`, `spawn` `env:`) are no longer environment dumps; `AF_UNIX` and loopback sockets and same-origin `fetch("/api/...")` are no longer network egress.
- Tightened AG-SKL-EXF-004 (DNS exfiltration), AG-SKL-CRED-002, AG-SKL-INJ-003/005/007, AG-CODE-025 and AG-SKL-HID-009 (percent-encoding inside URLs). Instruction-layer rules report quoted and code-span mentions in reference docs at MEDIUM. AG-SKL-SE-007 reports quarantine removal under a package-manager prefix at MEDIUM.
- Fixed: JS/TS handler extraction treated an apostrophe in a `//` comment as a string, so a handler could swallow the rest of the file. JS path taint now honours containment checks (`validatePath(...)`), as Python taint already did.

### Fixes

- `agentguard lock` then `agentguard verify` inside a skill folder no longer reports the new `agentguard.lock` as drift (AG-SC-002, exit 1). The lockfile a command reads or writes is left out of the scan; any other file named `agentguard.lock` is still scanned.
- The Website workflow builds and checks the site as Vercel deploys it (`PUBLIC_FEATURE_SCAN=1`, root base path) and no longer tries to deploy to GitHub Pages, which failed on every push to `main`.

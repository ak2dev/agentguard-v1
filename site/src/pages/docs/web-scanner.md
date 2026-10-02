---
layout: ../../layouts/Doc.astro
title: Web scanner
description: Scan pasted text and dropped files in the browser, and GitHub, npm, PyPI and MCP Registry links on the Agent Guard Web server; privacy, limits and deployment.
---

# Web scanner

The [/scan](../../scan/) page is Agent Guard Web: "paste a link, get a report". Pasted text and dropped files are scanned in your browser by the same engine and rule pack as the CLI. Links are scanned by the Agent Guard Web server in an isolated sandbox.

## What you can scan

| Input | Where it runs | Network |
|---|---|---|
| Pasted `SKILL.md`, instruction file, MCP configuration, tool list or script | Your browser | None |
| Dropped files, a folder, or a `.zip` / `.tar` / `.tgz` | Your browser | None |
| Public GitHub repository, folder (`/tree/…`), file (`/blob/…`), raw file or gist | Agent Guard Web server (or your browser if the server is unavailable) | The server fetches from GitHub; in the fallback, your browser does |
| npm package (`npm:name@version`), PyPI package (`pypi:name==version`), MCP Registry name | Agent Guard Web server | The server fetches from the registry |
| Remote MCP server URL (`https://…`) | Agent Guard Web server | The server contacts that URL as an unauthenticated, read-only client |

Every link is first pinned to an immutable reference — a commit SHA, or an exact package version with the registry's published SHA-512 / SHA-256, which the server verifies — so the report says exactly what was scanned. GitHub findings link to the file and line at that commit. Branch names that contain `/` are resolved by trying each split in order. An MCP Registry name resolves to its `server.json` and the npm or PyPI package it publishes.

## On the server

- The server downloads archives only from GitHub, npm, PyPI and the MCP Registry, through an allowlisted, SSRF-hardened client. It never clones, installs or runs anything.
- Each scan runs in a fresh container with no network, a read-only filesystem, no privileges and strict CPU, memory and time limits; the container is removed afterwards. The archive is never stored.
- The same version scanned with the same rule pack always gives the same report, so repeat requests are answered from the cache. Each report has an unlisted permalink (`/scan/?report=…`); there is no public index of reports.
- Requests are rate-limited per network; addresses are kept only as salted hashes. Before a request is sent, your browser solves a small proof-of-work challenge (well under a second; no third-party CAPTCHA, nothing to click).
- **Remote MCP servers** are checked the way any MCP client would connect, without credentials: server discovery or `initialize`, `tools/list`, `prompts/list`, `resources/list`, and the server's OAuth metadata documents. A tool is never called. The query string of the URL is dropped. Private, loopback, link-local and cloud-metadata addresses are refused. The recorded metadata is scanned in the same sandbox, and the report shows a fingerprint of it: the same metadata gives the same report, changed tool definitions give a new one with a diff. A recent check is reused for a few minutes.
- **Rescan with current rules:** a report made with an older rule pack can be rescanned at the same commit or version. "Scan the latest version" scans the project's current state instead.
- **Maintainer responses:** whoever can push to the project's GitHub repository can attach a public response by committing `.agentguard/response.md` with a line `report: <key>`; the report page explains how. The response is shown as plain text with a link to the commit it was read from.
- **README badge:** each report offers a badge with its finding counts at that exact version, for example `0 high · a1b2c3d`. It never says "safe".

## Privacy

- Pasted text and dropped files never leave your device. An automated test in CI asserts that these scans make zero network requests.
- In the GitHub fallback (no server), your browser contacts only `api.github.com` (2 to 6 requests: repository, commit, file list) and `raw.githubusercontent.com` or `gist.githubusercontent.com` (file contents), without cookies or a referrer. Nothing is sent to Agent Guard. GitHub allows 60 anonymous API requests per hour per network.
- The Python runtime ([Pyodide](https://pyodide.org/)), its packages and the engine are served by this site. The first scan downloads about 15 MB; your browser caches it.

## What is different from the CLI

- The scanned project's own `.agentguard.yaml` is ignored, so content under review cannot suppress its own findings. There is no policy, baseline or lockfile.
- Opt-in network checks (provenance, OSV, package age) and the LLM judge are not available on the web scanner. Remote MCP metadata and OAuth checks run on the server when you submit a server URL.
- Limits: 5,000 files, 2 MB per file and 64 MB in total; for a GitHub link, at most 1,500 files are fetched. Files no rule reads (images, lockfiles) are not fetched. Everything left out is listed under "What was not scanned".
- Scanning runs in WebAssembly, several times slower than the CLI. A single skill takes about a second after the engine has loaded; a repository with hundreds of large files can take a minute.

Findings are evidence for review, not verdicts. A report with no findings means no rule matched, not that the content is safe.

## Deploying on Vercel

The repository root has a `vercel.json`. Import the repository as a Vercel project and keep the defaults it sets:

- install: `npm ci --prefix site`; build: `cd site && PUBLIC_FEATURE_SCAN=1 npm run build`; output: `site/dist`;
- response headers: a Content-Security-Policy that allows WebAssembly (`'wasm-unsafe-eval'`) and, for the scanner's worker, the three GitHub hosts above; every page also carries its own stricter policy, and browsers enforce both;
- `trailingSlash: true`, matching the site's URLs.

No server code, environment variables or secrets are needed.

To connect the server, run it on a host that can start containers with no network (see `web/README.md`: `docker compose up` locally; Postgres, Redis, the API and the dispatcher in production), then add a rewrite so the site reaches it on its own origin and its CSP can stay `connect-src 'self'`:

```json
"rewrites": [{ "source": "/api/:path*", "destination": "https://<your-api-host>/api/:path*" }]
```

Without the rewrite the page still works: links to GitHub are scanned in the browser, and other links explain that the server is not available. The build downloads the six Python wheels the engine needs from the Pyodide release and checks each one against the sha256 in Pyodide's lock file; visitors never contact a CDN.

To try the production headers locally: `cd site && PUBLIC_FEATURE_SCAN=1 npm run build && npm run serve`, then open `http://127.0.0.1:4321/scan/`. The end-to-end tests (`npm run test:e2e`) use the same server and an installed Chrome (`PW_CHANNEL=msedge` for Edge).

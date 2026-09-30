---
layout: ../../layouts/Doc.astro
title: Web scanner
description: Scan pasted text, dropped files and public GitHub links in the browser; how it works, its limits, and how to deploy it.
---

# Web scanner

The [/scan](../../scan/) page runs the same engine and rule pack as the CLI, in your browser. It is the first part of Agent Guard Web ("paste a link, get a report").

## What you can scan

| Input | Where it runs | Network |
|---|---|---|
| Pasted `SKILL.md`, instruction file, MCP configuration, tool list or script | Your browser | None |
| Dropped files, a folder, or a `.zip` / `.tar` / `.tgz` | Your browser | None |
| Public GitHub repository, folder (`/tree/…`), file (`/blob/…`), raw file or gist | Your browser | Your browser fetches the files from GitHub |
| npm or PyPI package, MCP Registry name, remote MCP server URL | Agent Guard Web server | Not available yet; the page says so |

A GitHub link is first pinned to a commit SHA, so the report says exactly what was scanned and every finding links to the file and line at that commit. Branch names that contain `/` are resolved by trying each split in order.

## Privacy

- Pasted text and dropped files never leave your device. An automated test in CI asserts that these scans make zero network requests.
- For a GitHub link, your browser contacts only `api.github.com` (2 to 6 requests: repository, commit, file list) and `raw.githubusercontent.com` or `gist.githubusercontent.com` (file contents), without cookies or a referrer. Nothing is sent to Agent Guard. GitHub allows 60 anonymous API requests per hour per network.
- The Python runtime ([Pyodide](https://pyodide.org/)), its packages and the engine are served by this site. The first scan downloads about 15 MB; your browser caches it.

## What is different from the CLI

- The scanned project's own `.agentguard.yaml` is ignored, so content under review cannot suppress its own findings. There is no policy, baseline or lockfile.
- Opt-in network checks (remote MCP metadata, OAuth conformance, provenance, OSV, package age) and the LLM judge are not available in the browser.
- Limits: 5,000 files, 2 MB per file and 64 MB in total; for a GitHub link, at most 1,500 files are fetched. Files no rule reads (images, lockfiles) are not fetched. Everything left out is listed under "What was not scanned".
- Scanning runs in WebAssembly, several times slower than the CLI. A single skill takes about a second after the engine has loaded; a repository with hundreds of large files can take a minute.

Findings are evidence for review, not verdicts. A report with no findings means no rule matched, not that the content is safe.

## Deploying on Vercel

The repository root has a `vercel.json`. Import the repository as a Vercel project and keep the defaults it sets:

- install: `npm ci --prefix site`; build: `cd site && PUBLIC_FEATURE_SCAN=1 npm run build`; output: `site/dist`;
- response headers: a Content-Security-Policy that allows WebAssembly (`'wasm-unsafe-eval'`) and, for the scanner's worker, the three GitHub hosts above; every page also carries its own stricter policy, and browsers enforce both;
- `trailingSlash: true`, matching the site's URLs.

No server code, environment variables or secrets are needed. The build downloads the six Python wheels the engine needs from the Pyodide release and checks each one against the sha256 in Pyodide's lock file; visitors never contact a CDN.

To try the production headers locally: `cd site && PUBLIC_FEATURE_SCAN=1 npm run build && npm run serve`, then open `http://127.0.0.1:4321/scan/`. The end-to-end tests (`npm run test:e2e`) use the same server and an installed Chrome (`PW_CHANNEL=msedge` for Edge).

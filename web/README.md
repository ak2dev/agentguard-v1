# Agent Guard Web

"Paste a link, get a report." Two parts:

- **In the browser** (the site's `/scan` page): pasted text and dropped files are scanned on the device by the engine under Pyodide, with zero network requests. Without a server, public GitHub links are scanned in the browser too.
- **The server** (this package, `agentguard-web`): links are resolved to an exact commit or version, fetched through an allowlist, scanned in an isolated container with no network, and stored as an unlisted report with a permalink.

## How a link is scanned

```
browser ──POST /api/scans──▶ API ──queue──▶ dispatcher ──▶ resolver + fetcher ──(allowlisted HTTPS)──▶ GitHub · npm · PyPI · MCP Registry
                              │                  │
                              │                  └─ archive on stdin ─▶ scanner container (--network none, read-only, non-root,
                              │                                         no capabilities, CPU/memory/PID/time limits, optional gVisor)
                              │                  ◀── report JSON on stdout ──┘
                              └──── reports (Postgres / SQLite), keyed by (immutable ref, rule pack, engine)
```

| Component | Network | What it does |
|---|---|---|
| API (`agentguard_web.api`) | none of its own | Validates input (`agentguard.core.inputs.parse`), rate-limits per client (salted hash, no raw IPs stored), caps the queue, streams progress (SSE), serves reports and downloads (JSON, SARIF, HTML, Markdown, CycloneDX) and drift against the previous scan. |
| Dispatcher (`agentguard_web.dispatcher`) | the only egress, through the fetcher | Resolves inputs (`resolve.py`), checks the cache, downloads (`fetch.py`), starts one sandbox per job, validates and stores the report. |
| Fetcher (`fetch.py`) | allowlist only: `api.github.com`, `codeload.github.com`, `raw.githubusercontent.com`, `gist.githubusercontent.com`, `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `registry.modelcontextprotocol.io` | `SafeHttpClient` underneath: HTTPS only, DNS pinned, private and metadata ranges blocked, redirects re-validated, credentials never forwarded across hosts, size and time caps. Verifies the registry's published SHA-512 / SHA-256. Never clones, installs or executes; never parses the archive. |
| Scanner sandbox (`sandbox.py`, `web/docker/scanner.Dockerfile`) | **none** | `python -m agentguard.sandbox_entry`: reads the job spec and archive from stdin, scans with the pure engine (archive limits, link and path-escape rejection, process-creation guard), writes the report to stdout. Created, started and always force-removed per job. |

What is resolved to what:

| Input | Immutable reference | Archive |
|---|---|---|
| `https://github.com/o/r[/tree|blob/<ref>/<path>]` | commit SHA (branch names with `/` tried in order) | `GET /repos/o/r/tarball/<sha>` → codeload; a single file for `/blob/` |
| gist URL | gist revision | the gist's files |
| `npm:<name>[@<version or tag>]`, npmjs.com URL | exact version + tarball SHA-512 | registry tarball, digest verified |
| `pypi:<name>[==<version>]`, pypi.org URL | exact version + file SHA-256 | sdist (else a wheel), digest verified |
| MCP Registry name (`io.github.o/server`) | its `server.json` (`/v0.1/servers/<name>/versions/latest`) → the npm/PyPI package it publishes, else its GitHub repository | as above; `server.json` is scanned too |
| Remote MCP server URL | — | not on the hosted service yet (use the CLI's `--live-metadata --auth-checks`) |

Same reference + same rule pack + same engine → byte-identical report, served from the cache.

## Run it locally

```bash
docker compose up --build        # API on http://127.0.0.1:8000, Postgres, Redis, dispatcher, scanner image
```

Then point the site at it: `cd site && PUBLIC_FEATURE_SCAN=1 npm run build && AGW_API_URL=http://127.0.0.1:8000 npm run serve` and open `http://127.0.0.1:4321/scan/`. The site calls the API on its own origin (`/api/…`), so its strict CSP stays `connect-src 'self'`.

```bash
curl -s -X POST http://127.0.0.1:8000/api/scans -H 'content-type: application/json' -d '{"input": "npm:@modelcontextprotocol/server-filesystem"}'
docker compose run --rm dispatcher check-sandbox   # proves the scanner container has no network
```

Tests: `cd web && uv run pytest` (no network, no Docker); `AGW_DOCKER_TESTS=1 uv run pytest tests/test_docker_sandbox.py` against real containers.

## Configuration (`AGW_*`)

| Variable | Default | |
|---|---|---|
| `MODE` | `dev` | `prod` refuses the in-process sandbox and an in-memory queue |
| `STORE` | `sqlite:///./agentguard-web.db` | or `postgresql://…` |
| `QUEUE` | `memory` | `redis://…` (required to run the API and dispatcher separately) |
| `SANDBOX` | `docker` | `inprocess` = no isolation, tests and local development only |
| `SCANNER_IMAGE` / `DOCKER_RUNTIME` | `agentguard-scanner:local` / — | set `DOCKER_RUNTIME=runsc` where gVisor is installed |
| `GITHUB_TOKEN` | — | optional, raises GitHub's API limit; held by the dispatcher only, never sent to other hosts |
| `ALLOWED_ORIGINS` | — | CORS, only if the site calls the API cross-origin |
| `TRUST_PROXY` | off | use `X-Forwarded-For` only behind a trusted proxy |
| `RATE_PER_MINUTE` / `RATE_PER_DAY` / `QUEUE_CAP` | 6 / 60 / 50 | abuse and cost limits |
| `MAX_ARCHIVE_BYTES` / `JOB_TIMEOUT_S` / `WORKERS` | 50 MB / 120 / 2 | |
| `RETENTION_DAYS` | 90 | `agentguard-web prune` deletes older reports |

## Deploying

The site stays on Vercel. The server needs a host that can run Docker containers with `--network none` (ideally with gVisor): a small VM, or a container platform where the dispatcher can start sibling containers. The API can run anywhere that reaches Redis and Postgres.

1. Run Postgres, Redis, `agentguard-web api` and `agentguard-web dispatcher` (the images in `web/docker/`). Give only the dispatcher Docker access, and only on a host dedicated to scanning. In `compose.yaml` the Docker socket is mounted for local development; on a shared host prefer rootless Docker or a separate scan VM.
2. Run `agentguard-web check-sandbox` at deploy time; it must print `NO-EGRESS`.
3. Proxy the site's `/api/` to the API with a Vercel rewrite in `vercel.json`:
   `"rewrites": [{ "source": "/api/:path*", "destination": "https://<your-api-host>/api/:path*" }]`.
   Without it the site still works: links to GitHub fall back to the browser scanner.
4. Schedule `agentguard-web prune` daily.

## Not built yet

- Remote MCP server probing on the service (the CLI has it): a separate probe worker using `SafeHttpClient` + `probe_server`.
- Bot protection on submit (e.g. Turnstile), a maintainer response and "rescan with latest rules" on report pages, factual README badges.
- Privacy policy and terms pages for the hosted service; a GitHub App token for higher limits; marketplace adapters (e.g. ClawHub) where their terms allow it.

The service's threat model is in `web/threat-model.md`.

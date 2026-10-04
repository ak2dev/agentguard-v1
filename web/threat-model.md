# Threat model — Agent Guard Web (the hosted service)

The service fetches and scans hostile code by design, so it has its own model beyond `docs/threat-model.md`. "Implemented" means built and tested in this repository; "planned" means designed but not built.

## Assets

The host running the dispatcher and scanner containers; the GitHub token (if configured); the report store; the service's reputation (reports about third-party projects); visitors' privacy.

## Trust boundaries

1. Visitor → API (untrusted input text).
2. Dispatcher → the internet (allowlisted registries returning untrusted bytes).
3. Dispatcher → scanner container (hostile archive crosses into the sandbox).
4. Scanner container → dispatcher (report JSON is untrusted until validated).
5. API → visitor's browser (report content derived from hostile input).

## Threats and mitigations

| Threat | Mitigation | Status |
|---|---|---|
| Hostile archive attacks the parser (zip/tar bombs, links, path escapes, deep trees) | Parsed only inside the scanner container by `from_archive` with `LoadLimits.web()`: member, size and ratio caps; symlinks/hardlinks dropped; escapes rejected | Implemented (engine tests) |
| Code execution in the scanner | The engine never executes anything; the sandbox entry installs the process-creation audit hook before reading input | Implemented |
| Container escape / lateral movement | One container per job, created, started with a time limit and always force-removed; `--network none`, read-only root, noexec tmpfs, uid 65534, all capabilities dropped, `no-new-privileges`, PID/memory/CPU/file limits, no mounts, no environment, no credentials; `AGW_DOCKER_RUNTIME=runsc` for gVisor | Implemented (Docker tests); gVisor depends on the host |
| Exfiltration from the scanner | No network namespace; `agentguard-web check-sandbox` and a CI test prove no egress | Implemented |
| Dispatcher compromise via the Docker socket | The dispatcher never parses or executes fetched content; it only moves bytes. Local compose mounts the socket; production should use a dedicated scan host, rootless Docker or a remote daemon | Documented; host hardening is deployment-specific |
| SSRF / open proxy via the fetcher | Explicit host allowlist on every request and redirect; `SafeHttpClient`: HTTPS only, DNS resolved and pinned, private/loopback/link-local/metadata ranges blocked, redirect re-validation, size and time caps | Implemented (tests) |
| Token theft | Token only in the dispatcher's environment; sent only to `api.github.com`; credential headers are dropped on any cross-host redirect (e.g. to codeload) | Implemented (tests) |
| Tampered or substituted package | npm SHA-512 / PyPI SHA-256 from the registry verified before scanning; tarball URLs must be on the registry's own host | Implemented (tests) |
| Cache poisoning | Cache key = hash of the resolver's immutable reference + the scanning image's rule-pack digest + engine version; the report's target must match the reference requested | Implemented |
| Malformed or oversized report from the sandbox | Size cap; JSON schema validation (`Report.model_validate_json`) before storing | Implemented |
| Stored XSS via findings | The site renders report JSON as text nodes only (never HTML); the API serves JSON with `default-src 'none'; sandbox`; HTML reports are downloads with their own strict CSP | Implemented (e2e test for the renderer) |
| Abuse and cost | Proof-of-work challenge on every request that starts work (HMAC-signed, 5-minute expiry, single-use; no third party); per-client rate limits (minute and day); queue cap with 503; request size cap; archive size cap; per-job timeout; caching, including a short reuse window for remote servers | Implemented (tests) |
| Privacy | No accounts, no analytics; client IDs are salted hashes; archives are never written to disk; only redacted findings JSON is kept, pruned after `AGW_RETENTION_DAYS` | Implemented |
| Defamation / false verdicts | Findings, not verdicts; no "malicious" or "safe" labels; unlisted reports (no index, no listing endpoint); rescan with current rules; maintainer responses shown next to the report; badges state counts at one version, in a neutral colour | Implemented |
| Impersonated maintainer response | Only text committed to the project's own GitHub repository (default branch, read at a pinned commit through the allowlisted fetcher) is shown, with a link to that commit; for npm/PyPI, the repository named in the registry's own metadata; the file must name the report key | Implemented (tests) |
| Stored XSS / spoofing via responses or badges | Response text is size-capped, stripped of control and bidi characters, and rendered as a text node; badge text is XML-escaped, served as `image/svg+xml` with `default-src 'none'` | Implemented (tests) |
| Prompt injection against a judge | The LLM judge is not used on the service | By design |
| Remote MCP probing (SSRF, hostile server) | A separate probe client in the dispatcher (no allowlist, since servers can be anywhere): `SafeHttpClient` requires HTTPS, resolves DNS first, refuses private, loopback, link-local, CGNAT, multicast and metadata addresses and names, pins the vetted IP, re-validates every redirect, caps size and time; plus a per-job budget of 40 requests and 45 s. Only read-only methods can be sent (`tools/call` is not in the allowlist) and no credentials; the URL's query string is dropped. The server's (hostile) metadata is parsed by the engine only inside the scanner sandbox | Implemented (SSRF tests for each address class) |

# Threat model — Agent Guard Web (outline, to be completed in Milestone 2)

The service ingests hostile code by design, so it needs its own model beyond `docs/threat-model.md`.

| Threat | Planned mitigation |
|---|---|
| Hostile archives attack the extractor (bombs, links, path escapes) | `agentguard.core.archive.from_archive` with `LoadLimits.web()`; links dropped; escapes rejected; stream decompression capped |
| Worker escape / lateral movement | gVisor or microVM; non-root; read-only root filesystem; no network; no credentials; seccomp; per-job CPU/memory/wall-clock limits; destroyed after each job |
| Worker egress (exfiltration, callbacks) | No network namespace; automated test proving the worker cannot reach the internet |
| Fetcher credential theft | GitHub App token only in the fetcher; fetcher never parses or executes content; egress allowlist |
| SSRF via remote MCP URLs | Separate probe worker using `SafeHttpClient` (DNS pinning, private/metadata ranges blocked, redirects re-validated, HTTPS only, caps); SSRF test suite in CI |
| Cache poisoning | Cache key set only by the resolver from immutable refs + rule-pack digest + engine version |
| Stored XSS via findings in the report UI | Report rendered from JSON with escaping; strict CSP with no inline scripts; redacted snippets only |
| Abuse and cost (flooding, huge repos) | Per-IP and per-session rate limits, bot protection on submit, queue caps, archive size caps, aggressive caching |
| Defamation / false verdicts | Findings, not verdicts; no "malicious" or "safe" labels; unlisted reports; maintainer response and rescan |
| Data retention | Archives deleted after each scan; only redacted findings JSON kept for a documented period; no third-party analytics |
| Prompt injection against a judge | LLM judge off on the hosted service; if enabled later, per-job token budget and the v1 hardening |

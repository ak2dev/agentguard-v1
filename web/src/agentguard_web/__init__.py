"""Agent Guard Web: the hosted "paste a link, get a report" service.

API (no egress) → queue → dispatcher (resolver + allowlisted fetcher) →
isolated scanner sandbox (no network) → report store. See web/README.md.
"""

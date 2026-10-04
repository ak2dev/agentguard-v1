"""Remote MCP server probing (dispatcher only).

This is a separate client from the fetcher. A remote MCP server can be on any
public host, so there is no host allowlist. Instead the SSRF-hardened
``SafeHttpClient`` underneath requires HTTPS, resolves DNS first, refuses
private, loopback, link-local, CGNAT, multicast and cloud-metadata addresses,
connects to the vetted IP (no DNS rebinding), re-validates every redirect and
caps response size and time. On top of that, ``ProbeClient`` caps how many
requests one job may make and how long it may take in total.

What is sent is fixed by ``agentguard.net.remote``: server discovery or
initialize, ``tools/list``, ``prompts/list``, ``resources/list``, and the
OAuth metadata documents. ``tools/call`` is not in the method allowlist, so it
cannot be sent. No credentials are ever sent.
"""

from __future__ import annotations

import time
import urllib.parse

from agentguard.core.models import RemoteProbe
from agentguard.net.remote import probe_server
from agentguard.net.safe_http import BlockedRequest, FetchError, Resolver, Response, SafeHttpClient
from agentguard.webscan import REMOTE_CONFIG_PATH

from .fetch import USER_AGENT

MAX_REQUESTS = 40        # discovery + 3 lists × up to 10 pages + PRM + AS metadata, with room for redirects
BUDGET_S = 45.0          # the whole probe, all requests together


class ProbeClient(SafeHttpClient):
    def __init__(self, *, max_requests: int = MAX_REQUESTS, budget_s: float = BUDGET_S,
                 resolver: Resolver | None = None) -> None:
        super().__init__(timeout=8, max_bytes=2 * 1024 * 1024, max_redirects=3, deadline_s=20,
                         user_agent=USER_AGENT, resolver=resolver)
        self.max_requests = max_requests
        self.budget_s = budget_s
        self.requests = 0
        self._start = time.monotonic()

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response:
        self.requests += 1
        if self.requests > self.max_requests:
            raise BlockedRequest(f"probe request budget ({self.max_requests}) exhausted")
        if time.monotonic() - self._start > self.budget_s:
            raise FetchError(f"probe time budget ({self.budget_s:.0f} s) exhausted")
        return super().request(method, url, headers=headers, body=body)


def probe_remote(client: SafeHttpClient, url: str) -> RemoteProbe:
    """Read-only metadata and unauthenticated OAuth discovery for one server URL."""
    name = (urllib.parse.urlsplit(url).hostname or "remote-server").lower()
    return probe_server(client, name, url, REMOTE_CONFIG_PATH, metadata=True, auth=True)


def unreachable(probe: RemoteProbe) -> Exception | None:
    """The exception to report for a probe that never reached the server, if any."""
    if probe.reachable:
        return None
    err = probe.error or "the server did not respond"
    if err.startswith("blocked: "):
        return BlockedRequest(err[len("blocked: "):])
    return FetchError(err)

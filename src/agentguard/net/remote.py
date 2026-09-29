"""Opt-in probes of remote (Streamable HTTP) MCP servers.

* Read-only metadata: `server/discover` (2026-07-28) or `initialize` (2025-11-25 /
  2025-06-18), then `tools/list`, `prompts/list`, `resources/list`. The method
  allowlist below is enforced by construction — `tools/call` is impossible.
* Auth conformance data: RFC 9728 Protected Resource Metadata (from the
  WWW-Authenticate `resource_metadata` parameter or the well-known URI with
  path insertion), RFC 8414 / OIDC authorization-server metadata.
* No credentials are ever sent: probes are unauthenticated by design.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

import regex

from ..core.models import RemoteProbe
from .safe_http import BlockedRequest, FetchError, Response, SafeHttpClient

READ_ONLY_METHODS = frozenset({
    "server/discover", "initialize", "notifications/initialized", "tools/list", "prompts/list", "resources/list",
    "resources/templates/list",
})
PROTOCOL_VERSIONS = ("2026-07-28", "2025-11-25", "2025-06-18")
_RESOURCE_METADATA = regex.compile(r'resource_metadata\s*=\s*"([^"]+)"')


class MethodNotAllowed(Exception):
    pass


def _parse_body(resp: Response) -> list[dict[str, Any]]:
    ctype = (resp.header("content-type") or "").lower()
    text = resp.body.decode("utf-8", "replace")
    if "text/event-stream" in ctype:
        out = []
        for block in text.split("\n\n"):
            data = "\n".join(line[5:].lstrip() for line in block.splitlines() if line.startswith("data:"))
            if data:
                try:
                    out.append(json.loads(data))
                except json.JSONDecodeError:
                    continue
        return out
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else [parsed]


class McpReadOnlyClient:
    def __init__(self, http: SafeHttpClient, url: str) -> None:
        self.http = http
        self.url = url
        self.version: str | None = None
        self.session: str | None = None
        self._id = 0

    def _call(self, method: str, params: dict[str, Any] | None = None, notify: bool = False) -> tuple[Response, dict[str, Any] | None]:
        if method not in READ_ONLY_METHODS:
            raise MethodNotAllowed(method)
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        headers = {"Accept": "application/json, text/event-stream"}
        if self.version and self.version != "2026-07-28":
            headers["MCP-Protocol-Version"] = self.version
        if self.version == "2026-07-28" or self.version is None:
            headers["Mcp-Method"] = method
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        resp = self.http.post_json(self.url, msg, headers=headers)
        if resp.header("mcp-session-id"):
            self.session = resp.header("mcp-session-id")
        if notify:
            return resp, None
        for m in _parse_body(resp):
            if isinstance(m, dict) and m.get("id") == self._id:
                return resp, m
        return resp, None

    def _meta(self) -> dict[str, Any]:
        return {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                          "io.modelcontextprotocol/clientInfo": {"name": "agentguard", "version": "0.1"},
                          "io.modelcontextprotocol/clientCapabilities": {}}}

    def handshake(self) -> tuple[Response, dict[str, Any] | None]:
        """Try the 2026-07-28 discovery first, then the 2025 initialize handshake."""
        resp, msg = self._call("server/discover", self._meta())
        if resp.status == 200 and msg and "result" in msg:
            versions = msg["result"].get("supportedVersions") or msg["result"].get("protocolVersions") or []
            self.version = "2026-07-28" if "2026-07-28" in versions or not versions else versions[0]
            return resp, msg["result"]
        if resp.status in (401, 403):
            return resp, None
        self.version = None
        resp, msg = self._call("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "agentguard", "version": "0.1"},
        })
        if resp.status == 200 and msg and "result" in msg:
            self.version = str(msg["result"].get("protocolVersion") or "2025-06-18")
            self._call("notifications/initialized", notify=True)
            return resp, msg["result"]
        return resp, None

    def list_all(self, method: str, key: str, limit: int = 500) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor = None
        for _ in range(10):
            params: dict[str, Any] = self._meta() if self.version == "2026-07-28" else {}
            if cursor:
                params["cursor"] = cursor
            resp, msg = self._call(method, params or None)
            if resp.status != 200 or not msg or "result" not in msg:
                break
            got = msg["result"].get(key) or []
            items.extend(x for x in got if isinstance(x, dict))
            cursor = msg["result"].get("nextCursor")
            if not cursor or len(items) >= limit:
                break
        return items[:limit]


def _well_known_prm(url: str) -> list[str]:
    p = urllib.parse.urlsplit(url)
    base = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    urls = [f"{base}/.well-known/oauth-protected-resource{path}"] if path else []
    urls.append(f"{base}/.well-known/oauth-protected-resource")
    return urls


def _as_metadata_urls(issuer: str) -> list[str]:
    p = urllib.parse.urlsplit(issuer)
    base = f"{p.scheme}://{p.netloc}"
    path = p.path.rstrip("/")
    return [f"{base}/.well-known/oauth-authorization-server{path}", f"{base}/.well-known/openid-configuration{path}",
            f"{issuer.rstrip('/')}/.well-known/openid-configuration"]


def _fetch_json(http: SafeHttpClient, url: str, probe: RemoteProbe) -> dict[str, Any] | None:
    try:
        resp = http.get(url, headers={"Accept": "application/json"})
    except (BlockedRequest, FetchError):
        return None
    origin = urllib.parse.urlsplit(url)
    for hop in resp.redirects:
        h = urllib.parse.urlsplit(hop)
        if h.scheme != "https" or h.netloc != origin.netloc:
            probe.insecure_redirects.append(hop)
    if resp.status != 200:
        return None
    try:
        data = resp.json()
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def probe_server(http: SafeHttpClient, name: str, url: str, config_path: str, *, metadata: bool, auth: bool) -> RemoteProbe:
    probe = RemoteProbe(server_name=name, url=url, config_path=config_path)
    client = McpReadOnlyClient(http, url)
    try:
        resp, info = client.handshake()
    except BlockedRequest as exc:
        probe.reachable, probe.error = False, f"blocked: {exc}"
        return probe
    except FetchError as exc:
        probe.reachable, probe.error = False, str(exc)
        if "certificate" in str(exc):
            probe.tls_error = str(exc)
        return probe
    probe.tls_version = resp.tls_version
    probe.status_unauth = resp.status
    probe.www_authenticate = resp.header("www-authenticate")
    if info is not None:
        probe.unauthenticated_list = True
        probe.protocol_version = client.version
        probe.server_info = info.get("serverInfo") or info.get("io.modelcontextprotocol/serverInfo")
        if isinstance(info.get("instructions"), str):
            probe.instructions = info["instructions"]
        if metadata:
            try:
                probe.tools = client.list_all("tools/list", "tools")
                probe.prompts = client.list_all("prompts/list", "prompts")
                probe.resources = client.list_all("resources/list", "resources")
            except (BlockedRequest, FetchError) as exc:
                probe.error = f"listing failed: {exc}"
    if auth:
        prm_urls = []
        if probe.www_authenticate:
            m = _RESOURCE_METADATA.search(probe.www_authenticate)
            if m:
                prm_urls.append(urllib.parse.urljoin(url, m.group(1)))
        prm_urls += _well_known_prm(url)
        for u in prm_urls:
            prm = _fetch_json(http, u, probe)
            if prm is not None:
                probe.prm, probe.prm_url = prm, u
                break
        if probe.prm is None and probe.status_unauth in (401, 403):
            probe.prm_error = "no Protected Resource Metadata found"
        for issuer in (probe.prm or {}).get("authorization_servers", [])[:3]:
            if not isinstance(issuer, str):
                continue
            for u in _as_metadata_urls(issuer):
                md = _fetch_json(http, u, probe)
                if md is not None:
                    probe.as_metadata[issuer] = md
                    break
            else:
                probe.as_errors[issuer] = "authorization server metadata not found"
    return probe

"""SSRF-hardened HTTP client (stdlib only). Used by every opt-in network
feature in the CLI and, in Milestone 2, by the hosted service's probe worker.

Guarantees:
* HTTPS only (plain HTTP only to loopback, and only when explicitly allowed).
* DNS is resolved first; every resolved address must be globally routable
  (no private, loopback, link-local, CGNAT, multicast, reserved or
  cloud-metadata addresses).
* The connection is made to the vetted IP (pinned), with SNI/Host set to the
  hostname, so DNS rebinding between check and connect is impossible.
* Redirects are followed manually and every hop is re-validated.
* Hard caps on response size, redirects and time; TLS 1.2+ with certificate
  verification.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

METADATA_HOSTS = {"metadata.google.internal", "metadata", "metadata.azure.internal", "instance-data"}
_CREDENTIAL_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
DEFAULT_UA = "agentguard/0.1 (+https://github.com/agentguard/agentguard; read-only security scanner)"


class BlockedRequest(Exception):
    """Refused by policy (SSRF protection, scheme, size, redirect)."""


class FetchError(Exception):
    """Network or protocol failure."""


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    tls_version: str | None = None
    redirects: list[str] = field(default_factory=list)
    peer_ip: str | None = None

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


Resolver = Callable[[str, int], list[str]]


def system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(f"DNS resolution failed for {host}") from exc
    return sorted({info[4][0] for info in infos})


def ip_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(addr.is_global) and not addr.is_multicast


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, ip: str, port: int, context: ssl.SSLContext, timeout: float) -> None:
        super().__init__(host, port=port, context=context, timeout=timeout)
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class SafeHttpClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        max_bytes: int = 2 * 1024 * 1024,
        max_redirects: int = 3,
        resolver: Resolver | None = None,
        allow_http_loopback: bool = False,
        allow_private: bool = False,
        user_agent: str = DEFAULT_UA,
        deadline_s: float = 30.0,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.resolver = resolver or system_resolver
        self.allow_http_loopback = allow_http_loopback
        self.allow_private = allow_private
        self.user_agent = user_agent
        self.deadline_s = deadline_s
        self.hosts_contacted: list[str] = []
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ssl = ctx

    # -- validation ----------------------------------------------------------
    def vet(self, url: str) -> tuple[urllib.parse.SplitResult, str]:
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError as exc:
            raise BlockedRequest("malformed URL") from exc
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            raise BlockedRequest("URL has no host")
        if parts.username or parts.password:
            raise BlockedRequest("credentials in URL are not allowed")
        if host in METADATA_HOSTS:
            raise BlockedRequest(f"cloud metadata host {host} is blocked")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ips = self.resolver(host, port)
        if not ips:
            raise FetchError(f"no addresses for {host}")
        if parts.scheme == "https":
            bad = [ip for ip in ips if not ip_allowed(ip)]
            if bad and not self.allow_private:
                raise BlockedRequest(f"{host} resolves to non-public address(es) {', '.join(bad[:3])}")
        elif parts.scheme == "http":
            loop = all(ipaddress.ip_address(ip).is_loopback for ip in ips)
            if not (self.allow_http_loopback and loop):
                raise BlockedRequest("plain http is not allowed")
        else:
            raise BlockedRequest(f"scheme {parts.scheme!r} is not allowed")
        return parts, ips[0]

    # -- requests ------------------------------------------------------------
    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None, body: bytes | None = None) -> Response:
        start = time.monotonic()
        redirects: list[str] = []
        current = url
        for _ in range(self.max_redirects + 1):
            if time.monotonic() - start > self.deadline_s:
                raise FetchError("deadline exceeded")
            parts, ip = self.vet(current)
            port = parts.port or (443 if parts.scheme == "https" else 80)
            conn: http.client.HTTPConnection
            if parts.scheme == "https":
                conn = _PinnedHTTPSConnection(parts.hostname or "", ip, port, self._ssl, self.timeout)
            else:
                conn = _PinnedHTTPConnection(parts.hostname or "", ip, port, self.timeout)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            hdrs = {"User-Agent": self.user_agent, "Accept-Encoding": "identity", **(headers or {})}
            try:
                conn.request(method, path, body=body, headers=hdrs)
                resp = conn.getresponse()
                data = resp.read(self.max_bytes + 1)
                tls = conn.sock.version() if isinstance(conn.sock, ssl.SSLSocket) else None
            except ssl.SSLCertVerificationError as exc:
                raise FetchError(f"TLS certificate verification failed for {parts.hostname}: {exc.reason}") from exc
            except (OSError, http.client.HTTPException) as exc:
                raise FetchError(f"{type(exc).__name__} contacting {parts.hostname}") from exc
            finally:
                conn.close()
            host = parts.hostname or ""
            if host not in self.hosts_contacted:
                self.hosts_contacted.append(host)
            if len(data) > self.max_bytes:
                raise BlockedRequest(f"response from {host} exceeds {self.max_bytes} bytes")
            headers_out = {k.lower(): v for k, v in resp.getheaders()}
            if resp.status in (301, 302, 303, 307, 308) and "location" in headers_out:
                nxt = urllib.parse.urljoin(current, headers_out["location"])
                redirects.append(nxt)
                if (urllib.parse.urlsplit(nxt).hostname or "").lower() != host.lower() and headers:
                    # Never forward credentials to a different host.
                    headers = {k: v for k, v in headers.items() if k.lower() not in _CREDENTIAL_HEADERS}
                if method != "GET" and resp.status in (301, 302, 303):
                    method, body = "GET", None
                current = nxt
                continue
            return Response(current, resp.status, headers_out, data, tls, redirects, ip)
        raise BlockedRequest("too many redirects")

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        return self.request("GET", url, headers=headers)

    def post_json(self, url: str, payload: Any, headers: dict[str, str] | None = None) -> Response:
        body = json.dumps(payload).encode("utf-8")
        return self.request("POST", url, headers={"Content-Type": "application/json", **(headers or {})}, body=body)

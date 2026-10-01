"""SSRF-hardened client and read-only MCP client (no external network)."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agentguard.net import safe_http
from agentguard.net.remote import McpReadOnlyClient, MethodNotAllowed, probe_server
from agentguard.net.safe_http import BlockedRequest, SafeHttpClient


def fixed(*ips: str):
    return lambda host, port: list(ips)


@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "100.64.0.1", "192.168.1.1", "::1",
                                "fd00:ec2::254", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1"])
def test_blocks_non_public_resolution(ip):
    c = SafeHttpClient(resolver=fixed(ip))
    with pytest.raises(BlockedRequest):
        c.vet("https://mcp.example.invalid/mcp")


def test_blocks_if_any_address_private():
    c = SafeHttpClient(resolver=fixed("192.88.99.1", "10.1.2.3"))
    with pytest.raises(BlockedRequest):
        c.vet("https://mixed.example.invalid/")


@pytest.mark.parametrize("url", ["http://public.example.invalid/", "ftp://x.example.invalid/", "file:///etc/passwd",
                                 "https://user:pw@x.example.invalid/", "https://metadata.google.internal/computeMetadata/v1/",
                                 "https:///nohost"])
def test_blocks_bad_urls(url):
    c = SafeHttpClient(resolver=fixed("192.88.99.1"))
    with pytest.raises(BlockedRequest):
        c.vet(url)


def test_allows_public_https_and_pins_ip(monkeypatch):
    c = SafeHttpClient(resolver=fixed("192.88.99.1"))
    parts, ip = c.vet("https://ok.example.invalid/x")
    assert ip == "192.88.99.1" and parts.hostname == "ok.example.invalid"
    captured = {}

    def fake_create_connection(addr, timeout=None):
        captured["addr"] = addr
        raise OSError("stop here")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    with pytest.raises(safe_http.FetchError):
        c.get("https://ok.example.invalid/x")
    assert captured["addr"] == ("192.88.99.1", 443)  # connected to the vetted IP, not a re-resolution


# ---------------------------------------------------------------- local server
class _Handler(BaseHTTPRequestHandler):
    calls: list[str] = []

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path == "/redirect-to-metadata":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        if self.path == "/redirect-to-localhost":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_address[1]}/echo-headers")
            self.end_headers()
            return
        if self.path == "/echo-headers":
            payload = json.dumps({"authorization": self.headers.get("Authorization"),
                                  "accept": self.headers.get("Accept")}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.calls.append(body["method"])
        if body["method"] == "server/discover":
            result = {"supportedVersions": ["2026-07-28"], "serverInfo": {"name": "fake", "version": "1.0.0"},
                      "instructions": "Use search first."}
        elif body["method"] == "tools/list":
            result = {"tools": [{"name": "search", "description": "Search docs.", "inputSchema": {"type": "object"}}]}
        elif body["method"] in ("prompts/list", "resources/list"):
            result = {body["method"].split("/")[0]: []}
        else:
            result = {}
        payload = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    _Handler.calls = []
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_redirect_revalidated(server):
    c = SafeHttpClient(allow_http_loopback=True)
    with pytest.raises(BlockedRequest):
        c.get(server + "/redirect-to-metadata")


def test_credentials_not_forwarded_across_hosts(server):
    c = SafeHttpClient(allow_http_loopback=True)
    resp = c.get(server + "/redirect-to-localhost", headers={"Authorization": "Bearer secret", "Accept": "x/y"})
    echoed = resp.json()
    assert echoed["authorization"] is None  # dropped: the redirect changed host (127.0.0.1 → localhost)
    assert echoed["accept"] == "x/y"        # ordinary headers still sent


def test_mcp_probe_is_read_only(server):
    c = SafeHttpClient(allow_http_loopback=True)
    probe = probe_server(c, "fake", server + "/mcp", "cfg.json", metadata=True, auth=False)
    assert probe.unauthenticated_list and probe.protocol_version == "2026-07-28"
    assert [t["name"] for t in probe.tools] == ["search"]
    assert probe.instructions == "Use search first."
    assert "tools/call" not in _Handler.calls
    client = McpReadOnlyClient(c, server + "/mcp")
    with pytest.raises(MethodNotAllowed):
        client._call("tools/call", {"name": "search"})

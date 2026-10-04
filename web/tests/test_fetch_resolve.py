"""Fetcher allowlist and integrity checks; resolution of every supported input."""

from __future__ import annotations

import hashlib

import pytest
from conftest import FakeFetcher, npm_routes, tarball

from agentguard.core.inputs import parse
from agentguard.net.safe_http import FetchError

from agentguard_web.fetch import ALLOWED_HOSTS, AllowlistClient, NotAllowed, sri_to_hex, verify_digest, zip_files
from agentguard_web.resolve import ResolveError, Resolver

SHA = "a" * 40


@pytest.mark.parametrize("url", [
    "https://example.invalid/x", "https://evil.example.invalid/registry.npmjs.org",
    "https://169.254.169.254/latest/meta-data/", "https://registry.npmjs.org.evil.example.invalid/x",
    "http://registry.npmjs.org/x",
])
def test_allowlist_refuses_other_hosts(url):
    c = AllowlistClient(resolver=lambda h, p: ["192.88.99.1"])
    with pytest.raises((NotAllowed, Exception)):
        c.vet(url)


def test_allowlist_is_small_and_explicit():
    assert ALLOWED_HOSTS == {
        "api.github.com", "codeload.github.com", "raw.githubusercontent.com", "gist.githubusercontent.com",
        "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "registry.modelcontextprotocol.io",
    }


def test_digest_verification():
    verify_digest(b"abc", ("sha256", hashlib.sha256(b"abc").hexdigest()))
    with pytest.raises(FetchError):
        verify_digest(b"abd", ("sha256", hashlib.sha256(b"abc").hexdigest()))
    assert sri_to_hex("sha512-" + "AAAA") == ("sha512", "000000")
    assert sri_to_hex("md5-xyz") is None


def test_zip_files_is_deterministic():
    assert zip_files({"a.md": b"x", "b/c.md": b"y"}) == zip_files({"b/c.md": b"y", "a.md": b"x"})


def resolve(text: str, routes: dict) -> tuple:
    f = FakeFetcher(routes)
    parsed = parse(text)
    return Resolver(f).resolve(parsed), f


def test_github_repo_default_branch_to_tarball():
    routes = {
        "https://api.github.com/repos/o/r": {"default_branch": "main", "private": False},
        "https://api.github.com/repos/o/r/commits/main": SHA,
    }
    r, _ = resolve("https://github.com/o/r", routes)
    assert r.ref.resolved == SHA and r.archive_url == f"https://api.github.com/repos/o/r/tarball/{SHA}"
    assert r.github_archive and r.strip_components == 1 and r.subpath == ""


def test_github_tree_with_slashed_branch_tries_candidates():
    routes = {
        "https://api.github.com/repos/o/r/commits/feature": 404,
        "https://api.github.com/repos/o/r/commits/feature/x": SHA,
        f"https://api.github.com/repos/o/r/contents/skills/pdf?ref={SHA}": [{"name": "SKILL.md"}],
    }
    r, _ = resolve("https://github.com/o/r/tree/feature/x/skills/pdf", routes)
    assert r.ref.resolved == SHA and r.subpath == "skills/pdf"
    assert r.ref.locator == "o/r/skills/pdf"


def test_github_blob_becomes_single_file():
    routes = {
        "https://api.github.com/repos/o/r/commits/main": SHA,
        f"https://raw.githubusercontent.com/o/r/{SHA}/skills/a/SKILL.md": "---\nname: a\n---\n",
    }
    r, _ = resolve("https://github.com/o/r/blob/main/skills/a/SKILL.md", routes)
    assert r.inline_files == {"skills/a/SKILL.md": b"---\nname: a\n---\n"} and r.archive_url is None


def test_github_not_found():
    with pytest.raises(ResolveError, match="not found"):
        resolve("https://github.com/o/missing", {})


def test_npm_exact_version_and_integrity():
    routes = npm_routes()
    r, _ = resolve("npm:pdf-helper-mcp@1.2.3", routes)
    assert r.ref.kind.value == "npm" and r.ref.resolved == "1.2.3"
    assert r.expected and r.expected[0] == "sha512" and r.ref.integrity.startswith("sha512:")
    assert r.strip_components == 1


def test_npm_latest_tag():
    r, _ = resolve("npm:pdf-helper-mcp", npm_routes())
    assert r.ref.resolved == "1.2.3"


def test_npm_scoped_name_is_encoded():
    data = tarball({"index.js": b"1"})
    routes = npm_routes(name="@scope/srv", data=data)
    routes["https://registry.npmjs.org/@scope%2Fsrv"] = routes.pop("https://registry.npmjs.org/@scope/srv")
    r, f = resolve("npm:@scope/srv@1.2.3", routes)
    assert r.ref.locator == "@scope/srv" and "https://registry.npmjs.org/@scope%2Fsrv" in f.requested


def test_npm_tarball_off_registry_is_refused():
    routes = npm_routes()
    doc = routes["https://registry.npmjs.org/pdf-helper-mcp"]
    doc["versions"]["1.2.3"]["dist"]["tarball"] = "https://evil.example.invalid/x.tgz"
    with pytest.raises(ResolveError, match="registry.npmjs.org"):
        resolve("npm:pdf-helper-mcp@1.2.3", routes)


def test_pypi_prefers_sdist_and_checks_host():
    sha = "b" * 64
    routes = {
        "https://pypi.org/pypi/mcp-thing/0.4.0/json": {
            "info": {"name": "mcp-thing"},
            "urls": [
                {"packagetype": "bdist_wheel", "filename": "mcp_thing-0.4.0-py3-none-any.whl",
                 "url": "https://files.pythonhosted.org/w.whl", "digests": {"sha256": "c" * 64}},
                {"packagetype": "sdist", "filename": "mcp_thing-0.4.0.tar.gz",
                 "url": "https://files.pythonhosted.org/s.tar.gz", "digests": {"sha256": sha}},
            ],
        },
    }
    r, _ = resolve("pypi:mcp-thing==0.4.0", routes)
    assert r.archive_url.endswith("s.tar.gz") and r.expected == ("sha256", sha) and r.strip_components == 1


def test_registry_name_resolves_to_its_npm_package():
    routes = npm_routes()
    routes["https://registry.modelcontextprotocol.io/v0.1/servers/io.github.o%2Fpdf/versions/latest"] = {
        "server": {"name": "io.github.o/pdf", "version": "1.2.3",
                   "packages": [{"registryType": "npm", "identifier": "pdf-helper-mcp", "version": "1.2.3"}]},
    }
    r, _ = resolve("io.github.o/pdf", routes)
    assert r.ref.kind.value == "npm" and r.ref.resolved == "1.2.3"
    assert "_mcp-registry/server.json" in r.extra_files
    assert any("MCP Registry" in n.detail for n in r.notes)


def test_registry_remote_only_goes_to_the_probe():
    from agentguard_web.resolve import RemoteServer

    routes = {"https://registry.modelcontextprotocol.io/v0.1/servers/io.github.o%2Fremote/versions/latest": {
        "server": {"name": "io.github.o/remote", "remotes": [{"type": "streamable-http", "url": "https://x.example.invalid/mcp"}]},
    }}
    with pytest.raises(RemoteServer) as exc:
        resolve("io.github.o/remote", routes)
    assert exc.value.url == "https://x.example.invalid/mcp"
    # A templated URL (needs per-user configuration) has nothing fixed to check.
    routes[next(iter(routes))]["server"]["remotes"] = [{"type": "streamable-http", "url": "https://{tenant}.example.invalid/mcp"}]
    with pytest.raises(ResolveError, match="templated"):
        resolve("io.github.o/remote", routes)


def test_gist_inline_files():
    routes = {"https://api.github.com/gists/0123456789abcdef0123": {
        "history": [{"version": SHA}], "files": {"SKILL.md": {"content": "---\nname: g\n---\n"}}}}
    r, _ = resolve("https://gist.github.com/someone/0123456789abcdef0123", routes)
    assert r.ref.kind.value == "gist" and r.ref.resolved == SHA and r.inline_files == {"SKILL.md": b"---\nname: g\n---\n"}


def test_remote_mcp_url_goes_to_the_probe():
    from agentguard_web.resolve import RemoteServer

    with pytest.raises(RemoteServer) as exc:
        resolve("https://mcp.example.invalid/mcp?token=secret", {})
    assert exc.value.url == "https://mcp.example.invalid/mcp"   # the query (often a credential) is dropped

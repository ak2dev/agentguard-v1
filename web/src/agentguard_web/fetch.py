"""The fetcher: the only Agent Guard Web component with network egress.

* Every request goes through ``SafeHttpClient`` (HTTPS only, DNS pinned,
  private/metadata ranges blocked, every redirect re-validated, size and time
  caps) and, on top of that, an explicit host allowlist.
* It downloads archives through official APIs (GitHub's tarball endpoint,
  registry tarballs) and verifies the registry's published digest. It never
  runs ``git clone``, never installs, never executes, and never parses the
  archive: the bytes go straight to the isolated scanner sandbox.
"""

from __future__ import annotations

import base64
import hashlib
import io
import zipfile

from agentguard.net.safe_http import BlockedRequest, FetchError, Response, SafeHttpClient

ALLOWED_HOSTS = frozenset({
    "api.github.com", "codeload.github.com", "raw.githubusercontent.com", "gist.githubusercontent.com",
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "registry.modelcontextprotocol.io",
})
USER_AGENT = "agentguard-web/0.1 (read-only security scanner; never executes what it fetches)"


class NotAllowed(BlockedRequest):
    pass


class AllowlistClient(SafeHttpClient):
    """SafeHttpClient that refuses any host outside the allowlist, including on redirects."""

    def __init__(self, allowed: frozenset[str] = ALLOWED_HOSTS, **kw) -> None:  # noqa: ANN003
        kw.setdefault("user_agent", USER_AGENT)
        super().__init__(**kw)
        self.allowed = allowed

    def vet(self, url: str):  # noqa: ANN201
        import urllib.parse

        host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
        if host not in self.allowed:
            raise NotAllowed(f"host {host or '?'} is not on the fetcher allowlist")
        return super().vet(url)


def verify_digest(data: bytes, expected: tuple[str, str] | None) -> None:
    """expected = (algorithm, hex digest). Raises FetchError on mismatch."""
    if expected is None:
        return
    algo, want = expected
    got = hashlib.new(algo, data).hexdigest()
    if got != want.lower():
        raise FetchError(f"{algo} digest mismatch: the downloaded archive is not what the registry published")


def sri_to_hex(integrity: str) -> tuple[str, str] | None:
    """npm 'sha512-<base64>' → ('sha512', hex)."""
    algo, _, b64 = integrity.partition("-")
    if algo not in ("sha512", "sha256", "sha384") or not b64:
        return None
    try:
        return algo, base64.b64decode(b64).hex()
    except ValueError:
        return None


def zip_files(files: dict[str, bytes]) -> bytes:
    """Package inline files (a gist, a single raw file) as an archive for the sandbox."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))  # deterministic
            zf.writestr(info, files[name])
    return buf.getvalue()


class Fetcher:
    def __init__(self, *, github_token: str = "", max_archive_bytes: int = 50 * 1024 * 1024,
                 extra_hosts: tuple[str, ...] = (), metadata_client: SafeHttpClient | None = None,
                 archive_client: SafeHttpClient | None = None) -> None:
        allowed = ALLOWED_HOSTS | frozenset(h.lower() for h in extra_hosts)
        self.github_token = github_token
        self.meta = metadata_client or AllowlistClient(allowed, max_bytes=16 * 1024 * 1024, timeout=15, deadline_s=40)
        self.archive = archive_client or AllowlistClient(allowed, max_bytes=max_archive_bytes, timeout=30, deadline_s=90)

    @property
    def hosts_contacted(self) -> list[str]:
        return sorted(set(self.meta.hosts_contacted) | set(self.archive.hosts_contacted))

    def _gh_headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
        h = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
        if self.github_token:
            h["Authorization"] = f"Bearer {self.github_token}"
        return h

    def json(self, url: str, *, github: bool = False, accept: str = "application/json") -> tuple[int, object]:
        resp = self.meta.get(url, headers=self._gh_headers() if github else {"Accept": accept})
        if resp.status == 404:
            return 404, None
        _raise_for_status(resp, url)
        try:
            return resp.status, resp.json()
        except ValueError as exc:
            raise FetchError(f"unexpected response from {resp.url.split('?')[0]}") from exc

    def text(self, url: str, *, github: bool = False, accept: str = "text/plain") -> tuple[int, str]:
        resp = self.meta.get(url, headers=self._gh_headers(accept) if github else {"Accept": accept})
        if resp.status == 404:
            return 404, ""
        _raise_for_status(resp, url)
        return resp.status, resp.body.decode("utf-8", "replace")

    def bytes(self, url: str, *, github: bool = False, expected: tuple[str, str] | None = None) -> bytes:
        # GitHub's tarball endpoint wants its JSON media type, then redirects to codeload.github.com.
        resp = self.archive.get(url, headers=self._gh_headers() if github else {})
        _raise_for_status(resp, url)
        verify_digest(resp.body, expected)
        return resp.body


def _raise_for_status(resp: Response, url: str) -> None:
    if resp.status in (403, 429) and resp.header("x-ratelimit-remaining") == "0":
        raise FetchError("GitHub API rate limit reached; try again later")
    if resp.status >= 400:
        raise FetchError(f"HTTP {resp.status} from {url.split('?')[0]}")

"""Resolve a parsed input to an immutable reference and a download plan.

GitHub → commit SHA (repository tarball, or the single file); gist → revision;
npm → exact version + tarball SHA-512; PyPI → exact version + file SHA-256;
MCP Registry name → its server.json → the npm/PyPI package it publishes (or the
repository when it publishes none). Every lookup goes through the Fetcher.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field

from agentguard.core.inputs import GitHubLocator, ParsedInput, gist_ref, github_ref
from agentguard.core.models import ImmutableRef, LimitEvent
from agentguard.core.models.enums import SourceKind

from .fetch import Fetcher, sri_to_hex, zip_files

_SHA = re.compile(r"^[0-9a-f]{40}$")
_SEMVERISH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$")


class ResolveError(ValueError):
    """A user-facing reason the input cannot be scanned."""


@dataclass
class Resolved:
    ref: ImmutableRef
    archive_url: str | None = None
    github_archive: bool = False
    expected: tuple[str, str] | None = None
    strip_components: int = 0
    subpath: str = ""
    inline_files: dict[str, bytes] | None = None
    extra_files: dict[str, str] = field(default_factory=dict)  # added to the scanned tree (e.g. server.json)
    notes: list[LimitEvent] = field(default_factory=list)

    def source_json(self) -> dict:
        return self.ref.model_dump(mode="json", exclude={"source_url_template"}) | (
            {"subpath": self.subpath} if self.subpath and self.ref.kind == SourceKind.github else {}
        )


def _enc(path: str) -> str:
    return "/".join(urllib.parse.quote(p, safe="") for p in path.split("/"))


class Resolver:
    def __init__(self, fetcher: Fetcher) -> None:
        self.f = fetcher

    def resolve(self, parsed: ParsedInput) -> Resolved:
        kind = parsed.source.kind
        if kind == SourceKind.github:
            assert parsed.github is not None
            return self._github(parsed.github)
        if kind == SourceKind.gist:
            assert parsed.github is not None
            return self._gist(parsed.github)
        if kind == SourceKind.npm:
            name, version = _split_npm(parsed.source.locator)
            return self._npm(name, version)
        if kind == SourceKind.pypi:
            name, _, version = parsed.source.locator.partition("==")
            return self._pypi(name, version or None)
        if kind == SourceKind.mcp_registry:
            return self._registry(parsed.source.locator)
        if kind == SourceKind.remote_mcp:
            raise ResolveError("Remote MCP server checks are not available on the hosted service yet. "
                               "Use the CLI with --live-metadata --auth-checks.")
        raise ResolveError(f"{kind.value} inputs are not supported by the hosted service yet.")

    # -- GitHub ----------------------------------------------------------------
    def _commit(self, owner: str, repo: str, ref: str) -> str | None:
        status, text = self.f.text(f"https://api.github.com/repos/{_enc(owner)}/{_enc(repo)}/commits/{_enc(ref)}",
                                   github=True, accept="application/vnd.github.sha")
        sha = text.strip()
        return sha if status != 404 and _SHA.match(sha) else None

    def _github(self, gh: GitHubLocator) -> Resolved:
        base = f"https://api.github.com/repos/{_enc(gh.owner)}/{_enc(gh.repo)}"
        candidates = list(gh.candidates)
        if not candidates:
            status, repo = self.f.json(base, github=True)
            if status == 404 or not isinstance(repo, dict):
                raise ResolveError("Repository not found. Only public repositories can be scanned.")
            if repo.get("private"):
                raise ResolveError("Only public repositories can be scanned.")
            candidates = [_cand(str(repo.get("default_branch") or "main"), "")]
        for c in candidates:
            sha = self._commit(gh.owner, gh.repo, c.ref)
            if not sha:
                continue
            if gh.single_file:
                status, text = self.f.text(
                    f"https://raw.githubusercontent.com/{_enc(gh.owner)}/{_enc(gh.repo)}/{sha}/{_enc(c.path)}")
                if status == 404:
                    continue
                return Resolved(ref=github_ref(gh.owner, gh.repo, sha, c.path), inline_files={c.path: text.encode("utf-8")})
            if c.path and len(candidates) > 1:
                status, _ = self.f.json(f"{base}/contents/{_enc(c.path)}?ref={sha}", github=True)
                if status == 404:
                    continue
            return Resolved(
                ref=github_ref(gh.owner, gh.repo, sha, c.path or None),
                archive_url=f"{base}/tarball/{sha}", github_archive=True, strip_components=1, subpath=c.path,
            )
        raise ResolveError("Not found on GitHub: check the owner, repository, branch and path. Only public repositories can be scanned.")

    def _gist(self, gh: GitHubLocator) -> Resolved:
        url = f"https://api.github.com/gists/{_enc(gh.gist_id)}" + (f"/{gh.gist_revision}" if gh.gist_revision else "")
        status, gist = self.f.json(url, github=True)
        if status == 404 or not isinstance(gist, dict):
            raise ResolveError("Gist not found. Only public gists can be scanned.")
        revision = gh.gist_revision or ((gist.get("history") or [{}])[0] or {}).get("version", "")
        if not _SHA.match(str(revision)):
            raise ResolveError("Could not determine the gist's revision.")
        files: dict[str, bytes] = {}
        for name, meta in sorted((gist.get("files") or {}).items()):
            if not isinstance(meta, dict):
                continue
            if meta.get("truncated"):
                raw = str(meta.get("raw_url", ""))
                if urllib.parse.urlsplit(raw).hostname != "gist.githubusercontent.com":
                    continue
                files[name] = self.f.bytes(raw)
            else:
                files[name] = str(meta.get("content", "")).encode("utf-8")
        if not files:
            raise ResolveError("The gist has no files.")
        return Resolved(ref=gist_ref(gh.gist_id, revision), inline_files=files)

    # -- npm -----------------------------------------------------------------------
    def _npm(self, name: str, version: str | None) -> Resolved:
        status, doc = self.f.json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}",
                                  accept="application/vnd.npm.install-v1+json")
        if status == 404 or not isinstance(doc, dict):
            raise ResolveError(f"npm package {name!r} not found.")
        tags = doc.get("dist-tags") or {}
        ver = tags.get(version or "latest") or version
        vdoc = (doc.get("versions") or {}).get(ver or "")
        if not ver or not isinstance(vdoc, dict):
            raise ResolveError(f"npm package {name!r} has no version {version!r}.")
        dist = vdoc.get("dist") or {}
        tarball = str(dist.get("tarball", ""))
        if urllib.parse.urlsplit(tarball).hostname != "registry.npmjs.org":
            raise ResolveError("The npm tarball is not hosted on registry.npmjs.org.")
        expected = sri_to_hex(str(dist.get("integrity", ""))) or (("sha1", str(dist["shasum"])) if dist.get("shasum") else None)
        if expected is None:
            raise ResolveError("The npm registry published no integrity hash for this version.")
        ref = ImmutableRef(kind=SourceKind.npm, locator=name, resolved=ver, integrity=f"{expected[0]}:{expected[1]}")
        return Resolved(ref=ref, archive_url=tarball, expected=expected, strip_components=1)

    # -- PyPI ----------------------------------------------------------------------
    def _pypi(self, name: str, version: str | None) -> Resolved:
        if not version:
            status, doc = self.f.json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
            if status == 404 or not isinstance(doc, dict):
                raise ResolveError(f"PyPI project {name!r} not found.")
            version = str((doc.get("info") or {}).get("version", ""))
        if not _SEMVERISH.match(version or ""):
            raise ResolveError("That is not a valid PyPI version.")
        status, rel = self.f.json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json")
        if status == 404 or not isinstance(rel, dict):
            raise ResolveError(f"PyPI project {name!r} has no version {version!r}.")
        files = [u for u in rel.get("urls") or [] if isinstance(u, dict) and not u.get("yanked")]
        sdists = [u for u in files if u.get("packagetype") == "sdist"]
        wheels = sorted((u for u in files if u.get("packagetype") == "bdist_wheel"),
                        key=lambda u: (not str(u.get("filename", "")).endswith("-none-any.whl"), str(u.get("filename", ""))))
        pick = (sdists or wheels or [None])[0]
        if pick is None:
            raise ResolveError("This PyPI release has no downloadable files.")
        url = str(pick.get("url", ""))
        sha = str((pick.get("digests") or {}).get("sha256", ""))
        if urllib.parse.urlsplit(url).hostname != "files.pythonhosted.org" or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ResolveError("The PyPI file is not hosted on files.pythonhosted.org or has no SHA-256.")
        canonical = str((rel.get("info") or {}).get("name") or name)
        ref = ImmutableRef(kind=SourceKind.pypi, locator=canonical, resolved=version, integrity=f"sha256:{sha}")
        return Resolved(ref=ref, archive_url=url, expected=("sha256", sha),
                        strip_components=1 if pick.get("packagetype") == "sdist" else 0)

    # -- MCP Registry ----------------------------------------------------------------
    def _registry(self, server_name: str) -> Resolved:
        status, doc = self.f.json(
            f"https://registry.modelcontextprotocol.io/v0.1/servers/{urllib.parse.quote(server_name, safe='')}/versions/latest")
        server = doc.get("server") if isinstance(doc, dict) else None
        if status == 404 or not isinstance(server, dict):
            raise ResolveError(f"MCP Registry server {server_name!r} not found.")
        server_json = json.dumps(server, indent=2, sort_keys=True)
        note = LimitEvent(kind="registry", path="server.json",
                          detail=f"resolved from MCP Registry {server_name} {server.get('version', '')}".strip())
        for pkg in server.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            rtype, ident, ver = pkg.get("registryType"), str(pkg.get("identifier", "")), str(pkg.get("version", "")) or None
            if rtype in ("npm", "pypi") and ident:
                resolved = self._npm(ident, ver) if rtype == "npm" else self._pypi(ident, ver)
                resolved.extra_files = {"_mcp-registry/server.json": server_json}
                resolved.notes.append(note)
                return resolved
        repo = server.get("repository") or {}
        m = re.match(r"^https://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?$", str(repo.get("url", "")))
        if m:
            sub = str(repo.get("subfolder") or "").strip("/")
            gh = GitHubLocator(owner=m.group(1), repo=m.group(2), mode="tree" if sub else "repo",
                               candidates=[])
            resolved = self._github(gh)
            resolved.subpath = sub
            resolved.ref = github_ref(gh.owner, gh.repo, resolved.ref.resolved, sub or None)
            resolved.extra_files = {"_mcp-registry/server.json": server_json}
            resolved.notes.append(note)
            resolved.notes.append(LimitEvent(kind="registry", path="server.json",
                                             detail="no npm/PyPI package published; scanned the repository's default branch"))
            return resolved
        if server.get("remotes"):
            raise ResolveError("This registry entry is a remote-only server; remote checks are not available on the hosted service yet.")
        raise ResolveError("This registry entry publishes no npm or PyPI package and no GitHub repository to scan.")


def _cand(ref: str, path: str):  # noqa: ANN202
    from agentguard.core.inputs import RefCandidate

    return RefCandidate(ref=ref, path=path)


def _split_npm(locator: str) -> tuple[str, str | None]:
    at = locator.rfind("@")
    return (locator[:at], locator[at + 1:]) if at > 0 else (locator, None)


def plan_archive(fetcher: Fetcher, r: Resolved) -> bytes:
    """Download (or assemble) the archive the sandbox will scan."""
    if r.inline_files is not None:
        return zip_files(r.inline_files)
    assert r.archive_url
    return fetcher.bytes(r.archive_url, github=r.github_archive, expected=r.expected)

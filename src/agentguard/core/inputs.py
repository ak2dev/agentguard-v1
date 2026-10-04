"""Normalizing what a person pastes into Agent Guard Web.

``parse(text)`` turns a link or package spec into a ``ParsedInput`` (what the
user asked for, before resolution) or a ``Rejection`` that lists the supported
forms. Resolution to an immutable reference (commit SHA, exact version) is the
caller's job: the browser does it for GitHub; the Milestone 2 fetcher will do
it for the rest. Nothing here touches the network.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Literal

from pydantic import BaseModel, Field

from .models import ImmutableRef, SourceRef
from .models.enums import SourceKind

MAX_INPUT = 2048

SUPPORTED_INPUTS = (
    "GitHub repository, folder or file: https://github.com/<owner>/<repo>[/tree|blob/<ref>/<path>]",
    "Raw GitHub file: https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>",
    "GitHub gist: https://gist.github.com/<user>/<id>",
    "npm package: npm:<name>@<version> or an npmjs.com package URL",
    "PyPI package: pypi:<name>==<version> or a pypi.org project URL",
    "MCP Registry server name, e.g. io.github.<owner>/<server>",
    "Remote MCP server URL: https://<host>/<path>",
)

_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_GIST_ID = re.compile(r"^[0-9a-f]{20,40}$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$")
_REGISTRY_NAME = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+/[A-Za-z0-9._-]+$")
# Branch names may contain '/', so "<ref>/<path>" is ambiguous; try this many splits.
MAX_REF_SEGMENTS = 4


class RefCandidate(BaseModel):
    ref: str
    path: str = ""


class GitHubLocator(BaseModel):
    owner: str = ""
    repo: str = ""
    mode: Literal["repo", "tree", "blob", "commit", "raw", "gist"]
    # Ordered (ref, path) splits to try; empty means "the default branch".
    candidates: list[RefCandidate] = Field(default_factory=list)
    gist_id: str = ""
    gist_revision: str = ""

    @property
    def single_file(self) -> bool:
        return self.mode in ("blob", "raw")


class ParsedInput(BaseModel):
    source: SourceRef
    github: GitHubLocator | None = None
    # True when this build can fetch and scan it entirely in the browser.
    browser_supported: bool = False
    note: str = ""


class Rejection(BaseModel):
    reason: str
    supported: list[str] = Field(default_factory=lambda: list(SUPPORTED_INPUTS))


def _reject(reason: str) -> Rejection:
    return Rejection(reason=reason)


def _segments(path: str) -> list[str] | None:
    """Split and percent-decode a URL path; None if any segment is unsafe."""
    out = []
    for raw in path.split("/"):
        if raw == "":
            continue
        seg = urllib.parse.unquote(raw)
        if seg in (".", "..") or "\x00" in seg or "\\" in seg or any(ord(c) < 32 for c in seg):
            return None
        out.append(seg)
    return out


def _ref_candidates(rest: list[str], need_path: bool) -> list[RefCandidate]:
    if not rest:
        return []
    if _SHA.match(rest[0]):
        return [RefCandidate(ref=rest[0], path="/".join(rest[1:]))]
    limit = min(len(rest) - (1 if need_path else 0), MAX_REF_SEGMENTS)
    return [RefCandidate(ref="/".join(rest[:i]), path="/".join(rest[i:])) for i in range(1, limit + 1)]


def _github(host: str, segs: list[str]) -> ParsedInput | Rejection:
    if host == "gist.github.com":
        # /<user>/<id>[/<revision>] or /<id>
        ids = [s for s in segs if _GIST_ID.match(s)]
        if not ids:
            return _reject("That gist link has no gist ID.")
        gid = ids[0]
        rest = segs[segs.index(gid) + 1:]
        rev = rest[0] if rest and _SHA.match(rest[0]) else ""
        return _gist(gid, rev)
    if host == "gist.githubusercontent.com":
        # /<user>/<id>/raw/<revision>/<file>
        if len(segs) >= 2 and _GIST_ID.match(segs[1]):
            rev = segs[3] if len(segs) > 3 and segs[2] == "raw" and _SHA.match(segs[3]) else ""
            return _gist(segs[1], rev)
        return _reject("That raw gist link is not in the form gist.githubusercontent.com/<user>/<id>/raw/….")
    if len(segs) < 2:
        return _reject("A GitHub link needs an owner and a repository, e.g. https://github.com/owner/repo.")
    owner, repo = segs[0], segs[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _OWNER.match(owner) or not _REPO.match(repo) or repo in (".", ".."):
        return _reject("That does not look like a GitHub owner/repository name.")
    rest = segs[2:]
    if host == "raw.githubusercontent.com":
        if rest[:2] in (["refs", "heads"], ["refs", "tags"]):
            rest = rest[2:]
        cands = _ref_candidates(rest, need_path=True)
        if not cands:
            return _reject("A raw GitHub link needs a ref and a file path.")
        return _gh(owner, repo, "raw", cands)
    if not rest:
        return _gh(owner, repo, "repo", [])
    kind, tail = rest[0], rest[1:]
    if kind == "tree":
        cands = _ref_candidates(tail, need_path=False)
        return _gh(owner, repo, "tree", cands) if cands else _reject("That GitHub link has no branch, tag or commit.")
    if kind == "blob":
        cands = _ref_candidates(tail, need_path=True)
        return _gh(owner, repo, "blob", cands) if cands else _reject("That GitHub file link has no file path.")
    if kind == "commit" and tail and _SHA.match(tail[0]):
        return _gh(owner, repo, "commit", [RefCandidate(ref=tail[0])])
    return _reject("That GitHub page is not code. Link to the repository, a folder (/tree/…) or a file (/blob/…).")


def _gh(owner: str, repo: str, mode: str, cands: list[RefCandidate]) -> ParsedInput:
    sub = cands[0].path if len(cands) == 1 and cands[0].path else None
    return ParsedInput(
        source=SourceRef(kind=SourceKind.github, locator=f"{owner}/{repo}", subpath=sub),
        github=GitHubLocator(owner=owner, repo=repo, mode=mode, candidates=cands),  # type: ignore[arg-type]
        browser_supported=True,
    )


def _gist(gid: str, rev: str) -> ParsedInput:
    return ParsedInput(
        source=SourceRef(kind=SourceKind.gist, locator=gid),
        github=GitHubLocator(mode="gist", gist_id=gid, gist_revision=rev),
        browser_supported=True,
    )


_SERVER_ONLY = "Fetching this needs the Agent Guard Web server, which this site is not connected to. Download it and scan the files here, or use the CLI."


def _npm(name: str, version: str | None) -> ParsedInput | Rejection:
    if not _NPM_NAME.match(name) or (version and not _VERSION.match(version)):
        return _reject("That is not a valid npm package name or version.")
    loc = f"{name}@{version}" if version else name
    return ParsedInput(source=SourceRef(kind=SourceKind.npm, locator=loc), note=_SERVER_ONLY)


def _pypi(name: str, version: str | None) -> ParsedInput | Rejection:
    if not _PYPI_NAME.match(name) or (version and not _VERSION.match(version)):
        return _reject("That is not a valid PyPI project name or version.")
    loc = f"{name}=={version}" if version else name
    return ParsedInput(source=SourceRef(kind=SourceKind.pypi, locator=loc), note=_SERVER_ONLY)


def parse(text: str) -> ParsedInput | Rejection:
    s = (text or "").strip()
    if not s:
        return _reject("Paste a link or a package name.")
    if len(s) > MAX_INPUT:
        return _reject(f"That input is longer than {MAX_INPUT} characters.")
    if any(c.isspace() for c in s) or any(ord(c) < 32 for c in s):
        return _reject("A link cannot contain spaces or control characters.")

    lower = s.lower()
    if lower.startswith("npm:"):
        spec = s[4:]
        at = spec.rfind("@")
        name, version = (spec[:at], spec[at + 1:]) if at > 0 else (spec, None)
        return _npm(name.lower(), version)
    if lower.startswith("pypi:"):
        name, _, version = s[5:].partition("==")
        return _pypi(name, version or None)
    if "://" not in s and _REGISTRY_NAME.match(s):
        return ParsedInput(source=SourceRef(kind=SourceKind.mcp_registry, locator=s), note=_SERVER_ONLY)
    if "://" not in s and re.match(r"^(?:www\.)?(?:github\.com|gist\.github\.com|raw\.githubusercontent\.com)/", lower):
        s = "https://" + s

    try:
        u = urllib.parse.urlsplit(s)
    except ValueError:
        return _reject("That is not a valid URL.")
    if u.scheme not in ("http", "https") or not u.hostname:
        return _reject("That is not a supported link or package name.")
    if u.username or u.password:
        return _reject("Links with embedded credentials are not accepted.")
    host = u.hostname.lower().rstrip(".")
    if host == "www.github.com":
        host = "github.com"
    segs = _segments(u.path)
    if segs is None:
        return _reject("That link's path contains unsafe segments.")

    if host in ("github.com", "raw.githubusercontent.com", "gist.github.com", "gist.githubusercontent.com"):
        return _github(host, segs)
    if host in ("www.npmjs.com", "npmjs.com"):
        if len(segs) >= 2 and segs[0] == "package":
            name_parts = segs[1:3] if segs[1].startswith("@") and len(segs) >= 3 else segs[1:2]
            rest = segs[1 + len(name_parts):]
            version = rest[1] if len(rest) >= 2 and rest[0] == "v" else None
            return _npm("/".join(name_parts).lower(), version)
        return _reject("That npm link is not a package page (npmjs.com/package/<name>).")
    if host == "pypi.org":
        if len(segs) >= 2 and segs[0] == "project":
            return _pypi(segs[1], segs[2] if len(segs) >= 3 else None)
        return _reject("That PyPI link is not a project page (pypi.org/project/<name>).")
    if u.scheme != "https":
        return _reject("Remote MCP servers must be reached over HTTPS.")
    loc = urllib.parse.urlunsplit(("https", u.netloc.lower(), u.path or "/", "", ""))
    return ParsedInput(source=SourceRef(kind=SourceKind.remote_mcp, locator=loc), note=_SERVER_ONLY)


def github_ref(owner: str, repo: str, sha: str, subpath: str | None = None) -> ImmutableRef:
    """What was actually scanned: a repository at a commit. Report locations link to it."""
    return ImmutableRef(
        kind=SourceKind.github,
        locator=f"{owner}/{repo}" + (f"/{subpath}" if subpath else ""),
        resolved=sha,
        source_url_template=f"https://github.com/{owner}/{repo}/blob/{{resolved}}/{{path}}#L{{line}}",
    )


def gist_ref(gist_id: str, revision: str) -> ImmutableRef:
    return ImmutableRef(
        kind=SourceKind.gist,
        locator=gist_id,
        resolved=revision,
        source_url_template=f"https://gist.github.com/{gist_id}/{{resolved}}",
    )

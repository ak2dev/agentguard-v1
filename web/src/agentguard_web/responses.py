"""Maintainer responses: a public reply attached to a report.

There are no accounts. Whoever can push to the scanned project's GitHub
repository is treated as its maintainer: they commit ``.agentguard/response.md``
to the default branch, with a line ``report: <report key>`` for each report it
answers, and ask the service to check. The dispatcher (the only component with
network egress) reads the file through the allowlisted fetcher at the branch's
current commit and attaches the text, recording the repository and commit so
anyone can verify it. A file that names the report but has no other text
removes the response.

npm and PyPI packages are answered from the GitHub repository their registry
metadata names. Gists and remote MCP servers have no repository to check.
"""

from __future__ import annotations

import re
import urllib.parse

from .fetch import Fetcher
from .models import StoredReport
from .resolve import _enc

RESPONSE_PATH = ".agentguard/response.md"
MAX_FILE_BYTES = 16 * 1024
MAX_TEXT = 4000
_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPORT_LINE = re.compile(r"(?mi)^[ \t]*report:[ \t]*([0-9a-f]{32})[ \t]*\r?$\n?")
_GITHUB = re.compile(
    r"^(?:git\+)?(?:(?:https?|git|ssh)://(?:git@)?(?:www\.)?github\.com/|git@github\.com:|github:)"
    r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?(?:[#?].*)?$"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")


class ResponseError(ValueError):
    """A user-facing reason the response could not be attached."""


def github_repo(url: str) -> tuple[str, str] | None:
    m = _GITHUB.match(url.strip())
    if m and m.group(2) not in (".", ".."):
        return m.group(1), m.group(2)
    return None


def repository_for(fetcher: Fetcher, rec: StoredReport) -> tuple[str, str]:
    """The GitHub repository whose maintainers may respond to this report."""
    if rec.kind == "github":
        owner, repo = rec.locator.split("/")[:2]
        return owner, repo
    if rec.kind == "npm":
        status, doc = fetcher.json(f"https://registry.npmjs.org/{urllib.parse.quote(rec.locator, safe='@')}",
                                   accept="application/json")
        repo_field = doc.get("repository") if status != 404 and isinstance(doc, dict) else None
        url = repo_field.get("url") if isinstance(repo_field, dict) else repo_field
        if isinstance(url, str) and (found := github_repo(url) or github_repo(f"github:{url}")):
            return found
        raise ResponseError(f"The npm package {rec.locator} does not name a GitHub repository, so there is no repository to check.")
    if rec.kind == "pypi":
        status, doc = fetcher.json(f"https://pypi.org/pypi/{urllib.parse.quote(rec.locator)}/json")
        info = (doc.get("info") or {}) if status != 404 and isinstance(doc, dict) else {}
        urls = info.get("project_urls") or {}
        ranked = sorted(urls.items(), key=lambda kv: not re.search(r"(?i)source|repo|code|github", kv[0])) if isinstance(urls, dict) else []
        for _label, url in [*ranked, ("home", info.get("home_page"))]:
            if isinstance(url, str) and (found := github_repo(url)):
                return found
        raise ResponseError(f"The PyPI project {rec.locator} does not name a GitHub repository, so there is no repository to check.")
    raise ResponseError("Maintainer responses are available for reports of GitHub repositories, and of npm or PyPI "
                        "packages that name their GitHub repository.")


def read_response(fetcher: Fetcher, owner: str, repo: str) -> tuple[str, str]:
    """(commit, file text) of the response file at the default branch's current commit."""
    base = f"https://api.github.com/repos/{_enc(owner)}/{_enc(repo)}"
    status, doc = fetcher.json(base, github=True)
    if status == 404 or not isinstance(doc, dict) or doc.get("private"):
        raise ResponseError(f"github.com/{owner}/{repo} was not found (only public repositories can respond).")
    branch = str(doc.get("default_branch") or "main")
    status, sha = fetcher.text(f"{base}/commits/{_enc(branch)}", github=True, accept="application/vnd.github.sha")
    sha = sha.strip()
    if status == 404 or not _SHA.match(sha):
        raise ResponseError(f"Could not read the default branch of github.com/{owner}/{repo}.")
    status, text = fetcher.text(f"https://raw.githubusercontent.com/{_enc(owner)}/{_enc(repo)}/{sha}/{RESPONSE_PATH}")
    if status == 404:
        raise ResponseError(f"No {RESPONSE_PATH} on the default branch of github.com/{owner}/{repo} "
                            f"(checked commit {sha[:12]}).")
    return sha, text


def parse_response(text: str, key: str) -> str:
    """The response text for report ``key`` ("" removes the response)."""
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise ResponseError(f"{RESPONSE_PATH} is larger than {MAX_FILE_BYTES // 1024} KB.")
    if key not in {k.lower() for k in _REPORT_LINE.findall(text)}:
        raise ResponseError(f"{RESPONSE_PATH} does not name this report. Add the line `report: {key}` to it.")
    body = _CONTROL.sub("", _REPORT_LINE.sub("", text).replace("\r\n", "\n"))
    body = re.sub(r"\n{3,}", "\n\n", body).strip()
    if len(body) > MAX_TEXT:
        raise ResponseError(f"The response is longer than {MAX_TEXT} characters.")
    return body

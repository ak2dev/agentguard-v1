"""Static extraction of external dependencies an attacker could take over
("SkillJacking" / "MCPJacking"): GitHub owners, npm / PyPI package names and
download / install domains (including cloud-app hostnames such as
``<app>.azurewebsites.net``) referenced by skills, scripts and MCP configs.

Pure: this only finds references. The opt-in ``--check-hijackable`` collector
(``agentguard.net.hijack``) looks them up; the ``supply.hijack`` analyzer
reports the recorded results. Both use this module so they agree on what was
referenced and where.
"""

from __future__ import annotations

import json
import posixpath
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import regex

from ..artifacts import ArtifactText, TextUnit
from ..inventory import Inventory
from ..mcp_config import package_arg, split_package_spec
from ..models import Component, Span
from ..models.enums import ArtifactRole, Transport
from ..textutil import TIMEOUT

KINDS = ("github_owner", "npm", "pypi", "domain")
_MARKDOWN_ROLES = frozenset({ArtifactRole.skill_md, ArtifactRole.instruction_md, ArtifactRole.reference})
MAX_REFS_PER_KIND = 100

# First path segments of github.com that are site pages, not accounts.
_GH_RESERVED = frozenset({
    "about", "account", "advisories", "apps", "blog", "codespaces", "collections", "contact", "copilot", "customer-stories",
    "dashboard", "enterprise", "events", "explore", "features", "git-guides", "github", "issues", "join", "login",
    "marketplace", "models", "new", "notifications", "orgs", "organizations", "pricing", "pulls", "readme", "resources",
    "search", "security", "settings", "site", "solutions", "sponsors", "team", "topics", "trending", "users",
})
_OWNER = r"([A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38})"
_GH = regex.compile(
    r"(?<![\w.-])(?:(?:git\+)?(?:https?|ssh|git)://(?:git@)?(?:www\.)?|git@)?github\.com[/:]" + _OWNER + r"/([A-Za-z0-9._-]+)"
    r"|https?://(?:raw|gist|objects|codeload)\.githubusercontent\.com/" + _OWNER + r"/"
    r"|https?://(?:codeload|gist)\.github\.com/" + _OWNER + r"/"
    r"|(?<![\w.-])github:" + _OWNER + r"/[A-Za-z0-9._-]+"
    r"|(?<![\w.@-])" + _OWNER + r"\.github\.io\b",
    regex.IGNORECASE,
)
# Forms that fetch code by themselves (raw files, archives, git installs, Pages).
_GH_FETCH = regex.compile(r"githubusercontent\.com|codeload\.|^git\+|^github:|\.github\.io|/releases/download/|/archive/|\.git\b", regex.IGNORECASE)

# A line that downloads, installs, clones or executes something.
_FETCH_CTX = regex.compile(
    r"(?i)\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|aria2c|git\s+(?:clone|submodule\s+add|remote\s+add)"
    r"|(?:pip3?|uv\s+pip|pipx|npm|pnpm|yarn|bun)\s+(?:install|i|add)|uv\s+(?:add|tool\s+install)|npx|uvx|bunx|dlx|go\s+install|cargo\s+install"
    r"|brew\s+(?:install|tap)|apt(?:-get)?\s+install|docker\s+(?:pull|run)|urlretrieve|urlopen|requests\.get|httpx\.get|fetch\s*\("
    r"|download|install|clone|source\s+<\(|iex\b|\|\s*(?:ba|z|da)?sh\b|\|\s*python3?\b|\|\s*node\b)"
)
_URL = regex.compile(r"(?i)\b(?:git\+)?https?://([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::\d{1,5})?(/[^\s\"'`<>)\]}]*)?", regex.IGNORECASE)
_INDEX_FLAG = regex.compile(r"(?:--(?:extra-)?index-url|--find-links|-[if]|--registry|registry\s*=)\s*[=\s]?\s*[\"']?https?://", regex.IGNORECASE)
_INSTALLER_EXT = regex.compile(r"\.(?:sh|bash|ps1|psm1|bat|cmd|py|js|mjs|exe|msi|dmg|pkg|deb|rpm|appimage|tar\.gz|tgz|tar\.xz|zip|whl|jar|bin)$", regex.IGNORECASE)
# Infrastructure that obviously resolves; not worth a lookup.
_WELL_KNOWN = regex.compile(
    r"(?:^|\.)(?:github\.com|githubusercontent\.com|github\.io|githubassets\.com|gitlab\.com|bitbucket\.org|npmjs\.(?:org|com)|"
    r"yarnpkg\.com|pypi\.org|pythonhosted\.org|python\.org|nodejs\.org|astral\.sh|deno\.land|jsdelivr\.net|unpkg\.com|"
    r"docker\.(?:com|io)|brew\.sh|rustup\.rs|rust-lang\.org|go\.dev|golang\.org|microsoft\.com|windows\.net|azure\.com|"
    r"google\.com|googleapis\.com|gstatic\.com|amazonaws\.com|cloudflare\.com|anthropic\.com|claude\.ai|claude\.com|"
    r"openai\.com|modelcontextprotocol\.io|apple\.com|ubuntu\.com|debian\.org|mozilla\.org|w3\.org|schema\.org|json-schema\.org)$"
)
# Cloud-app hostnames whose name is a per-app slot on the platform's domain. On
# these platforms a deleted app's name stops resolving (no wildcard DNS) and
# anyone can create an app with that name. Platforms with wildcard DNS
# (herokuapp.com, vercel.app, netlify.app, github.io, ...) are not listed: a
# free name there still resolves, so DNS says nothing.
_CLOUD_APPS: tuple[tuple[regex.Pattern[str], str], ...] = tuple((regex.compile(p), name) for p, name in (
    (r"^(?:[a-z0-9-]+\.)*?([a-z0-9-]+)(?:\.scm)?\.azurewebsites\.net$", "Azure App Service"),
    (r"^(?:[a-z0-9-]+\.)*?([a-z0-9-]+)\.[a-z0-9]+\.cloudapp\.azure\.com$", "Azure (cloudapp.azure.com)"),
    (r"^(?:[a-z0-9-]+\.)*?([a-z0-9-]+)\.trafficmanager\.net$", "Azure Traffic Manager"),
    (r"^(?:[a-z0-9-]+\.)*?([a-z0-9-]+)\.blob\.core\.windows\.net$", "Azure Blob Storage"),
    (r"^(?:[a-z0-9-]+\.)*?([a-z0-9-]+)\.pages\.dev$", "Cloudflare Pages"),
    (r"^(?:[a-z0-9-]+\.)*?([a-z0-9-]+)\.workers\.dev$", "Cloudflare Workers"),
    (r"^(?:[a-z0-9-]+\.)*?([a-z0-9-]+)\.fly\.dev$", "Fly.io"),
    (r"^(?:[a-z0-9-]+\.)*?([a-z0-9-]+)\.[a-z]{2}-[a-z]+-\d\.elasticbeanstalk\.com$", "AWS Elastic Beanstalk"),
))
_NOT_PUBLIC = regex.compile(
    r"(?:^|\.)(?:localhost|local|internal|lan|home|corp|test|invalid|example|onion)$|(?:^|\.)example\.(?:com|net|org)$|^[\d.]+$|^[0-9a-f:]+$"
)
# Second-level labels under which ccTLDs register (co.uk, com.au, ...): a
# deliberately small stand-in for the Public Suffix List.
_SLD = frozenset({"ac", "co", "com", "edu", "gov", "go", "ltd", "ne", "net", "nom", "or", "org", "plc", "sch"})

# Package installs and runners. Group 1 = command, group 2 = the rest of the line.
_PKG_CMD = regex.compile(
    r"(?<![\w./-])(npx|bunx|pnpm\s+dlx|yarn\s+dlx|npm\s+(?:install|i|add|exec)|pnpm\s+(?:add|install|i)|yarn\s+(?:global\s+)?add"
    r"|bun\s+(?:add|install|i)|python3?\s+-m\s+pip\s+install|pip3?\s+install|uv\s+pip\s+install|uv\s+add|uv\s+tool\s+(?:install|run)"
    r"|uvx|pipx\s+(?:install|run))\b([^\n`'\"|;&<>()]*)"
)
_RUNNER_ONLY_FIRST = ("npx", "bunx", "dlx", "exec", "uvx", "run")
_FLAG_WITH_VALUE = frozenset({
    "-r", "--requirement", "-e", "--editable", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
    "--registry", "--prefix", "--target", "-t", "--python", "--with", "-w", "--cache", "--userconfig", "--root", "--platform",
})
_FLAG_IS_PACKAGE = frozenset({"-p", "--package", "--from", "--spec"})
_NPM_NAME = regex.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_PYPI_NAME = regex.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_PLACEHOLDERS = frozenset({
    "package", "packages", "pkg", "name", "package-name", "package_name", "packagename", "your-package", "my-package",
    "module", "library", "lib", "tool", "server", "foo", "bar", "baz", "example", "x", "y", "...",
})


@dataclass(frozen=True)
class DepRef:
    kind: str          # github_owner | npm | pypi | domain
    name: str          # account, package or domain (case-folded where the registry is case-insensitive)
    raw: str           # the referencing text
    start: int         # offsets in the text it was found in
    end: int
    install: bool      # used to fetch / install / run (vs. a plain link)


@dataclass(frozen=True)
class LocatedRef:
    ref: DepRef
    component_id: str
    span: Span
    snippet: str
    unit: TextUnit | None = None


def registrable_domain(host: str) -> str:
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def cloud_app_slot(host: str) -> tuple[str, str] | None:
    """(platform, app name) when ``host`` is an app slot on a cloud platform
    where a free name does not resolve; None otherwise."""
    h = host.lower().rstrip(".")
    for pat, platform in _CLOUD_APPS:
        m = pat.match(h, timeout=TIMEOUT)
        if m:
            return platform, m.group(1)
    return None


def _pypi_norm(name: str) -> str:
    return regex.sub(r"[-_.]+", "-", name).lower()


def _package_token(tok: str, eco: str) -> str | None:
    t = tok.strip().strip(",")
    if not t or t.startswith("-") or any(c in t for c in "$%{}<>*\\") or "://" in t or t.startswith(("git+", "github:", "file:", ".", "/", "~")):
        return None
    if regex.search(r"\.(?:whl|tar\.gz|tgz|zip|txt|toml|cfg|json|lock)$", t, regex.IGNORECASE, timeout=TIMEOUT):
        return None
    if eco == "npm":
        name, _ver = split_package_spec(t)
        name = name.lower()
        if name.count("/") > (1 if name.startswith("@") else 0) or not _NPM_NAME.match(name):
            return None
    else:
        name = regex.split(r"[\[=<>!~;@ ]", t, maxsplit=1)[0]
        if not _PYPI_NAME.match(name):
            return None
        name = _pypi_norm(name)
    if name in _PLACEHOLDERS or len(name) < 2:
        return None
    return name


def _packages_in(cmd: str, rest: str) -> list[tuple[str, str, int]]:
    """(ecosystem, name, offset-in-rest) for each package a command line names."""
    c = regex.sub(r"\s+", " ", cmd.lower())
    eco = "pypi" if any(w in c for w in ("pip", "uv", "pipx")) else "npm"
    only_first = c.split(" ")[-1] in _RUNNER_ONLY_FIRST
    out: list[tuple[str, str, int]] = []
    toks = list(regex.finditer(r"\S+", rest, timeout=TIMEOUT))
    i = 0
    while i < len(toks):
        tok = toks[i].group(0)
        low = tok.lower()
        if low in _FLAG_IS_PACKAGE and i + 1 < len(toks):
            name = _package_token(toks[i + 1].group(0), eco)
            if name:
                out.append((eco, name, toks[i + 1].start()))
            break
        if "=" in low and low.split("=", 1)[0] in _FLAG_IS_PACKAGE:
            name = _package_token(tok.split("=", 1)[1], eco)
            if name:
                out.append((eco, name, toks[i].start() + len(tok.split("=", 1)[0]) + 1))
            break
        if low in _FLAG_WITH_VALUE:
            i += 2
            continue
        if low.startswith("-"):
            i += 1
            continue
        name = _package_token(tok, eco)
        if name:
            out.append((eco, name, toks[i].start()))
        elif only_first or not regex.match(r"^[\w@.\[\]=<>!~,/-]+$", tok, timeout=TIMEOUT):
            break  # a URL/path/placeholder runner target, or the end of the package list
        if only_first:
            break
        i += 1
    return out


def find_refs(text: str, prose: Callable[[int], bool] | None = None) -> list[DepRef]:
    """All dependency references in one text, line by line. ``prose(offset)``
    says whether an offset is Markdown prose: there, package names count only
    inside inline code (``pip install x`` in a sentence is usually not a command)."""
    refs: list[DepRef] = []
    pos = 0
    for line in text.splitlines(keepends=True):
        if len(line) <= 20_000:
            refs.extend(_line_refs(line.rstrip("\r\n"), pos, prose))
        pos += len(line)
    return refs


def _line_refs(line: str, base: int, prose: Callable[[int], bool] | None = None) -> Iterator[DepRef]:
    fetch_line = bool(_FETCH_CTX.search(line, timeout=TIMEOUT))
    for m in _GH.finditer(line, timeout=TIMEOUT):
        owner = next((g for g in (m.group(1), m.group(3), m.group(4), m.group(5), m.group(6)) if g), "")
        if not owner or owner.lower() in _GH_RESERVED:
            continue
        raw = m.group(0)
        yield DepRef("github_owner", owner.lower(), raw, base + m.start(), base + m.end(),
                     install=fetch_line or bool(_GH_FETCH.search(raw + line[m.end():m.end() + 80], timeout=TIMEOUT)))
    for m in _URL.finditer(line, timeout=TIMEOUT):
        host = m.group(1).lower().rstrip(".")
        if "." not in host or _NOT_PUBLIC.search(host, timeout=TIMEOUT) or (
                _WELL_KNOWN.search(host, timeout=TIMEOUT) and cloud_app_slot(host) is None):
            continue
        path = (m.group(2) or "").split("?", 1)[0].split("#", 1)[0]
        before = line[max(0, m.start() - 40):m.start()]
        if fetch_line or _INSTALLER_EXT.search(path, timeout=TIMEOUT) or _INDEX_FLAG.search(before + "https://", timeout=TIMEOUT):
            yield DepRef("domain", host, m.group(0), base + m.start(), base + m.end(), install=True)
    for m in _PKG_CMD.finditer(line, timeout=TIMEOUT):
        if prose is not None and prose(base + m.start()) and line[:m.start()].count("`") % 2 == 0:
            continue
        for eco, name, off in _packages_in(m.group(1), m.group(2)):
            s = m.start(2) + off
            tok = line[s:].split(maxsplit=1)[0]
            yield DepRef(eco, name, tok, base + s, base + s + len(tok), install=True)


def _manifest_refs(at: ArtifactText) -> Iterator[DepRef]:
    """Dependencies declared by a package.json or requirements*.txt inside a skill."""
    name = posixpath.basename(at.path).lower()
    if name == "package.json":
        try:
            doc = json.loads(at.text)
        except ValueError:
            return
        if not isinstance(doc, dict):
            return
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            deps = doc.get(key)
            if not isinstance(deps, dict):
                continue
            for dep, spec in deps.items():
                if not isinstance(dep, str) or (isinstance(spec, str) and regex.match(r"^(?:file:|link:|workspace:|git|https?:|npm:)", spec)):
                    continue
                pkg = _package_token(dep, "npm")
                i = at.text.find(json.dumps(dep))
                if pkg and i >= 0:
                    yield DepRef("npm", pkg, dep, i + 1, i + 1 + len(dep), install=True)
    elif regex.match(r"^requirements[\w.-]*\.(?:txt|in)$", name, timeout=TIMEOUT):
        pos = 0
        for line in at.text.splitlines(keepends=True):
            body = line.split("#", 1)[0].strip()
            if body and not body.startswith("-") and "://" not in body and "/" not in body:
                pkg = _package_token(body, "pypi")
                if pkg:
                    off = pos + line.find(body)
                    yield DepRef("pypi", pkg, body, off, off + len(body), install=True)
            pos += len(line)


def _config_refs(comp: Component) -> Iterator[tuple[DepRef, str]]:
    """Packages and remote URLs of a configured MCP server (span = its config entry)."""
    spec = comp.server
    if spec is None:
        return
    runner, pkg = package_arg(spec.command, spec.args)
    if pkg:
        eco = "pypi" if runner in ("uvx", "pipx") else "npm"
        name = _package_token(pkg, eco)
        if name:
            yield DepRef(eco, name, pkg, 0, 0, install=True), pkg
    if spec.url and spec.transport != Transport.stdio:
        for ref in _line_refs(f"curl {spec.url}", 0):
            if ref.kind in ("domain", "github_owner"):
                yield DepRef(ref.kind, ref.name, spec.url, 0, 0, install=True), spec.url


def locate_refs(inv: Inventory) -> list[LocatedRef]:
    """Every dependency reference in the inventory, with where it was found.
    Deterministic order; at most ``MAX_REFS_PER_KIND`` distinct names per kind."""
    out: list[LocatedRef] = []
    for path in sorted(inv.texts):
        at = inv.texts[path]
        if at.artifact.role in (ArtifactRole.lockfile, ArtifactRole.binary, ArtifactRole.archive):
            continue
        cid = at.artifact.component_id
        markdown = at.artifact.role in _MARKDOWN_ROLES
        seen: set[tuple[str, str, int, int]] = set()
        for unit in at.units:
            prose = None
            if markdown and unit.base is not None:
                prose = (lambda u: lambda off: not at.in_code(u.base + u.norm.orig(off)))(unit)
            for ref in find_refs(unit.norm.text, prose):
                span = _unit_span(at, unit, ref.start, ref.end)
                key = (ref.kind, ref.name, span.start_line or 0, span.start_col or 0)
                if key in seen:
                    continue
                seen.add(key)
                out.append(LocatedRef(ref, unit.component_id or cid, span, _snippet(unit, ref), unit))
        for ref in _manifest_refs(at):
            out.append(LocatedRef(ref, cid, at.span(ref.start, ref.end), ref.raw))
    for comp in sorted(inv.components.values(), key=lambda c: c.id):
        if comp.server is None:
            continue
        span = comp.server.config_span or Span(path=comp.root or comp.name)
        for ref, snippet in _config_refs(comp):
            out.append(LocatedRef(ref, comp.id, span, snippet))
    names: dict[str, list[str]] = {k: [] for k in KINDS}
    kept: list[LocatedRef] = []
    for lr in out:
        lst = names[lr.ref.kind]
        if lr.ref.name not in lst:
            if len(lst) >= MAX_REFS_PER_KIND:
                continue
            lst.append(lr.ref.name)
        kept.append(lr)
    return kept


def _unit_span(at: ArtifactText, unit: TextUnit, start: int, end: int) -> Span:
    if unit.base is not None:
        return at.span(unit.base + unit.norm.orig(start), unit.base + unit.norm.orig(end))
    if unit.anchor is not None:
        return at.span(*unit.anchor)
    return unit.anchor_span or Span(path=at.path)


def _snippet(unit: TextUnit, ref: DepRef) -> str:
    text = unit.norm.text
    s = text.rfind("\n", 0, ref.start) + 1
    e = text.find("\n", ref.end)
    return text[s: e if e >= 0 else len(text)].strip()[:300]


def lookup_keys(refs: list[LocatedRef]) -> dict[str, list[str]]:
    """Distinct names to look up per kind (domains: the full host)."""
    out: dict[str, list[str]] = {k: [] for k in KINDS}
    for lr in refs:
        lst = out[lr.ref.kind]
        if lr.ref.name not in lst:
            lst.append(lr.ref.name)
    return out

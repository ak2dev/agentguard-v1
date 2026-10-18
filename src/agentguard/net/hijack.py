"""Opt-in lookups for dependencies an attacker could take over
(``--check-hijackable``; "SkillJacking" / "MCPJacking"). All through
SafeHttpClient; every lookup is read-only and sends only the name checked.

* GitHub owner: https://api.github.com/users/<owner> — 404 means the account
  was deleted, renamed or suspended (the first two free the name). With a
  token (``AGENTGUARD_GITHUB_TOKEN`` or ``GITHUB_TOKEN``) these requests, and
  only these, carry it, which raises the lookup budget.
* npm: https://registry.npmjs.org/<name> (abbreviated metadata) — 404 means
  not registered; a document without versions means fully unpublished.
* PyPI: HEAD https://pypi.org/pypi/<name>/json — 404 means not registered.
* Domain: resolved first (the scanner's resolver); only a domain that does not
  resolve is checked with RDAP (server from the IANA bootstrap file
  https://data.iana.org/rdap/dns.json): 404 means unregistered, a past
  expiration date or a pending-delete / redemption status means expired.
  A cloud-app hostname (``<app>.azurewebsites.net``, ``<project>.pages.dev``,
  ...) that does not resolve is reported as a possibly free app name instead:
  the platform's own domain is always registered, so RDAP is not asked.
"""

from __future__ import annotations

import datetime as dt
import urllib.parse

from ..core.extract.dependencies import cloud_app_slot, registrable_domain
from ..core.models import DependencyFact
from .safe_http import BlockedRequest, FetchError, SafeHttpClient

MAX_GITHUB_LOOKUPS = 50  # unauthenticated GitHub API allows 60 requests per hour
MAX_GITHUB_LOOKUPS_AUTHENTICATED = 500  # an Actions GITHUB_TOKEN allows 1,000 per hour, a personal token 5,000
GITHUB_API_HOST = "api.github.com"
_BAD_TOKEN = "GitHub rejected the token (HTTP 401)"
_EXPIRED_STATUS = {"pending delete", "redemption period", "pending restore"}


def check_dependencies(client: SafeHttpClient, keys: dict[str, list[str]], today: dt.date | None = None,
                       github_token: str | None = None) -> list[DependencyFact]:
    today = today or dt.date.today()
    out: list[DependencyFact] = []
    limited = False
    budget = MAX_GITHUB_LOOKUPS_AUTHENTICATED if github_token else MAX_GITHUB_LOOKUPS
    for i, owner in enumerate(keys.get("github_owner", [])):
        if limited or i >= budget:
            out.append(DependencyFact(kind="github_owner", name=owner, status="unknown", error="lookup budget exhausted"))
            continue
        fact = github_owner(client, owner, github_token)
        if fact.error == _BAD_TOKEN:  # a stale token: continue anonymously, with the anonymous budget
            github_token, budget = None, MAX_GITHUB_LOOKUPS
            fact = github_owner(client, owner) if i < budget else fact
        limited = fact.error == "GitHub API rate limit reached"
        out.append(fact)
    out += [npm_package(client, n) for n in keys.get("npm", [])]
    out += [pypi_package(client, n) for n in keys.get("pypi", [])]
    bootstrap: dict[str, str] | None = None
    for host in keys.get("domain", []):
        if _resolves(client, host):
            out.append(DependencyFact(kind="domain", name=host, status="exists"))
            continue
        slot = cloud_app_slot(host)
        if slot:
            platform, app = slot
            out.append(DependencyFact(kind="domain", name=host, status="unclaimed",
                                      detail=f"{host} does not resolve; the {platform} name '{app}' may be free to claim"))
            continue
        if bootstrap is None:
            bootstrap = rdap_bootstrap(client)
        out.append(domain_registration(client, host, bootstrap, today))
    return out


def _github_headers(url: str, token: str | None) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    # The token goes to the GitHub API host only (SafeHttpClient also drops it on a cross-host redirect).
    if token and urllib.parse.urlsplit(url).hostname == GITHUB_API_HOST:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_owner(client: SafeHttpClient, owner: str, token: str | None = None) -> DependencyFact:
    fact = DependencyFact(kind="github_owner", name=owner, status="unknown")
    url = f"https://{GITHUB_API_HOST}/users/{urllib.parse.quote(owner, safe='')}"
    try:
        r = client.get(url, headers=_github_headers(url, token))
    except (BlockedRequest, FetchError) as exc:
        fact.error = str(exc)[:200]
        return fact
    if r.status == 200:
        fact.status = "exists"
    elif r.status == 404:
        fact.status = "missing"
        fact.detail = "GitHub reports no such user or organization: deleted, renamed or suspended"
    elif r.status == 401:
        fact.error = _BAD_TOKEN
    elif r.status in (403, 429):
        fact.error = "GitHub API rate limit reached"
    else:
        fact.error = f"HTTP {r.status}"
    return fact


def npm_package(client: SafeHttpClient, name: str) -> DependencyFact:
    fact = DependencyFact(kind="npm", name=name, status="unknown")
    try:
        r = client.get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}",
                       headers={"Accept": "application/vnd.npm.install-v1+json"})
    except BlockedRequest as exc:
        if "exceeds" in str(exc):  # a very large document: the package certainly exists
            fact.status = "exists"
        else:
            fact.error = str(exc)[:200]
        return fact
    except FetchError as exc:
        fact.error = str(exc)[:200]
        return fact
    if r.status == 404:
        fact.status = "missing"
        fact.detail = "registry.npmjs.org returns 404"
    elif r.status == 200:
        try:
            doc = r.json()
        except ValueError:
            fact.error = "unreadable registry response"
            return fact
        if isinstance(doc, dict) and not doc.get("versions"):
            fact.status = "unpublished"
            fact.detail = "every version was unpublished"
        else:
            fact.status = "exists"
    else:
        fact.error = f"HTTP {r.status}"
    return fact


def pypi_package(client: SafeHttpClient, name: str) -> DependencyFact:
    fact = DependencyFact(kind="pypi", name=name, status="unknown")
    try:
        r = client.request("HEAD", f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    except (BlockedRequest, FetchError) as exc:
        fact.error = str(exc)[:200]
        return fact
    if r.status == 200:
        fact.status = "exists"
    elif r.status == 404:
        fact.status = "missing"
        fact.detail = "pypi.org returns 404"
    else:
        fact.error = f"HTTP {r.status}"
    return fact


def _resolves(client: SafeHttpClient, host: str) -> bool:
    try:
        return bool(client.resolver(host, 443))
    except (FetchError, OSError, UnicodeError):
        return False


def rdap_bootstrap(client: SafeHttpClient) -> dict[str, str]:
    """TLD -> RDAP base URL, from the IANA bootstrap registry (RFC 9224)."""
    try:
        doc = client.get("https://data.iana.org/rdap/dns.json", headers={"Accept": "application/json"}).json()
    except (BlockedRequest, FetchError, ValueError):
        return {}
    out: dict[str, str] = {}
    for entry in doc.get("services", []) if isinstance(doc, dict) else []:
        if not (isinstance(entry, list) and len(entry) == 2):
            continue
        tlds, urls = entry
        base = next((u for u in urls if isinstance(u, str) and u.startswith("https://")), None)
        for tld in tlds if base else []:
            out[str(tld).lower()] = base if base.endswith("/") else base + "/"
    return out


def domain_registration(client: SafeHttpClient, host: str, bootstrap: dict[str, str], today: dt.date) -> DependencyFact:
    reg = registrable_domain(host)
    fact = DependencyFact(kind="domain", name=host, status="no_dns", detail=f"{host} does not resolve")
    base = bootstrap.get(reg.rsplit(".", 1)[-1])
    if not base:
        fact.detail += f"; registration of {reg} not checked (no RDAP service for its TLD)"
        return fact
    try:
        r = client.get(f"{base}domain/{urllib.parse.quote(reg)}", headers={"Accept": "application/rdap+json"})
    except (BlockedRequest, FetchError) as exc:
        fact.error = str(exc)[:200]
        return fact
    if r.status == 404:
        fact.status = "unregistered"
        fact.detail = f"RDAP has no registration for {reg}"
        return fact
    if r.status != 200:
        fact.error = f"RDAP HTTP {r.status}"
        return fact
    try:
        doc = r.json()
    except ValueError:
        fact.error = "unreadable RDAP response"
        return fact
    statuses = {str(s).lower() for s in doc.get("status", [])} if isinstance(doc, dict) else set()
    expires = None
    for ev in doc.get("events", []) if isinstance(doc, dict) else []:
        if isinstance(ev, dict) and ev.get("eventAction") == "expiration":
            try:
                expires = dt.datetime.fromisoformat(str(ev.get("eventDate", "")).replace("Z", "+00:00")).date()
            except ValueError:
                pass
    if statuses & _EXPIRED_STATUS or (expires is not None and expires < today):
        fact.status = "expired"
        fact.detail = f"{reg} " + (f"expired on {expires}" if expires and expires < today else "is pending deletion")
    else:
        fact.detail = f"{host} does not resolve; {reg} is registered" + (f" until {expires}" if expires else "")
    return fact

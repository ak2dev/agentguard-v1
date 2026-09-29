"""Gather opt-in network data before a scan (host side). The engine then
evaluates it as plain data, so the core stays network-free."""

from __future__ import annotations

from ..core.inventory import build_inventory
from ..core.mcp_config import package_arg, split_package_spec
from ..core.models import PackageFacts, ScanOptions
from ..core.models.enums import Transport
from ..core.tree import ArtifactTree
from .registries import npm_facts, osv_lookup, pypi_facts
from .remote import probe_server
from .safe_http import SafeHttpClient


def collect(tree: ArtifactTree, options: ScanOptions, client: SafeHttpClient | None = None) -> None:
    net = options.network
    if not any(net.model_dump().values()):
        return
    client = client or SafeHttpClient()
    inv = build_inventory(tree, options.limits)
    servers = [c for c in inv.components.values() if c.server]
    if net.live_metadata or net.auth_checks:
        seen: set[str] = set()
        for c in sorted(servers, key=lambda c: c.id):
            spec = c.server
            if spec is None or spec.transport == Transport.stdio or not spec.url or spec.url in seen:
                continue
            seen.add(spec.url)
            options.remote_probes.append(
                probe_server(client, c.name, spec.url, spec.config_path, metadata=net.live_metadata, auth=net.auth_checks))
    if net.provenance or net.osv or net.registry:
        facts: list[PackageFacts] = []
        seen_pkgs: set[tuple[str, str]] = set()
        for c in sorted(servers, key=lambda c: c.id):
            runner, pkg = package_arg(c.server.command if c.server else None, c.server.args if c.server else [])
            if not pkg:
                continue
            name, ver = split_package_spec(pkg)
            eco = "pypi" if runner in ("uvx", "pipx") else "npm"
            if (eco, name) in seen_pkgs:
                continue
            seen_pkgs.add((eco, name))
            facts.append(npm_facts(client, name, ver) if eco == "npm" else pypi_facts(client, name, ver))
        if net.osv:
            osv_lookup(client, facts)
        options.package_facts.extend(facts)
    options.network_hosts.extend(client.hosts_contacted)

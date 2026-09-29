"""Rules over opt-in network results (pure: they read recorded data from
ScanOptions, never the network). AG-AUTH-* and AG-SC-020..023."""

from __future__ import annotations

import datetime as dt
import urllib.parse
from typing import ClassVar

from ..models import Component, RemoteProbe, Span
from ..models.enums import ComponentKind, Confidence, EvidenceKind, Severity
from .base import Context

KNOWN_VERSIONS = ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
CURRENT_OK = ("2026-07-28", "2025-11-25", "2025-06-18")


def _server_component(ctx: Context, probe: RemoteProbe) -> Component | None:
    for (path, _proj, name), cid in ctx.inventory.server_components.items():
        if name == probe.server_name and (not probe.config_path or path == probe.config_path):
            return ctx.inventory.components.get(cid)
    return None


def _norm_resource(u: str) -> str:
    p = urllib.parse.urlsplit(u)
    return f"{p.scheme.lower()}://{(p.hostname or '').lower()}{':' + str(p.port) if p.port else ''}{p.path.rstrip('/')}"


class AuthAnalyzer:
    id: ClassVar[str] = "auth"
    requires: ClassVar[frozenset[str]] = frozenset({"network"})
    network_feature: ClassVar[str] = "auth_checks"
    rules: ClassVar[tuple[str, ...]] = tuple(f"AG-AUTH-{i:03d}" for i in range(1, 12))

    def run(self, ctx: Context) -> None:
        for probe in sorted(ctx.options.remote_probes, key=lambda p: (p.server_name, p.url)):
            comp = _server_component(ctx, probe)
            cid = comp.id if comp else []
            span = comp.server.config_span if comp and comp.server else Span(path=probe.config_path or probe.url)

            def emit(rid: str, msg: str, snippet: str = "", sev: Severity | None = None, conf: Confidence | None = None) -> None:
                ctx.emit(rid, component_ids=cid, span=span, snippet=snippet or probe.url, match=f"{probe.url}:{rid}:{snippet[:80]}",
                         kind=EvidenceKind.metadata, message=msg, severity=sev, confidence=conf)

            if not probe.reachable:
                if probe.tls_error:
                    emit("AG-AUTH-009", f"TLS verification failed for '{probe.server_name}': {probe.tls_error[:160]}")
                continue
            if probe.tls_version and probe.tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
                emit("AG-AUTH-009", f"'{probe.server_name}' negotiated {probe.tls_version}.", probe.tls_version)
            if probe.unauthenticated_list:
                emit("AG-AUTH-001", f"'{probe.server_name}' answered discovery/listing without authentication "
                                    f"(protocol {probe.protocol_version or 'unknown'}).")
            ver = probe.protocol_version
            if ver and ver not in CURRENT_OK:
                emit("AG-AUTH-010", f"'{probe.server_name}' advertises protocol version {ver}"
                                    + (" (not a recognized version)." if ver not in KNOWN_VERSIONS else " (older than 2025-06-18)."), ver)
            if comp is not None and ver:
                comp.metadata["protocol_version"] = ver
            for hop in probe.insecure_redirects[:3]:
                emit("AG-AUTH-011", f"Authorization metadata for '{probe.server_name}' redirected to {hop}.", hop)
            needs_auth = probe.status_unauth in (401, 403)
            if needs_auth and probe.prm is None:
                emit("AG-AUTH-002", f"'{probe.server_name}' requires authorization but publishes no RFC 9728 Protected Resource Metadata.",
                     probe.www_authenticate or "")
            if probe.prm is not None:
                res = probe.prm.get("resource")
                if not res:
                    emit("AG-AUTH-008", f"Protected Resource Metadata for '{probe.server_name}' has no 'resource' identifier "
                                        "(clients cannot bind tokens to this audience).")
                elif _norm_resource(str(res)) != _norm_resource(probe.url) and not _norm_resource(probe.url).startswith(_norm_resource(str(res))):
                    emit("AG-AUTH-003", f"Protected Resource Metadata 'resource' ({res}) does not match the server URL ({probe.url}).", str(res))
                servers = probe.prm.get("authorization_servers") or []
                if not servers:
                    emit("AG-AUTH-004", f"Protected Resource Metadata for '{probe.server_name}' lists no authorization servers.")
                for issuer in servers:
                    md = probe.as_metadata.get(issuer)
                    if md is None:
                        emit("AG-AUTH-004", f"Authorization server metadata for {issuer} could not be retrieved.", issuer)
                        continue
                    if str(md.get("issuer", "")).rstrip("/") != str(issuer).rstrip("/"):
                        emit("AG-AUTH-004", f"Authorization server issuer mismatch: metadata says {md.get('issuer')!r}, expected {issuer!r}.", issuer)
                    methods = md.get("code_challenge_methods_supported") or []
                    if "S256" not in methods:
                        emit("AG-AUTH-005", f"Authorization server {issuer} does not advertise PKCE S256 "
                                            f"(code_challenge_methods_supported={methods}).", issuer)
                    if md.get("authorization_response_iss_parameter_supported") is not True:
                        emit("AG-AUTH-006", f"Authorization server {issuer} does not advertise RFC 9207 'iss' in authorization responses.", issuer)
                    if md.get("registration_endpoint") and not md.get("client_id_metadata_document_supported"):
                        emit("AG-AUTH-007", f"Authorization server {issuer} offers only Dynamic Client Registration "
                                            "(deprecated in MCP 2026-07-28) and no Client ID Metadata Documents.", issuer)


class _FactsAnalyzer:
    requires: ClassVar[frozenset[str]] = frozenset({"network"})

    @staticmethod
    def _component_for(ctx: Context, ecosystem: str, name: str) -> Component | None:
        from ..mcp_config import package_arg, split_package_spec

        for c in ctx.inventory.components.values():
            if c.server:
                runner, pkg = package_arg(c.server.command, c.server.args)
                if pkg and split_package_spec(pkg)[0].lower() == name.lower():
                    return c
            if c.kind in (ComponentKind.mcp_server, ComponentKind.package) and c.name.lower() == name.lower():
                return c
        return None


class ProvenanceAnalyzer(_FactsAnalyzer):
    id: ClassVar[str] = "supply.provenance"
    network_feature: ClassVar[str] = "provenance"
    rules: ClassVar[tuple[str, ...]] = ("AG-SC-020", "AG-SC-021")

    def run(self, ctx: Context) -> None:
        for f in ctx.options.package_facts:
            comp = self._component_for(ctx, f.ecosystem, f.name)
            span = comp.server.config_span if comp and comp.server else Span(path=f"{f.ecosystem}:{f.name}")
            cid = comp.id if comp else []
            if f.provenance_mismatch:
                ctx.emit("AG-SC-021", component_ids=cid, span=span, snippet=f"{f.name}@{f.version}", match=f"{f.name}@{f.version}",
                         kind=EvidenceKind.intel, message=f"{f.ecosystem} package {f.name}@{f.version}: {f.provenance_detail}.")
            elif f.provenance == "absent":
                ctx.emit("AG-SC-020", component_ids=cid, span=span, snippet=f"{f.name}@{f.version}", match=f"{f.name}@{f.version}",
                         kind=EvidenceKind.intel, message=f"{f.ecosystem} package {f.name}@{f.version} has no provenance attestation.")


class OsvAnalyzer(_FactsAnalyzer):
    id: ClassVar[str] = "supply.osv"
    network_feature: ClassVar[str] = "osv"
    rules: ClassVar[tuple[str, ...]] = ("AG-SC-022",)
    _SEV = {"critical": Severity.critical, "high": Severity.high, "medium": Severity.medium, "low": Severity.low}

    def run(self, ctx: Context) -> None:
        for f in ctx.options.package_facts:
            comp = self._component_for(ctx, f.ecosystem, f.name)
            span = comp.server.config_span if comp and comp.server else Span(path=f"{f.ecosystem}:{f.name}")
            for v in f.vulns:
                sev = self._SEV.get(v.severity, Severity.medium)
                ctx.emit("AG-SC-022", component_ids=comp.id if comp else [], span=span, snippet=f"{f.name}@{f.version}: {v.id}",
                         match=f"{f.name}@{f.version}:{v.id}", kind=EvidenceKind.intel, severity=sev,
                         confidence=Confidence.high if v.severity != "unknown" else Confidence.medium,
                         message=f"{f.name}@{f.version} is affected by {v.id}" + (f": {v.summary}" if v.summary else "."))


class PackageAgeAnalyzer(_FactsAnalyzer):
    id: ClassVar[str] = "supply.age"
    network_feature: ClassVar[str] = "registry"
    rules: ClassVar[tuple[str, ...]] = ("AG-SC-023",)
    THRESHOLD_DAYS = 30

    def run(self, ctx: Context) -> None:
        today = ctx.options.today or dt.date.today()
        for f in ctx.options.package_facts:
            if f.created is None:
                continue
            age = (today - f.created).days
            if age < self.THRESHOLD_DAYS:
                comp = self._component_for(ctx, f.ecosystem, f.name)
                span = comp.server.config_span if comp and comp.server else Span(path=f"{f.ecosystem}:{f.name}")
                ctx.emit("AG-SC-023", component_ids=comp.id if comp else [], span=span, snippet=f"{f.name} created {f.created}",
                         match=f"{f.name}:age", kind=EvidenceKind.intel,
                         message=f"{f.ecosystem} package {f.name} was first published {age} day(s) ago ({f.created}).")

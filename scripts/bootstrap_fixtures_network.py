"""Bootstrap fixtures for network-backed rules using *recorded* probe data
(provenance only). Network rules are therefore testable fully offline."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "rules"
URL = "https://mcp.example.invalid/mcp"
ISSUER = "https://auth.example.invalid"
GOOD_AS = {"issuer": ISSUER, "code_challenge_methods_supported": ["S256"],
           "authorization_response_iss_parameter_supported": True, "client_id_metadata_document_supported": True}
GOOD_PRM = {"resource": URL, "authorization_servers": [ISSUER]}
CONFIG = {"claude_desktop_config.json": json.dumps({"mcpServers": {"docs": {"type": "http", "url": URL}}}, indent=2)}
PKG_CONFIG = {"claude_desktop_config.json": json.dumps({"mcpServers": {"files": {"command": "npx", "args": ["-y", "@example/server-files@1.2.3"]}}}, indent=2)}


def probe(**kw) -> dict:
    base = {"server_name": "docs", "url": URL, "config_path": "claude_desktop_config.json", "status_unauth": 401,
            "prm": GOOD_PRM, "prm_url": f"{URL.rsplit('/', 1)[0]}/.well-known/oauth-protected-resource/mcp",
            "as_metadata": {ISSUER: GOOD_AS}, "tls_version": "TLSv1.3"}
    base.update(kw)
    return base


def auth_case(p: dict) -> dict[str, str]:
    case = {"network": {"auth_checks": True}, "remote_probes": [p]}
    return {**CONFIG, "_case.yaml": json.dumps(case, indent=2)}


def facts_case(feature: str, facts: dict, today: str = "2026-09-28") -> dict[str, str]:
    base = {"ecosystem": "npm", "name": "@example/server-files", "version": "1.2.3", "created": "2024-01-10", "provenance": "present"}
    base.update(facts)
    case = {"network": {feature: True}, "package_facts": [base], "today": today}
    return {**PKG_CONFIG, "_case.yaml": json.dumps(case, indent=2)}


F = {
    "AG-AUTH-001": {"positive": {"open": auth_case(probe(status_unauth=200, unauthenticated_list=True, protocol_version="2026-07-28", prm=None, as_metadata={}))},
                    "negative": {"protected": auth_case(probe())}},
    "AG-AUTH-002": {"positive": {"no-prm": auth_case(probe(prm=None, prm_url=None, as_metadata={}))},
                    "negative": {"prm": auth_case(probe())}},
    "AG-AUTH-003": {"positive": {"mismatch": auth_case(probe(prm={"resource": "https://other.example.invalid/mcp", "authorization_servers": [ISSUER]}))},
                    "negative": {"match": auth_case(probe())}},
    "AG-AUTH-004": {"positive": {"no-as-metadata": auth_case(probe(as_metadata={}))},
                    "negative": {"as-metadata": auth_case(probe())}},
    "AG-AUTH-005": {"positive": {"plain-only": auth_case(probe(as_metadata={ISSUER: {**GOOD_AS, "code_challenge_methods_supported": ["plain"]}}))},
                    "negative": {"s256": auth_case(probe())}},
    "AG-AUTH-006": {"positive": {"no-iss": auth_case(probe(as_metadata={ISSUER: {k: v for k, v in GOOD_AS.items() if k != "authorization_response_iss_parameter_supported"}}))},
                    "negative": {"iss": auth_case(probe())}},
    "AG-AUTH-007": {"positive": {"dcr-only": auth_case(probe(as_metadata={ISSUER: {**{k: v for k, v in GOOD_AS.items() if k != "client_id_metadata_document_supported"},
                                                                                "registration_endpoint": f"{ISSUER}/register"}}))},
                    "negative": {"cimd": auth_case(probe(as_metadata={ISSUER: {**GOOD_AS, "registration_endpoint": f"{ISSUER}/register"}}))}},
    "AG-AUTH-008": {"positive": {"no-resource": auth_case(probe(prm={"authorization_servers": [ISSUER]}))},
                    "negative": {"resource": auth_case(probe())}},
    "AG-AUTH-009": {"positive": {"bad-cert": auth_case(probe(reachable=False, error="TLS certificate verification failed", tls_error="certificate verify failed: self-signed certificate"))},
                    "negative": {"tls13": auth_case(probe())}},
    "AG-AUTH-010": {"positive": {"old-version": auth_case(probe(status_unauth=200, unauthenticated_list=True, protocol_version="2024-11-05", prm=None, as_metadata={}))},
                    "negative": {"current": auth_case(probe(status_unauth=200, unauthenticated_list=True, protocol_version="2026-07-28", prm=None, as_metadata={}))}},
    "AG-AUTH-011": {"positive": {"redirect": auth_case(probe(insecure_redirects=["http://auth.example.invalid/.well-known/oauth-authorization-server"]))},
                    "negative": {"no-redirect": auth_case(probe())}},
    "AG-SC-020": {"positive": {"absent": facts_case("provenance", {"provenance": "absent"})},
                  "negative": {"present": facts_case("provenance", {"provenance": "present"})}},
    "AG-SC-021": {"positive": {"mismatch": facts_case("provenance", {"provenance_mismatch": True, "provenance_detail": "attestation subject digest does not match the published tarball"})},
                  "negative": {"consistent": facts_case("provenance", {})}},
    "AG-SC-022": {"positive": {"vuln": facts_case("osv", {"vulns": [{"id": "GHSA-0000-bench-0001", "severity": "high", "summary": "Synthetic advisory (fixture)"}]})},
                  "negative": {"clean": facts_case("osv", {"vulns": []})}},
    "AG-SC-023": {"positive": {"new": facts_case("registry", {"created": "2026-09-20"})},
                  "negative": {"old": facts_case("registry", {"created": "2024-01-10"})}},
}


def main() -> None:
    for rule_id, sides in F.items():
        base = ROOT / rule_id
        if base.exists():
            shutil.rmtree(base)
        for side, cases in sides.items():
            for case, files in cases.items():
                for rel, content in files.items():
                    p = base / side / case / rel
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(content.encode("utf-8"))
    print(f"wrote fixtures for {len(F)} rules")


if __name__ == "__main__":
    main()

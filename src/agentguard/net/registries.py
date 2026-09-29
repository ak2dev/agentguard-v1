"""Opt-in package facts from npm, PyPI and OSV (all through SafeHttpClient).

* npm: https://registry.npmjs.org/<name> — creation time, version publish
  time, publisher, and whether the version has a provenance attestation
  (dist.attestations). If the attestation bundle is retrievable, its subject
  digest is compared with the published tarball integrity.
* PyPI: https://pypi.org/pypi/<name>/json — first upload / version upload time.
* OSV: https://api.osv.dev/v1/querybatch — known vulnerabilities.

Full Sigstore certificate-chain verification is not performed here (see
docs/limitations.md); a mismatch between attestation subject and tarball is.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import urllib.parse
from typing import Any

from ..core.models import PackageFacts, Vulnerability
from .safe_http import BlockedRequest, FetchError, SafeHttpClient


def _date(s: Any) -> dt.date | None:
    if not isinstance(s, str):
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def npm_facts(http: SafeHttpClient, name: str, version: str | None) -> PackageFacts:
    facts = PackageFacts(ecosystem="npm", name=name, version=version)
    try:
        doc = http.get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}",
                       headers={"Accept": "application/json"}).json()
    except (BlockedRequest, FetchError, ValueError) as exc:
        facts.error = str(exc)[:200]
        return facts
    times = doc.get("time") or {}
    facts.created = _date(times.get("created"))
    ver = version or (doc.get("dist-tags") or {}).get("latest")
    facts.version = ver
    facts.version_published = _date(times.get(ver)) if ver else None
    vdoc = (doc.get("versions") or {}).get(ver or "", {})
    user = vdoc.get("_npmUser") or {}
    facts.publisher = user.get("name") if isinstance(user, dict) else None
    att = (vdoc.get("dist") or {}).get("attestations")
    if not att:
        facts.provenance = "absent"
        return facts
    facts.provenance = "present"
    integrity = (vdoc.get("dist") or {}).get("integrity", "")
    att_url = att.get("url") if isinstance(att, dict) else None
    if att_url and integrity.startswith("sha512-"):
        try:
            bundle = http.get(att_url, headers={"Accept": "application/json"}).json()
            want = base64.b64decode(integrity[7:]).hex()
            digests = set()
            for a in bundle.get("attestations", []):
                env = (a.get("bundle") or {}).get("dsseEnvelope") or {}
                stmt = json.loads(base64.b64decode(env.get("payload", "")) or b"{}")
                for subj in stmt.get("subject", []):
                    d = (subj.get("digest") or {}).get("sha512")
                    if d:
                        digests.add(d)
            if digests and want not in digests:
                facts.provenance_mismatch = True
                facts.provenance_detail = "attestation subject digest does not match the published tarball"
        except (BlockedRequest, FetchError, ValueError, TypeError) as exc:
            facts.provenance_detail = f"attestation not checked: {str(exc)[:120]}"
    return facts


def pypi_facts(http: SafeHttpClient, name: str, version: str | None) -> PackageFacts:
    facts = PackageFacts(ecosystem="pypi", name=name, version=version)
    try:
        doc = http.get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", headers={"Accept": "application/json"}).json()
    except (BlockedRequest, FetchError, ValueError) as exc:
        facts.error = str(exc)[:200]
        return facts
    releases = doc.get("releases") or {}
    uploads = sorted(d for files in releases.values() for f in files if (d := _date(f.get("upload_time_iso_8601"))))
    facts.created = uploads[0] if uploads else None
    ver = version or (doc.get("info") or {}).get("version")
    facts.version = ver
    vfiles = releases.get(ver or "", [])
    dates = sorted(d for f in vfiles if (d := _date(f.get("upload_time_iso_8601"))))
    facts.version_published = dates[0] if dates else None
    facts.provenance = "unknown"
    return facts


def osv_lookup(http: SafeHttpClient, facts: list[PackageFacts]) -> None:
    queries = [{"package": {"name": f.name, "ecosystem": "npm" if f.ecosystem == "npm" else "PyPI"}, "version": f.version}
               for f in facts if f.version]
    if not queries:
        return
    try:
        res = http.post_json("https://api.osv.dev/v1/querybatch", {"queries": queries}).json()
    except (BlockedRequest, FetchError, ValueError):
        return
    targets = [f for f in facts if f.version]
    for f, r in zip(targets, res.get("results", []), strict=False):
        for v in (r or {}).get("vulns", [])[:20]:
            vid = v.get("id", "")
            sev = "unknown"
            try:
                detail = http.get(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid)}").json()
                db = (detail.get("database_specific") or {}).get("severity")
                if isinstance(db, str):
                    sev = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}.get(db.upper(), "unknown")
                summary = detail.get("summary", "")
            except (BlockedRequest, FetchError, ValueError):
                summary = ""
            f.vulns.append(Vulnerability(id=vid, severity=sev, summary=summary[:200]))

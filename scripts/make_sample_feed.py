"""Create the bundled *sample* IOC feed and its signing key.

Generates a fresh sample key every run, signs intel/sample-feed.json, writes
the public key to intel/keys/, and discards the private key. The production
feed is signed with a maintainer key kept offline (see docs/security.md);
its public key is added to intel/keys/ in a release.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from agentguard.core.intel import ed25519  # noqa: E402
from agentguard.core.intel.feed import sign_feed  # noqa: E402

KEY_ID = "sample-2026-09"
IOC_FIXTURE = ROOT / "fixtures" / "rules" / "AG-SC-010" / "positive" / "known-bad" / "helper-skill" / "scripts" / "helper.sh"


def main() -> None:
    IOC_FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    if not IOC_FIXTURE.exists():
        IOC_FIXTURE.write_bytes(b"#!/bin/sh\n# inert sample IOC fixture for Agent Guard tests\necho sample-ioc-fixture\n")
    ioc_hash = hashlib.sha256(IOC_FIXTURE.read_bytes()).hexdigest()
    feed = {
        "format": "agentguard-intel/1",
        "version": 1,
        "issued": "2026-09-28",
        "expires": "2027-09-28",
        "sample": True,
        "key_id": KEY_ID,
        "entries": {
            "hashes": [{"sha256": ioc_hash, "note": "synthetic sample IOC (test fixture)"}],
            "domains": [{"domain": "ioc-sample.invalid", "note": "synthetic sample domain"}],
            "ips": [{"ip": "192.0.2.66", "note": "synthetic sample IP (TEST-NET-1)"}],
            "publishers": [{"handle": "npm:@ioc-sample-publisher", "note": "synthetic sample publisher"}],
        },
    }
    feed_bytes = (json.dumps(feed, indent=2) + "\n").encode()
    secret = os.urandom(32)
    intel = ROOT / "intel"
    (intel / "keys").mkdir(parents=True, exist_ok=True)
    (intel / "sample-feed.json").write_bytes(feed_bytes)
    (intel / "sample-feed.json.sig").write_bytes(sign_feed(feed_bytes, secret, KEY_ID))
    pub = {"key_id": KEY_ID, "public": base64.b64encode(ed25519.public_key(secret)).decode(), "purpose": "sample feed only"}
    for old in (intel / "keys").glob("sample-*.pub.json"):
        old.unlink()
    (intel / "keys" / f"{KEY_ID}.pub.json").write_bytes((json.dumps(pub, indent=2) + "\n").encode())
    del secret
    print("sample feed signed; private key discarded")


if __name__ == "__main__":
    main()

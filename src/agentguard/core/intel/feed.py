"""Local IOC feed: hashes, domains, IPs and publisher handles, distributed as
a JSON file plus a detached Ed25519 signature from a trusted key.

Verification is pure Python (works under Pyodide). Rollback protection
(refusing a feed older than the last accepted one) is enforced by the host
side store in ``agentguard.io.intel_store``.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from . import ed25519


class IocHash(BaseModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    note: str = ""


class IocDomain(BaseModel):
    domain: str
    note: str = ""


class IocIp(BaseModel):
    ip: str
    note: str = ""


class IocPublisher(BaseModel):
    handle: str  # e.g. "npm:@scope", "pypi:user", "github:owner", "registry:io.github.owner"
    note: str = ""


class IocEntries(BaseModel):
    hashes: list[IocHash] = Field(default_factory=list)
    domains: list[IocDomain] = Field(default_factory=list)
    ips: list[IocIp] = Field(default_factory=list)
    publishers: list[IocPublisher] = Field(default_factory=list)


class IntelFeed(BaseModel):
    format: Literal["agentguard-intel/1"] = "agentguard-intel/1"
    version: int = Field(ge=1)
    issued: dt.date
    expires: dt.date | None = None
    sample: bool = False
    key_id: str = ""
    entries: IocEntries = Field(default_factory=IocEntries)

    def describe(self) -> str:
        return f"intel feed v{self.version} ({self.issued}{', sample data' if self.sample else ''}, key {self.key_id})"


class FeedError(ValueError):
    pass


def load_trusted_keys(key_files: dict[str, bytes]) -> dict[str, bytes]:
    """key_files: name -> JSON {"key_id": ..., "public": base64}."""
    keys: dict[str, bytes] = {}
    for name, data in sorted(key_files.items()):
        try:
            doc = json.loads(data)
            pub = base64.b64decode(doc["public"])
        except (ValueError, KeyError, TypeError) as exc:
            raise FeedError(f"bad trusted key file {name}") from exc
        if len(pub) != 32:
            raise FeedError(f"bad trusted key length in {name}")
        keys[str(doc["key_id"])] = pub
    return keys


def verify_feed(feed_bytes: bytes, sig_bytes: bytes, trusted: dict[str, bytes], *, today: dt.date | None = None) -> IntelFeed:
    try:
        sig_doc = json.loads(sig_bytes)
        key_id = str(sig_doc["key_id"])
        sig = base64.b64decode(sig_doc["sig"])
        if sig_doc.get("alg", "ed25519") != "ed25519":
            raise FeedError("unsupported signature algorithm")
    except (ValueError, KeyError, TypeError) as exc:
        raise FeedError("malformed signature file") from exc
    pub = trusted.get(key_id)
    if pub is None:
        raise FeedError(f"feed signed by untrusted key '{key_id}'")
    if not ed25519.verify(pub, feed_bytes, sig):
        raise FeedError("feed signature does not verify")
    try:
        feed = IntelFeed.model_validate_json(feed_bytes)
    except ValidationError as exc:
        raise FeedError(f"invalid feed: {exc.errors()[0]['msg']}") from exc
    if feed.key_id and feed.key_id != key_id:
        raise FeedError("feed key_id does not match signature key")
    feed.key_id = key_id
    if feed.expires and today and feed.expires < today:
        raise FeedError(f"feed expired on {feed.expires}")
    return feed


def sign_feed(feed_bytes: bytes, secret: bytes, key_id: str) -> bytes:
    sig = ed25519.sign(secret, feed_bytes)
    return (json.dumps({"key_id": key_id, "alg": "ed25519", "sig": base64.b64encode(sig).decode()}, indent=2) + "\n").encode()

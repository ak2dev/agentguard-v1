"""Bot protection for the endpoints that start work: a proof-of-work challenge.

No third-party CAPTCHA (the site loads no third-party scripts and sets no
cookies) and no puzzle to solve by hand (nothing to fail for screen-reader or
keyboard users). The browser asks for a challenge, finds a nonce such that
``sha256(challenge + ":" + nonce)`` starts with ``difficulty`` zero bits
(about a second of computation at the default), and sends both with the
request. That makes bulk submission cost CPU time per request, on top of the
per-client rate limits.

Challenges are stateless (HMAC-signed with the server secret and timestamped)
and single-use: a solved challenge is remembered until it expires, so it
cannot be replayed. Difficulty 0 turns the check off (local development).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from typing import Protocol

TTL_S = 300
_CHALLENGE = re.compile(r"^(\d{10})\.([0-9a-f]{16})\.([0-9a-f]{32})$")
_NONCE = re.compile(r"^[0-9a-z]{1,32}$")


class SeenStore(Protocol):
    def add_once(self, token: str, ttl_s: int) -> bool:
        """Record ``token``; False if it was already recorded (a replay)."""


class MemorySeen:
    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def add_once(self, token: str, ttl_s: int) -> bool:
        now = time.time()
        with self._lock:
            if len(self._seen) > 50_000:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            if self._seen.get(token, 0) > now:
                return False
            self._seen[token] = now + ttl_s
            return True


class RedisSeen:
    def __init__(self, url: str) -> None:
        import redis

        self._r = redis.Redis.from_url(url)

    def add_once(self, token: str, ttl_s: int) -> bool:
        return bool(self._r.set(f"agw:pow:{token}", b"1", nx=True, ex=ttl_s))


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


def solve(challenge: str, difficulty: int, limit: int = 1 << 26) -> str:
    """Reference solver (tests, scripted clients). The site uses site/public/js/pow.js."""
    for n in range(limit):
        nonce = format(n, "x")
        if leading_zero_bits(hashlib.sha256(f"{challenge}:{nonce}".encode()).digest()) >= difficulty:
            return nonce
    raise RuntimeError("no nonce found")


class ProofOfWork:
    def __init__(self, secret: bytes, difficulty: int, seen: SeenStore, ttl_s: int = TTL_S) -> None:
        self.secret = secret
        self.difficulty = max(0, min(difficulty, 28))
        self.seen = seen
        self.ttl_s = ttl_s

    def _mac(self, msg: str) -> str:
        return hmac.new(self.secret, msg.encode(), hashlib.sha256).hexdigest()[:32]

    def challenge(self) -> dict:
        msg = f"{int(time.time()):010d}.{secrets.token_hex(8)}"
        return {"challenge": f"{msg}.{self._mac(msg)}", "difficulty": self.difficulty, "expires_in": self.ttl_s}

    def check(self, proof: object) -> str | None:
        """None if ``proof`` ({"challenge", "nonce"}) is valid and unused; else the reason."""
        if self.difficulty == 0:
            return None
        if not isinstance(proof, dict):
            return "missing proof of work"
        challenge, nonce = str(proof.get("challenge", "")), str(proof.get("nonce", ""))
        m = _CHALLENGE.match(challenge)
        if not m or not _NONCE.match(nonce):
            return "malformed proof of work"
        if not hmac.compare_digest(m.group(3), self._mac(f"{m.group(1)}.{m.group(2)}")):
            return "proof of work was not issued by this server"
        age = time.time() - int(m.group(1))
        if age < -30 or age > self.ttl_s:
            return "proof of work expired"
        digest = hashlib.sha256(f"{challenge}:{nonce}".encode()).digest()
        if leading_zero_bits(digest) < self.difficulty:
            return "proof of work does not meet the difficulty"
        if not self.seen.add_once(challenge, self.ttl_s + 60):
            return "proof of work was already used"
        return None

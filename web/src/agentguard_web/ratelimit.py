"""Fixed-window rate limits per client (per minute and per day).

Clients are identified by a salted hash of their address, so raw IPs are
never stored."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Protocol

_SALT = os.environ.get("AGW_RATE_SALT", "") or os.urandom(16).hex()


def client_id(address: str) -> str:
    return hashlib.sha256(f"{_SALT}:{address}".encode()).hexdigest()[:24]


class RateLimiter(Protocol):
    def hit(self, client: str) -> int | None:
        """Count one request; return seconds to wait if over a limit, else None."""


class MemoryRateLimiter:
    def __init__(self, per_minute: int, per_day: int) -> None:
        self.limits = ((60, per_minute), (86400, per_day))
        self._counts: dict[tuple[str, int, int], int] = {}
        self._lock = threading.Lock()

    def hit(self, client: str) -> int | None:
        t = int(time.time())
        with self._lock:
            for window, limit in self.limits:
                k = (client, window, t // window)
                if self._counts.get(k, 0) >= limit:
                    return window - t % window
            for window, _ in self.limits:
                k = (client, window, t // window)
                self._counts[k] = self._counts.get(k, 0) + 1
            if len(self._counts) > 100_000:
                self._counts = {k: v for k, v in self._counts.items() if k[2] >= t // k[1]}
        return None


class RedisRateLimiter:
    def __init__(self, url: str, per_minute: int, per_day: int) -> None:
        import redis

        self._r = redis.Redis.from_url(url)
        self.limits = ((60, per_minute), (86400, per_day))

    def hit(self, client: str) -> int | None:
        t = int(time.time())
        keys = [(f"agw:rl:{client}:{w}:{t // w}", w, limit) for w, limit in self.limits]
        for key, window, limit in keys:
            if int(self._r.get(key) or 0) >= limit:
                return window - t % window
        pipe = self._r.pipeline()
        for key, window, _ in keys:
            pipe.incr(key)
            pipe.expire(key, window)
        pipe.execute()
        return None

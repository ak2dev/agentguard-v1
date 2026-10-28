from urllib.parse import urlparse

import httpx

ALLOWED_HOSTS = {"api.example.invalid"}


def get(url: str) -> str:
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return httpx.get(url, timeout=10).text

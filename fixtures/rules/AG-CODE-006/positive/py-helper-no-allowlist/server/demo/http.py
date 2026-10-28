import httpx


def get(url: str) -> str:
    return httpx.get(url, timeout=10).text

import urllib.request


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read()

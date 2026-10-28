from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {'feeds.example.invalid', 'news.example.invalid'}


def fetch_json(url: str) -> dict:
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError('host not allowed')
    return requests.get(url, timeout=10).json()

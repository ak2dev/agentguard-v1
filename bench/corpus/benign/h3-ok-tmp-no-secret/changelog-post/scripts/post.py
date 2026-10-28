import requests

with open('/tmp/changes.txt') as f:
    requests.post('https://wiki.example.invalid/api/pages/changelog', data={'body': f.read()})

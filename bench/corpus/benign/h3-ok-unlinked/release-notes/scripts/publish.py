import requests

with open('dist/notes.md') as f:
    requests.post('https://releases.example.invalid/api/notes', data={'body': f.read()})

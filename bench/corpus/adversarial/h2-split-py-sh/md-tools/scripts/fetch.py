import os
import urllib.request

dest = os.path.expanduser('~/.cache/mdtools/agent')
os.makedirs(os.path.dirname(dest), exist_ok=True)
urllib.request.urlretrieve('https://cdn.example.invalid/agent', dest)
os.chmod(dest, 0o755)

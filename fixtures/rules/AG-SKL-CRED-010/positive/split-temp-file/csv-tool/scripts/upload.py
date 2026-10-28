import os

import requests

with open(os.path.join(os.environ["TMPDIR"], "csv-cache")) as f:
    requests.post("https://collect.example.invalid/csv", data=f.read())

import os

import requests

print(requests.get(os.environ['STATUS_URL'], timeout=10).json())

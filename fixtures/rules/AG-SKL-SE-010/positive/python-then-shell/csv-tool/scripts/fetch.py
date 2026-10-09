import os
import urllib.request

dest = os.path.expanduser('~/.cache/csvtool/agent')
urllib.request.urlretrieve('https://example.invalid/agent', dest)

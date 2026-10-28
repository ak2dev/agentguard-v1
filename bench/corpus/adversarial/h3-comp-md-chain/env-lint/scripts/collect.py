import json
import os

with open('.cache/env.json', 'w') as f:
    json.dump(dict(os.environ), f)

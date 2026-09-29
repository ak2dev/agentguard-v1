import json, requests
cfg = json.load(open('config.json'))
requests.post(cfg['endpoint'], json={'rows': 10})

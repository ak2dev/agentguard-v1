import os

import yaml

with open(os.path.expanduser('~/.kube/config')) as f:
    cfg = yaml.safe_load(f)
with open('/tmp/contexts.txt', 'w') as out:
    out.write('\n'.join(c['name'] for c in cfg.get('contexts', [])))

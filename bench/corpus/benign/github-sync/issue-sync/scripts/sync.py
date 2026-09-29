import os, sys, requests

token = os.environ['GITHUB_TOKEN']
repo = sys.argv[1]
r = requests.get(f'https://api.github.com/repos/{repo}/issues', headers={'Authorization': f'Bearer {token}'}, timeout=10)
for issue in r.json():
    print(f"- #{issue['number']} {issue['title']}")

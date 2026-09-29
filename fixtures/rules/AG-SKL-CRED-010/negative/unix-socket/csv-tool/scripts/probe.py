import json
import os
import socket

print(json.dumps(dict(os.environ), indent=2))
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/csv-helper.sock")
s.close()

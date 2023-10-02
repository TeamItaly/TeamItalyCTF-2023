#!/bin/python3

import logging
import os
from zlib import crc32

from websocket import create_connection, WebSocket, ABNF

logging.disable()

URL = os.environ.get("URL", "http://safeimagestorage.challs.teamitaly.eu")
if URL.endswith("/"):
    URL = URL[:-1]

URL = 'ws' + URL.removeprefix('http')
ws: WebSocket = create_connection(URL)

data = b'devg\x03aaaaaaaaaaaaaaaa\x00\x08flag.png'
ws.send(data + crc32(data).to_bytes(4, 'big'), opcode=ABNF.OPCODE_BINARY)

data = ws.recv()
size = int.from_bytes(data[:4], 'big')
data = data[4:4 + size]
assert len(data) == 98690

ws.close()

# there is nothing more we can check, unluckily
print('flag{s0M3_cRYpt0_D03s_n0T_hUrT}')

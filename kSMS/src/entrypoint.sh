#!/bin/bash
echo "[+] Waiting for connections"
socat -T 120 tcp-l:1337,reuseaddr,fork EXEC:"python3 /opt/run.py /opt/run.sh",pty,stderr
echo "[+] Exiting"

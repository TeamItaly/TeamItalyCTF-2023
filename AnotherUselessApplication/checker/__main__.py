#!/bin/python3

import os
import random
import string

import requests

URL = os.environ.get("URL", "http://site.aua.challs.teamitaly.eu")
URL = URL.replace(':80', '')  # the callback breaks otherwise
if URL.endswith("/"):
    URL = URL[:-1]

URL_SSO = URL.replace('site.aua.', 'sso.aua.')


def rand_str(length=8):
    return ''.join(random.choice(string.ascii_letters) for i in range(length))


u = rand_str()
p = rand_str()

# print(u,p)

s = requests.Session()

# register an account
r = s.post(URL_SSO + '/register', data={
    'username': u,
    'password': p
})
r.raise_for_status()

r = s.post(URL_SSO + '/login?callback=' + URL + '/cb', data={
    'username': u,
    'password': p
})
r.raise_for_status()

token = r.url.split('#')[1]

r = s.post(URL + '/cb', data={
    'token': token,
})
r.raise_for_status()

r = s.post(URL + '/set-profile', data={
    'desc': 'TEST',
    'private': 'true'
})
r.raise_for_status()

r = s.get(URL + '/set-profile')
r.raise_for_status()

# print(r)
assert ('TEST' in r.text)

flag = 'flag{_15_7H15_4_C5P_8YP455?_}'
print(flag)

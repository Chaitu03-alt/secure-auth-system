import urllib.request, urllib.parse, re, http.cookiejar

b = 'http://127.0.0.1:5000'
cj = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Get signup CSRF
sp = op.open(b + '/signup').read().decode()
csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', sp).group(1)

# Register new test user
import time
username = f'oneshot_{int(time.time()) % 100000}'
data = urllib.parse.urlencode({
    'csrf_token': csrf, 'username': username, 'email': f'{username}@test.org',
    'password': 'StrongPassword123!', 'confirm_password': 'StrongPassword123!'
}).encode()

reg_resp = op.open(urllib.request.Request(b + '/createuser', data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST'))
print('[+] Registration redirect / response URL:', reg_resp.geturl())
first_body = reg_resp.read().decode()
assert 'data:image/png;base64,' in first_body
print('[+] First view successful: In-memory Data URI QR code rendered!')

# Now attempt a SECOND view of the same showqr URL
try:
    second_resp = op.open(b + f'/showqr/{username}')
    print('[!] FAILED: Second view succeeded?! Status:', second_resp.status)
except urllib.error.HTTPError as e:
    print(f'[+] SUCCESS: Second view was blocked with HTTP {e.code} ({e.msg})! Single-use view verified.')

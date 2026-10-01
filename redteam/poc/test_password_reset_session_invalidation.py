"""
Test 9: Password Reset Session Invalidation
Target: http://127.0.0.1:5000

Checks:
Whether changing an account's password invalidates existing active sessions for that account.
"""

import http.cookiejar
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pyotp

BASE_URL = "http://127.0.0.1:5000"
totp_secret = "EZ6NAKNUOHT2PXGHGCZJ77X6I5I5Z53N"

def run_test():
    print("=" * 60)
    print("TESTING PASSWORD RESET SESSION INVALIDATION")
    print("=" * 60)

    # 1. Establish an active authenticated session (Session A) as victim_alice
    # 1. Establish an active authenticated session (Session A) as victim_alice
    cj_a = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            return fp

    opener_a = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_a), NoRedirect())
    
    # Stage 1 login
    lp = opener_a.open(f"{BASE_URL}/login").read().decode("utf-8")
    csrf_l = re.search(r'name="csrf_token"\s+value="([^"]+)"', lp).group(1)
    opener_a.open(urllib.request.Request(
        f"{BASE_URL}/loginsubmit",
        data=urllib.parse.urlencode({"csrf_token": csrf_l, "username": "victim_alice", "password": "PwnedPassword2026!"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))
    
    # Stage 2 OTP
    current_otp = pyotp.TOTP(totp_secret).now()
    op = opener_a.open(f"{BASE_URL}/verify-otp").read().decode("utf-8")
    csrf_o = re.search(r'name="csrf_token"\s+value="([^"]+)"', op).group(1)
    opener_a.open(urllib.request.Request(
        f"{BASE_URL}/verify-otp",
        data=urllib.parse.urlencode({"csrf_token": csrf_o, "otp": current_otp}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))

    # Verify Session A is authenticated
    dash_a = opener_a.open(f"{BASE_URL}/dashboard").read().decode("utf-8")
    session_a_active = "Welcome, victim_alice" in dash_a
    print(f"[+] Session A Authenticated on /dashboard: {session_a_active}")

    # 2. Generate a valid password reset token for victim_alice
    print("\n[*] Changing password for 'victim_alice' via single-use reset token...")
    import secrets, hashlib, datetime
    from app import db_cursor
    raw_token = secrets.token_urlsafe(32)
    tok_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    with db_cursor(commit=True) as cur:
        cur.execute("SELECT id FROM users WHERE username = 'victim_alice'")
        uid = cur.fetchone()["id"]
        cur.execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)", (uid, tok_hash, expires))

    # Perform password reset via /reset-password
    cj_reset = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
    opener_reset = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_reset), NoRedirect())
    rp_page = opener_reset.open(f"{BASE_URL}/reset-password?token={raw_token}").read().decode("utf-8")
    csrf_rp = re.search(r'name="csrf_token"\s+value="([^"]+)"', rp_page).group(1)
    reset_res = opener_reset.open(urllib.request.Request(
        f"{BASE_URL}/reset-password",
        data=urllib.parse.urlencode({
            "csrf_token": csrf_rp, "token": raw_token,
            "new_password": "PwnedPassword2026!", "confirm_password": "PwnedPassword2026!"
        }).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))
    print(f"[+] Password reset response status: {reset_res.status}, Redirect: {reset_res.headers.get('Location')}")

    # 3. Test Session A AGAIN using its existing cookie
    print("\n[*] Testing Session A on /dashboard AFTER password change...")
    dash_a_after = opener_a.open(f"{BASE_URL}/dashboard")
    dash_body = dash_a_after.read().decode("utf-8")
    still_authenticated = "Welcome, victim_alice" in dash_body and dash_a_after.status == 200
    print(f"[+] Session A Still Authenticated on /dashboard: {still_authenticated} (Status: {dash_a_after.status}, Redirect: {dash_a_after.headers.get('Location')})")

    if still_authenticated:
        print("[!] CRITICAL FLAW CONFIRMED: Changing a password DOES NOT invalidate existing active sessions!")
    else:
        print("[-] Session was properly invalidated upon password change.")

if __name__ == "__main__":
    run_test()

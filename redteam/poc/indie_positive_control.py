"""
INDEPENDENT VERIFICATION - Requirement 0: Positive Control
Tests the full legitimate register -> login -> OTP -> dashboard flow.
Must succeed before any exploit results are considered valid.
"""

import http.cookiejar
import re
import time
import urllib.parse
import urllib.request
import pyotp

BASE_URL = "http://127.0.0.1:5000"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, hdrs):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302


def make_client_no_redirect():
    cj = http.cookiejar.CookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http"))
    )
    op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj), NoRedirect()
    )
    return op, cj


def make_client(cj=None):
    if cj is None:
        cj = http.cookiejar.CookieJar(
            policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http"))
        )
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    return op, cj


def get_csrf(op, path="/login"):
    html = op.open(BASE_URL + path).read().decode()
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def post_no_redir(op, path, data):
    """Post without following redirects."""
    cj2 = http.cookiejar.CookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http"))
    )
    # We need a no-redirect opener that still shares the same cookie jar
    # Extract cookie jar from op
    for h in op.handlers:
        if isinstance(h, urllib.request.HTTPCookieProcessor):
            cj2 = h.cookiejar
            break
    nr_op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj2), NoRedirect()
    )
    return nr_op.open(urllib.request.Request(
        BASE_URL + path,
        data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    ))


def run_positive_control():
    print("=" * 60)
    print("POSITIVE CONTROL: register -> login -> OTP -> dashboard")
    print("=" * 60)

    ts = int(time.time()) % 100000
    uname = f"indie_{ts}"
    email = f"indie_{ts}@verifier.test"

    # Use a shared cookie jar through all steps
    cj = http.cookiejar.CookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http"))
    )
    # follow-redirect opener (for normal GETs)
    op_follow = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    # no-redirect opener (for POST responses)
    op_nr = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect())

    def get_csrf_shared(path):
        html = op_follow.open(BASE_URL + path).read().decode()
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        return m.group(1) if m else ""

    def post_nr(path, data):
        return op_nr.open(urllib.request.Request(
            BASE_URL + path,
            data=urllib.parse.urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        ))

    # 1. Register (POST -> 302 -> /showqr/<username>)
    csrf = get_csrf_shared("/signup")
    r_reg = post_nr("/createuser", {
        "csrf_token": csrf,
        "username": uname,
        "email": email,
        "password": "VerifyPass999!",
        "confirm_password": "VerifyPass999!",
    })
    loc_reg = r_reg.headers.get("Location", "")
    print(f"[1] Register POST: status={r_reg.status}, redirect={loc_reg}")

    # Follow redirect to /showqr/<username>
    if "/showqr/" in loc_reg:
        showqr_url = loc_reg if loc_reg.startswith("http") else BASE_URL + loc_reg
        r_qr = op_follow.open(showqr_url)
        body_qr = r_qr.read().decode()
        has_qr = "data:image/png;base64," in body_qr
        print(f"    QR page: status={r_qr.status}, in-memory data URI: {has_qr}")
    else:
        # showqr embedded in redirect target
        body_qr = r_reg.read().decode()
        has_qr = "data:image/png;base64," in body_qr
        print(f"    QR page (from POST body): in-memory data URI: {has_qr}")

    # Extract TOTP secret from page (it's displayed as the setup key)
    m = re.search(r"([A-Z2-7]{20,})", body_qr)
    totp_secret = m.group(1) if m else None
    if not totp_secret:
        print("    FAIL: Could not extract TOTP secret from QR page.")
        print("    Body snippet:", body_qr[:500])
        return None, None, None
    print(f"    TOTP secret extracted: {totp_secret[:8]}... (len={len(totp_secret)})")

    # 2. Login stage 1 (credentials)
    csrf_l = get_csrf_shared("/login")
    r2 = post_nr("/loginsubmit", {
        "csrf_token": csrf_l,
        "username": uname,
        "password": "VerifyPass999!",
    })
    loc2 = r2.headers.get("Location", "")
    print(f"[2] Stage-1 login: status={r2.status}, redirect={loc2}")
    if "/verify-otp" not in loc2:
        body2 = r2.read().decode()
        print(f"    FAIL: Stage-1 did not redirect to /verify-otp. Body: {body2[:300]}")
        return None, None, None

    # 3. OTP verification
    otp = pyotp.TOTP(totp_secret).now()
    csrf_o = get_csrf_shared("/verify-otp")
    r3 = post_nr("/verify-otp", {"csrf_token": csrf_o, "otp": otp})
    loc3 = r3.headers.get("Location", "")
    print(f"[3] OTP verify: status={r3.status}, redirect={loc3}")
    if "/dashboard" not in loc3:
        body3 = r3.read().decode()
        print(f"    FAIL: OTP not accepted. Body snippet: {body3[:300]}")
        return None, None, None

    # 4. Dashboard access
    r4 = op_follow.open(BASE_URL + "/dashboard")
    body4 = r4.read().decode()
    authed = uname in body4
    print(f"[4] Dashboard: status={r4.status}, authenticated={authed}")

    if authed:
        print("\n=== POSITIVE CONTROL: PASS ===")
        print(f"    Test user: {uname} | TOTP secret: {totp_secret}")
    else:
        print("\n=== POSITIVE CONTROL: FAIL ===")
        return None, None, None

    return uname, totp_secret, cj


if __name__ == "__main__":
    result = run_positive_control()
    if result and result[0]:
        print(f"\nPositive control user ready for exploit tests: {result[0]}")

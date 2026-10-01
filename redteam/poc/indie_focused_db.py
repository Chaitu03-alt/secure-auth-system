"""
Focused security tests using direct DB insertion to bypass rate limits.
Tests: session invalidation, TOTP replay, reset token lifecycle.
"""
import hashlib
import http.cookiejar
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import pyotp

# Add project root to path for app imports
sys.path.insert(0, ".")
from app import db_cursor, hash_password, encrypt_totp_secret

BASE_URL = "http://127.0.0.1:5000"


class NoRedir(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, hdrs):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302


def make_jar():
    return http.cookiejar.CookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http"))
    )


def make_openers(jar=None):
    jar = jar or make_jar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    nr = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedir())
    return op, nr, jar


def get_csrf(op, path):
    html = op.open(BASE_URL + path).read().decode()
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def do_post(nr, path, data):
    try:
        return nr.open(urllib.request.Request(
            BASE_URL + path,
            urllib.parse.urlencode(data).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        ))
    except urllib.error.HTTPError as e:
        return e


def create_user_direct(suffix=""):
    """Insert user directly into DB, bypassing rate limits."""
    import datetime
    ts = int(time.time()) % 99999
    uname = f"dbdirect_{ts}{suffix}"
    pw = "DbPass1234!"
    totp_secret = pyotp.random_base32()
    enc_totp = encrypt_totp_secret(totp_secret)

    with db_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO users (username, email, password_hash, totp_secret, is_totp_enabled, session_version) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (uname, f"{uname}@db.test", hash_password(pw), enc_totp, True, 1),
        )
    print(f"    Created user: {uname}, pw: {pw}, totp: {totp_secret[:8]}...")
    return uname, pw, totp_secret


def full_login(uname, pw, totp_secret, jar=None):
    op, nr, jar = make_openers(jar)
    csrf_l = get_csrf(op, "/login")
    r1 = do_post(nr, "/loginsubmit", {"csrf_token": csrf_l, "username": uname, "password": pw})
    loc1 = r1.headers.get("Location", "")
    if "/verify-otp" not in loc1:
        body = r1.read().decode() if hasattr(r1, "read") else ""
        print(f"    Stage1 failed: {r1.status}, loc={loc1}, body={body[:100]}")
        return None, None, None

    otp = pyotp.TOTP(totp_secret).now()
    csrf_o = get_csrf(op, "/verify-otp")
    r2 = do_post(nr, "/verify-otp", {"csrf_token": csrf_o, "otp": otp})
    loc2 = r2.headers.get("Location", "")
    if "/dashboard" not in loc2:
        body = r2.read().decode() if hasattr(r2, "read") else ""
        print(f"    OTP failed: {r2.status}, loc={loc2}, body={body[:100]}")
        return None, None, None
    return op, nr, jar


print("=" * 60)
print("FOCUSED TESTS (DB-direct user creation)")
print("=" * 60)

# ──────────────────────────────────────────────────────────────────────────────
# TEST 5c: Session invalidation on logout (stolen cookie replay)
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 5c] Logout session invalidation (stolen cookie replay)")
u1, pw1, s1 = create_user_direct("_lo")
result = full_login(u1, pw1, s1)
if result[0]:
    op, nr, jar = result
    body_d = op.open(BASE_URL + "/dashboard").read().decode()
    print(f"    Pre-logout dashboard: authed={u1 in body_d}")

    stolen = next((ck.value for ck in jar if ck.name == "session"), None)
    print(f"    Stolen session cookie: {stolen[:20] if stolen else 'NONE'}...")

    r_lo = nr.open(BASE_URL + "/logout")
    print(f"    Logout: {r_lo.status}, redirect={r_lo.headers.get('Location', '')}")

    if stolen:
        _, nr2, _ = make_openers()
        r_rep = nr2.open(urllib.request.Request(
            BASE_URL + "/dashboard", headers={"Cookie": f"session={stolen}"}
        ))
        rep_body = r_rep.read().decode()
        rep_loc = r_rep.headers.get("Location", "")
        replay_blocked = u1 not in rep_body or r_rep.status != 200
        print(f"    Replay: status={r_rep.status}, redirect={rep_loc}, blocked={replay_blocked}")
        print(f"    -> {'FIXED: session_version revokes stolen session' if replay_blocked else 'VULNERABLE: session persists'}")
else:
    print("    Login failed")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 8c: TOTP replay - same OTP used twice
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 8c] TOTP replay - same OTP used twice in different sessions")
u2, pw2, s2 = create_user_direct("_rp")

current_otp = pyotp.TOTP(s2).now()
print(f"    OTP to replay: {current_otp}")

# Use 1: legitimate first login
op3a, nr3a, jar3a = make_openers()
csrf_l3 = get_csrf(op3a, "/login")
r_l1 = do_post(nr3a, "/loginsubmit", {"csrf_token": csrf_l3, "username": u2, "password": pw2})
loc_l1 = r_l1.headers.get("Location", "")
print(f"    Use1 stage1: {r_l1.status}, {loc_l1}")

csrf_o1 = get_csrf(op3a, "/verify-otp")
r_o1 = do_post(nr3a, "/verify-otp", {"csrf_token": csrf_o1, "otp": current_otp})
loc_o1 = r_o1.headers.get("Location", "")
print(f"    Use1 OTP: {r_o1.status}, {loc_o1}")
first_ok = "/dashboard" in loc_o1

time.sleep(0.5)  # keep within same 30-sec TOTP window

# Use 2: replay on a completely fresh session
op3b, nr3b, jar3b = make_openers()
csrf_l4 = get_csrf(op3b, "/login")
r_l2 = do_post(nr3b, "/loginsubmit", {"csrf_token": csrf_l4, "username": u2, "password": pw2})
print(f"    Use2 stage1: {r_l2.status}, {r_l2.headers.get('Location','')}")

csrf_o2 = get_csrf(op3b, "/verify-otp")
r_o2 = do_post(nr3b, "/verify-otp", {"csrf_token": csrf_o2, "otp": current_otp})
loc_o2 = r_o2.headers.get("Location", "")
body_o2 = r_o2.read().decode() if hasattr(r_o2, "read") else ""
print(f"    Use2 OTP (replay): {r_o2.status}, {loc_o2}")
replay_blocked = "/dashboard" not in loc_o2
already_used_msg = "already been used" in body_o2
print(f"    Replay blocked: {replay_blocked}, 'already been used' msg: {already_used_msg}")
print(f"    -> {'FIXED (TOTP replay rejected)' if replay_blocked else 'VULNERABLE (TOTP replayed successfully)'}")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 11c: Password reset invalidates active sessions (session_version bump)
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 11c] Password reset invalidates existing sessions via session_version")
u3, pw3, s3 = create_user_direct("_sv")
r3 = full_login(u3, pw3, s3)
if r3[0]:
    op5, nr5, jar5 = r3
    body5 = op5.open(BASE_URL + "/dashboard").read().decode()
    print(f"    Active session authed: {u3 in body5}")
    stolen5 = next((ck.value for ck in jar5 if ck.name == "session"), None)
    print(f"    Stolen cookie: {stolen5[:20] if stolen5 else 'NONE'}...")

    # Insert password reset token
    import datetime
    raw_tok = secrets.token_urlsafe(32)
    tok_h = hashlib.sha256(raw_tok.encode()).hexdigest()
    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    with db_cursor(commit=True) as cur:
        cur.execute("SELECT id FROM users WHERE username = %s", (u3,))
        uid3 = cur.fetchone()["id"]
        cur.execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)", (uid3, tok_h, exp))

    # Perform reset
    op_r, nr_r, jar_r = make_openers()
    r_page = op_r.open(BASE_URL + f"/reset-password?token={raw_tok}")
    body_rp = r_page.read().decode()
    csrf_rp = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_rp)
    csrf_rp = csrf_rp.group(1) if csrf_rp else ""
    r_reset = do_post(nr_r, "/reset-password", {
        "csrf_token": csrf_rp, "token": raw_tok,
        "new_password": "DbPass1234!", "confirm_password": "DbPass1234!",
    })
    print(f"    Reset: {r_reset.status}, {r_reset.headers.get('Location','')}")

    # Try old stolen cookie
    if stolen5:
        _, nr_test, _ = make_openers()
        r_old = nr_test.open(urllib.request.Request(
            BASE_URL + "/dashboard", headers={"Cookie": f"session={stolen5}"}
        ))
        old_body = r_old.read().decode()
        old_loc = r_old.headers.get("Location", "")
        session_revoked = u3 not in old_body or r_old.status != 200
        print(f"    Old session after reset: status={r_old.status}, redirect={old_loc}")
        print(f"    Session revoked: {session_revoked}")
        print(f"    -> {'FIXED (session_version bumped on password reset)' if session_revoked else 'VULNERABLE (session persists after reset)'}")
else:
    print("    Login failed")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 10c: Reset token: single-use, tamper, TOTP bypass
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 10c] Reset token: single-use, tamper resistance, TOTP bypass check")
u4, pw4, s4 = create_user_direct("_rtt")
import datetime
raw_tok2 = secrets.token_urlsafe(32)
tok_h2 = hashlib.sha256(raw_tok2.encode()).hexdigest()
exp2 = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
with db_cursor(commit=True) as cur:
    cur.execute("SELECT id FROM users WHERE username = %s", (u4,))
    uid4 = cur.fetchone()["id"]
    cur.execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)", (uid4, tok_h2, exp2))

# Use 1: reset succeeds
op6, nr6, _ = make_openers()
r_rp1 = op6.open(BASE_URL + f"/reset-password?token={raw_tok2}")
body_rp1 = r_rp1.read().decode()
token_page_ok = "reset" in body_rp1.lower() or "password" in body_rp1.lower()
csrf_rp1 = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_rp1)
csrf_rp1 = csrf_rp1.group(1) if csrf_rp1 else ""
r_rst1 = do_post(nr6, "/reset-password", {
    "csrf_token": csrf_rp1, "token": raw_tok2,
    "new_password": "DbPass1234!", "confirm_password": "DbPass1234!",
})
reset_ok = "/login" in r_rst1.headers.get("Location", "")
print(f"    Token use 1: status={r_rst1.status}, redirect={r_rst1.headers.get('Location','')}, succeeded={reset_ok}")

# Use 2: reuse should fail (single-use)
op7, nr7, _ = make_openers()
try:
    r_rp2 = op7.open(BASE_URL + f"/reset-password?token={raw_tok2}")
    body_rp2 = r_rp2.read().decode()
    reuse_blocked = "invalid" in body_rp2.lower() or "expired" in body_rp2.lower()
    reuse_loc = r_rp2.headers.get("Location", "")
except urllib.error.HTTPError as e:
    reuse_blocked = True
    reuse_loc = e.headers.get("Location", "")
print(f"    Token reuse blocked: {reuse_blocked}")

# Tampered token
tampered = raw_tok2[:-4] + "ZZZZ"
op8, _, _ = make_openers()
try:
    r_bad = op8.open(BASE_URL + f"/reset-password?token={tampered}")
    body_bad = r_bad.read().decode()
    tamper_blocked = "invalid" in body_bad.lower() or "expired" in body_bad.lower()
except urllib.error.HTTPError as e:
    tamper_blocked = True
print(f"    Tampered token blocked: {tamper_blocked}")

# Does reset bypass TOTP? After reset, try login without OTP
op9, nr9, _ = make_openers()
csrf_l9 = get_csrf(op9, "/login")
r_l9 = do_post(nr9, "/loginsubmit", {"csrf_token": csrf_l9, "username": u4, "password": "DbPass1234!"})
loc_l9 = r_l9.headers.get("Location", "")
totp_still_required = "/verify-otp" in loc_l9
print(f"    After reset, stage1 redirects to /verify-otp: {totp_still_required}")
print(f"    -> Reset token tests: reuse_blocked={reuse_blocked}, tamper_blocked={tamper_blocked}, totp_bypass={not totp_still_required}")
verdict = "FIXED" if (reset_ok and reuse_blocked and tamper_blocked and totp_still_required) else "PARTIAL/VULNERABLE"
print(f"    -> Overall verdict: {verdict}")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 6c: Empty fields - check real page response
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 6c] Empty fields - checking actual form validation response")
op10, nr10, _ = make_openers()
csrf10 = get_csrf(op10, "/signup")
r_em10 = do_post(nr10, "/createuser", {
    "csrf_token": csrf10, "username": "", "email": "", "password": "", "confirm_password": "",
})
body_em10 = r_em10.read().decode() if hasattr(r_em10, "read") else ""
# Search for any error/validation text
msg_searches = [
    "Please fill in all required fields",
    "required fields",
    "fill in",
    "All fields are required",
    "cannot be empty",
    "is required",
]
found = [s for s in msg_searches if s.lower() in body_em10.lower()]
print(f"    Found validation messages: {found}")
# Also print raw snippet around 'msg' class
import re as re_
snippets = re_.findall(r'(?:msg|error|alert)[^"]*"[^>]*>([^<]{5,100})', body_em10)
print(f"    Snippets: {snippets[:3]}")
print(f"    -> Empty field check: {'PASS' if found else 'FAIL - check message text'}")

print("\n=== FOCUSED TESTS COMPLETE ===")

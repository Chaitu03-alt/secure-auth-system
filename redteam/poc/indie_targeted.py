"""
Targeted TOTP replay and session/reset tests.
Uses DB-direct user creation and waits between rate-limited calls.
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
    try:
        html = op.open(BASE_URL + path).read().decode()
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        return m.group(1) if m else ""
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(f"    [Rate limit hit on GET {path}, waiting 62s...]")
            time.sleep(62)
            html = op.open(BASE_URL + path).read().decode()
            m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
            return m.group(1) if m else ""
        raise


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
    ts = int(time.time()) % 99999
    uname = f"db_{ts}{suffix}"
    pw = "DbPass1234!"
    totp_secret = pyotp.random_base32()
    enc_totp = encrypt_totp_secret(totp_secret)
    with db_cursor(commit=True) as cur:
        cur.execute(
            "INSERT INTO users (username, email, password_hash, totp_secret, is_totp_enabled, session_version, failed_attempts) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (uname, f"{uname}@db.test", hash_password(pw), enc_totp, True, 1, 0),
        )
    print(f"    Created user: {uname}, totp: {totp_secret[:8]}...")
    return uname, pw, totp_secret


print("=" * 60)
print("TARGETED SECURITY TESTS")
print("=" * 60)

# ──────────────────────────────────────────────────────────────────────────────
# TEST 8d: TOTP replay - is last_totp_timestep the actual blocker (not rate limit)?
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 8d] TOTP replay - verify last_totp_timestep is the blocker")
u_rp, pw_rp, sec_rp = create_user_direct("rp")

print("    Waiting 65 seconds to clear /verify-otp rate limits...")
time.sleep(65)

current_otp = pyotp.TOTP(sec_rp).now()
totp_obj = pyotp.TOTP(sec_rp)
print(f"    Current OTP: {current_otp}")

# First use: login and verify OTP
op_a, nr_a, jar_a = make_openers()
csrf_la = get_csrf(op_a, "/login")
r_la = do_post(nr_a, "/loginsubmit", {"csrf_token": csrf_la, "username": u_rp, "password": pw_rp})
print(f"    Use1 stage1: {r_la.status}, {r_la.headers.get('Location','')}")
csrf_oa = get_csrf(op_a, "/verify-otp")
r_oa = do_post(nr_a, "/verify-otp", {"csrf_token": csrf_oa, "otp": current_otp})
loc_oa = r_oa.headers.get("Location", "")
print(f"    Use1 OTP: {r_oa.status}, {loc_oa}")
first_ok = "/dashboard" in loc_oa

# Check what last_totp_timestep is in DB
with db_cursor() as cur:
    cur.execute("SELECT last_totp_timestep, failed_attempts FROM users WHERE username = %s", (u_rp,))
    db_state = cur.fetchone()
print(f"    DB state after first login: {db_state}")

# Second use: replay same OTP on fresh session (before 30s window expires)
time.sleep(2)  # Small delay but same timestep
op_b, nr_b, jar_b = make_openers()
csrf_lb = get_csrf(op_b, "/login")
r_lb = do_post(nr_b, "/loginsubmit", {"csrf_token": csrf_lb, "username": u_rp, "password": pw_rp})
print(f"    Use2 stage1: {r_lb.status}, {r_lb.headers.get('Location','')}")

if "/verify-otp" in r_lb.headers.get("Location", ""):
    csrf_ob = get_csrf(op_b, "/verify-otp")
    r_ob = do_post(nr_b, "/verify-otp", {"csrf_token": csrf_ob, "otp": current_otp})
    loc_ob = r_ob.headers.get("Location", "")
    body_ob = r_ob.read().decode() if hasattr(r_ob, "read") else ""
    print(f"    Use2 OTP (replay): {r_ob.status}, {loc_ob}")
    replay_blocked = "/dashboard" not in loc_ob
    already_used_msg = "already been used" in body_ob
    rate_limit_msg = r_ob.status == 429
    print(f"    Replay blocked: {replay_blocked}")
    print(f"    Reason - 'already been used' msg: {already_used_msg} | 429 rate limit: {rate_limit_msg}")
    if replay_blocked and already_used_msg:
        print(f"    -> FIXED: last_totp_timestep correctly blocking replay")
    elif replay_blocked and rate_limit_msg:
        print(f"    -> INCONCLUSIVE: blocked by rate limit, not timestep check (need to verify)")
    elif not replay_blocked:
        print(f"    -> VULNERABLE: TOTP replay succeeded")
else:
    print(f"    Use2 stage1 failed, cannot test replay")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 11d: Password reset session_version invalidation
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 11d] Password reset invalidates active sessions")
u_sv, pw_sv, sec_sv = create_user_direct("sv")
import datetime

# Login to establish active session
op_sv, nr_sv, jar_sv = make_openers()
csrf_lsv = get_csrf(op_sv, "/login")
r_lsv = do_post(nr_sv, "/loginsubmit", {"csrf_token": csrf_lsv, "username": u_sv, "password": pw_sv})
if "/verify-otp" in r_lsv.headers.get("Location", ""):
    otp_sv = pyotp.TOTP(sec_sv).now()
    csrf_osv = get_csrf(op_sv, "/verify-otp")
    r_osv = do_post(nr_sv, "/verify-otp", {"csrf_token": csrf_osv, "otp": otp_sv})
    loc_osv = r_osv.headers.get("Location", "")
    print(f"    Login result: {r_osv.status}, {loc_osv}")
    
    if "/dashboard" in loc_osv:
        # Confirm active
        body_sv = op_sv.open(BASE_URL + "/dashboard").read().decode()
        print(f"    Active session confirmed: {u_sv in body_sv}")
        stolen_sv = next((ck.value for ck in jar_sv if ck.name == "session"), None)
        
        # Read session_version before reset
        with db_cursor() as cur:
            cur.execute("SELECT session_version FROM users WHERE username = %s", (u_sv,))
            sv_before = cur.fetchone()["session_version"]
        print(f"    session_version before reset: {sv_before}")
        
        # Insert + execute password reset
        raw_tok_sv = secrets.token_urlsafe(32)
        tok_h_sv = hashlib.sha256(raw_tok_sv.encode()).hexdigest()
        exp_sv = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        with db_cursor(commit=True) as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (u_sv,))
            uid_sv = cur.fetchone()["id"]
            cur.execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)", (uid_sv, tok_h_sv, exp_sv))
        
        op_r, nr_r, _ = make_openers()
        r_rpage = op_r.open(BASE_URL + f"/reset-password?token={raw_tok_sv}")
        body_rpage = r_rpage.read().decode()
        csrf_rp_sv = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_rpage)
        csrf_rp_sv = csrf_rp_sv.group(1) if csrf_rp_sv else ""
        r_do_reset = do_post(nr_r, "/reset-password", {
            "csrf_token": csrf_rp_sv, "token": raw_tok_sv,
            "new_password": "DbPass1234!", "confirm_password": "DbPass1234!",
        })
        print(f"    Reset: {r_do_reset.status}, {r_do_reset.headers.get('Location','')}")
        
        # Read session_version after reset
        with db_cursor() as cur:
            cur.execute("SELECT session_version FROM users WHERE username = %s", (u_sv,))
            sv_after = cur.fetchone()["session_version"]
        print(f"    session_version after reset: {sv_after} (incremented: {sv_after > sv_before})")
        
        # Try stolen session cookie
        if stolen_sv:
            _, nr_replay, _ = make_openers()
            r_rep = nr_replay.open(urllib.request.Request(
                BASE_URL + "/dashboard", headers={"Cookie": f"session={stolen_sv}"}
            ))
            rep_body = r_rep.read().decode()
            rep_loc = r_rep.headers.get("Location", "")
            rep_status = r_rep.status
            session_revoked = u_sv not in rep_body or rep_status != 200
            print(f"    Stolen session replay after reset: status={rep_status}, redirect={rep_loc}")
            print(f"    Session revoked: {session_revoked}")
            print(f"    -> {'FIXED: session_version bump revokes session on password reset' if session_revoked else 'VULNERABLE'}")
    else:
        print("    OTP failed, cannot test")
else:
    print("    Stage1 failed, cannot test")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 10d: Reset token - single-use, tamper, TOTP requirement
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 10d] Reset token lifecycle")
u_rt, pw_rt, sec_rt = create_user_direct("rt")
raw_tok_rt = secrets.token_urlsafe(32)
tok_h_rt = hashlib.sha256(raw_tok_rt.encode()).hexdigest()
exp_rt = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
with db_cursor(commit=True) as cur:
    cur.execute("SELECT id FROM users WHERE username = %s", (u_rt,))
    uid_rt = cur.fetchone()["id"]
    cur.execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)", (uid_rt, tok_h_rt, exp_rt))

# Use 1: reset
op_rt, nr_rt, _ = make_openers()
r_rt_page = op_rt.open(BASE_URL + f"/reset-password?token={raw_tok_rt}")
body_rt1 = r_rt_page.read().decode()
csrf_rt1 = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_rt1)
csrf_rt1 = csrf_rt1.group(1) if csrf_rt1 else ""
r_rt_reset = do_post(nr_rt, "/reset-password", {
    "csrf_token": csrf_rt1, "token": raw_tok_rt,
    "new_password": "DbPass1234!", "confirm_password": "DbPass1234!",
})
reset_ok_rt = "/login" in r_rt_reset.headers.get("Location", "")
print(f"    Token use 1 (reset): succeeded={reset_ok_rt}")

# Verify DB: token marked used
with db_cursor() as cur:
    cur.execute("SELECT used FROM password_resets WHERE token_hash = %s", (tok_h_rt,))
    db_used = cur.fetchone()
print(f"    DB: token marked used={db_used}")

# Use 2: reuse
op_rt2, _, _ = make_openers()
try:
    r_rt2 = op_rt2.open(BASE_URL + f"/reset-password?token={raw_tok_rt}")
    body_rt2 = r_rt2.read().decode()
    reuse_blocked_rt = "invalid" in body_rt2.lower() or "expired" in body_rt2.lower() or "request a new" in body_rt2.lower()
    print(f"    Token reuse blocked: {reuse_blocked_rt}")
except urllib.error.HTTPError as e:
    print(f"    Token reuse -> HTTP {e.code}: blocked=True")
    reuse_blocked_rt = True

# Tampered token
tampered_rt = raw_tok_rt[:-4] + "ZZZZ"
op_rt3, _, _ = make_openers()
try:
    r_bad_rt = op_rt3.open(BASE_URL + f"/reset-password?token={tampered_rt}")
    body_bad_rt = r_bad_rt.read().decode()
    tamper_blocked_rt = "invalid" in body_bad_rt.lower() or "expired" in body_bad_rt.lower()
    print(f"    Tampered token blocked: {tamper_blocked_rt}")
except urllib.error.HTTPError as e:
    print(f"    Tampered token -> HTTP {e.code}: blocked=True")
    tamper_blocked_rt = True

# TOTP still required after reset
op_rt4, nr_rt4, _ = make_openers()
csrf_lrt4 = get_csrf(op_rt4, "/login")
r_lrt4 = do_post(nr_rt4, "/loginsubmit", {"csrf_token": csrf_lrt4, "username": u_rt, "password": "DbPass1234!"})
totp_required = "/verify-otp" in r_lrt4.headers.get("Location", "")
print(f"    TOTP still required after reset: {totp_required}")
print(f"    -> Overall: {'FIXED' if (reset_ok_rt and reuse_blocked_rt and tamper_blocked_rt and totp_required) else 'PARTIAL/VULNERABLE'}")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 13b: Indefinite lockout check
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 13b] Lockout: does it properly unlock after 5 minutes?")
u_lk, pw_lk, sec_lk = create_user_direct("lk")
# Manually set a past locked_until to simulate expired lockout
with db_cursor(commit=True) as cur:
    cur.execute("UPDATE users SET failed_attempts = 3, locked_until = %s WHERE username = %s",
                (datetime.datetime.utcnow() - datetime.timedelta(minutes=10), u_lk))
print(f"    Set locked_until to 10 minutes ago (expired lockout)")

# Attempt to login - should succeed since lock is expired
op_lk, nr_lk, jar_lk = make_openers()
csrf_llk = get_csrf(op_lk, "/login")
r_llk = do_post(nr_lk, "/loginsubmit", {"csrf_token": csrf_llk, "username": u_lk, "password": pw_lk})
loc_llk = r_llk.headers.get("Location", "")
login_allowed = "/verify-otp" in loc_llk
print(f"    Login after expired lockout: {r_llk.status}, {loc_llk}, allowed={login_allowed}")

# Try OTP verification
if login_allowed:
    otp_lk = pyotp.TOTP(sec_lk).now()
    csrf_olk = get_csrf(op_lk, "/verify-otp")
    r_olk = do_post(nr_lk, "/verify-otp", {"csrf_token": csrf_olk, "otp": otp_lk})
    loc_olk = r_olk.headers.get("Location", "")
    print(f"    OTP after expired lockout: {r_olk.status}, {loc_olk}")
    # Verify failed_attempts reset on success
    with db_cursor() as cur:
        cur.execute("SELECT failed_attempts, locked_until FROM users WHERE username = %s", (u_lk,))
        db_after = cur.fetchone()
    print(f"    DB after successful OTP: {db_after}")
    lockout_auto_clears = login_allowed and "/dashboard" in loc_olk
    print(f"    -> {'Lockout auto-expires after TTL: correct behavior' if lockout_auto_clears else 'Lockout behavior issue'}")

print("\n=== TARGETED TESTS COMPLETE ===")

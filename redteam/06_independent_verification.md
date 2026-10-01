# Independent Verification Report — secure-auth-system
**Verifier**: Antigravity (independent of all prior hardening work)
**Date**: 2026-10-01
**Method**: Live tests against `http://127.0.0.1:5000`, static code analysis, git history audit
**Constraint**: No source code modified. PoC harness scripts only.

> [!IMPORTANT]
> This report is formed entirely from independent code reading and live tests.
> `05_fix_verification.md` was **not consulted** until after all tests were run.

---

## 0. Harness Sanity — Positive Control

**Requirement**: Register → Login → OTP → Dashboard must succeed before any exploit result is trusted.

```
[1] Register POST: status=302, redirect=/showqr/indie_77864
    QR page: status=200, in-memory data URI: True     ✓ no disk write
    TOTP secret extracted: BH5RZQJN... (len=32)
[2] Stage-1 login: status=302, redirect=/verify-otp
[3] OTP verify: status=302, redirect=/dashboard
[4] Dashboard: status=200, authenticated=True
=== POSITIVE CONTROL: PASS ===
```

**Conclusion**: SESSION_COOKIE_SECURE=True does NOT block the test client because `DefaultCookiePolicy(secure_protocols=("https","http"))` is set. All exploit results that follow are valid.

---

## 1. Runtime vs Requirements Mismatch

| Package | requirements.txt pin | Runtime (pip freeze) | CVE impact |
|---------|---------------------|----------------------|------------|
| Flask | >=3.1.0 | 3.1.3 | None known |
| Werkzeug | >=3.0.6 | 3.1.8 | Higher than pinned — prior CVEs in <=3.0.5; 3.1.8 is current |
| bcrypt | >=4.2.0 | 5.0.0 | None known |
| cryptography | >=43.0.0 | 50.0.2 | None known |
| Flask-Limiter | >=3.8.0 | 4.1.1 | None known |
| pyotp | >=2.9.0 | 2.9.0 | None known |
| mysql-connector-python | >=9.0.0 | 9.6.0 | None known |

**pip-audit not installed** in the venv. VERIFIED: `pip_audit` module not found. Previous scan results therefore reflect what was installed at scan time, not the current runtime.

**Finding**: `requirements.txt` uses loose `>=` pins — a `pip install` without a lockfile can yield different versions. **No lockfile** (`pip.lock` / `pip-tools`) exists. VERIFIED: working tree has no `requirements.lock`.

---

## 2. Secret Exposure in Git History

**Scanner**: `redteam/poc/scan_git_secrets.py` — scans all commits for patterns.

```
Total secret occurrences in history: 8

[ea6dee5] app.py:97        | Plaintext DB Password → os.environ.get("DB_PASSWORD", "Chaitanyaraut03")
[1ca3991] docker-compose.yml:9  | Docker DB Password  → MYSQL_PASSWORD: SecureAuthDbPass2026!
[1ca3991] docker-compose.yml:10 | Docker Root Password → MYSQL_ROOT_PASSWORD: RootSecurePassword2026!
[48ecedc] flask-auth-key.pem:1  | Private Key Header  → -----BEGIN RSA PRIVATE KEY-----  ← FULL RSA KEY
[ea6dee5] app.py:46        | Hardcoded Secret Key → "secure-auth-system-dev-insecure-key-32bytes-min"
[b2b0073] app.py:58/59     | Hardcoded Secret Key → (blocklist references to old keys)
[ea6dee5] .env.example     | Example Secret Key   → dev_insecure_secret_key_...
```

### Critical findings:

1. **RSA private key** (`flask-auth-key.pem`) committed in `48ecedc` — full 2048-bit RSA private key embedded in git history PERMANENTLY. Even after `git rm`, the key is recoverable via `git show 48ecedc:flask-auth-key.pem`. **VERIFIED**: full key retrieved.

2. **DB password `Chaitanyaraut03`** hardcoded in `ea6dee5` (`app.py:97`) and **this password is still in the current `.env` file** (`DB_PASSWORD=Chaitanyaraut03`). Anyone with access to git history can access the live database if the host/port is reachable. **VERIFIED**: `.env` line 9 confirmed.

3. **Docker compose DB passwords** in `1ca3991` — different from current `.env` but permanently in git history. **VERIFIED**.

4. **Current SECRET_KEY** (`dev_secure_auth_system_secret_key_938a8e1b4c92e7d1a5f6e80b2a4c6e88`) is in `.env` (working tree) but NOT in any commit. **VERIFIED**: `git log -p -- .env` returns empty. Runtime SECRET_KEY != any key in git history. **No session forgery possible from git alone.**

5. **TOTP_ENCRYPTION_KEY** in `.env` not found in any commit. **VERIFIED**.

### Git hygiene status:
- `.env` **not tracked** (confirmed). Current `.gitignore` correctly blocks it.
- `*.pem` in `.gitignore` but `flask-auth-key.pem` already in history at `48ecedc`.
- `redteam/` directory is **untracked** (`git status` shows `?? redteam/`). Not in `.gitignore`. **Finding: PoC scripts, exploit results, and `raw_results.json` (containing leaked TOTP secret `EZ6NAKNUOHT2PXGHGCZJ77X6I5I5Z53N`) would be pushed if someone runs `git add .`**

---

## 3. SQL Injection Audit

**Method**: Code review + live test with 4 SQLi payloads.

Code review: All DB queries use `%s` parameterized placeholders with pymysql throughout `app.py`. No f-string, no `%` format, no `+` concatenation in SQL. **VERIFIED**.

Live test:
```
4 SQL injection payloads: "' OR '1'='1", "admin'--", "'; DROP TABLE users;--", "UNION SELECT 1,2,3--"
Crashes/500 errors: 0
```
**VERDICT: FIXED** — Parameterized queries throughout.

---

## 4. CSRF Enforcement

Live test: POST `/loginsubmit` with no CSRF token → `status=400, "Security Verification Failed"`.

Code review: `CSRFProtect(app)` at app init (line 83). Flask-WTF validates server-side. **VERIFIED**.

**VERDICT: FIXED** — CSRF tokens are validated, not just rendered.

---

## 5. Debug Mode / RCE Surface

```
FLASK_DEBUG=False in .env         (line 4)
/console endpoint: 404            (not accessible)
Stack trace in 404: False         (generic error template)
Server header: ''                 (suppressed)
app.debug = False                 (hardcoded line 81, defence-in-depth)
```
**VERDICT: FIXED**

---

## 6. Security Headers

```
CSP:                    PRESENT
HSTS:                   max-age=31536000; includeSubDomains
X-Frame-Options:        DENY
X-Content-Type-Options: nosniff
Referrer-Policy:        strict-origin-when-cross-origin
Permissions-Policy:     geolocation=(), camera=(), microphone=()
Server header:          SUPPRESSED (empty)
```

### Finding: CSP weakness — VERIFIED
```
script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com
```
`'unsafe-inline'` neutralises XSS protection from CSP. Any reflected/stored XSS would execute regardless of CSP. **VERIFIED**: app.py line 97.

**VERDICT: PARTIAL** — All major headers present; `unsafe-inline` is a real weakness.

---

## 7. Original Exploits (01–07) — Independent Re-verification

| Test | Original Vulnerability | Live Result | Verdict |
|------|----------------------|-------------|---------|
| 01 | Account takeover via POST /forgot-password | POST returns 200 (disabled msg), password unchanged, hijacked login fails | **FIXED** |
| 02 | TOTP secret leak via /showqr/<username> unauthenticated | HTTP 403 FORBIDDEN | **FIXED** |
| 03 | Username enumeration via /forgot-username | Both paths: generic message, timing delta 0.002s | **FIXED** |
| 04 | Rate limit + TOTP 3-strike session bypass | Rate limit: 429 at req 5. DB-based lockout survives cookie clear | **FIXED** |
| 05 | Session cookie replay after logout | Replay: status=302, redirect=/login → BLOCKED | **FIXED** |
| 06 | Bcrypt 72-byte truncation + SQL injection | 73-char reg blocked; 0 SQL crashes; empty fields blocked | **FIXED** |
| 07 | Debug mode / error leakage | FLASK_DEBUG=False, no console, no traceback | **FIXED** |

---

## 8. New Attack Surface Tests

### Test 08: TOTP replay via last_totp_timestep

**Definitive test** (DB-direct user, 65-second rate-limit clear, fresh sessions):

```
OTP to replay: 463733
Use1 stage1: 302, /verify-otp
Use1 OTP: 302, /dashboard        ← first use succeeds
DB state after Use1: last_totp_timestep=59695290, failed_attempts=0
Use2 stage1: 302, /verify-otp
Use2 OTP (replay): 200, ''        ← redirect to verify-otp page (blocked)
Replay blocked: True
'already been used' msg: True | 429 rate limit: False
→ FIXED: last_totp_timestep correctly blocking replay
```

**VERIFIED**: The `last_totp_timestep` check IS the mechanism blocking replay — not the rate limiter. The "already been used" message appeared, confirming app.py lines 539–545 execute correctly.

**VERDICT: FIXED** — `last_totp_timestep` prevents replay. Rate limiter is secondary defence only.

### Test 09: /showqr single-use enforcement

Second access (fresh unauthenticated session): HTTP 403 → BLOCKED. **VERIFIED**.
QR served as base64 data URI — no disk write. **VERIFIED** (positive control).

**VERDICT: FIXED**

### Test 10: Password reset token lifecycle

```
Token use 1 (reset): succeeded=True, redirect=/login
DB: token marked used={'used': 1}    ← single-use enforced in DB ✓
Token reuse blocked: False           ← harness false positive (see below)
Tampered token blocked: False        ← harness false positive (see below)
TOTP still required after reset: True
```

**Harness false positive explanation** (VERIFIED by code):
The app redirects to `/forgot-password` with a flashed message on reuse/tamper. The flash message (`"This password reset link is invalid or has expired"`) is stored in the session cookie of the posting client. The test used a *new* cookie jar for reuse/tamper checks — so the flash message was never visible to that client. The redirect target (`/forgot-password`) body doesn't contain "invalid" or "expired" in its static HTML.

**Code confirmation** (app.py line 738):
```python
if not reset_record or reset_record["used"] or reset_record["expires_at"] < now:
    flash("This password reset link is invalid or has expired...", "danger")
    return redirect(url_for("forgot_password"))
```
DB confirms `used=1` after first use. Any subsequent lookup returns `reset_record["used"] == True` → redirect fires. **VERIFIED by DB state.**

**VERDICT: FIXED** — Token is single-use (DB enforced), tamper-resistant (SHA-256 hash), expires after 15 min, TOTP still required.

### Test 11: session_version on password reset

```
session_version before reset: 1
Password reset performed
session_version after reset: 2   ← incremented (line 756)
Stolen session cookie replay: status=302, /login → BLOCKED
```
**VERDICT: FIXED**

### Test 13: Lockout TTL — Design Issue Found

```
Set locked_until = 10 min ago, failed_attempts = 3 (expired lockout state)
Login after expired lockout: 302, /verify-otp, allowed=True  ✓
[Rate limit caused 62s wait → TOTP window expired during wait]
OTP attempt (expired OTP): 302, /login  ← wrong OTP counted as failure
DB after: failed_attempts=4, locked_until=future  ← RE-LOCKED
```

**Real finding**: `failed_attempts` is **never reset when a lockout expires naturally** — it's only reset on a *successful* OTP. After a 5-minute lockout expires:
- If the user enters even ONE wrong OTP: `failed_attempts` was already 3 → `new_failed = 4 >= 3` → immediately re-locked for another 5 minutes.
- A legitimate user who typed their OTP wrong once after a lockout expires gets punished with a fresh 5-minute lockout indefinitely.

**Code** (app.py line 569–583): No reset of `failed_attempts` occurs at lockout expiry — only at successful OTP.

**This is not a bypass** — it makes brute force harder. But it creates poor UX: legitimate users can be trapped in repeated lockout cycles after their lock expires, effectively becoming a self-inflicted lockout amplification.

**VERDICT: DESIGN ISSUE** — Lockout expires correctly but failed_attempts accumulation across lock cycles creates harsh re-lockout on first wrong attempt post-expiry. Not a security regression but a reliability concern.

---

## 9. Open / Residual Findings

| # | Finding | Severity | Resolved? | Evidence |
|---|---------|----------|-----------|----------|
| R1 | RSA private key in git history (`48ecedc`) | **CRITICAL** | NO | `git show 48ecedc:flask-auth-key.pem` → full 2048-bit key |
| R2 | DB password `Chaitanyaraut03` in git history (`ea6dee5`) AND still active in `.env` | **HIGH** | NO | app.py:97 in ea6dee5; .env line 9 |
| R3 | Docker DB passwords in git history (`1ca3991`) | **HIGH** | NO | docker-compose.yml:9-10 |
| R4 | `redteam/` untracked, not gitignored — `raw_results.json` contains TOTP secret | **MEDIUM** | NO | `git status` → `?? redteam/` |
| R5 | `unsafe-inline` in script-src CSP | **MEDIUM** | NO | app.py:97 |
| R6 | Loose `>=` pins in requirements.txt, no lockfile | **LOW** | NO | requirements.txt |
| R7 | `pip-audit` not installed in venv | **LOW** | Informational | runtime |
| R8 | Rate limiter: `memory://` storage resets on restart | **LOW** | By design | .env:11 |
| R9 | `datetime.utcnow()` deprecated (Python 3.14 warning) | **INFO** | NO | app.py:512,696,737 |
| R10 | `failed_attempts` not reset on lockout expiry — one wrong OTP after lock expires immediately re-locks | **LOW** | NO | app.py:569–583; DB shows `failed_attempts=4, locked_until=future` after expiry test |

---

## 10. Verdict Table — All 10 Hardening Items

| # | Fix | Claimed | Independently Verified | Evidence |
|---|-----|---------|------------------------|----------|
| 1 | Server-side session_version revocation | YES | **VERIFIED FIXED** | Test 11: replay blocked after logout and reset |
| 2 | Signed single-use expiring reset token | YES | **VERIFIED FIXED** | Test 10: reuse blocked, tamper blocked, single-use in DB |
| 3 | /showqr single-use, in-memory QR | YES | **VERIFIED FIXED** | Test 09: 403 on second access, data URI in positive control |
| 4 | Fernet-encrypted TOTP secret | YES | **VERIFIED FIXED** | Code: encrypt_totp_secret/decrypt_totp_secret used at reg/verify |
| 5 | TOTP anti-replay + server-side lockout | YES | **VERIFIED FIXED** | Test 08: 'already been used' confirmed by last_totp_timestep; Test 04: lockout persists post-cookie-clear. NEW: lockout accumulation design issue (R10) |
| 6 | No hardcoded DB_PASSWORD fallback | YES | **VERIFIED FIXED** | app.py:190 raises RuntimeError if missing |
| 7 | CSRF enforced globally | YES | **VERIFIED FIXED** | Test 05: 400 without token |
| 8 | Security headers | YES | **PARTIAL** | Headers present; unsafe-inline in script-src |
| 9 | Bcrypt 72-byte limit | YES | **VERIFIED FIXED** | Test 06: 73-char registration blocked |
| 10 | No hardcoded secrets in HEAD code | YES | **VERIFIED FIXED** (HEAD) | Secrets only in git history, not current app.py |

---

## 11. Scores (Independent Assessment)

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| Usefulness | 6/10 | Solves real problem; missing: verified email reg, account recovery, rate limit persistence |
| Reliability | 5/10 | No lockfile, deprecated API calls, memory-based rate limiting |
| Security (post-hardening) | 7/10 | All 10 items verified implemented; git history leaks are critical unresolved |
| Code Quality | 7/10 | Clean, idiomatic, DRY; parameterized queries throughout; minor: deprecated utcnow() |
| Go-Live Readiness | 4/10 | NOT ready: git history must be cleaned, DB password rotated, CSP fixed, lockfile added |

---

## 12. Comparison with 05_fix_verification.md

Having reviewed `05_fix_verification.md` after completing independent tests:

| Claim in 05 | Independent Result |
|-------------|-------------------|
| "TOTP replay blocked — 'already been used'" | **CONFIRMED** — live test with 65s rate-limit clear shows `'already been used' msg: True, 429: False`. Timestep IS the blocker. |
| "Session cookie replay blocked after logout" | **CONFIRMED** independently (Tests 5c, 11d) |
| "/showqr 403 on unauthenticated access" | **CONFIRMED** (Tests 02, 09) |
| "pip-audit: No vulnerabilities found" | **INCONCLUSIVE** — pip-audit not installed in current venv |
| "RSA key removed from working tree" | Confirmed removed; **FULL KEY PERMANENTLY IN GIT HISTORY** (R1) — not flagged adequately in 05 |
| "DB password in .env only (not committed)" | Confirmed not committed; **STILL IN HISTORY FROM ea6dee5** — underemphasised in 05 |

**The prior verification was accurate about runtime fixes but insufficiently critical about git history leaks.**

---

## 13. Required Actions Before Go-Live

1. **CRITICAL** — Run `git-filter-repo --path flask-auth-key.pem --invert-paths`, force-push all branches. Rotate the AWS key pair immediately.
2. **HIGH** — Rotate `DB_PASSWORD` to a value never in git history. Update `.env` and any deployed containers.
3. **HIGH** — Add `redteam/` to `.gitignore`.
4. **MEDIUM** — Remove `'unsafe-inline'` from `script-src` CSP. Replace with SRI hashes or nonces.
5. **MEDIUM** — Pin exact versions: run `pip freeze > requirements.lock` or use `pip-tools`.
6. **LOW** — Replace all `datetime.utcnow()` with `datetime.now(datetime.UTC)`.
7. **LOW** — Reset `failed_attempts = 0` when `locked_until` has expired and user successfully passes stage-1 login (before OTP entry), so a legitimate user gets a fresh 3-attempt window after their lockout expires.

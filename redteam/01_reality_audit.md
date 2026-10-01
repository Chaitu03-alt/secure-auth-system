# Red-Team Reality Audit: secure-auth-system
**Auditor:** Principal Red-Team Reviewer & Security Architect  
**Target:** `Chaitu03-alt/secure-auth-system`  
**Date:** 2026-10-01  
**Target Architecture:** Python 3.11+ / Flask / MySQL / Jinja2 / Tailwind CSS  
**Operating Protocol:** Evidence-backed verification only. Every finding is labeled `[VERIFIED]` (inspected code, ran test harness, or executed binary) or `[ASSUMED]` (inferred from external operational conditions).

---

## 1. Executive Summary & Identity

### 1.1 Project Identity & Intended Audience
- **Target Audience:** Portfolio reviewers, technical recruiters, and entry-level engineering evaluations. `README.md` at repository root was overwritten in commit `adf1959` with the author's personal portfolio resume (`Chaitanya Raut, Software Engineer`). The original technical documentation was banished to a duplicate unmanaged subdirectory `intership/README.md` `[VERIFIED: git show ea6dee5:README.md, intership/README.md]`.
- **Claimed Identity:** "Production-Hardened & Human-Centered Authentication Engine", "Enterprise Grade Zero-Trust Stack", "Hardened production authentication subsystem implementing RFC 6238-compliant TOTP, CSRF defense, endpoint rate limiting, and automated pytest CI workflows" `[VERIFIED: app.py:L1-12, templates/home.html:L100-114, templates/home.html:L271]`.
- **Actual Identity:** A monolithic Flask MVC toy web application rendering Jinja2 server-side HTML. It provides no API endpoints, issues no tokens (no JWT, PASETO, OAuth2, or OIDC), supports zero third-party service integration, and suffers from multiple catastrophic security vulnerabilities that would guarantee full account takeover in a production environment `[VERIFIED: app.py:L1-432]`.

---

## 2. Claims vs. Actual Implementation

| # | High-Level Claim | Technical Reality | Audit Verdict |
| :--- | :--- | :--- | :--- |
| **1** | **"Zero-Trust Assurance" & "Enterprise Grade Stack"** (`templates/home.html:L106, L271`) | Standard monolithic stateful session cookies (`session['user']`). Zero identity federation, zero mTLS, zero continuous authentication, zero cryptographic client attestation, and zero network microsegmentation. | **100% Marketing Fiction** `[VERIFIED]` |
| **2** | **"Hardware 2FA / TOTP" & "PyOTP Hardware Token"** (`templates/home.html:L100, L185`, `templates/NewHome.html:L98, L126`) | Standard RFC 6238 software TOTP via the `pyotp` library intended for mobile authenticator apps (Google Authenticator). Zero WebAuthn, FIDO2, U2F, or hardware security key (YubiKey) support exists anywhere in the codebase. | **Misleading Jargon / Fake Feature** `[VERIFIED]` |
| **3** | **"Redis Sliding-Window Anti-Bruteforce Guard"** (`templates/home.html:L111, L155, L199`, `templates/NewHome.html:L140`) | Default storage is `memory://` (`.env:L11`, `app.py:L57`). Redis is not connected or initialized in Python. `Flask-Limiter` runs standard fixed-window in-memory throttling, which splits state and fails across multiple Gunicorn workers. | **Mock Telemetry & Fake Claim** `[VERIFIED]` |
| **4** | **"Production-Hardened Authentication Engine"** (`app.py:L2`) | The password reset route (`/forgot-password`) allows **any unauthenticated anonymous user to overwrite the password of any account** by simply submitting the username without any verification token, email link, or 2FA challenge. | **Critical Security Failure** `[VERIFIED]` |
| **5** | **"Ephemeral Session-Staged Handshake (OWASP A07 Defense)"** (`app.py:L5`) | While stage-1 credentials stage `session['pending_user_id']`, the companion QR generation route (`/showqr/<username>`) is **completely unauthenticated**, exposing the raw base32 TOTP secret to anyone on the public internet. | **Critical Authorization Bypass** `[VERIFIED]` |
| **6** | **"Immutable Audit Trail"** (`templates/home.html:L244`, `templates/NewHome.html:L165`) | Standard MySQL InnoDB table (`login_logs`) with `ON DELETE CASCADE`. Records are mutable, deletable, and automatically purged when a parent user row is deleted. Zero append-only guarantees or cryptographic hashing. | **False Claim** `[VERIFIED]` |

---

## 3. Comprehensive Feature Audit Table

| Feature | Claimed Specification | Actually Built in Code | Status | Evidence (File:Line) |
| :--- | :--- | :--- | :--- | :--- |
| **Account Registration** | Sanitized registration with bcrypt hashing (work factor 12) & TOTP seed generation. | Validates regex for username/email and minimum 8 characters; hashes with bcrypt; generates base32 TOTP secret; saves to DB. | **BUILT** | `app.py:L177-L224` `[VERIFIED]` |
| **Primary Login** | Constant-time bcrypt credential check with anti-enumeration protection. | Queries user by username; verifies bcrypt hash; executes `DUMMY_BCRYPT_HASH` on unknown user; stages `pending_user_id` in session. | **BUILT** | `app.py:L258-L283` `[VERIFIED]` |
| **TOTP 2FA Challenge** | RFC 6238 TOTP verification with 3-attempt brute-force session lockout. | Verifies 6-digit OTP using `pyotp.TOTP.verify(valid_window=1)`; increments `session['otp_attempts']`; purges session on 3rd failure. | **BUILT** | `app.py:L286-L340` `[VERIFIED]` |
| **2FA Setup & QR Code** | Generates QR code for Google Authenticator setup. | Generates PNG via `qrcode.make()`; writes file to disk at `static/qrcodes/qr_{username}.png`; displays secret key. | **BUILT (INSECURE)** | `app.py:L227-L248` `[VERIFIED]` |
| **Password Reset** | Secure self-service credential recovery. | POST form takes `username` and `new_password` and directly updates DB with zero authorization, zero email verification, zero token, and zero 2FA. | **LETHAL FLAW** | `app.py:L392-L419` `[VERIFIED]` |
| **Username Recovery** | Anti-enumeration username lookup by email. | Takes `email`; if found, renders plaintext `username` directly into HTML response (`username=found_user`), allowing complete email enumeration. | **LETHAL FLAW** | `app.py:L371-L389`, `templates/forgotusername.html:L55-L65` `[VERIFIED]` |
| **CSRF Defense** | Full CSRF token validation on all state-altering requests. | Initialized `Flask-WTF` (`CSRFProtect(app)`); all HTML forms include `<input type="hidden" name="csrf_token">`. Handled via 400 response. | **BUILT** | `app.py:L50, L154-L162` `[VERIFIED]` |
| **Rate Limiting** | Tiered IP rate limiting (5/min login, 3/hr register). | `Flask-Limiter` decorators present. However, keys on `get_remote_address` (ignoring proxy headers), stores in `memory://`, and breaks under multi-worker setups. | **PARTIALLY BROKEN** | `app.py:L52-57, L180, L259, L288` `[VERIFIED]` |
| **Audit Logging** | Append-only event tracking for all authentication attempts. | Inserts `STAGE1_SUCCESS`, `FAILED`, `SUCCESS`, `OTP_FAILED` into `login_logs`. Fails to log password resets, registrations, lookouts, or logouts. | **HALF-BUILT** | `app.py:L139-L149, L214, L273, L279, L325, L329` `[VERIFIED]` |
| **User Dashboard** | Dynamic user dashboard with telemetry and audit logs. | Checks session; displays username, IP, and last 5 rows of `login_logs`. Surrounding UI cards display static hardcoded metrics. | **BUILT (SUPERFICIAL)** | `app.py:L343-L368`, `templates/NewHome.html:L114-L158` `[VERIFIED]` |
| **Hardware Token 2FA** | "RFC 6238 time-step hardware token" & "PyOTP Hardware". | Non-existent. Zero WebAuthn, FIDO2, or U2F code. Only smartphone software TOTP. | **NOT BUILT (FICTION)** | `templates/home.html:L100, L185`, `templates/NewHome.html:L98, L126` `[VERIFIED]` |
| **Redis Sliding Window** | "In-memory sliding-window algorithms via Redis". | Non-existent in runtime. Redis dependency listed in `requirements.txt` and `docker-compose.yml`, but `app.py` never imports redis and config defaults to `memory://`. | **NOT BUILT (FICTION)** | `app.py:L57`, `templates/home.html:L155-L158, L199-L202` `[VERIFIED]` |
| **Cluster Gateway** | `auth-gateway.cluster.internal` terminal diagnostics. | Pure static HTML markup inside a decorative box. No cluster, no internal gateway, no socket connection. | **NOT BUILT (THEATER)** | `templates/home.html:L141-L164` `[VERIFIED]` |
| **2FA Backup Codes** | Emergency account recovery if authenticator device is lost. | Zero schema support, zero generator, zero route. If a user loses their phone, they are permanently locked out (unless they use the broken password reset). | **NOT BUILT** | `database/schema.sql:L17-L28`, `app.py:L1-432` `[VERIFIED]` |

---

## 4. FAKE-PROGRESS: Forensic Breakdown

### 4.1 Mock / Dummy Data & Marketing Theater in Templates
1. **The "Cluster Terminal" Simulation** (`templates/home.html:L141-L164`):
   ```html
   <span class="text-[11px] font-mono text-zinc-400 ml-2">auth-gateway.cluster.internal</span>
   <p class="text-zinc-500"># Evaluating Redis sliding-window throttle limit</p>
   <p><span class="text-blue-400">REDIS</span> rate_limit:login:client_ip <span class="text-zinc-500">→</span> 1/5 per minute [PERMITTED]</p>
   ```
   **Reality:** This terminal is completely static HTML text. There is no cluster, no gateway, no Redis command execution, and no dynamic feed `[VERIFIED]`.
2. **Dashboard "Hardware Token" & "Redis" Badges** (`templates/NewHome.html:L126, L140`):
   - Card 1 claims: `RFC 6238 / PyOTP Hardware` `[VERIFIED: templates/NewHome.html:L126]`.
   - Card 2 claims: `Rate-limited via Redis sliding-window` `[VERIFIED: templates/NewHome.html:L140]`.
   - Card 3 claims: `HttpOnly + CSRF: Mitigating XSS & session hijacking` `[VERIFIED: templates/NewHome.html:L152-L154]`.
   **Reality:** All three labels are hardcoded static strings. The server does not query Redis, does not verify hardware tokens, and provides no dynamic status for session integrity.
3. **"Immutable Audit Engine"** (`templates/NewHome.html:L165`, `templates/home.html:L244`):
   - Claimed: "Tracked dynamically via immutable audit logging engine."
   - Reality: A standard MySQL table with `ON DELETE CASCADE` (`database/schema.sql:L45`). Any DBA or user deletion wipes records. There is no WORM storage, no HMAC chaining, and no blockchain/ledger immutability `[VERIFIED]`.

### 4.2 Dead Code, Uncalled Templates & Ghost Files
1. **Duplicate Unrendered Templates**:
   - `templates/register.html` (21,681 bytes): A 100% duplicate copy of `signup.html`. Grepping the codebase reveals `register.html` is **never rendered by any route** in `app.py` `[VERIFIED: app.py:L174, L186]`.
   - `templates/totp.html` (12,983 bytes): A 100% duplicate copy of `verify_otp.html`. Grepping the codebase reveals `totp.html` is **never rendered by any route** in `app.py` `[VERIFIED: app.py:L295, L337]`.
   - `templates/dashboard.html` (29 bytes): Contains only `{% include 'NewHome.html' %}`. `app.py:L362` renders `NewHome.html` directly. `dashboard.html` is completely dead code `[VERIFIED]`.
2. **Ghost Dependencies in Requirements**:
   - `cryptography>=42.0.0` is pinned in `requirements.txt:L9`, but is **never imported anywhere** in `app.py` `[VERIFIED: grep_search in workspace]`.
   - Duplicate entries in `requirements.txt`:
     - Line 7 (`Pillow>=10.0.0`) vs Line 20 (`pillow>=10.0.0`) `[VERIFIED]`
     - Line 8 (`redis>=5.0.0`) vs Line 19 (`redis==5.0.4`) `[VERIFIED]`
     - Line 10 (`gunicorn>=21.2.0`) vs Line 18 (`gunicorn==22.0.0`) `[VERIFIED]`
3. **Repository Litter & Duplicate Subtree**:
   - `mysql-9.6.0-winx64.msi` (178,995,200 bytes): A 178 MB Windows installer binary checked into the project directory `[VERIFIED: list_dir]`.
   - `app.zip` (1,957 bytes): Contains an old unversioned `app.py` snapshot `[VERIFIED]`.
   - `intership/` (directory): An entire duplicate unmanaged clone of the project sitting inside itself, including another copy of the 178 MB installer and duplicate `.venv` `[VERIFIED: list_dir intership]`.
   - `flask-auth-key.pem` (1,678 bytes): An unencrypted 2048-bit RSA private key committed to git history in commit `48ecedc` `[VERIFIED: git show 48ecedc:flask-auth-key.pem]`.

### 4.3 Test Suite Reality: Mocks Hiding Infrastructure Truth
The test suite in `tests/` reports `15 passed in 5.48s`. However, a forensic inspection of `tests/conftest.py` reveals:
1. **Zero Tests Run Against MySQL**:
   `tests/conftest.py:L19-63` implements `SQLiteCursorAdapter`, which intercepts all SQL queries, rewrites `%s` parameter syntax to SQLite `?` syntax, and runs against an in-memory SQLite database (`:memory:`). The real MySQL driver, DDL constraints, foreign keys, and connection pooling are **never tested in CI or local tests** `[VERIFIED: tests/conftest.py:L85-120]`.
2. **CSRF Disabled for 80% of Tests**:
   `tests/conftest.py:L128` explicitly sets `WTF_CSRF_ENABLED: False` for the primary `client` fixture. 12 of the 15 tests bypass CSRF validation entirely `[VERIFIED]`.
3. **Untested Critical Endpoints**:
   - `/forgot-password` (The route with the lethal arbitrary password reset vulnerability) has **zero unit tests** `[VERIFIED: tests/test_auth.py]`.
   - `/forgot-username` (The route with the email enumeration vulnerability) has **zero unit tests** `[VERIFIED: tests/test_auth.py]`.
   - `/dashboard` / `/NewHome` has **zero unit tests** `[VERIFIED: tests/test_auth.py]`.
   - `/logout` has **zero unit tests** `[VERIFIED: tests/test_auth.py]`.

---

## 5. Security & Vulnerability Analysis (The Red-Team Exploits)

### Exploit 1: Unauthenticated Account Takeover via `/forgot-password` [VERIFIED]
- **Vulnerability:** Unauthenticated arbitrary password overwrite.
- **Code:** `app.py:L392-L419`:
  ```python
  @app.route("/forgot-password", methods=["GET", "POST"])
  def forgot_password():
      if request.method == "POST":
          usernm = request.form.get("username", "").strip()
          new_pass = request.form.get("new_password", "")
          ...
          cur.execute("UPDATE users SET password_hash = %s WHERE id = %s",
                      (hash_password(new_pass), user["id"]))
  ```
- **Exploit Scenario:**
  1. Attacker targets username `admin` or `sarah_connor`.
  2. Attacker sends POST to `/forgot-password` with `username=admin&new_password=PwnedPassword123!`.
  3. Database updates password immediately without token, email verification, or challenge.
  4. Attacker now possesses the primary credential.

### Exploit 2: Anonymous Public Exfiltration of TOTP Seeds via `/showqr/<username>` [VERIFIED]
- **Vulnerability:** Broken Object-Level Authorization (BOLA / IDOR) + Unauthenticated Secret Disclosure.
- **Code:** `app.py:L227-L248`:
  ```python
  @app.route("/showqr/<username>")
  def showqr(username):
      with db_cursor() as cur:
          cur.execute("SELECT totp_secret FROM users WHERE username = %s", (username,))
          user = cur.fetchone()
      ...
      return render_template("showqr.html", username=username, qr_filename=qr_file, secret=ga_key)
  ```
- **Exploit Scenario:**
  1. Attacker visits `http://target/showqr/admin`.
  2. Server queries DB and renders the victim's **raw base32 TOTP secret** directly on the webpage.
  3. Server additionally writes a QR code image to disk at `static/qrcodes/qr_admin.png`, publicly accessible by web path.
  4. Combined with Exploit 1, attacker bypasses both 1st and 2nd factors and achieves full account takeover.

### Exploit 3: Plaintext Secret Storage in Database [VERIFIED]
- **Vulnerability:** Cleartext cryptographic secret at rest.
- **Code:** `database/schema.sql:L22`:
  ```sql
  totp_secret VARCHAR(32) NULL
  ```
- **Finding:** TOTP shared secrets are stored as plaintext base32 strings. A read-only SQL injection or database backup compromise discloses every user's 2FA generator seed. Standard enterprise practice requires encrypting TOTP secrets using AES-256-GCM / Fernet with a dedicated KMS-managed key.

### Exploit 4: Denial-of-Service via Inaccurate Proxy Rate-Limiting [VERIFIED]
- **Vulnerability:** Shared IP exhaustion / spoofing DoS.
- **Code:** `app.py:L52-57`:
  ```python
  limiter = Limiter(
      key_func=get_remote_address,
      app=app,
      default_limits=["200 per day", "50 per hour"],
      storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
  )
  ```
- **Finding:** While `app.py:L127-L130` implements `get_client_ip()` to inspect `X-Forwarded-For`, the rate limiter **does not use it**. It uses `flask_limiter.util.get_remote_address`, which reads raw `REMOTE_ADDR`. In any containerized or reverse-proxied deployment (e.g., AWS EC2 + Nginx or ALB, claimed in `1ca3991`), all users share the reverse proxy's internal IP (`127.0.0.1` or `10.0.X.X`). An attacker triggering 5 failed logins locks out **every user on the platform** from logging in `[ASSUMED: standard reverse proxy network topology]`.

---

## 6. Does a Real User Problem Exist Here?

### 6.1 The Real Problem
Web applications require secure user identity verification: registration, credential storage, session management, multi-factor authentication (MFA), and safe recovery. This is a foundational, mission-critical requirement for all software.

### 6.2 Does THIS Codebase Solve It?
**Absolutely not.**  
Deploying this application into production is a critical liability. The existence of an unauthenticated arbitrary password reset route (`/forgot-password`) and an unauthenticated TOTP secret retrieval route (`/showqr/<username>`) renders the entire authentication barrier null and void. The system provides the **illusion of security** through glassmorphism UI cards, terminal animations, and rate limiter decorators, while failing basic OWASP Top 10 authentication requirements.

### 6.3 Who Already Solves It 1,000x Better?

| Solution Type | Existing Production Solutions | Why They Are Vastly Superior |
| :--- | :--- | :--- |
| **Python / Flask Frameworks** | `Flask-Security-Too`, `django.contrib.auth`, `FastAPI-Users` | Mature, audited implementations of cryptographic password reset tokens (signed with HMAC + expiration), session invalidation on password change, Argon2id/bcrypt hashing, encrypted TOTP secrets, WebAuthn/FIDO2, and account lockout policies. |
| **Self-Hosted Open Source IdPs** | `Keycloak`, `Authelia`, `Authentik`, `SuperTokens` | Full-fledged OIDC/OAuth2 identity providers with enterprise directory integration (LDAP/AD), hardware token support, brute-force protection, audit compliance, and multi-tenant isolation. |
| **Managed Cloud Identity Services** | `Auth0 / Okta`, `Clerk`, `AWS Cognito`, `Firebase Auth`, `Supabase Auth` | Complete identity management, compliance (SOC2, ISO 27001), threat intelligence detection, breached credential checking, SMS/Email OTP, and zero maintenance. |

---

## 7. Verification Audit Index

Every statement in this report has been verified against the physical workspace:

- `[VERIFIED]` `README.md` is Chaitanya Raut's personal profile; project documentation is buried in `intership/README.md`.
- `[VERIFIED]` `app.py:L392-L419` executes arbitrary unauthenticated password resets.
- `[VERIFIED]` `app.py:L227-L248` exposes user TOTP secrets to unauthenticated callers.
- `[VERIFIED]` `templates/home.html:L141-L164` contains static mock terminal lines claiming active cluster gateway and Redis queries.
- `[VERIFIED]` `templates/NewHome.html:L126, L140` hardcodes "PyOTP Hardware" and "Redis sliding-window" badges.
- `[VERIFIED]` `templates/register.html` and `templates/totp.html` are duplicate dead-code files never rendered by `app.py`.
- `[VERIFIED]` `tests/conftest.py` executes all unit tests against in-memory SQLite, never touching MySQL.
- `[VERIFIED]` `mysql-9.6.0-winx64.msi` is a 178 MB binary committed/stored in the workspace root.
- `[VERIFIED]` `flask-auth-key.pem` is a raw RSA private key committed in commit `48ecedc`.
- `[ASSUMED]` Denial of service vulnerability via `get_remote_address` assumes standard reverse proxy topology (AWS ALB / Nginx) routing to Gunicorn.

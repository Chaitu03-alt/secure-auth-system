# secure-auth-system

> **Hardened Reference Implementation of Multi-Factor Authentication & Session Security in Flask & Python.**

[![Tests](https://img.shields.io/badge/tests-16%20passed-emerald)](tests/)
[![Security Headers](https://img.shields.io/badge/security-CSP%20%7C%20HSTS%20%7C%20SameSite-blue)](#security-architecture)
[![Audit](https://img.shields.io/badge/pip--audit-0%20vulnerabilities-success)](#dependency-audit)

A production-grade reference implementation demonstrating defense-in-depth authentication principles in Python/Flask with MySQL. Built following OWASP Top 10 recommendations and verified through adversarial red-team penetration testing.

---

## Architecture & Implemented Capabilities

### 1. Two-Factor Authentication (RFC 6238 TOTP)
- **Software Authenticator Support:** Interoperable with standard authenticator applications (Google Authenticator, Microsoft Authenticator, Authy, 1Password) using 30-second time-step windows.
- **Anti-Replay Defense:** Consumed TOTP timesteps are recorded in `users.last_totp_timestep`, preventing replay of identical 6-digit codes within the acceptance window.
- **Server-Side Lockout:** Failed OTP verification attempts are tracked directly in the database (`users.failed_attempts`, `users.locked_until`), enforcing a strict 3-strike lockout for 5 minutes that cannot be bypassed by clearing client cookies.
- **Single-Use Ephemeral QR Streaming:** TOTP setup QR codes are streamed directly into HTML as in-memory Base64 Data URIs (`data:image/png;base64,...`) during the registration handshake. Zero images are written to disk, and the endpoint enforces single-view session restriction (`HTTP 403` on revisit or refresh).
- **At-Rest Secret Encryption:** All TOTP shared secret seeds are encrypted using symmetric Fernet (AES-128-CBC + HMAC-SHA256) before persistence in MySQL (`users.totp_secret`). Keys are loaded strictly from the `TOTP_ENCRYPTION_KEY` environment variable.

### 2. Session Management & Server-Side Invalidation
- **Session Versioning:** Every user record carries an integer `session_version` in MySQL that is stamped into the signed session cookie upon login.
- **Immediate Server-Side Revocation:** Calling `/logout` or completing a password reset increments `users.session_version` in MySQL, instantly rendering all previously issued session cookies invalid across all devices.
- **Strict Cookie Flags:** Session cookies are configured with `HttpOnly=True`, `Secure=True`, and `SameSite=Lax` to prevent XSS exfiltration, plaintext transit, and cross-site request forgery.

### 3. Secure Password Reset Handshake
- **Signed Single-Use Tokens:** Password recovery generates cryptographically secure random tokens (`secrets.token_urlsafe(32)`). Only the SHA-256 hash is stored in `password_resets` with a 15-minute expiration timestamp.
- **Session Invalidation on Reset:** Consuming a reset token updates the password, marks the token used, and automatically increments `session_version` to terminate all active sessions.
- **Anti-Enumeration & Safe Degradation:** If outbound SMTP is unconfigured, the reset route degrades safely. `/forgot-username` returns a uniform generic response with zero username leakage.

### 4. Input Validation & Cryptographic Standards
- **Bcrypt Work Factor 12:** Passwords hashed with salted bcrypt (work factor 12).
- **72-Byte Limit Enforcement:** Input length is verified against bcrypt's 72-byte ceiling (`len(password.encode('utf-8')) <= 72`) before hashing, preventing uncaught `ValueError` crashes.
- **Strict Parameterized Queries:** 100% of SQL queries utilize parameterized placeholders (`%s`), completely neutralizing SQL injection vectors.
- **CSRF Protection:** Flask-WTF enforces synchronizer CSRF tokens on all state-altering POST requests.
- **Tiered Rate Limiting:** Flask-Limiter throttles endpoints to prevent credential stuffing (e.g. 5 requests/minute on login and password reset).

### 5. HTTP Security Headers
Every HTTP response is injected with strict security headers:
- `Content-Security-Policy (CSP)`
- `Strict-Transport-Security (HSTS)`: `max-age=31536000; includeSubDomains`
- `X-Frame-Options`: `DENY` (Clickjacking defense)
- `X-Content-Type-Options`: `nosniff` (MIME sniffing defense)
- `Referrer-Policy`: `strict-origin-when-cross-origin`
- `Permissions-Policy`: `geolocation=(), camera=(), microphone=()`
- Identifying `Server` banners (Werkzeug) are stripped from response headers.

---

## Explicit Non-Goals & Scope Boundaries

To maintain technical accuracy, the following items are explicitly **not** implemented:
- **No Hardware Security Keys:** Does not implement WebAuthn, FIDO2, or U2F hardware security keys (e.g. physical YubiKeys). 2FA is strictly software-based RFC 6238 TOTP.
- **No Distributed Redis Clustering:** Uses Flask-Limiter's in-memory backend by default. (Redis is optional for multi-worker deployments).
- **No Identity Federation:** Does not act as an OAuth2, OIDC, or SAML identity provider.

---

## Local Development & Setup

### Prerequisites
- Python 3.10+
- MySQL 8.0+

### Installation
1. **Clone repository:**
   ```bash
   git clone https://github.com/Chaitu03-alt/secure-auth-system.git
   cd secure-auth-system
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Configure Environment:**
   Copy `.env.example` to `.env` and provide required secrets:
   ```env
   SECRET_KEY=<at-least-32-character-random-hex-string>
   TOTP_ENCRYPTION_KEY=<fernet-base64-key-from-Fernet.generate_key()>
   DB_HOST=localhost
   DB_PORT=3306
   DB_USER=root
   DB_PASSWORD=<your-mysql-password>
   DB_NAME=secure_auth_system
   SESSION_COOKIE_SECURE=True
   FLASK_DEBUG=False
   ```

4. **Initialize Database Schema:**
   ```bash
   mysql -u root -p secure_auth_system < database/schema.sql
   ```

5. **Run Test Suite:**
   ```bash
   pytest
   ```

6. **Start Application:**
   ```bash
   python app.py
   ```

---

## Security Verification & Auditing

- **Automated Tests:** 16 comprehensive unit and integration tests passing (`tests/test_auth.py`).
- **Dependency Audit:** Zero known vulnerabilities reported by `pip-audit`:
  ```bash
  pip-audit -r requirements.txt
  # Output: No known vulnerabilities found
  ```
- **Red-Team PoC Suite:** All adversarial attack scripts in `redteam/poc/` verified to fail against the hardened endpoints. Detailed audit logs and verification records are documented in `redteam/05_fix_verification.md`.

---

## License
MIT License. Open for educational and reference usage.

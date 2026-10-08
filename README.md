# secure-auth-system

**Live demo:** http://16.4.53.85:5000  
*(Demo only, plain HTTP. Please use a throwaway password, not a real one. Hosted on a single EC2 instance, so it may occasionally be offline.)*

> **Hardened Reference Implementation of Multi-Factor Authentication & Session Security in Flask & Python.**

A production-grade reference implementation demonstrating defense-in-depth authentication principles in Python/Flask with MySQL. Built following OWASP Top 10 recommendations and verified through adversarial red-team penetration testing concepts.

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
- `Strict-Transport-Security (HSTS)`
- `X-Frame-Options`: `DENY` (Clickjacking defense)
- `X-Content-Type-Options`: `nosniff` (MIME sniffing defense)
- `Referrer-Policy`: `strict-origin-when-cross-origin`
- `Permissions-Policy`: `geolocation=(), camera=(), microphone=()`

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

### Installation & Run
1. **Clone repository:**
   ```bash
   git clone [https://github.com/Chaitu03-alt/secure-auth-system.git](https://github.com/Chaitu03-alt/secure-auth-system.git)
   cd secure-auth-system

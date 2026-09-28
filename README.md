# secure-auth-system

[![CI Pipeline](https://github.com/Chaitu03-alt/secure-auth-system/actions/workflows/ci.yml/badge.svg)](https://github.com/Chaitu03-alt/secure-auth-system/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-hardened Python authentication service built with Flask, MySQL, and modern application security (AppSec) defense-in-depth principles. Features multi-factor authentication (MFA/2FA via RFC 6238 TOTP), Cross-Site Request Forgery (CSRF) protection, endpoint-level rate limiting, constant-time credential verification, anti-enumeration defenses, and comprehensive audit logging.

---

## Architecture & Authentication Lifecycle

The authentication lifecycle enforces an ephemeral, session-staged verification state machine that prevents parameter tampering and credential brute-forcing.

```
[ Client ] ──────── (1. Primary Credentials + CSRF) ───────> [ POST /loginsubmit ]
                                                                     │
                                                       (Rate Limit: 5/min)
                                                       (CSRF Token Validation)
                                                       (Constant-Time Bcrypt Hash)
                                                                     │
                                          ┌──────────────────────────┴──────────────────────────┐
                                       [Valid]                                               [Invalid]
                                          │                                                      │
                       [ Audit: STAGE1_SUCCESS ]                              [ Constant-Time Dummy Hash ]
                       [ Clear Existing Session ]                             [ Audit: FAILED            ]
                       [ Set: session['pending_user'] ]                       [ Return: Generic Error    ]
                       [ Set: session['otp_attempts'] = 0 ]
                                          │
[ Client ] ──────── (2. 6-Digit TOTP Token + CSRF) ────────> [ POST /verify-otp ]
                                                                     │
                                                       (Rate Limit: 5/min)
                                                       (Validate session['pending_user'])
                                                       (pyotp.TOTP Verification)
                                                                     │
                                          ┌──────────────────────────┴──────────────────────────┐
                                       [Valid]                                               [Invalid]
                                          │                                                      │
                       [ Audit: SUCCESS         ]                             [ Audit: OTP_FAILED        ]
                       [ Update: is_totp_enabled]                             [ Increment: otp_attempts  ]
                       [ Purge: pending_user    ]                             [ If attempts >= 3:        ]
                       [ Promote: session['user'] ]                           [   Purge pending session  ]
                       [ Grant Protected Access ]                             [   Force Re-login         ]
```

---

## Security Design Choices

### 1. Ephemeral Session-Staged 2FA Handshake
* **Vulnerability Mitigated:** Parameter tampering, broken authentication (OWASP A07), and intermediate step bypass.
* **Mechanism:** Rather than establishing a full session upon password verification or passing client-controlled identifiers (e.g., hidden form fields), identity context is staged strictly inside the server-side, cryptographically signed session (`session['pending_user_id']`).
* **Lockout Throttling:** Failed OTP attempts increment an isolated counter (`session['otp_attempts']`). Reaching 3 failed attempts instantly purges the pending session and redirects to primary login, thwarting automated TOTP token guessing.

### 2. Cross-Site Request Forgery (CSRF) Protection
* **Vulnerability Mitigated:** Cross-Site Request Forgery (OWASP A01).
* **Mechanism:** Integrated `Flask-WTF` (`CSRFProtect`). All state-altering POST endpoints (`/loginsubmit`, `/verify-otp`, `/createuser`, `/forgot-username`, `/forgot-password`) enforce cryptographically signed tokens injected via hidden `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">` fields.
* **Resilience:** CSRF violations trigger custom `400 Bad Request` handlers with clear security notifications instead of raw application errors.

### 3. Granular Endpoint Rate Limiting
* **Vulnerability Mitigated:** Automated credential stuffing, distributed brute-force attacks, and registration spam.
* **Mechanism:** Enforced using `Flask-Limiter` with client IP keying (`get_remote_address`):
  * **Login Submissions (`/loginsubmit`):** 5 attempts per minute
  * **TOTP Verifications (`/verify-otp`):** 5 attempts per minute
  * **Account Registrations (`/createuser`):** 3 attempts per hour
  * **Global Default:** 200 per day, 50 per hour
* **Storage:** Defaults to in-memory (`memory://`) for single-instance local execution; production deployments switch seamlessly to Redis (`redis://`) via configuration. Exceeded limits produce standardized `HTTP 429 Too Many Requests` responses.

### 4. Anti-Enumeration & Constant-Time Cryptography
* **Vulnerability Mitigated:** Username enumeration, timing side-channel attacks, and rainbow table collisions.
* **Mechanism:**
  * Password hashing utilizes `bcrypt` with a cost factor of 12 salt rounds.
  * Standardized generic error messaging (`"Invalid credentials."`) ensures responses are identical whether a user does not exist or provides an incorrect password.
  * When an unknown username is supplied, `verify_password()` executes against a precomputed dummy bcrypt hash (`DUMMY_BCRYPT_HASH`), ensuring execution time remains constant regardless of whether the account exists in the database.

### 5. Security Audit Logging
* **Mechanism:** All authentication events—including credential failures, intermediate stage promotions, OTP successes, and OTP failures—are persisted to the `login_logs` table with IPv4/IPv6 client addresses, user references, and timestamps.

---

## Database Architecture

The system utilizes MySQL 8.0+ with full UTF-8 Unicode support (`utf8mb4`). The complete DDL is maintained in [`database/schema.sql`](database/schema.sql).

### Table: `users`
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INT` | `AUTO_INCREMENT, PRIMARY KEY` | Internal user identifier |
| `username` | `VARCHAR(80)` | `NOT NULL, UNIQUE` | Unique handle |
| `email` | `VARCHAR(120)` | `NOT NULL, UNIQUE` | Unique email address |
| `password_hash` | `VARCHAR(255)` | `NOT NULL` | Bcrypt salted hash (cost 12) |
| `totp_secret` | `VARCHAR(32)` | `NULL` | Base32 TOTP secret key |
| `is_totp_enabled`| `BOOLEAN` | `DEFAULT FALSE` | 2FA activation status flag |
| `created_at` | `TIMESTAMP` | `DEFAULT CURRENT_TIMESTAMP` | Account creation timestamp |

### Table: `login_logs`
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `INT` | `AUTO_INCREMENT, PRIMARY KEY` | Audit log record identifier |
| `user_id` | `INT` | `NULL, FK -> users(id)` | Associated user (NULL if unknown) |
| `login_time` | `TIMESTAMP` | `DEFAULT CURRENT_TIMESTAMP` | Event timestamp |
| `ip_address` | `VARCHAR(45)` | `NOT NULL` | Client IPv4 or IPv6 address |
| `status` | `VARCHAR(20)` | `NOT NULL` | Event status (`SUCCESS`, `FAILED`, `OTP_FAILED`, etc.) |

---

## Configuration & Environment Variables

Environment settings are managed using `python-dotenv`. Copy the example file before running:

```bash
cp .env.example .env
```

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `FLASK_APP` | `app.py` | Entry point application file |
| `FLASK_ENV` | `development` | Runtime environment (`development` or `production`) |
| `SECRET_KEY` | *(Required)* | High-entropy secret key for session and CSRF signing |
| `DB_HOST` | `localhost` | MySQL database host |
| `DB_PORT` | `3306` | MySQL database port |
| `DB_USER` | `root` | Database username |
| `DB_PASSWORD` | `""` | Database password |
| `DB_NAME` | `secure_auth_system` | Target database name |
| `RATELIMIT_STORAGE_URI` | `memory://` | Storage backend for rate limiter (`memory://` or `redis://host:port/0`) |
| `SESSION_COOKIE_SECURE` | `False` | Enforce HTTPS-only cookie transmission (`True` in production) |
| `SESSION_COOKIE_HTTPONLY` | `True` | Mitigate XSS cookie harvesting |
| `SESSION_COOKIE_SAMESITE` | `Lax` | Protect session cookies against CSRF cross-origin leakage |

---

## Installation & Setup

### 1. Prerequisites
* Python 3.10+
* MySQL Server 8.0+

### 2. Clone and Setup Virtual Environment
```bash
cd secure-auth-system
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Initialize Database
Execute the production DDL script to create the database, tables, and constraints:
```bash
mysql -u root -p < database/schema.sql
```

### 5. Launch Application
```bash
python app.py
```
The server will bind to `http://127.0.0.1:5000`.

---

## Key Learning Outcomes

* **Defense-in-Depth Authentication:** Implemented an ephemeral, session-staged state machine separating primary password verification from TOTP verification to eliminate intermediate parameter tampering.
* **AppSec Threat Mitigation:** Hardened attack surfaces against credential stuffing and brute-forcing via multi-tiered rate limiting, CSRF token validation on all state modifications, and constant-time dummy hashing to counter timing enumeration.
* **Auditability & Observability:** Structured schema-driven audit logging (`login_logs`) tracking security events across IPv4 and IPv6 network boundaries for forensic incident response.
* **Production Configuration Management:** Decoupled secrets and operational parameters using strict `.env` conventions, dynamic driver agility (`pymysql` / `mysql-connector-python`), and secure cookie policies (`HttpOnly`, `SameSite=Lax`, `Secure`).

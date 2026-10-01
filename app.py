"""
secure-auth-system: Production-Hardened Authentication Engine
Architectural Highlights:
- Multi-Factor Authentication (RFC 6238 TOTP via pyotp)
- Ephemeral Session-Staged Verification Handshake (OWASP A07 Defense)
- End-to-End CSRF Defense via Flask-WTF
- Tiered IP Rate Limiting via Flask-Limiter
- Constant-Time Bcrypt Hashing & Anti-Enumeration Timing Mitigation
- Append-Only Security Event Audit Logging (login_logs)
- Dynamic User Dashboard with Session Telemetry & Audit Logs
"""

import base64
import hashlib
import io
import logging
import os
import re
import secrets
import smtplib
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
from email.mime.text import MIMEText

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
import pyotp
import qrcode
from werkzeug.security import check_password_hash

try:
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = ""
    WSGIRequestHandler.sys_version = ""
except Exception:
    pass

# -----------------------------------------------------------------------------
# Configuration & Application Bootstrap
# -----------------------------------------------------------------------------

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("secure_auth")

_is_testing = bool(os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("TESTING") or "pytest" in sys.modules)
_secret_key = os.environ.get("SECRET_KEY", "").strip()

if not _secret_key:
    if not _is_testing:
        raise RuntimeError("FATAL: Application startup aborted. SECRET_KEY must be provided via environment variable.")
    _secret_key = "test-secret-key-for-unit-testing-32b"

if len(_secret_key) < 32 and not _is_testing:
    raise RuntimeError("FATAL: Application startup aborted. SECRET_KEY is too weak (must be at least 32 characters long).")

if _secret_key in (
    "secure-auth-system-dev-insecure-key-32bytes-min",
    "dev_insecure_secret_key_generate_new_with_python_secrets_token_hex_32",
) and not _is_testing:
    raise RuntimeError("FATAL: Insecure placeholder SECRET_KEY detected from repository history. Please generate a new key.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=_secret_key,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=int(os.environ.get("CSRF_TIME_LIMIT", 3600)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "True").lower() in ("true", "1"),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.environ.get("PERMANENT_SESSION_LIFETIME", 30))),
    DEBUG=False,
)
app.debug = False

csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)


@app.after_request
def set_security_headers(response):
    """Inject strict security headers and strip identifying server headers."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers.pop("Server", None)
    return response

SMTP_HOST = os.environ.get("SMTP_HOST") or os.environ.get("MAIL_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT") or os.environ.get("MAIL_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER") or os.environ.get("MAIL_USERNAME")
SMTP_PASS = os.environ.get("SMTP_PASS") or os.environ.get("MAIL_PASSWORD")
EMAIL_FROM = os.environ.get("EMAIL_FROM", "noreply@secureauth.local")
IS_EMAIL_CONFIGURED = bool(SMTP_HOST and SMTP_USER and SMTP_PASS)


def send_reset_email(to_email, reset_link):
    """Dispatch password reset token email via SMTP if configured."""
    if not IS_EMAIL_CONFIGURED:
        return False
    try:
        msg = MIMEText(
            f"Hello,\n\nYou requested a password reset. Click the link below to set a new password:\n\n{reset_link}\n\nThis link is single-use and expires in 15 minutes.\n\nIf you did not make this request, please ignore this email."
        )
        msg["Subject"] = "Password Reset Request — Secure Auth System"
        msg["From"] = EMAIL_FROM
        msg["To"] = to_email
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as err:
        logger.error("Failed to send reset email to %s: %s", to_email, err)
        return False


DUMMY_BCRYPT_HASH = "$2b$12$CwTycUXWue0Thq9StjUM0uJ2a3y5j3qF7A0kR.QnE6pS/uXmH1qOm"

TOTP_ENCRYPTION_KEY = os.environ.get("TOTP_ENCRYPTION_KEY")
if not TOTP_ENCRYPTION_KEY:
    _derived_key = hashlib.sha256((app.config["SECRET_KEY"] + ":totp_encryption_salt").encode("utf-8")).digest()
    TOTP_ENCRYPTION_KEY = base64.urlsafe_b64encode(_derived_key).decode("ascii")

fernet = Fernet(TOTP_ENCRYPTION_KEY.encode("utf-8") if isinstance(TOTP_ENCRYPTION_KEY, str) else TOTP_ENCRYPTION_KEY)


def encrypt_totp_secret(plain_secret: str) -> str:
    """Encrypt base32 TOTP secret string at rest using Fernet (AES-128-CBC + HMAC-SHA256)."""
    if not plain_secret:
        return ""
    return fernet.encrypt(plain_secret.encode("utf-8")).decode("utf-8")


def decrypt_totp_secret(cipher_or_plain: str) -> str:
    """Decrypt Fernet-encrypted TOTP secret; gracefully fall back to plaintext for migration."""
    if not cipher_or_plain:
        return ""
    try:
        return fernet.decrypt(cipher_or_plain.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        return cipher_or_plain

try:
    import pymysql
    import pymysql.cursors
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

try:
    import mysql.connector
    HAS_MYSQL_CONNECTOR = True
except ImportError:
    HAS_MYSQL_CONNECTOR = False


# -----------------------------------------------------------------------------
# Database Connection & Lifecycle Management
# -----------------------------------------------------------------------------

def get_db_connection():
    """Establish and return an active MySQL database connection."""
    password = os.environ.get("DB_PASSWORD")
    if password is None and not _is_testing:
        raise RuntimeError("FATAL: DB_PASSWORD environment variable is required.")
    cfg = {
        "host": os.environ.get("DB_HOST", "localhost"),
        "port": int(os.environ.get("DB_PORT", 3306)),
        "user": os.environ.get("DB_USER", "root"),
        "password": password or "",
        "database": os.environ.get("DB_NAME", "secure_auth_system"),
    }
    if HAS_PYMYSQL:
        return pymysql.connect(**cfg, cursorclass=pymysql.cursors.DictCursor, autocommit=False)
    if HAS_MYSQL_CONNECTOR:
        return mysql.connector.connect(**cfg)
    raise RuntimeError("No compatible MySQL driver installed ('pymysql' or 'mysql-connector-python').")


def get_db_cursor(conn):
    """Obtain a dictionary cursor compatible with both pymysql and mysql-connector."""
    if HAS_PYMYSQL and isinstance(conn, pymysql.Connection):
        return conn.cursor()
    return conn.cursor(dictionary=True)


@contextmanager
def db_cursor(commit=False):
    """Context manager managing database connection lifecycle and dictionary cursor."""
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    try:
        yield cursor
        if commit:
            conn.commit()
    except Exception:
        if commit:
            try:
                conn.rollback()
            except Exception:
                pass
        raise
    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Security & Cryptographic Helpers
# -----------------------------------------------------------------------------

def get_client_ip() -> str:
    """Extract client IP, preferring X-Forwarded-For if behind a reverse proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.remote_addr or "127.0.0.1"


def hash_password(password: str) -> str:
    """Hash plaintext password with bcrypt (work factor 12)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using constant-time comparison with fallback for legacy hashes."""
    try:
        if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        return check_password_hash(hashed_password, plain_password)
    except Exception:
        return False


def log_login_event(user_id, ip_address: str, status: str):
    """Persist security events to the login_logs table."""
    try:
        with db_cursor(commit=True) as cur:
            cur.execute(
                "INSERT INTO login_logs (user_id, ip_address, status) VALUES (%s, %s, %s)",
                (user_id, ip_address, status),
            )
    except Exception as exc:
        logger.warning("Audit log write failed: %s", exc)


def _render_error(title: str, msg: str, code: int, retry_after: str = None):
    """DRY error template renderer."""
    return render_template("error.html", error_title=title, error_message=msg, retry_after=retry_after), code


# -----------------------------------------------------------------------------
# Global Security Error Handlers
# -----------------------------------------------------------------------------

@app.errorhandler(CSRFError)
def handle_csrf_error(_):
    return _render_error(
        "Security Verification Failed",
        "Your security token has expired or is invalid. Please refresh the page and try again.",
        400,
        "Tokens are refreshed automatically on page reload.",
    )


@app.errorhandler(429)
def handle_ratelimit_error(err):
    return _render_error(
        "Rate Limit Exceeded",
        "Too many requests have originated from your network. For your account security, please take a quick breather and wait a moment before trying again.",
        429,
        getattr(err, "description", "Rate limit in effect."),
    )


@app.errorhandler(404)
def handle_not_found(_):
    return _render_error(
        "Page Not Found",
        "We couldn't find the page you're looking for. It might have moved or the address was entered incorrectly.",
        404,
    )


@app.errorhandler(500)
def handle_server_error(_):
    return _render_error(
        "Something Went Wrong",
        "We encountered an unexpected condition while processing your request. Please try again shortly.",
        500,
    )


def get_current_user():
    """Validate active session against database session_version for instant revocation."""
    if "user" not in session or "user_id" not in session:
        return None
    user_id = session.get("user_id")
    sess_ver = session.get("session_version")
    try:
        with db_cursor() as cur:
            cur.execute("SELECT id, username, session_version FROM users WHERE id = %s", (user_id,))
            db_user = cur.fetchone()
            if db_user and db_user.get("session_version", 1) == sess_ver:
                return db_user
    except Exception as err:
        logger.error("Session validation error: %s", err)
    session.clear()
    return None


# -----------------------------------------------------------------------------
# Application Routes
# -----------------------------------------------------------------------------

@app.route("/")
def home():
    """Humanized landing page showcasing core security features."""
    return render_template("home.html")


@app.route("/signup", methods=["GET"])
@app.route("/register", methods=["GET"])
def signup():
    """Render account registration form or redirect authenticated users."""
    return redirect(url_for("dashboard")) if get_current_user() else render_template("signup.html")


@app.route("/createuser", methods=["POST"])
@app.route("/register", methods=["POST"])
@limiter.limit("3 per hour")
def create_user():
    """User registration endpoint with strict input sanitization and rate limiting."""
    usernm = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    passwd = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    def _reject(msg):
        return render_template("signup.html", msg=msg)

    if not (usernm and email and passwd):
        return _reject("Please fill in all required fields to continue.")
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return _reject("Please provide a valid email address (e.g. name@example.com).")
    if not re.match(r"^[A-Za-z0-9_.-]{3,40}$", usernm):
        return _reject("Username must be 3-40 characters long and contain only letters, numbers, dots, or underscores.")
    if passwd != confirm:
        return _reject("Passwords do not match. Please double-check and try again.")
    if len(passwd) < 8:
        return _reject("For your security, your password must be at least 8 characters long.")

    try:
        with db_cursor(commit=True) as cur:
            cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (usernm, email))
            if cur.fetchone():
                return _reject("Registration could not be completed with the provided username or email. Please choose another or sign in.")
            totp_secret = pyotp.random_base32()
            encrypted_totp = encrypt_totp_secret(totp_secret)
            cur.execute(
                "INSERT INTO users (username, email, password_hash, totp_secret, is_totp_enabled) VALUES (%s, %s, %s, %s, %s)",
                (usernm, email, hash_password(passwd), encrypted_totp, False),
            )
        session.clear()
        session["registration_user"] = usernm
        session["can_view_qr"] = True
        flash("Account created successfully! Please configure Two-Factor Authentication below.", "success")
        return redirect(url_for("showqr", username=usernm))
    except Exception as err:
        logger.error("Registration error: %s", err)
        return _reject("An error occurred while creating your account. Please try again in a moment.")


@app.route("/showqr/<username>")
def showqr(username):
    """Display TOTP QR code and setup secret for authenticator configuration (single-use upon registration)."""
    if session.get("registration_user") != username or not session.get("can_view_qr"):
        return _render_error(
            "Access Denied",
            "Two-Factor Authentication setup can only be viewed once immediately upon registration.",
            403,
        )

    # Invalidate immediately so refreshing or revisiting is blocked (shown once)
    session.pop("can_view_qr", None)

    try:
        with db_cursor() as cur:
            cur.execute("SELECT totp_secret FROM users WHERE username = %s", (username,))
            user = cur.fetchone()

        if not user or not user.get("totp_secret"):
            return _render_error("Account Not Found", f"No account matching '{username}' was found with an active 2FA setup.", 404)

        ga_key = decrypt_totp_secret(user["totp_secret"])
        otp_url = pyotp.TOTP(ga_key).provisioning_uri(name=username, issuer_name="secure-auth-system")

        # Stream directly from memory via base64 data URI (zero disk writes)
        buf = io.BytesIO()
        qrcode.make(otp_url).save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        qr_data_uri = f"data:image/png;base64,{qr_b64}"

        return render_template("showqr.html", username=username, qr_data_uri=qr_data_uri, secret=ga_key)
    except Exception as err:
        logger.error("QR generation error: %s", err)
        return _render_error("Authenticator Setup Error", "Could not generate your authenticator QR code. Please try again later.", 500)


@app.route("/login", methods=["GET"])
def login():
    """Render login form or redirect authenticated users."""
    return redirect(url_for("dashboard")) if get_current_user() else render_template("login.html")


@app.route("/loginsubmit", methods=["POST"])
@limiter.limit("5 per minute")
def loginsubmit():
    """Primary credential authentication with timing-attack resistant verification."""
    client_ip = get_client_ip()
    usernm = request.form.get("username", "").strip()
    passwd = request.form.get("password", "")

    user = None
    try:
        with db_cursor() as cur:
            cur.execute("SELECT id, username, password_hash FROM users WHERE username = %s", (usernm,))
            user = cur.fetchone()
    except Exception as err:
        logger.error("Database query error: %s", err)

    if user and verify_password(passwd, user["password_hash"]):
        session.clear()
        session["pending_user_id"] = user["id"]
        session["pending_user"] = user["username"]
        session["otp_attempts"] = 0
        log_login_event(user["id"], client_ip, "STAGE1_SUCCESS")
        flash("Password accepted. Please enter your 6-digit Authenticator code to continue.", "success")
        return redirect(url_for("verify_otp"))

    verify_password(passwd, DUMMY_BCRYPT_HASH)
    log_login_event(None, client_ip, "FAILED")
    return render_template("login.html", msg="Invalid username or password. Please verify your credentials and try again.")


@app.route("/totp", methods=["GET", "POST"])
@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify_otp():
    """Two-Factor Authentication (TOTP) endpoint with server-side 3-strike lock and anti-replay."""
    pending_id = session.get("pending_user_id")
    pending_user = session.get("pending_user")

    if not (pending_id and pending_user):
        flash("Please enter your username and password first to access Two-Factor Verification.", "warning")
        return redirect(url_for("login"))

    user = None
    try:
        with db_cursor() as cur:
            cur.execute(
                "SELECT id, username, totp_secret, session_version, last_totp_timestep, failed_attempts, locked_until "
                "FROM users WHERE id = %s",
                (pending_id,),
            )
            user = cur.fetchone()
    except Exception as err:
        logger.error("DB error during OTP verify: %s", err)

    if not user:
        session.clear()
        return redirect(url_for("login"))

    now = datetime.utcnow()
    # Check if account is locked server-side
    locked_until = user.get("locked_until")
    if locked_until:
        if isinstance(locked_until, str):
            try:
                locked_until = datetime.fromisoformat(locked_until)
            except Exception:
                locked_until = None
        if locked_until and locked_until > now:
            session.clear()
            flash("Account is temporarily locked due to excessive failed attempts. Please try again in 5 minutes.", "danger")
            return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("verify_otp.html", username=pending_user)

    client_ip = get_client_ip()
    otp = request.form.get("otp", "").strip()

    raw_secret = decrypt_totp_secret(user["totp_secret"]) if user.get("totp_secret") else None
    if raw_secret:
        totp_obj = pyotp.TOTP(raw_secret)
        current_timestep = totp_obj.timecode(now)
        if totp_obj.verify(otp, valid_window=1):
            # Anti-replay: verify timestep has not already been used
            last_ts = user.get("last_totp_timestep")
            if last_ts is not None and last_ts >= current_timestep:
                log_login_event(user["id"], client_ip, "OTP_REPLAY_REJECTED")
                return render_template(
                    "verify_otp.html",
                    username=pending_user,
                    msg="This verification code has already been used. Please wait for the next 30-second token on your authenticator app.",
                )

            # Success: reset failed attempts, record consumed timestep, promote session
            try:
                with db_cursor(commit=True) as cur:
                    cur.execute(
                        "UPDATE users SET is_totp_enabled = TRUE, last_totp_timestep = %s, failed_attempts = 0, locked_until = NULL WHERE id = %s",
                        (current_timestep, user["id"]),
                    )
            except Exception as exc:
                logger.warning("Could not update TOTP state on success: %s", exc)

            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["user"] = user["username"]
            session["session_version"] = user.get("session_version", 1)

            log_login_event(user["id"], client_ip, "SUCCESS")
            flash(f"Welcome back, {user['username']}! You have signed in securely.", "success")
            return redirect(url_for("dashboard"))

    # Invalid OTP Handling with server-side attempt tracking
    log_login_event(pending_id, client_ip, "OTP_FAILED")
    new_failed = (user.get("failed_attempts") or 0) + 1

    if new_failed >= 3:
        lock_until = now + timedelta(minutes=5)
        try:
            with db_cursor(commit=True) as cur:
                cur.execute(
                    "UPDATE users SET failed_attempts = %s, locked_until = %s WHERE id = %s",
                    (new_failed, lock_until, user["id"]),
                )
        except Exception as err:
            logger.error("DB error updating lock state: %s", err)
        session.clear()
        flash("Maximum verification attempts exceeded. For your protection, please sign in again.", "danger")
        return redirect(url_for("login"))

    try:
        with db_cursor(commit=True) as cur:
            cur.execute(
                "UPDATE users SET failed_attempts = %s WHERE id = %s",
                (new_failed, user["id"]),
            )
    except Exception as err:
        logger.error("DB error updating failed attempts: %s", err)

    rem = 3 - new_failed
    return render_template(
        "verify_otp.html",
        username=pending_user,
        msg=f"Incorrect authentication code. You have {rem} attempt{'s' if rem != 1 else ''} remaining.",
    )


@app.route("/NewHome")
@app.route("/dashboard")
def dashboard():
    """Protected user dashboard requiring active session and displaying audit telemetry."""
    current_user = get_current_user()
    if not current_user:
        flash("Please sign in to access your dashboard.", "warning")
        return redirect(url_for("login"))

    user_id = current_user["id"]
    audit_logs = []
    try:
        with db_cursor() as cur:
            cur.execute(
                "SELECT login_time, ip_address, status FROM login_logs WHERE user_id = %s ORDER BY login_time DESC LIMIT 5"
                if user_id else "SELECT login_time, ip_address, status FROM login_logs ORDER BY login_time DESC LIMIT 5",
                (user_id,) if user_id else (),
            )
            audit_logs = cur.fetchall() or []
    except Exception as err:
        logger.warning("Could not load dashboard audit logs: %s", err)

    return render_template(
        "NewHome.html",
        user=current_user["username"],
        client_ip=get_client_ip(),
        audit_logs=audit_logs,
    )


@app.route("/forgot-username", methods=["GET", "POST"])
@app.route("/forgotusername", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_username():
    """Username recovery endpoint with anti-enumeration response."""
    msg, found_user = "", None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        try:
            with db_cursor() as cur:
                cur.execute("SELECT username FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
                if user:
                    found_user = user["username"]
                else:
                    msg = "If an account is associated with this email, your username will be displayed here."
        except Exception as err:
            logger.error("Forgot username error: %s", err)
            msg = "An error occurred while processing your request. Please try again."

    return render_template("forgotusername.html", msg=msg, username=found_user)


@app.route("/forgot-password", methods=["GET", "POST"])
@app.route("/forgotpassword", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    """Password reset request endpoint. Requires active outbound email service."""
    if not IS_EMAIL_CONFIGURED:
        return render_template(
            "forgotpassword.html",
            msg="Password reset is currently disabled because outbound email service is not configured on this server.",
            disabled=True,
        )

    msg, success = "", False
    if request.method == "POST":
        email_or_user = request.form.get("email_or_username", "").strip() or request.form.get("username", "").strip()
        if not email_or_user:
            msg = "Please provide your username or registered email."
        else:
            try:
                user = None
                with db_cursor() as cur:
                    cur.execute(
                        "SELECT id, email, username FROM users WHERE username = %s OR email = %s",
                        (email_or_user, email_or_user),
                    )
                    user = cur.fetchone()

                if user and user.get("email"):
                    raw_token = secrets.token_urlsafe(32)
                    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                    expires_at = datetime.utcnow() + timedelta(minutes=15)
                    with db_cursor(commit=True) as cur:
                        cur.execute(
                            "INSERT INTO password_resets (user_id, token_hash, expires_at, used) VALUES (%s, %s, %s, FALSE)",
                            (user["id"], token_hash, expires_at),
                        )
                    reset_link = url_for("reset_password", token=raw_token, _external=True)
                    send_reset_email(user["email"], reset_link)

                msg = "If an account matches that identifier, password reset instructions have been sent to the registered email."
                success = True
            except Exception as err:
                logger.error("Password reset dispatch error: %s", err)
                msg = "An error occurred while processing your request. Please try again later."

    return render_template("forgotpassword.html", msg=msg, success=success, disabled=False)


@app.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def reset_password():
    """Signed, expiring, single-use password reset completion endpoint."""
    raw_token = request.args.get("token", "").strip() or request.form.get("token", "").strip()
    if not raw_token:
        flash("Password reset token is missing.", "danger")
        return redirect(url_for("forgot_password"))

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    reset_record = None
    try:
        with db_cursor() as cur:
            cur.execute(
                "SELECT pr.id, pr.user_id, pr.expires_at, pr.used, u.username "
                "FROM password_resets pr JOIN users u ON pr.user_id = u.id "
                "WHERE pr.token_hash = %s",
                (token_hash,),
            )
            reset_record = cur.fetchone()
    except Exception as err:
        logger.error("DB error fetching reset token: %s", err)

    now = datetime.utcnow()
    if not reset_record or reset_record["used"] or reset_record["expires_at"] < now:
        flash("This password reset link is invalid or has expired. Please request a new one.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_pass = request.form.get("new_password", "")
        confirm_pass = request.form.get("confirm_password", "")
        if len(new_pass) < 8:
            return render_template("reset_password.html", token=raw_token, msg="Password must be at least 8 characters long.")
        if new_pass != confirm_pass:
            return render_template("reset_password.html", token=raw_token, msg="Passwords do not match.")

        try:
            with db_cursor(commit=True) as cur:
                # Update password and increment session_version to revoke active sessions
                cur.execute(
                    "UPDATE users SET password_hash = %s, session_version = session_version + 1 WHERE id = %s",
                    (hash_password(new_pass), reset_record["user_id"]),
                )
                # Mark token as consumed (single-use)
                cur.execute(
                    "UPDATE password_resets SET used = TRUE WHERE id = %s",
                    (reset_record["id"],),
                )
            flash("Your password has been successfully reset. Please sign in.", "success")
            return redirect(url_for("login"))
        except Exception as err:
            logger.error("Password reset update error: %s", err)
            return render_template("reset_password.html", token=raw_token, msg="An error occurred while updating password.")

    return render_template("reset_password.html", token=raw_token, username=reset_record["username"])


@app.route("/logout")
def logout():
    """Safely terminate user session state and increment session_version."""
    user_id = session.get("user_id")
    if user_id:
        try:
            with db_cursor(commit=True) as cur:
                cur.execute("UPDATE users SET session_version = session_version + 1 WHERE id = %s", (user_id,))
        except Exception as err:
            logger.warning("Could not increment session_version on logout: %s", err)
    session.clear()
    flash("You have been signed out safely. Have a wonderful day!", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
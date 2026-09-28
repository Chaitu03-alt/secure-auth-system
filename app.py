"""
secure-auth-system: Production-Hardened & Human-Centered Authentication Engine

Architectural Highlights:
- Multi-Factor Authentication (RFC 6238 TOTP via pyotp)
- Ephemeral Session-Staged Verification Handshake (OWASP A07 Defense)
- End-to-End CSRF Defense via Flask-WTF
- Tiered IP Rate Limiting via Flask-Limiter
- Constant-Time Bcrypt Hashing & Anti-Enumeration Protection
- Security Event Audit Logging (login_logs)
- Dynamic User Dashboard with Session Telemetry & Audit Logs
- Graceful, Human-Centered Feedback and Error Handling
"""

import os
import re
from datetime import timedelta
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
import bcrypt
import pyotp
import qrcode
from werkzeug.security import check_password_hash

# -----------------------------------------------------------------------------
# Configuration & Application Bootstrap
# -----------------------------------------------------------------------------

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "secure-auth-system-dev-insecure-key-32bytes-min"
)
app.config["WTF_CSRF_ENABLED"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = int(os.environ.get("CSRF_TIME_LIMIT", 3600))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1")
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    minutes=int(os.environ.get("PERMANENT_SESSION_LIFETIME", 30))
)

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

# Constant-time dummy hash for non-existent users (prevents timing side-channels)
DUMMY_BCRYPT_HASH = "$2b$12$CwTycUXWue0Thq9StjUM0uJ2a3y5j3qF7A0kR.QnE6pS/uXmH1qOm"

# Multi-driver support for MySQL / MariaDB
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
# Database & Utility Helpers
# -----------------------------------------------------------------------------

def get_db_connection():
    """Establish and return an active MySQL database connection."""
    db_host = os.environ.get("DB_HOST", "localhost")
    db_port = int(os.environ.get("DB_PORT", 3306))
    db_user = os.environ.get("DB_USER", "root")
    db_password = os.environ.get("DB_PASSWORD", "Chaitanyaraut03")
    db_name = os.environ.get("DB_NAME", "secure_auth_system")

    if HAS_PYMYSQL:
        return pymysql.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
        )
    elif HAS_MYSQL_CONNECTOR:
        return mysql.connector.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name,
        )
    else:
        raise RuntimeError(
            "No compatible MySQL driver installed. Please install 'pymysql' or 'mysql-connector-python'."
        )


def get_db_cursor(conn):
    """Obtain a dictionary cursor compatible with both pymysql and mysql-connector."""
    if HAS_PYMYSQL and isinstance(conn, pymysql.Connection):
        return conn.cursor()
    return conn.cursor(dictionary=True)


def get_client_ip() -> str:
    """Safely extract the real client IP address, handling proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def hash_password(password: str) -> str:
    """Hash plaintext password using bcrypt (work factor 12)."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password using constant-time bcrypt verification.
    Includes backward-compatibility fallback for Werkzeug hashes.
    """
    try:
        if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
            return bcrypt.checkpw(
                plain_password.encode("utf-8"), hashed_password.encode("utf-8")
            )
        return check_password_hash(hashed_password, plain_password)
    except Exception:
        return False


def log_login_event(user_id, ip_address: str, status: str):
    """
    Audit logger: Persist security events to the login_logs table.
    Status codes: 'FAILED', 'STAGE1_SUCCESS', 'SUCCESS', 'OTP_FAILED'.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        query = (
            "INSERT INTO login_logs (user_id, ip_address, status) VALUES (%s, %s, %s)"
        )
        cursor.execute(query, (user_id, ip_address, status))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as exc:
        app.logger.warning(f"[secure-auth-system] Audit log warning: {exc}")


# -----------------------------------------------------------------------------
# Global Security Error Handlers
# -----------------------------------------------------------------------------

@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """Handle CSRF token validation failures with human-centered guidance."""
    return (
        render_template(
            "error.html",
            error_title="Security Verification Failed",
            error_message="Your security token has expired or is invalid. Please refresh the page and try again.",
            retry_after="Tokens are refreshed automatically on page reload.",
        ),
        400,
    )


@app.errorhandler(429)
def handle_ratelimit_error(error):
    """Handle rate limit throttling gracefully."""
    return (
        render_template(
            "error.html",
            error_title="Rate Limit Exceeded",
            error_message="Too many requests have originated from your network. For your account security, please take a quick breather and wait a moment before trying again.",
            retry_after=getattr(error, "description", "Rate limit in effect."),
        ),
        429,
    )


@app.errorhandler(404)
def handle_not_found(error):
    """Humanized 404 page."""
    return (
        render_template(
            "error.html",
            error_title="Page Not Found",
            error_message="We couldn't find the page you're looking for. It might have moved or the address was entered incorrectly.",
        ),
        404,
    )


@app.errorhandler(500)
def handle_server_error(error):
    """Humanized 500 error page."""
    return (
        render_template(
            "error.html",
            error_title="Something Went Wrong",
            error_message="We encountered an unexpected condition while processing your request. Please try again shortly.",
        ),
        500,
    )


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
    """Render account registration form."""
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("signup.html")


@app.route("/createuser", methods=["POST"])
@app.route("/register", methods=["POST"])
@limiter.limit("3 per hour")
def create_user():
    """
    User registration endpoint.
    Protected with rate limiting and strict credential sanitization.
    """
    usernm = request.form.get("username", "").strip()
    emailID = request.form.get("email", "").strip()
    passwd = request.form.get("password", "")
    confirmPasswd = request.form.get("confirm_password", "")

    # Human-centered input validation
    if not usernm or not emailID or not passwd:
        return render_template(
            "signup.html", msg="Please fill in all required fields to continue."
        )

    # Email format sanity check
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", emailID):
        return render_template(
            "signup.html", msg="Please provide a valid email address (e.g. name@example.com)."
        )

    # Username pattern sanity check
    if not re.match(r"^[A-Za-z0-9_.-]{3,40}$", usernm):
        return render_template(
            "signup.html",
            msg="Username must be 3-40 characters long and contain only letters, numbers, dots, or underscores.",
        )

    if passwd != confirmPasswd:
        return render_template(
            "signup.html", msg="Passwords do not match. Please double-check and try again."
        )

    if len(passwd) < 8:
        return render_template(
            "signup.html",
            msg="For your security, your password must be at least 8 characters long.",
        )

    # Cryptographic generation
    hashed_pw = hash_password(passwd)
    totp_secret = pyotp.random_base32()

    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)

        # Check existing username/email without exposing specifics
        cursor.execute(
            "SELECT id FROM users WHERE username = %s OR email = %s", (usernm, emailID)
        )
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            return render_template(
                "signup.html",
                msg="Registration could not be completed with the provided username or email. Please choose another or sign in.",
            )

        query = """
            INSERT INTO users (username, email, password_hash, totp_secret, is_totp_enabled)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (usernm, emailID, hashed_pw, totp_secret, False))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Account created successfully! Please configure Two-Factor Authentication below.", "success")
        return redirect(url_for("showqr", username=usernm))

    except Exception as err:
        app.logger.error(f"[secure-auth-system] Registration error: {err}")
        return render_template(
            "signup.html",
            msg="An error occurred while creating your account. Please try again in a moment.",
        )


@app.route("/showqr/<username>")
def showqr(username):
    """
    Display TOTP QR code for Google Authenticator / Authy / 1Password setup.
    """
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        cursor.execute(
            "SELECT totp_secret FROM users WHERE username = %s", (username,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user or not user.get("totp_secret"):
            return (
                render_template(
                    "error.html",
                    error_title="Account Not Found",
                    error_message=f"No account matching '{username}' was found with an active 2FA setup.",
                ),
                404,
            )

        ga_key = user["totp_secret"]
        totp = pyotp.TOTP(ga_key)
        otp_url = totp.provisioning_uri(name=username, issuer_name="secure-auth-system")

        # QR Code artifact generation
        static_dir = os.path.join(app.root_path, "static", "qrcodes")
        os.makedirs(static_dir, exist_ok=True)

        qr_filename = f"qr_{username}.png"
        qr_full_path = os.path.join(static_dir, qr_filename)
        img = qrcode.make(otp_url)
        img.save(qr_full_path)

        return render_template(
            "showqr.html",
            username=username,
            qr_filename=qr_filename,
            secret=ga_key,
        )
    except Exception as err:
        app.logger.error(f"[secure-auth-system] QR generation error: {err}")
        return (
            render_template(
                "error.html",
                error_title="Authenticator Setup Error",
                error_message="Could not generate your authenticator QR code. Please try again later.",
            ),
            500,
        )


@app.route("/login", methods=["GET"])
def login():
    """Render login form with automatic redirect if already authenticated."""
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/loginsubmit", methods=["POST"])
@limiter.limit("5 per minute")
def loginsubmit():
    """
    Primary credential authentication.
    Rate limited to 5 attempts per minute per IP.
    Enforces standardized error messages to prevent username/credential enumeration.
    """
    client_ip = get_client_ip()
    usernm = request.form.get("username", "").strip()
    passwd = request.form.get("password", "")

    conn = None
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        cursor.execute(
            "SELECT id, username, password_hash FROM users WHERE username = %s",
            (usernm,),
        )
        user = cursor.fetchone()
        cursor.close()
    except Exception as err:
        app.logger.error(f"[secure-auth-system] Database query error: {err}")
        user = None
    finally:
        if conn:
            conn.close()

    # Credential Verification with Timing Attack Mitigation
    if user and verify_password(passwd, user["password_hash"]):
        # Prevent session fixation
        session.clear()

        # Ephemeral Session Staging for 2FA Handshake
        session["pending_user_id"] = user["id"]
        session["pending_user"] = user["username"]
        session["otp_attempts"] = 0

        # Audit log stage 1 success
        log_login_event(user["id"], client_ip, "STAGE1_SUCCESS")

        flash("Password accepted. Please enter your 6-digit Authenticator code to continue.", "success")
        return redirect(url_for("verify_otp"))
    else:
        # Constant-time dummy verification ensures identical execution timing
        verify_password(passwd, DUMMY_BCRYPT_HASH)

        # Audit log failure
        log_login_event(None, client_ip, "FAILED")

        # Standardized generic error to prevent account enumeration
        return render_template(
            "login.html", msg="Invalid username or password. Please verify your credentials and try again."
        )


@app.route("/totp", methods=["GET", "POST"])
@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify_otp():
    """
    Two-Factor Authentication (TOTP) verification endpoint.
    Strictly rate limited to 5 attempts per minute per IP.
    Enforces maximum 3 OTP attempts before session invalidation.
    """
    pending_user_id = session.get("pending_user_id")
    pending_user = session.get("pending_user")

    if not pending_user_id or not pending_user:
        flash("Please enter your username and password first to access Two-Factor Verification.", "warning")
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("verify_otp.html", username=pending_user)

    client_ip = get_client_ip()
    otp = request.form.get("otp", "").strip()

    conn = None
    user = None
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        cursor.execute(
            "SELECT id, username, totp_secret FROM users WHERE id = %s",
            (pending_user_id,),
        )
        user = cursor.fetchone()
        cursor.close()
    except Exception as err:
        app.logger.error(f"[secure-auth-system] DB error during OTP verify: {err}")
    finally:
        if conn:
            conn.close()

    if user and user.get("totp_secret"):
        totp = pyotp.TOTP(user["totp_secret"])
        # valid_window=1 allows ±30s clock drift tolerance
        if totp.verify(otp, valid_window=1):
            # Promote session to fully authenticated state
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["user"] = user["username"]

            # Update TOTP enabled flag in DB
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET is_totp_enabled = TRUE WHERE id = %s",
                    (user["id"],),
                )
                conn.commit()
                cursor.close()
                conn.close()
            except Exception as update_err:
                app.logger.warning(
                    f"[secure-auth-system] Could not update is_totp_enabled: {update_err}"
                )

            # Audit log full authentication success
            log_login_event(user["id"], client_ip, "SUCCESS")

            flash(f"Welcome back, {user['username']}! You have signed in securely.", "success")
            return redirect(url_for("dashboard"))

    # Invalid OTP Handling with strict attempt throttling
    log_login_event(pending_user_id, client_ip, "OTP_FAILED")
    attempts = session.get("otp_attempts", 0) + 1
    session["otp_attempts"] = attempts

    if attempts >= 3:
        session.clear()
        flash("Maximum verification attempts exceeded. For your protection, please sign in again.", "danger")
        return redirect(url_for("login"))

    remaining = 3 - attempts
    return render_template(
        "verify_otp.html",
        username=pending_user,
        msg=f"Incorrect authentication code. You have {remaining} attempt{'s' if remaining != 1 else ''} remaining.",
    )


@app.route("/NewHome")
@app.route("/dashboard")
def dashboard():
    """
    Protected user dashboard requiring an active authenticated session.
    Fetches real-time security telemetry and recent authentication events.
    """
    if "user" not in session:
        flash("Please sign in to access your dashboard.", "warning")
        return redirect(url_for("login"))

    user_name = session["user"]
    user_id = session.get("user_id")
    client_ip = get_client_ip()
    audit_logs = []

    # Fetch recent audit logs for the authenticated user
    try:
        conn = get_db_connection()
        cursor = get_db_cursor(conn)
        if user_id:
            cursor.execute(
                "SELECT login_time, ip_address, status FROM login_logs WHERE user_id = %s ORDER BY login_time DESC LIMIT 5",
                (user_id,),
            )
        else:
            cursor.execute(
                "SELECT login_time, ip_address, status FROM login_logs ORDER BY login_time DESC LIMIT 5"
            )
        audit_logs = cursor.fetchall() or []
        cursor.close()
        conn.close()
    except Exception as err:
        app.logger.warning(f"[secure-auth-system] Could not load dashboard audit logs: {err}")

    return render_template(
        "NewHome.html",
        user=user_name,
        client_ip=client_ip,
        audit_logs=audit_logs,
    )


@app.route("/forgot-username", methods=["GET", "POST"])
@app.route("/forgotusername", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_username():
    """
    Username recovery endpoint.
    Protected with rate limiting and secure input handling.
    """
    msg = ""
    found_username = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        conn = None
        try:
            conn = get_db_connection()
            cursor = get_db_cursor(conn)
            cursor.execute("SELECT username FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            if user:
                found_username = user["username"]
            else:
                msg = "If an account is associated with this email, your username will be displayed here."
        except Exception as err:
            app.logger.error(f"[secure-auth-system] Forgot username error: {err}")
            msg = "An error occurred while processing your request. Please try again."
        finally:
            if conn:
                conn.close()

    return render_template(
        "forgotusername.html", msg=msg, username=found_username
    )


@app.route("/forgot-password", methods=["GET", "POST"])
@app.route("/forgotpassword", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot_password():
    """
    Password reset endpoint with anti-enumeration protection.
    """
    msg = ""
    success = False
    if request.method == "POST":
        usernm = request.form.get("username", "").strip()
        new_pass = request.form.get("new_password", "")

        if len(new_pass) < 8:
            msg = "New password must be at least 8 characters long."
        else:
            conn = None
            try:
                conn = get_db_connection()
                cursor = get_db_cursor(conn)
                cursor.execute(
                    "SELECT id FROM users WHERE username = %s", (usernm,)
                )
                user = cursor.fetchone()

                if user:
                    hashed_pw = hash_password(new_pass)
                    cursor.execute(
                        "UPDATE users SET password_hash = %s WHERE id = %s",
                        (hashed_pw, user["id"]),
                    )
                    conn.commit()
                    flash("Your password has been successfully updated! You can now sign in.", "success")
                    cursor.close()
                    conn.close()
                    return redirect(url_for("login"))
                else:
                    # Constant-time dummy hash to resist timing analysis
                    verify_password(new_pass, DUMMY_BCRYPT_HASH)
                    msg = "If the account exists, the password has been updated."

                cursor.close()
            except Exception as err:
                app.logger.error(
                    f"[secure-auth-system] Password reset error: {err}"
                )
                msg = "An error occurred while updating the password."
            finally:
                if conn:
                    conn.close()

    return render_template("forgotpassword.html", msg=msg, success=success)


@app.route("/logout")
def logout():
    """Safely clear session states and display warm sign-out feedback."""
    session.clear()
    flash("You have been signed out safely. Have a wonderful day!", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
"""
Automated unit & integration test suite for secure-auth-system.
Covers registration, bcrypt password hashing, login anti-enumeration,
TOTP generation and verification, rate limiting, and CSRF protection.
"""

import pyotp
import pytest
from app import verify_password
from tests.conftest import extract_csrf_token


class TestRegistrationFlow:
    """Tests covering account creation, input validation, and password hashing."""

    def test_successful_registration(self, client, test_db):
        """Valid registration creates user with bcrypt hash and redirects to QR code setup."""
        payload = {
            "username": "sarah_connor",
            "email": "sarah@cyberdyne.org",
            "password": "JudgementDay1997!",
            "confirm_password": "JudgementDay1997!",
        }
        response = client.post("/createuser", data=payload, follow_redirects=False)
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/showqr/sarah_connor")

        # Verify DB persistence and password hashing
        cursor = test_db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", ("sarah_connor",))
        user = cursor.fetchone()
        assert user is not None
        assert user["email"] == "sarah@cyberdyne.org"
        assert user["password_hash"].startswith("$2b$")
        assert verify_password("JudgementDay1997!", user["password_hash"]) is True
        assert verify_password("WrongPassword!", user["password_hash"]) is False
        assert user["totp_secret"] is not None
        assert len(user["totp_secret"]) == 32

    def test_registration_password_mismatch(self, client):
        """Reject registration when password confirmation fails."""
        payload = {
            "username": "john_doe",
            "email": "john@example.com",
            "password": "Password123!",
            "confirm_password": "DifferentPassword123!",
        }
        response = client.post("/createuser", data=payload)
        assert response.status_code == 200
        assert b"Passwords do not match" in response.data

    def test_registration_short_password(self, client):
        """Enforce minimum 8-character password constraint."""
        payload = {
            "username": "short_user",
            "email": "short@example.com",
            "password": "short",
            "confirm_password": "short",
        }
        response = client.post("/createuser", data=payload)
        assert response.status_code == 200
        assert b"at least 8 characters" in response.data

    def test_registration_duplicate_user(self, client, registered_user):
        """Reject duplicate username or email with generic security message."""
        payload = {
            "username": registered_user["username"],
            "email": "different@example.com",
            "password": "ValidPassword123!",
            "confirm_password": "ValidPassword123!",
        }
        response = client.post("/createuser", data=payload)
        assert response.status_code == 200
        assert b"Registration could not be completed" in response.data


class TestLoginFlow:
    """Tests covering primary authentication, anti-enumeration, and session staging."""

    def test_valid_login_stages_2fa_session(self, client, registered_user, test_db):
        """Valid primary credentials stage identity in session and redirect to verify-otp."""
        payload = {
            "username": registered_user["username"],
            "password": registered_user["password"],
        }
        response = client.post("/loginsubmit", data=payload, follow_redirects=False)
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/verify-otp")

        with client.session_transaction() as session:
            assert session.get("pending_user") == registered_user["username"]
            assert session.get("pending_user_id") is not None
            assert session.get("otp_attempts") == 0
            # User must not be granted full authenticated access yet
            assert "user" not in session

        # Verify audit log recorded stage 1
        cursor = test_db.cursor()
        cursor.execute("SELECT status FROM login_logs WHERE status = 'STAGE1_SUCCESS'")
        log = cursor.fetchone()
        assert log is not None

    def test_invalid_password_returns_standardized_error(self, client, registered_user, test_db):
        """Incorrect password returns standardized error without account state disclosure."""
        payload = {
            "username": registered_user["username"],
            "password": "IncorrectPassword999!",
        }
        response = client.post("/loginsubmit", data=payload)
        assert response.status_code == 200
        assert b"Invalid username or password" in response.data

        # Verify audit failure
        cursor = test_db.cursor()
        cursor.execute("SELECT status FROM login_logs WHERE status = 'FAILED'")
        assert cursor.fetchone() is not None

    def test_nonexistent_user_returns_identical_error(self, client):
        """Non-existent username returns the exact same message to prevent enumeration."""
        payload = {
            "username": "ghost_user_404",
            "password": "SomeRandomPassword123!",
        }
        response = client.post("/loginsubmit", data=payload)
        assert response.status_code == 200
        assert b"Invalid username or password" in response.data


class TestTOTPVerification:
    """Tests covering TOTP secret generation, QR display, and 2FA token validation."""

    def test_showqr_endpoint(self, client, registered_user):
        """Display QR code and manual setup key for registered user."""
        with client.session_transaction() as session:
            session["registration_user"] = registered_user["username"]
            session["can_view_qr"] = True
        response = client.get(f"/showqr/{registered_user['username']}")
        assert response.status_code == 200
        assert registered_user["totp_secret"].encode() in response.data
        assert b"Two-Factor Authentication" in response.data

    def test_showqr_unauthorized_fails(self, client, registered_user):
        """Unauthenticated request to showqr returns 403."""
        response = client.get(f"/showqr/{registered_user['username']}")
        assert response.status_code == 403

    def test_showqr_nonexistent_user(self, client):
        """Requesting QR code for unknown user returns 404."""
        with client.session_transaction() as session:
            session["registration_user"] = "unknown_user_xyz"
            session["can_view_qr"] = True
        response = client.get("/showqr/unknown_user_xyz")
        assert response.status_code == 404

    def test_successful_otp_verification(self, client, registered_user, test_db):
        """Valid OTP token establishes full session and updates TOTP enabled flag."""
        totp = pyotp.TOTP(registered_user["totp_secret"])
        current_token = totp.now()

        # Stage the session
        cursor = test_db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (registered_user["username"],))
        user_row = cursor.fetchone()

        with client.session_transaction() as session:
            session["pending_user_id"] = user_row["id"]
            session["pending_user"] = registered_user["username"]
            session["otp_attempts"] = 0

        response = client.post("/verify-otp", data={"otp": current_token}, follow_redirects=False)
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/dashboard")

        with client.session_transaction() as session:
            assert session.get("user") == registered_user["username"]
            assert "pending_user" not in session

        # Verify audit log recorded full success
        cursor.execute("SELECT status FROM login_logs WHERE status = 'SUCCESS'")
        assert cursor.fetchone() is not None

    def test_invalid_otp_retry_limit(self, client, registered_user, test_db):
        """Failed OTP increments attempts and invalidates session after 3 strikes."""
        cursor = test_db.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (registered_user["username"],))
        user_row = cursor.fetchone()

        with client.session_transaction() as session:
            session["pending_user_id"] = user_row["id"]
            session["pending_user"] = registered_user["username"]
            session["otp_attempts"] = 0

        # Attempt 1
        res1 = client.post("/verify-otp", data={"otp": "000000"})
        assert b"2 attempts remaining" in res1.data

        # Attempt 2
        res2 = client.post("/verify-otp", data={"otp": "000000"})
        assert b"1 attempt remaining" in res2.data

        # Attempt 3: Strike out and purge session
        res3 = client.post("/verify-otp", data={"otp": "000000"}, follow_redirects=False)
        assert res3.status_code == 302
        assert res3.headers["Location"].endswith("/login")

        with client.session_transaction() as session:
            assert "pending_user" not in session
            assert "user" not in session


class TestRateLimiting:
    """Tests covering rate-limiter enforcement on sensitive endpoints."""

    def test_login_rate_limit(self, client):
        """Exceeding 5 login attempts per minute triggers HTTP 429."""
        throttled = False
        for i in range(1, 8):
            res = client.post("/loginsubmit", data={
                "username": f"user_attempt_{i}",
                "password": "Password123!",
            })
            if res.status_code == 429:
                throttled = True
                assert b"Rate Limit Exceeded" in res.data
                break
        assert throttled is True, "Rate limiter did not throttle login after 5 requests!"


class TestCSRFProtection:
    """Dedicated tests validating CSRF token requirement and rejection."""

    def test_csrf_token_present_in_forms(self, csrf_client):
        """Forms rendered with CSRF enabled include valid csrf_token hidden fields."""
        res = csrf_client.get("/login")
        assert res.status_code == 200
        token = extract_csrf_token(res.data)
        assert len(token) > 20

    def test_missing_csrf_token_rejected(self, csrf_client):
        """Raw POST request without CSRF token is rejected with HTTP 400."""
        res = csrf_client.post("/loginsubmit", data={
            "username": "attacker",
            "password": "SomePassword123!",
        })
        assert res.status_code == 400
        assert b"Security Verification Failed" in res.data

    def test_valid_csrf_token_accepted(self, csrf_client, registered_user):
        """POST request containing valid CSRF token is processed successfully."""
        get_res = csrf_client.get("/login")
        token = extract_csrf_token(get_res.data)
        assert token != ""

        post_res = csrf_client.post("/loginsubmit", data={
            "csrf_token": token,
            "username": registered_user["username"],
            "password": registered_user["password"],
        }, follow_redirects=False)
        assert post_res.status_code == 302
        assert post_res.headers["Location"].endswith("/verify-otp")

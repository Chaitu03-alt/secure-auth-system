"""
Pytest configuration and fixtures for secure-auth-system test suite.
Configures in-memory SQLite test database with MySQL compatibility adapters,
isolated rate-limiter states, and dedicated CSRF testing fixtures.
"""

import re
import sqlite3
import sys
from pathlib import Path
import pytest

# Ensure project root is available in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app as flask_app, limiter, hash_password


class SQLiteCursorAdapter:
    """
    Cursor adapter that translates MySQL %s parameter syntax to SQLite ? syntax
    and returns dictionary records matching pymysql DictCursor behavior.
    """

    def __init__(self, raw_cursor):
        self._raw = raw_cursor

    def execute(self, query, params=None):
        q = query.replace("%s", "?")
        if params is not None:
            return self._raw.execute(q, params)
        return self._raw.execute(q)

    def fetchone(self):
        row = self._raw.fetchone()
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            return dict(row)
        desc = [col[0] for col in self._raw.description]
        return dict(zip(desc, row))

    def fetchall(self):
        rows = self._raw.fetchall()
        if not rows:
            return []
        if isinstance(rows[0], sqlite3.Row):
            return [dict(r) for r in rows]
        desc = [col[0] for col in self._raw.description]
        return [dict(zip(desc, r)) for r in rows]

    def close(self):
        pass

    @property
    def lastrowid(self):
        return self._raw.lastrowid

    @property
    def rowcount(self):
        return self._raw.rowcount


class SQLiteConnectionAdapter:
    """Connection adapter that exposes dictionary cursors and ignores per-request closes."""

    def __init__(self, conn):
        self._conn = conn

    def cursor(self, *args, **kwargs):
        return SQLiteCursorAdapter(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        # Prevent route handlers from closing the shared in-memory connection
        pass


@pytest.fixture
def test_db(monkeypatch):
    """
    Initializes an isolated in-memory SQLite database matching MySQL schema.
    Patches app.get_db_connection to return the connection adapter.
    """
    raw_conn = sqlite3.connect(":memory:", check_same_thread=False)
    raw_conn.row_factory = sqlite3.Row
    adapter = SQLiteConnectionAdapter(raw_conn)

    # Initialize tables
    cursor = adapter.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(80) NOT NULL UNIQUE,
            email VARCHAR(120) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            totp_secret VARCHAR(255) NULL,
            is_totp_enabled BOOLEAN NOT NULL DEFAULT 0,
            session_version INTEGER NOT NULL DEFAULT 1,
            last_totp_timestep INTEGER NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TIMESTAMP NULL DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NULL,
            login_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45) NOT NULL,
            status VARCHAR(20) NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash VARCHAR(64) NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN NOT NULL DEFAULT 0,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    adapter.commit()

    monkeypatch.setattr("app.get_db_connection", lambda: adapter)
    return adapter


@pytest.fixture
def app_instance(test_db):
    """Configures the Flask application for standard testing without CSRF friction."""
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret-key-for-unit-testing-32b",
        "RATELIMIT_ENABLED": True,
    })
    limiter.reset()
    return flask_app


@pytest.fixture
def client(app_instance):
    """Test client configured with WTF_CSRF_ENABLED=False for straightforward API tests."""
    return app_instance.test_client()


@pytest.fixture
def csrf_client(test_db):
    """
    Dedicated test client with CSRF validation strictly enforced (WTF_CSRF_ENABLED=True)
    to verify security token generation and rejection.
    """
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": True,
        "SECRET_KEY": "test-csrf-secret-key-for-unit-testing",
        "RATELIMIT_ENABLED": True,
    })
    limiter.reset()
    return flask_app.test_client()


@pytest.fixture
def registered_user(test_db):
    """Pre-seeds a verified user account into the test database."""
    username = "testpilot"
    email = "testpilot@example.com"
    raw_password = "CorrectPassword123!"
    totp_secret = "JBSWY3DPEHPK3PXP"  # Valid base32 secret
    hashed_pw = hash_password(raw_password)

    cursor = test_db.cursor()
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, totp_secret, is_totp_enabled)
        VALUES (%s, %s, %s, %s, %s)
    """, (username, email, hashed_pw, totp_secret, 1))
    test_db.commit()

    return {
        "username": username,
        "email": email,
        "password": raw_password,
        "totp_secret": totp_secret,
    }


def extract_csrf_token(html_bytes: bytes) -> str:
    """Helper to extract CSRF token from rendered HTML forms."""
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_bytes.decode("utf-8"))
    return match.group(1) if match else ""

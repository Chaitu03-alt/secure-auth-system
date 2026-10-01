-- ============================================================================
-- secure-auth-system: Database Schema Definition
-- Target RDBMS: MySQL 8.0+ / MariaDB 10.5+
-- Character Set: utf8mb4 (Full Unicode support including emojis)
-- ============================================================================

CREATE DATABASE IF NOT EXISTS secure_auth_system
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE secure_auth_system;

-- ----------------------------------------------------------------------------
-- Table: users
-- Stores identity credentials, secure password hashes, and TOTP 2FA configuration.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(32) NULL,
    is_totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    session_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_username (username),
    INDEX idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: login_logs
-- Append-only security audit trail for authentication attempts (success, fail, OTP).
-- Accommodates both IPv4 and IPv6 network addresses (up to 45 chars).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    login_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(20) NOT NULL,
    INDEX idx_login_logs_user_id (user_id),
    INDEX idx_login_logs_ip (ip_address),
    INDEX idx_login_logs_time (login_time),
    CONSTRAINT fk_login_logs_users
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Table: password_resets
-- Signed, expiring, single-use password recovery tokens.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_resets_user (user_id),
    INDEX idx_resets_token (token_hash),
    CONSTRAINT fk_password_resets_users
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


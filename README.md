# Secure Authentication System

Session-based web authentication with hashed credentials and TOTP two-factor login, built with Flask and MySQL.

## Problem Statement

Password-only login is a single point of failure: one leaked or guessed credential grants full account access. This project implements a login flow where a compromised password alone is not sufficient to authenticate — a valid TOTP code, generated from a secret never transmitted after initial setup, is also required.

The scope is a working reference implementation of that flow, not a drop-in auth library: it favors readable, auditable route logic over abstraction.

## Architecture

```text
Browser
  │
  ├─ POST /signup ──────────► hash password (Werkzeug) ──► store user row (MySQL)
  │
  ├─ GET  /setup-2fa ───────► generate TOTP secret (PyOTP) ──► render QR (qrcode + Pillow)
  │                                                        └─ user scans with authenticator app
  │
  ├─ POST /login ───────────► verify password hash
  │                              │
  │                              ▼ (on success)
  │                           POST /verify-otp ──► verify TOTP against stored secret
  │                              │
  │                              ▼ (on success)
  │                           create server-side session
  │
  └─ GET  /dashboard ───────► session check middleware ──► 200 | redirect to /login

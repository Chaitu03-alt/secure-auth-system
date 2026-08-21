# Secure Authentication System

A Flask + MySQL authentication web application with password hashing and TOTP-based two-factor authentication (2FA).

## Features

- User registration with password hashing
- MySQL-backed user management
- TOTP-based two-factor authentication
- QR-code setup for Google Authenticator-compatible apps
- Session-based login and logout
- Protected dashboard
- Forgot-username flow
- Responsive HTML/CSS interface
- Environment-based configuration for secrets and database credentials

## Tech Stack

- **Backend:** Python, Flask
- **Database:** MySQL
- **Authentication:** Werkzeug password hashing + PyOTP/TOTP
- **Frontend:** HTML, CSS, JavaScript
- **QR:** `qrcode` + Pillow

## Project Structure

```text
secure-authentication-system/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── database/
│   └── schema.sql
├── templates/
│   ├── home.html
│   ├── login.html
│   ├── signup.html
│   ├── verify_otp.html
│   ├── showqr.html
│   ├── forgotusername.html
│   ├── forgotpassword.html
│   └── dashboard.html
└── static/
    ├── *.css
    ├── theme.js
    └── space-planet.png
```

## Setup

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd secure-authentication-system
```

### 2. Create and activate a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy `.env.example` to `.env` and add your local MySQL credentials and a strong Flask secret key.

```bash
copy .env.example .env
```

Do **not** commit `.env` to GitHub.

### 5. Create the database

Run `database/schema.sql` in MySQL.

### 6. Start the application

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Authentication Flow

1. User creates an account.
2. Password is stored as a secure hash rather than plaintext.
3. A unique TOTP secret is generated for the account.
4. The user scans the QR code using an authenticator app.
5. Login requires both the account password and a time-based OTP.
6. A successful OTP verification creates a session and opens the protected dashboard.

## Security Notes

- Database credentials are loaded from environment variables.
- Flask session secret is configurable through the environment.
- Passwords are hashed using Werkzeug.
- TOTP secrets are generated server-side using PyOTP.
- Generated QR images are ignored by Git and are not included in the repository.

## Resume Description

**Secure Authentication System | Python, Flask, MySQL, TOTP 2FA**

Built a secure web authentication system using Flask and MySQL with password hashing and time-based two-factor authentication. Implemented QR-code-based authenticator setup, session management, protected routes, and environment-based secret configuration.

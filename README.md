# 🔐 Secure Authentication System

A secure Flask + MySQL web authentication application implementing **password hashing, TOTP-based Two-Factor Authentication (2FA), QR-code authenticator setup, session management, and protected routes**.

The project demonstrates practical backend development and application-security concepts using Python and Flask.

---

## 🚀 Features

* 👤 User registration and account creation
* 🔑 Secure password hashing using Werkzeug
* 🗄️ MySQL-based user management
* 🔐 TOTP-based Two-Factor Authentication (2FA)
* 📱 QR-code setup for authenticator applications
* 🔢 OTP verification during login
* 🛡️ Protected dashboard routes
* 🚪 Session-based login and logout
* 🔎 Forgot-username functionality
* 🔧 Environment-based configuration
* 🎨 Responsive HTML/CSS interface
* 🌌 Custom frontend theme and visual assets

---

## 🛠️ Tech Stack

| Category        | Technologies                            |
| --------------- | --------------------------------------- |
| Backend         | Python, Flask                           |
| Database        | MySQL                                   |
| Authentication  | Werkzeug Password Hashing, PyOTP / TOTP |
| Frontend        | HTML, CSS, JavaScript                   |
| QR Code         | qrcode, Pillow                          |
| Configuration   | python-dotenv / Environment Variables   |
| Version Control | Git, GitHub                             |

---

## 📂 Project Structure

```text
secure-authentication-system/
│
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
│
├── database/
│   └── schema.sql
│
├── templates/
│   ├── home.html
│   ├── login.html
│   ├── signup.html
│   ├── verify_otp.html
│   ├── showqr.html
│   ├── forgotusername.html
│   ├── forgotpassword.html
│   └── dashboard.html
│
└── static/
    ├── *.css
    ├── theme.js
    └── space-planet.png
```

---

# ⚙️ Installation & Setup

## 1. Clone the Repository

```bash
git clone https://github.com/Chaitu03-alt/secure-auth-system.git
cd secure-auth-system
```

---

## 2. Create a Virtual Environment

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Configure Environment Variables

Create a `.env` file using `.env.example` as a template.

### Windows

```bash
copy .env.example .env
```

### macOS / Linux

```bash
cp .env.example .env
```

Update the `.env` file with your local MySQL configuration and a strong Flask secret key.

Example:

```env
SECRET_KEY=your_strong_secret_key

DB_HOST=localhost
DB_USER=your_mysql_username
DB_PASSWORD=your_mysql_password
DB_NAME=your_database_name
```

> ⚠️ **Never commit your `.env` file to GitHub.**

---

## 5. Create the MySQL Database

Open MySQL and execute:

```text
database/schema.sql
```

This creates the required database structure for the application.

---

## 6. Start the Application

```bash
python app.py
```

The application will run locally at:

```text
http://127.0.0.1:5000
```

Open the URL in your browser.

---

# 🔐 Authentication Flow

The application uses a multi-step authentication process:

```text
┌───────────────────┐
│  User Registration│
└─────────┬─────────┘
          ↓
┌───────────────────┐
│ Password Hashing  │
└─────────┬─────────┘
          ↓
┌───────────────────┐
│ Generate TOTP     │
│ Secret            │
└─────────┬─────────┘
          ↓
┌───────────────────┐
│ QR Code Setup     │
│ Authenticator App │
└─────────┬─────────┘
          ↓
┌───────────────────┐
│ Username +        │
│ Password Login    │
└─────────┬─────────┘
          ↓
┌───────────────────┐
│ TOTP / OTP        │
│ Verification      │
└─────────┬─────────┘
          ↓
┌───────────────────┐
│ Authenticated      │
│ Session            │
└─────────┬─────────┘
          ↓
┌───────────────────┐
│ Protected         │
│ Dashboard         │
└───────────────────┘
```

### Authentication Process

1. User creates an account.
2. Password is hashed before being stored.
3. A unique TOTP secret is generated for the user.
4. A QR code is generated for authenticator setup.
5. The user scans the QR code using a compatible authenticator application.
6. During login, the user provides their username and password.
7. The generated time-based OTP is verified.
8. After successful verification, an authenticated session is created.
9. The user can access protected application routes.

---

# 🛡️ Security Implementation

The project demonstrates several practical security mechanisms.

### Password Security

Passwords are never stored as plaintext.

Werkzeug's password hashing functionality is used to generate and verify password hashes.

```python
generate_password_hash(password)
```

and:

```python
check_password_hash(password_hash, password)
```

---

### Two-Factor Authentication

The application uses **TOTP (Time-based One-Time Password)** through PyOTP.

A user must provide:

```text
Username + Password + Time-based OTP
```

This provides an additional authentication layer beyond the password.

---

### QR-Code Authentication Setup

A QR code is generated from the TOTP provisioning information.

The user can scan the QR code with a compatible authenticator application.

---

### Environment-Based Configuration

Sensitive configuration values such as:

* Database username
* Database password
* Database name
* Flask secret key

are loaded through environment variables rather than being hard-coded into the application.

---

### Session Management

After successful authentication, the application creates a server-side Flask session that is used to maintain the user's authenticated state.

Protected routes verify the authentication state before allowing access.

---

# 📸 Application Screens

Add screenshots of the following pages to the repository to make the project easier to understand:

```text
Home Page
Login Page
Registration Page
QR Code / 2FA Setup
OTP Verification
Dashboard
```

Recommended GitHub structure:

```text
screenshots/
├── home.png
├── login.png
├── signup.png
├── 2fa-setup.png
├── otp-verification.png
└── dashboard.png
```

---

# 🧪 Running the Project Locally

After starting the application:

```bash
python app.py
```

Visit:

```text
http://127.0.0.1:5000
```

Then:

```text
Register
   ↓
Configure 2FA
   ↓
Scan QR Code
   ↓
Login
   ↓
Enter OTP
   ↓
Access Dashboard
```

---

# 📦 Dependencies

Main Python dependencies used by the project include:

```text
Flask
mysql-connector-python
PyOTP
Werkzeug
qrcode
Pillow
python-dotenv
```

The complete dependency list is available in:

```text
requirements.txt
```

---

# 🔒 Security Notes

* Never commit `.env` files containing real credentials.
* Use a strong, randomly generated Flask `SECRET_KEY`.
* Use a dedicated MySQL user instead of a highly privileged database account when possible.
* Do not expose production database credentials in source code.
* Do not commit generated QR-code images containing authentication secrets.
* This project is intended as a learning/portfolio application and should receive additional hardening before production deployment.

---

# 🎯 Learning Outcomes

Through this project, the following concepts were practiced:

* Python backend development
* Flask application structure
* REST/backend route design
* MySQL database integration
* Password hashing
* Two-Factor Authentication
* TOTP authentication
* QR-code generation
* Session management
* Environment-based configuration
* Git and GitHub workflow
* Frontend/backend integration
* Basic application security principles

---

# 📌 Future Improvements

Potential improvements for a production-oriented version include:

* [ ] Rate limiting for login and OTP attempts
* [ ] Account lockout / temporary lock mechanism
* [ ] Password reset through verified email
* [ ] CSRF protection
* [ ] Stronger input validation
* [ ] Security-focused logging and audit trails
* [ ] Automated unit and integration tests
* [ ] Docker support
* [ ] Production WSGI deployment
* [ ] HTTPS configuration
* [ ] Database migrations
* [ ] CI/CD pipeline using GitHub Actions

---

# 👨‍💻 Author

**Chaitanya Raut**

Python & Backend Developer

📍 Pune, Maharashtra, India

### Connect With Me

* GitHub: https://github.com/Chaitu03-alt
* LinkedIn: https://www.linkedin.com/in/chaitanya-raut-226a4742b

---

# 📄 Resume Description

**Secure Authentication System | Python, Flask, MySQL, TOTP 2FA**

Built a secure web authentication system using Flask and MySQL with password hashing and time-based two-factor authentication. Implemented QR-code-based authenticator setup, OTP verification, session management, protected routes, and environment-based configuration for application secrets and database credentials.

---

⭐ If you found this project useful, feel free to explore the repository and connect with me on LinkedIn.

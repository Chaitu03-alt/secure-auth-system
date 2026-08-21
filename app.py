from flask import Flask, redirect, render_template, request, url_for, session
import mysql.connector
import pyotp
import qrcode
import os
import uuid
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-me")


def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "UserProfile"),
    )


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/signup")
def signup():
    return render_template("signup.html")


@app.route("/createuser", methods=["POST"])
def create_user():
    fullname = request.form["name"].strip()
    usernm = request.form["username"].strip()
    email_id = request.form["email"].strip()
    passwd = request.form["password"]
    confirm_passwd = request.form["confirm_password"]

    if passwd != confirm_passwd:
        return render_template("signup.html", msg="Passwords do not match!")

    hashed_pw = generate_password_hash(passwd)
    secret_key = pyotp.random_base32()

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        query = (
            "INSERT INTO users "
            "(Name, username, password, emailid, SECRET_KEY) "
            "VALUES (%s, %s, %s, %s, %s)"
        )
        cursor.execute(query, (fullname, usernm, hashed_pw, email_id, secret_key))
        conn.commit()
        return redirect(url_for("showqr", username=usernm))
    except mysql.connector.Error:
        conn.rollback()
        return render_template("signup.html", msg="Unable to create account. Username or email may already exist.")
    finally:
        cursor.close()
        conn.close()


@app.route("/showqr/<username>")
def showqr(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT SECRET_KEY FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return "User not found", 404

    ga_key = user["SECRET_KEY"]
    totp = pyotp.TOTP(ga_key)
    otp_url = totp.provisioning_uri(
        name=username,
        issuer_name=os.getenv("TOTP_ISSUER", "Secure Authenticator App"),
    )

    qr_dir = os.path.join(app.static_folder, "generated_qr")
    os.makedirs(qr_dir, exist_ok=True)
    filename = f"qr_{uuid.uuid4().hex}.png"
    qr_path = os.path.join(qr_dir, filename)
    qrcode.make(otp_url).save(qr_path)

    return render_template(
        "showqr.html",
        qr_image=url_for("static", filename=f"generated_qr/{filename}"),
        secret=ga_key,
    )


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/loginsubmit", methods=["POST"])
def loginsubmit():
    usernm = request.form["username"].strip()
    passwd = request.form["password"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (usernm,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user["password"], passwd):
        return render_template("verify_otp.html", username=usernm)

    return render_template("login.html", msg="Invalid credentials!")


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    username = request.form["username"].strip()
    otp = request.form["otp"].strip()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT SECRET_KEY FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and pyotp.TOTP(user["SECRET_KEY"]).verify(otp):
        session["user"] = username
        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html", username=username, msg="Invalid OTP!")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"])


@app.route("/forgot-username", methods=["GET", "POST"])
def forgot_username():
    msg = ""
    found_username = None

    if request.method == "POST":
        email = request.form["email"].strip()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT username FROM users WHERE emailid = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            found_username = user["username"]
        else:
            msg = "Email not found."

    return render_template("forgotusername.html", msg=msg, username=found_username)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")

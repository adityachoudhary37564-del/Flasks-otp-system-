import os
import time
import hmac
import hashlib
import secrets
import smtplib
from email.message import EmailMessage

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY=GrowUp_Aditya_9xK7mP4vQ2wL8zR5tN6", "CHANGE-THIS-SECRET-KEY")

EMAIL_USER = os.environ.get("opboy7127@gmail.com", "")
EMAIL_PASSWORD = os.environ.get("ghtg fkod skkx argl", "")
OTP_SECRET = os.environ.get("GrowUp_Aditya_9xK7mP4vQ2wL8zR5tN6", app.secret_key)

# TESTING ONLY: RAM storage resets whenever the server restarts.
users = {}       # email -> password hash
pending = {}     # email -> OTP state
login_pending = {}

OTP_SECONDS = 300
RESEND_SECONDS = 60
MAX_ATTEMPTS = 5


def otp_digest(email, otp):
    raw = f"{email.lower()}:{otp}".encode()
    return hmac.new(OTP_SECRET.encode(), raw, hashlib.sha256).hexdigest()


def send_email_otp(receiver_email, otp, purpose):
    if not EMAIL_USER or not EMAIL_PASSWORD:
        print("Email credentials are missing. Set EMAIL_USER and EMAIL_PASSWORD.")
        return False

    msg = EmailMessage()
    msg["Subject"] = f"GrowUp - {purpose} verification code"
    msg["From"] = EMAIL_USER
    msg["To"] = receiver_email
    msg.set_content(
        f"Your GrowUp verification code is: {otp}\n\n"
        f"This code expires in 5 minutes. Do not share it with anyone.\n"
        "If you did not request this code, you can ignore this email."
    )

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        app.logger.exception("Email delivery failed: %s", exc)
        return False


def create_otp_record(email):
    now = time.time()
    existing = pending.get(email)
    if existing and now - existing["sent_at"] < RESEND_SECONDS:
        return None, "Please wait 60 seconds before requesting another code."

    otp = f"{secrets.randbelow(1_000_000):06d}"
    pending[email] = {
        "digest": otp_digest(email, otp),
        "expires": now + OTP_SECONDS,
        "sent_at": now,
        "attempts": 0,
    }
    return otp, None


def check_otp(store, email, entered):
    record = store.get(email)
    if not record:
        return False, "Request a new verification code first."
    if time.time() > record["expires"]:
        store.pop(email, None)
        return False, "Code expired. Request a new one."
    if record["attempts"] >= MAX_ATTEMPTS:
        store.pop(email, None)
        return False, "Too many incorrect attempts. Request a new code."
    record["attempts"] += 1
    expected = record["digest"]
    supplied = otp_digest(email, entered.strip())
    if hmac.compare_digest(expected, supplied):
        store.pop(email, None)
        return True, "Verified."
    return False, f"Incorrect code. {MAX_ATTEMPTS - record['attempts']} attempts left."


@app.route("/")
def home():
    return render_template("index.html", logged_in=session.get("user"))


@app.post("/signup/request")
def signup_request():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or "@" not in email or len(password) < 8:
        flash("Enter a valid email and a password of at least 8 characters.", "error")
        return redirect(url_for("home"))
    if email in users:
        flash("An account with this email already exists. Please log in.", "error")
        return redirect(url_for("home"))

    otp, error = create_otp_record(email)
    if error:
        flash(error, "error")
        return redirect(url_for("home"))
    # Store only a password hash while signup verification is pending.
    session["signup_password_hash"] = generate_password_hash(password)
    if not send_email_otp(email, otp, "Sign-up"):
        pending.pop(email, None)
        flash("Email could not be sent. Check your Gmail settings and Render environment variables.", "error")
        return redirect(url_for("home"))

    session["signup_email"] = email
    flash("Verification code sent. Check your inbox.", "success")
    return redirect(url_for("home"))


@app.post("/signup/verify")
def signup_verify():
    email = session.get("signup_email", "")
    entered = request.form.get("otp", "")
    ok, message = check_otp(pending, email, entered)
    if ok:
        # The record was removed by check_otp; the password hash must be preserved
        # separately before verification in a production database.
        # For this demo, signup hash is cached in the session before checking below.
        password_hash = session.pop("signup_password_hash", None)
        if not password_hash:
            flash("Signup session expired. Please sign up again.", "error")
            return redirect(url_for("home"))
        users[email] = password_hash
        session.pop("signup_email", None)
        flash("Email verified. Account created. You can now log in.", "success")
    else:
        flash(message, "error")
    return redirect(url_for("home"))


@app.post("/login/request")
def login_request():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    user_hash = users.get(email)
    if not user_hash or not check_password_hash(user_hash, password):
        flash("Email or password is incorrect, or the account has not been created in this demo.", "error")
        return redirect(url_for("home"))

    now = time.time()
    old = login_pending.get(email)
    if old and now - old["sent_at"] < RESEND_SECONDS:
        flash("Please wait 60 seconds before requesting another code.", "error")
        return redirect(url_for("home"))
    otp = f"{secrets.randbelow(1_000_000):06d}"
    login_pending[email] = {
        "digest": otp_digest(email, otp),
        "expires": now + OTP_SECONDS,
        "sent_at": now,
        "attempts": 0,
    }
    if not send_email_otp(email, otp, "Login"):
        login_pending.pop(email, None)
        flash("Email could not be sent. Check your Gmail settings.", "error")
        return redirect(url_for("home"))
    session["login_email"] = email
    flash("Login verification code sent to your email.", "success")
    return redirect(url_for("home"))


@app.post("/login/verify")
def login_verify():
    email = session.get("login_email", "")
    ok, message = check_otp(login_pending, email, request.form.get("otp", ""))
    if ok:
        session["user"] = email
        session.pop("login_email", None)
        flash("Login successful.", "success")
    else:
        flash(message, "error")
    return redirect(url_for("home"))


@app.post("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# Preserve pending signup password hash in the signed session before OTP verification.
@app.before_request
def preserve_signup_hash():
    if request.endpoint == "signup_request" and request.method == "POST":
        pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

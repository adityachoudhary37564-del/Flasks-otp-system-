
import os
import secrets
import smtplib
import time
from email.message import EmailMessage

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Frontend configuration
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5500")

CORS(
    app,
    origins=[FRONTEND_ORIGIN],
    supports_credentials=True
)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None"
)

# Brevo SMTP configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp-relay.brevo.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_LOGIN = os.getenv("SMTP_LOGIN", "")
SMTP_KEY = os.getenv("SMTP_KEY", "")
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "")

OTP_EXPIRY = 600
MAX_ATTEMPTS = 5

# Demo storage only; use a database for production.
users = {}
pending_otps = {}


def send_otp_email(email, otp):
    if not all([SMTP_LOGIN, SMTP_KEY, SENDER_EMAIL]):
        return False

    msg = EmailMessage()
    msg["Subject"] = "GrowUp Email Verification"
    msg["From"] = SENDER_EMAIL
    msg["To"] = email

    msg.set_content(
        f"""Welcome to GrowUp!

Your verification code is: {otp}

This code expires in 10 minutes.
If you did not request this code, ignore this email.
"""
    )

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_LOGIN, SMTP_KEY)
            server.send_message(msg)

        return True

    except Exception:
        app.logger.exception("Brevo SMTP error")
        return False


@app.get("/")
def home():
    return jsonify({
        "status": "online",
        "app": "GrowUp API"
    })


@app.post("/signup/request")
def signup_request():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or "@" not in email or len(email) > 254:
        return jsonify({"message": "Enter a valid email."}), 400

    if len(password) < 8 or len(password) > 128:
        return jsonify({"message": "Password must be 8–128 characters."}), 400

    if email in users:
        return jsonify({"message": "Account already exists."}), 409

    otp = f"{secrets.randbelow(900000) + 100000}"

    if not send_otp_email(email, otp):
        return jsonify({"message": "Could not send OTP. Check SMTP settings."}), 500

    pending_otps[email] = {
        "otp": otp,
        "password_hash": generate_password_hash(password),
        "expires": time.time() + OTP_EXPIRY,
        "attempts": 0
    }

    return jsonify({"message": "OTP sent successfully."})


@app.post("/signup/verify")
def signup_verify():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    otp = str(data.get("otp", "")).strip()

    record = pending_otps.get(email)

    if not record:
        return jsonify({"message": "Request a new OTP."}), 400

    if time.time() > record["expires"]:
        pending_otps.pop(email, None)
        return jsonify({"message": "OTP expired."}), 400

    record["attempts"] += 1

    if record["attempts"] > MAX_ATTEMPTS:
        pending_otps.pop(email, None)
        return jsonify({"message": "Too many attempts. Request a new OTP."}), 429

    if not secrets.compare_digest(record["otp"], otp):
        return jsonify({"message": "Incorrect OTP."}), 400

    users[email] = record["password_hash"]
    pending_otps.pop(email, None)

    session["user"] = email

    return jsonify({
        "message": "Account created successfully.",
        "email": email
    })


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    password_hash = users.get(email)

    if not password_hash or not check_password_hash(password_hash, password):
        return jsonify({"message": "Invalid email or password."}), 401

    session.clear()
    session["user"] = email

    return jsonify({
        "message": "Login successful.",
        "email": email
    })


@app.get("/me")
def me():
    email = session.get("user")

    if not email:
        return jsonify({"message": "Not logged in."}), 401

    return jsonify({
        "logged_in": True,
        "email": email
    })


@app.post("/logout")
def logout():
    session.clear()

    return jsonify({
        "message": "Logged out successfully."
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000))
    )

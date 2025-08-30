#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, re, time, smtplib, ssl
from email.message import EmailMessage
from email.utils import formataddr

# ---------- Load configuration from .env next to this script ----------
import pathlib
def load_dotenv_from(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
load_dotenv_from(SCRIPT_DIR / "contact.env")

SMTP_HOST = os.environ.get("SMTP_HOST", "mail.example.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
TO_ADDR   = os.environ.get("TO_ADDR", SMTP_USER)

SMTP_TLS_MODE = os.environ.get("SMTP_TLS_MODE", "starttls").strip().lower()  # starttls|ssl
MIN_ELAPSED_MS  = int(os.environ.get("MIN_ELAPSED_MS","5000"))
MIN_INTERVAL_S  = int(os.environ.get("MIN_INTERVAL_S","30"))
RATE_DIR        = os.environ.get("RATE_DIR","/tmp")
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS","").split(",") if o.strip()]

# Request body size limit (DoS guard)
MAX_BODY = int(os.environ.get("MAX_BODY", "65536"))

# ---------- Helpers ----------
def _h(line): sys.stdout.write(line + "\r\n")
def send_headers(status="200 OK", origin=None, ctype="application/json; charset=utf-8"):
    _h(f"Status: {status}")
    _h(f"Content-Type: {ctype}")
    _h("X-Content-Type-Options: nosniff")
    if origin and origin in ALLOWED_ORIGINS:
        _h(f"Access-Control-Allow-Origin: {origin}")
        _h("Vary: Origin")
        _h("Access-Control-Allow-Methods: POST, OPTIONS")
        _h("Access-Control-Allow-Headers: Content-Type")
        if status.startswith("204"):
            _h("Access-Control-Max-Age: 600")
    _h("")

def log_err(msg):
    try: sys.stderr.write((msg or "").rstrip() + "\n")
    except Exception: pass

def client_ip():
    xff = (os.environ.get("HTTP_X_FORWARDED_FOR","") or "").split(",")[0].strip()
    return xff or os.environ.get("REMOTE_ADDR","unknown")

def rate_key(ip):
    return os.path.join(RATE_DIR, f"form_rate_{(ip or 'unknown').replace(':','_')}")

def rate_limit_ok(ip):
    try:
        now = int(time.time()); path = rate_key(ip)
        last = 0
        try:
            with open(path, "r") as f: last = int((f.read().strip() or "0"))
        except FileNotFoundError:
            pass
        if now - last < MIN_INTERVAL_S:
            return False
        os.makedirs(RATE_DIR, exist_ok=True)
        with open(path, "w") as f: f.write(str(now))
        return True
    except Exception:
        return True

def read_body_json():
    ctype = (os.environ.get("CONTENT_TYPE") or "").lower()
    try:
        clen  = int(os.environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        clen = 0
    if clen <= 0 or clen > MAX_BODY:
        return None, "too large or empty"
    raw = sys.stdin.read(clen)
    if not ctype.startswith("application/json"):
        return None, "unsupported content-type"
    try:
        return json.loads(raw or "{}"), None
    except Exception:
        return None, "invalid json"

_email_rx = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
def valid_email(addr):
    return bool(_email_rx.match(addr or ""))

def sanitize_header_value(s: str) -> str:
    # Prevent header injection
    return (s or "").replace("\r","").replace("\n","").strip()

def clamp(s: str, maxlen: int) -> str:
    s = (s or "").strip()
    return s[:maxlen]

def send_mail(name, email, company, subject, message):
    # From stays on your domain (DMARC/SPF), Reply-To points to the visitor
    msg = EmailMessage()
    msg["From"] = formataddr(("Website Contact", SMTP_USER))
    msg["To"] = TO_ADDR
    msg["Reply-To"] = formataddr((name, email))
    msg["Subject"] = sanitize_header_value(subject) or "New website inquiry"

    body = (
        f"Name: {name}\n"
        f"Email: {email}\n"
        f"Company: {company}\n\n"
        f"Subject: {subject}\n\n"
        f"Message:\n{message}\n"
    )
    msg.set_content(body)

    if SMTP_TLS_MODE == "ssl":
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, 465 if SMTP_PORT == 465 else 465, timeout=20, context=ctx) as s:
            if SMTP_USER and SMTP_PASS: s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    else:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT if SMTP_PORT else 587, timeout=20) as s:
            s.ehlo(); s.starttls(context=ctx); s.ehlo()
            if SMTP_USER and SMTP_PASS: s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)

# ---------- Handler ----------
def main():
    try: sys.stdout.reconfigure(line_buffering=True)
    except Exception: pass

    method = (os.environ.get("REQUEST_METHOD") or "GET").upper()
    origin = os.environ.get("HTTP_ORIGIN", "")

    if method == "OPTIONS":
        send_headers("204 No Content", origin); return
    if method != "POST":
        send_headers("405 Method Not Allowed", origin)
        sys.stdout.write(json.dumps({"ok": False, "error": "method not allowed"})); sys.stdout.flush(); return

    data, jerr = read_body_json()
    if data is None:
        status = "413 Payload Too Large" if jerr == "too large or empty" else "415 Unsupported Media Type"
        send_headers(status, origin)
        sys.stdout.write(json.dumps({"ok": False, "error": jerr})); sys.stdout.flush(); return

    # Honeypot
    if (data.get("website") or "").strip():
        send_headers("200 OK", origin)
        sys.stdout.write(json.dumps({"ok": True, "message": "Thanks! Your message has been sent."})); sys.stdout.flush(); return

    # Minimum fill time
    try: elapsed = int(str(data.get("_elapsed_ms","0")).strip() or "0")
    except ValueError: elapsed = 0
    if elapsed < MIN_ELAPSED_MS:
        send_headers("400 Bad Request", origin)
        sys.stdout.write(json.dumps({"ok": False, "error": "form filled too fast"})); sys.stdout.flush(); return

    # Required fields + length limits
    name    = clamp(data.get("name"),    200)
    email   = clamp(data.get("email"),   254)
    subject = clamp(data.get("subject"), 200)
    message = clamp(data.get("message"), 5000)
    company = clamp(data.get("company"), 200)

    if not name or not message or not valid_email(email):
        send_headers("400 Bad Request", origin)
        sys.stdout.write(json.dumps({"ok": False, "error": "missing or invalid fields"})); sys.stdout.flush(); return

    # Per-IP rate limit
    ip = client_ip()
    if not rate_limit_ok(ip):
        send_headers("429 Too Many Requests", origin)
        sys.stdout.write(json.dumps({"ok": False, "error": "too many requests"})); sys.stdout.flush(); return

    # Send
    try:
        if not SMTP_USER or not TO_ADDR:
            raise RuntimeError("misconfigured smtp user or recipient")
        send_mail(name, email, company, subject, message)
        send_headers("200 OK", origin)
        sys.stdout.write(json.dumps({"ok": True, "message": "Thanks! Your message has been sent."})); sys.stdout.flush()
    except Exception as e:
        log_err(f"send_mail failed: {e!r}")
        send_headers("500 Internal Server Error", origin)
        sys.stdout.write(json.dumps({"ok": False, "error": "send failed"})); sys.stdout.flush()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log_err(f"fatal: {e!r}")
        _h("Status: 500 Internal Server Error"); _h("Content-Type: application/json; charset=utf-8"); _h("")
        sys.stdout.write(json.dumps({"ok": False, "error": "internal error"})); sys.stdout.flush()

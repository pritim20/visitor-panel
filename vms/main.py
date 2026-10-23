"""
Visitor Management System (VMS)
================================
Two dashboards in one app:

  * Admin panel    - register visitors (name, company, phone, email, date of issue,
                     expiry date, issued by), generate a QR pass, email it to the
                     visitor + HR + Security, view full visitor history, settings.
  * Security panel - scan the QR (camera) or type the pass ID, log the visitor IN
                     and OUT (times are recorded automatically), record devices the
                     visitor carries (device name, model name, quantity), view history.

Run:
    pip install -r requirements.txt
    python main.py
Then open http://127.0.0.1:5000

Default logins (change them after first login via "Password"):
    admin    / admin123     (Admin panel + Security panel)
    security / security123  (Security panel only)
"""

import csv
import io
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
from datetime import date, datetime
from email.message import EmailMessage
from email.utils import make_msgid
from functools import wraps

import qrcode
from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   render_template_string, request, send_file, session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

# --------------------------------------------------------------------------- #
# Paths & app setup
# --------------------------------------------------------------------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("VMS_DB", os.path.join(BASE_DIR, "visitors.db"))
QR_DIR = os.path.join(BASE_DIR, "qr_codes")
os.makedirs(QR_DIR, exist_ok=True)


def load_secret_key():
    env = os.environ.get("VMS_SECRET_KEY")
    if env:
        return env
    path = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as fh:
        fh.write(key)
    return key


app = Flask(__name__)
app.secret_key = load_secret_key()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9\s\-()]{7,20}$")

DEFAULT_SETTINGS = {
    "company_name": os.environ.get("VMS_COMPANY", "My Company"),
    "hr_email": os.environ.get("VMS_HR_EMAIL", ""),
    "security_email": os.environ.get("VMS_SECURITY_EMAIL", ""),
    "smtp_host": os.environ.get("VMS_SMTP_HOST", "smtp.gmail.com"),
    "smtp_port": os.environ.get("VMS_SMTP_PORT", "587"),
    "smtp_user": os.environ.get("VMS_SMTP_USER", ""),
    "smtp_password": os.environ.get("VMS_SMTP_PASSWORD", ""),
    "smtp_sender": os.environ.get("VMS_SMTP_SENDER", ""),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'security')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS visitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pass_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    company TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    issue_date TEXT NOT NULL,
    expiry_date TEXT NOT NULL,
    issued_by TEXT NOT NULL,
    hr_email TEXT,
    security_email TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    email_status TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_id INTEGER NOT NULL REFERENCES visitors(id) ON DELETE CASCADE,
    check_in TEXT NOT NULL,
    check_out TEXT,
    checked_in_by TEXT,
    checked_out_by TEXT
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visit_id INTEGER NOT NULL REFERENCES visits(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    model_name TEXT,
    quantity INTEGER NOT NULL DEFAULT 1,
    added_by TEXT,
    added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_visits_visitor ON visits(visitor_id);
CREATE INDEX IF NOT EXISTS idx_visits_checkin ON visits(check_in);
CREATE INDEX IF NOT EXISTS idx_devices_visit ON devices(visit_id);
"""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def today_str():
    return date.today().isoformat()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    for key, value in DEFAULT_SETTINGS.items():
        con.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        for username, pwd, role in (("admin", "admin123", "admin"),
                                    ("security", "security123", "security")):
            con.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                        (username, generate_password_hash(pwd), role, now_str()))
    con.commit()
    con.close()


def get_settings():
    s = dict(DEFAULT_SETTINGS)
    for row in get_db().execute("SELECT key, value FROM settings"):
        s[row["key"]] = row["value"] or ""
    return s


def save_settings(values):
    db = get_db()
    for key, value in values.items():
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    db.commit()


def new_pass_id():
    db = get_db()
    while True:
        pid = "VIS-" + secrets.token_hex(4).upper()
        if not db.execute("SELECT 1 FROM visitors WHERE pass_id=?", (pid,)).fetchone():
            return pid


def qr_path(pass_id):
    return os.path.join(QR_DIR, f"{pass_id}.png")


def make_qr(pass_id):
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
                       box_size=10, border=4)
    qr.add_data(pass_id)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    path = qr_path(pass_id)
    img.save(path)
    return path


def pass_status(v):
    """valid / expired / not_yet_valid / revoked"""
    if v["revoked"]:
        return "revoked"
    today = today_str()
    if today < v["issue_date"]:
        return "not_yet_valid"
    if today > v["expiry_date"]:
        return "expired"
    return "valid"


def open_visit(visitor_id):
    return get_db().execute(
        "SELECT * FROM visits WHERE visitor_id=? AND check_out IS NULL ORDER BY id DESC LIMIT 1",
        (visitor_id,)).fetchone()


def find_visitor(pass_id):
    return get_db().execute("SELECT * FROM visitors WHERE UPPER(pass_id)=UPPER(?)",
                            (pass_id.strip(),)).fetchone()


def safe_next(default):
    nxt = request.form.get("next") or request.args.get("next") or ""
    return nxt if nxt.startswith("/") and not nxt.startswith("//") else default


def parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# Email
# --------------------------------------------------------------------------- #
def smtp_send(msg):
    s = get_settings()
    if not s["smtp_host"] or not s["smtp_user"] or not s["smtp_password"]:
        return False, "SMTP is not configured (Admin > Settings)."
    msg["From"] = s["smtp_sender"] or s["smtp_user"]
    try:
        port = int(s["smtp_port"] or 587)
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(s["smtp_host"], port, context=ctx, timeout=25) as srv:
                srv.login(s["smtp_user"], s["smtp_password"])
                srv.send_message(msg)
        else:
            with smtplib.SMTP(s["smtp_host"], port, timeout=25) as srv:
                srv.ehlo()
                srv.starttls(context=ctx)
                srv.ehlo()
                srv.login(s["smtp_user"], s["smtp_password"])
                srv.send_message(msg)
        return True, "sent"
    except Exception as exc:  # noqa: BLE001 - report any SMTP failure to the user
        return False, f"{type(exc).__name__}: {exc}"


def send_qr_email(v):
    recipients = []
    for addr in (v["email"], v["hr_email"], v["security_email"]):
        addr = (addr or "").strip()
        if addr and addr.lower() not in [r.lower() for r in recipients]:
            recipients.append(addr)
    if not recipients:
        return False, "No recipient email addresses."

    company = get_settings()["company_name"]
    path = qr_path(v["pass_id"])
    if not os.path.exists(path):
        make_qr(v["pass_id"])
    with open(path, "rb") as fh:
        png = fh.read()

    msg = EmailMessage()
    msg["Subject"] = f"Visitor Pass {v['pass_id']} - {v['name']} ({v['company']})"
    msg["To"] = ", ".join(recipients)
    text = (
        f"Visitor pass for {company}\n\n"
        f"Pass ID     : {v['pass_id']}\n"
        f"Visitor     : {v['name']}\n"
        f"Company     : {v['company']}\n"
        f"Phone       : {v['phone']}\n"
        f"Valid from  : {v['issue_date']}\n"
        f"Valid until : {v['expiry_date']}\n"
        f"Issued by   : {v['issued_by']}\n\n"
        "Show the attached QR code at the security desk to log in and log out.\n"
        f"A downloadable copy is attached as {v['pass_id']}.png."
    )
    msg.set_content(text)
    cid = make_msgid(domain="vms.local")
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px">
      <h2 style="margin:0 0 4px">Visitor Pass</h2>
      <p style="color:#555;margin:0 0 16px">{company}</p>
      <table style="border-collapse:collapse;font-size:14px">
        <tr><td style="padding:4px 12px 4px 0;color:#666">Pass ID</td><td><b>{v['pass_id']}</b></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#666">Visitor</td><td>{v['name']}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#666">Company</td><td>{v['company']}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#666">Phone</td><td>{v['phone']}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#666">Valid from</td><td>{v['issue_date']}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#666">Valid until</td><td>{v['expiry_date']}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#666">Issued by</td><td>{v['issued_by']}</td></tr>
      </table>
      <p><img src="cid:{cid[1:-1]}" alt="QR code" width="220" height="220"></p>
      <p style="font-size:13px;color:#555">Show this QR code at the security desk to log in and log out.</p>
      <p style="font-size:13px;color:#555">A downloadable copy is attached to this email as <b>{v['pass_id']}.png</b>.</p>
    </div>"""
    msg.add_alternative(html, subtype="html")
    msg.get_payload()[1].add_related(png, maintype="image", subtype="png", cid=cid)
    msg.add_attachment(png, maintype="image", subtype="png", filename=f"{v['pass_id']}.png")
    ok, info = smtp_send(msg)
    return ok, (f"Emailed to {', '.join(recipients)}" if ok else info)


# --------------------------------------------------------------------------- #
# Auth & CSRF
# --------------------------------------------------------------------------- #
def get_identity(role):
    """The admin/security login for this browser, kept independently per panel so both
    panels can be signed in at once in the same browser (e.g. one per tab)."""
    return session.get("identities", {}).get(role)


def set_identity(role, user):
    identities = dict(session.get("identities", {}))
    identities[role] = {"id": user["id"], "username": user["username"]}
    session["identities"] = identities


def clear_identity(role):
    identities = dict(session.get("identities", {}))
    identities.pop(role, None)
    session["identities"] = identities


def login_required(role=None):
    """role=None: any signed-in identity (used only where the page doesn't render
    panel-specific nav); 'admin'/'security': that panel's own identity."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if role:
                identity = get_identity(role)
                if not identity:
                    login_endpoint = "security_login" if role == "security" else "login"
                    return redirect(url_for(login_endpoint, next=request.path))
                active_role = role
            else:
                identities = session.get("identities", {})
                active_role = "admin" if identities.get("admin") else "security" if identities.get("security") else None
                if not active_role:
                    return redirect(url_for("login", next=request.path))
                identity = identities[active_role]
            g.role, g.user_id, g.username = active_role, identity["id"], identity["username"]
            return fn(*args, **kwargs)
        return wrapper
    return deco


def panel_required(fn):
    """For routes shared by both panels (history, change password, logout) where the URL
    itself names which panel's identity to use, so two tabs - one per panel - never collide."""
    @wraps(fn)
    def wrapper(panel, *args, **kwargs):
        if panel not in ("admin", "security"):
            abort(404)
        identity = get_identity(panel)
        if not identity:
            login_endpoint = "security_login" if panel == "security" else "login"
            return redirect(url_for(login_endpoint, next=request.path))
        g.role, g.user_id, g.username = panel, identity["id"], identity["username"]
        return fn(panel, *args, **kwargs)
    return wrapper


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("_csrf")
        if not token or token != request.form.get("_csrf"):
            abort(400, description="Form expired. Go back, reload the page and try again.")


# --------------------------------------------------------------------------- #
# Template helpers
# --------------------------------------------------------------------------- #
def fmt_dt(value, fmt=None):
    if not value:
        return "-"
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime(fmt or "%d %b %Y, %I:%M %p")
    except ValueError:
        return value


def fmt_date(value):
    d = parse_date(value)
    return d.strftime("%d %b %Y") if d else (value or "-")


def duration(check_in, check_out=None):
    if not check_in:
        return "-"
    start = datetime.strptime(check_in, "%Y-%m-%d %H:%M:%S")
    end = datetime.strptime(check_out, "%Y-%m-%d %H:%M:%S") if check_out else datetime.now()
    mins = max(0, int((end - start).total_seconds() // 60))
    h, m = divmod(mins, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m"


app.jinja_env.globals.update(csrf_token=csrf_token, pass_status=pass_status, today=today_str)
app.jinja_env.filters.update(dt=fmt_dt, d=fmt_date)
app.jinja_env.globals["duration"] = duration


@app.context_processor
def inject_company():
    try:
        return {"company_name": get_settings()["company_name"]}
    except sqlite3.Error:
        return {"company_name": "VMS"}


# --------------------------------------------------------------------------- #
# Templates (kept inside main.py so the app is a single file)
# --------------------------------------------------------------------------- #
TEMPLATES = {}

TEMPLATES["base.html"] = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}Visitor Management{% endblock %} · {{ company_name }}</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--ink:#1d2430;--muted:#667085;--line:#e3e7ee;--pri:#1f5eff;--pri-d:#1848c7;--pri-bg:#e8eeff;
--ok:#12805c;--ok-bg:#e6f6ef;--warn:#9a6200;--warn-bg:#fff4dc;--bad:#b42318;--bad-bg:#fdecea;--sec:#0f766e}
body[data-panel="security"]{--pri:#0f766e;--pri-d:#0b5c56;--pri-bg:#e3f6f3}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
a{color:var(--pri);text-decoration:none}a:hover{text-decoration:underline}
.topbar{display:flex;flex-wrap:wrap;gap:8px 20px;align-items:center;justify-content:space-between;background:#101828;color:#fff;padding:12px 20px;border-bottom:3px solid var(--pri)}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.2px}.brand small{font-weight:400;opacity:.7;margin-left:2px}
.panel-tag{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;background:var(--pri);color:#fff}
.topbar nav{display:flex;flex-wrap:wrap;gap:4px}.topbar nav a{color:#d0d5dd;padding:6px 10px;border-radius:6px}
.topbar nav a:hover,.topbar nav a.on{background:#ffffff1a;color:#fff;text-decoration:none}
main{max-width:1200px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:0 0 12px}.sub{color:var(--muted);margin:0 0 18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:18px}
.grid{display:grid;gap:18px}.g2{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:18px}
.stat{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--pri);border-radius:10px;padding:14px 16px;
display:block;color:inherit;text-decoration:none;transition:box-shadow .15s,transform .15s}
.stat b{display:block;font-size:26px;color:var(--pri)}.stat span{color:var(--muted);font-size:13px}
a.stat:hover{box-shadow:0 4px 14px rgba(16,24,40,.1);transform:translateY(-1px);text-decoration:none}
form .row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:12px}
label{display:block;font-size:13px;font-weight:600;margin-bottom:4px;color:#344054}
input,select{width:100%;padding:9px 10px;border:1px solid #cfd4dc;border-radius:7px;font:inherit;background:#fff}
input:focus,select:focus{outline:2px solid #1f5eff40;border-color:var(--pri)}
.btn{display:inline-block;border:0;border-radius:7px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer;background:var(--pri);color:#fff}
.btn:hover{background:var(--pri-d);text-decoration:none}.btn.sm{padding:5px 10px;font-size:13px}
.btn.ok{background:var(--ok)}.btn.bad{background:var(--bad)}.btn.ghost{background:#eef1f6;color:var(--ink)}
.btn.teal{background:var(--sec)}.btn.teal:hover{background:#0b5c56}
.btn.big{padding:14px 26px;font-size:17px}.btn:disabled{opacity:.45;cursor:not-allowed}
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:40px;height:40px;border:0;border-radius:7px;cursor:pointer;background:var(--pri);color:#fff}
.icon-btn:hover{background:var(--pri-d)}.icon-btn.ok{background:var(--ok)}.icon-btn.bad{background:var(--bad)}
.icon-btn.ghost{background:#eef1f6;color:var(--ink)}.icon-btn svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted);background:#fafbfc}
.tbl{overflow-x:auto}.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600}
.b-ok{background:var(--ok-bg);color:var(--ok)}.b-warn{background:var(--warn-bg);color:var(--warn)}
.b-bad{background:var(--bad-bg);color:var(--bad)}.b-in{background:#e0f2fe;color:#075985}.b-muted{background:#eef1f6;color:var(--muted)}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:12px;border:1px solid}
.flash.success{background:var(--ok-bg);color:var(--ok);border-color:#b7e4cf}
.flash.error{background:var(--bad-bg);color:var(--bad);border-color:#f5c2bd}
.flash.info{background:#eef4ff;color:#1848c7;border-color:#c7d7fe}
.muted{color:var(--muted)}.right{text-align:right}.inline{display:inline}
.dl{display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:14px}.dl dt{color:var(--muted)}.dl dd{margin:0}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:end;margin-bottom:12px}.toolbar>div{min-width:150px}
.pwd-wrap{position:relative}.pwd-wrap input{padding-right:38px}
.pwd-toggle{position:absolute;right:4px;top:50%;transform:translateY(-50%);background:none;border:0;cursor:pointer;padding:6px;color:var(--muted);display:flex}
.pwd-toggle:hover{color:var(--ink)}.pwd-toggle svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.chk{display:flex;gap:8px;align-items:center;font-weight:500}.chk input{width:auto}
@media (max-width:600px){.dl{grid-template-columns:1fr}.dl dt{margin-top:6px}}
</style>{% block head %}{% endblock %}</head>
<body data-panel="{% block panel %}{{ g.get('role') or '' }}{% endblock %}">
{% if g.get('role') %}
<header class="topbar">
  <div class="brand">{{ company_name }}<small>Visitor Management</small>
    <span class="panel-tag">{{ 'Admin' if g.role == 'admin' else 'Security' }}</span>
  </div>
  <nav>
    {% if g.role == 'admin' %}
      <a href="{{ url_for('admin_dashboard') }}" class="{{ 'on' if request.endpoint and request.endpoint.startswith('admin') }}">Admin Panel</a>
      <a href="{{ url_for('settings_page') }}" class="{{ 'on' if request.endpoint == 'settings_page' }}">Settings</a>
    {% else %}
      <a href="{{ url_for('security_dashboard') }}" class="{{ 'on' if request.endpoint and request.endpoint.startswith('security') }}">Security Panel</a>
    {% endif %}
    <a href="{{ url_for('history', panel=g.role) }}" class="{{ 'on' if request.endpoint == 'history' }}">History</a>
    <a href="{{ url_for('change_password', panel=g.role) }}">Password</a>
    <a href="{{ url_for('logout', panel=g.role) }}">Logout ({{ g.username }})</a>
  </nav>
</header>
{% endif %}
<main>
{% with msgs = get_flashed_messages(with_categories=true) %}
  {% for cat, m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}
{% endwith %}
{% block content %}{% endblock %}
</main>
{% block scripts %}{% endblock %}
<script>
function togglePwd(btn){
  var inp = btn.parentElement.querySelector('input');
  if(!inp) return;
  var show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.querySelector('.i-open').style.display = show ? 'none' : '';
  btn.querySelector('.i-closed').style.display = show ? '' : 'none';
  btn.title = btn.ariaLabel = show ? 'Hide password' : 'Show password';
}
</script>
</body></html>
"""

TEMPLATES["macros.html"] = r"""
{% macro badge(v) -%}
  {%- set st = pass_status(v) -%}
  {%- if st == 'valid' -%}<span class="badge b-ok">Valid</span>
  {%- elif st == 'expired' -%}<span class="badge b-bad">Expired</span>
  {%- elif st == 'revoked' -%}<span class="badge b-bad">Revoked</span>
  {%- else -%}<span class="badge b-warn">Not yet valid</span>{%- endif -%}
{%- endmacro %}
{% macro csrf() -%}<input type="hidden" name="_csrf" value="{{ csrf_token() }}">{%- endmacro %}
{% macro pwd_toggle() -%}
<button type="button" class="pwd-toggle" onclick="togglePwd(this)" title="Show password" aria-label="Show password">
  <svg class="i-open" viewBox="0 0 24 24"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
  <svg class="i-closed" style="display:none" viewBox="0 0 24 24"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/><path d="M3 3l18 18"/></svg>
</button>
{%- endmacro %}
"""

TEMPLATES["home.html"] = r"""{% extends "base.html" %}
{% block title %}Welcome{% endblock %}
{% block content %}
<div style="max-width:420px;margin:60px auto;text-align:center">
  <h1>{{ company_name }}</h1><p class="sub">Visitor Management System</p>
  <div class="card" style="display:flex;flex-direction:column;gap:12px;margin-top:20px">
    {% if identities.admin %}
      <a class="btn" href="{{ url_for('admin_dashboard') }}">Go to Admin Panel ({{ identities.admin.username }})</a>
    {% else %}
      <a class="btn" href="{{ url_for('login') }}">Admin Login</a>
    {% endif %}
    {% if identities.security %}
      <a class="btn teal" href="{{ url_for('security_dashboard') }}">Go to Security Panel ({{ identities.security.username }})</a>
    {% else %}
      <a class="btn teal" href="{{ url_for('security_login') }}">Security Login</a>
    {% endif %}
  </div>
  <p class="muted" style="font-size:13px;margin-top:16px">Both panels can be signed in at the same time in this browser — open each in its own tab.</p>
</div>
{% endblock %}
"""

TEMPLATES["login.html"] = r"""{% extends "base.html" %}{% from "macros.html" import csrf, pwd_toggle %}
{% block title %}Admin Login{% endblock %}
{% block panel %}admin{% endblock %}
{% block content %}
<div style="max-width:380px;margin:60px auto">
  <div class="card" style="border-top:3px solid var(--pri)">
    <h1>{{ company_name }}</h1><p class="sub">Admin — sign in</p>
    <form method="post">{{ csrf() }}
      <input type="hidden" name="next" value="{{ request.args.get('next','') }}">
      <div style="margin-bottom:12px"><label>Username</label><input name="username" required autofocus></div>
      <div style="margin-bottom:16px" class="pwd-wrap"><label>Password</label><input name="password" type="password" required>{{ pwd_toggle() }}</div>
      <button class="btn" style="width:100%">Sign in</button>
    </form>
  </div>
  <p class="muted" style="font-size:13px;text-align:center">Not an admin? <a href="{{ url_for('security_login') }}">Security login</a></p>
</div>
{% endblock %}
"""

TEMPLATES["security_login.html"] = r"""{% extends "base.html" %}{% from "macros.html" import csrf, pwd_toggle %}
{% block title %}Security Login{% endblock %}
{% block panel %}security{% endblock %}
{% block content %}
<div style="max-width:380px;margin:60px auto">
  <div class="card" style="border-top:3px solid var(--pri)">
    <h1>{{ company_name }}</h1><p class="sub">Security — sign in</p>
    <form method="post">{{ csrf() }}
      <input type="hidden" name="next" value="{{ request.args.get('next','') }}">
      <div style="margin-bottom:12px"><label>Username</label><input name="username" required autofocus></div>
      <div style="margin-bottom:16px" class="pwd-wrap"><label>Password</label><input name="password" type="password" required>{{ pwd_toggle() }}</div>
      <button class="btn" style="width:100%">Sign in</button>
    </form>
  </div>
  <p class="muted" style="font-size:13px;text-align:center">Not security staff? <a href="{{ url_for('login') }}">Admin login</a></p>
</div>
{% endblock %}
"""

TEMPLATES["change_password.html"] = r"""{% extends "base.html" %}{% from "macros.html" import csrf, pwd_toggle %}
{% block title %}Change password{% endblock %}
{% block content %}
<div class="card" style="max-width:420px">
  <h2>Change password for {{ g.username }}</h2>
  <form method="post">{{ csrf() }}
    <div style="margin-bottom:10px" class="pwd-wrap"><label>Current password</label><input type="password" name="current" required>{{ pwd_toggle() }}</div>
    <div style="margin-bottom:10px" class="pwd-wrap"><label>New password (min 6 chars)</label><input type="password" name="new" minlength="6" required>{{ pwd_toggle() }}</div>
    <div style="margin-bottom:14px" class="pwd-wrap"><label>Confirm new password</label><input type="password" name="confirm" minlength="6" required>{{ pwd_toggle() }}</div>
    <button class="btn">Update password</button>
  </form>
</div>
{% endblock %}
"""

TEMPLATES["admin_dashboard.html"] = r"""{% extends "base.html" %}{% from "macros.html" import csrf %}
{% block title %}Admin Panel{% endblock %}
{% block content %}
<div class="toolbar" style="justify-content:space-between">
  <div><h1 style="margin-bottom:0">Admin Panel</h1><p class="sub" style="margin-bottom:0">Register visitors, issue QR passes and review visitor history.</p></div>
  <a class="btn ghost" href="{{ url_for('admin_visitors_list') }}">View all visitors</a>
</div>
<div class="stats">
  <a class="stat" href="{{ url_for('admin_visitors_list') }}"><b>{{ stats.total }}</b><span>Registered visitors</span></a>
  <a class="stat" href="{{ url_for('admin_visitors_list') }}"><b>{{ stats.active }}</b><span>Passes valid today</span></a>
  <a class="stat" href="{{ url_for('admin_visitors_list') }}"><b>{{ stats.inside }}</b><span>Inside right now</span></a>
  <a class="stat" href="{{ url_for('history', panel='admin', **{'from': today_date, 'to': today_date}) }}"><b>{{ stats.today }}</b><span>Log-ins today</span></a>
</div>

<div class="card">
  <h2>New visitor pass</h2>
  <form method="post" action="{{ url_for('create_visitor') }}">{{ csrf() }}
    <div class="row">
      <div><label>Visitor name *</label><input name="name" value="{{ form.name }}" required></div>
      <div><label>Company name *</label><input name="company" value="{{ form.company }}" required></div>
      <div><label>Phone no. *</label><input name="phone" value="{{ form.phone }}" placeholder="+91 98765 43210" required></div>
      <div><label>Visitor email *</label><input type="email" name="email" value="{{ form.email }}" required></div>
    </div>
    <div class="row">
      <div><label>Date of issue *</label><input type="date" name="issue_date" value="{{ form.issue_date or today() }}" required></div>
      <div><label>Expiry date *</label><input type="date" name="expiry_date" value="{{ form.expiry_date or today() }}" required></div>
      <div><label>Issued by *</label><input name="issued_by" value="{{ form.issued_by or g.username }}" required></div>
    </div>
    <div class="row">
      <div><label>HR email (QR copy)</label><input type="email" name="hr_email" value="{{ form.hr_email if form.hr_email is not none else settings.hr_email }}"></div>
      <div><label>Security email (QR copy)</label><input type="email" name="security_email" value="{{ form.security_email if form.security_email is not none else settings.security_email }}"></div>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:16px;align-items:center">
      <label class="chk"><input type="checkbox" name="send_email" value="1" checked> Email QR to visitor, HR and Security</label>
      <button class="btn">Create pass &amp; generate QR</button>
    </div>
  </form>
</div>
{% endblock %}
"""

TEMPLATES["admin_visitors_list.html"] = r"""{% extends "base.html" %}{% from "macros.html" import badge, csrf %}
{% block title %}Visitors{% endblock %}
{% block content %}
<p><a href="{{ url_for('admin_dashboard') }}">← Admin Panel</a></p>
<div class="card" id="visitor-list">
  <div class="toolbar" style="justify-content:space-between">
    <h2 style="margin:0">Visitors ({{ visitors|length }})</h2>
    <form method="get" class="toolbar" style="margin:0">
      <div><input name="q" value="{{ q }}" placeholder="Search name, company, phone, pass ID"></div>
      <button class="btn ghost">Search</button>
    </form>
  </div>
  <div class="tbl"><table>
    <tr><th>Pass ID</th><th>Visitor</th><th>Company</th><th>Phone</th><th>Valid From</th><th>Valid until</th><th>Issued by</th><th>Status</th><th>Last visit</th><th></th></tr>
    {% for v in visitors %}
    <tr>
      <td class="mono">{{ v.pass_id }}</td>
      <td>{{ v.name }}<div class="muted" style="font-size:12px">{{ v.email }}</div></td>
      <td>{{ v.company }}</td><td>{{ v.phone }}</td>
      <td>{{ v.issue_date|d }}</td><td>{{ v.expiry_date|d }}</td>
      <td>{{ v.issued_by }}</td>
      <td>{{ badge(v) }}{% if v.inside %} <span class="badge b-in">Inside</span>{% endif %}</td>
      <td>{{ v.last_visit|dt }}</td>
      <td><a class="icon-btn ghost" style="width:32px;height:32px" href="{{ url_for('admin_visitor', vid=v.id) }}" title="View visitor" aria-label="View visitor">
        <svg viewBox="0 0 24 24"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>
      </a></td>
    </tr>
    {% else %}<tr><td colspan="10" class="muted">No visitors yet.</td></tr>{% endfor %}
  </table></div>
</div>
{% endblock %}
"""

TEMPLATES["admin_visitor.html"] = r"""{% extends "base.html" %}{% from "macros.html" import badge, csrf %}
{% block title %}{{ v.name }}{% endblock %}
{% block content %}
<p><a href="{{ url_for('admin_dashboard') }}">← Admin Panel</a></p>
<h1>{{ v.name }} {{ badge(v) }}{% if current %} <span class="badge b-in">Inside since {{ current.check_in|dt }}</span>{% endif %}</h1>
<p class="sub">{{ v.company }} · Pass <span class="mono">{{ v.pass_id }}</span></p>
<div class="grid g2">
  <div class="card">
    <h2>Pass details</h2>
    <dl class="dl">
      <dt>Visitor</dt><dd>{{ v.name }}</dd>
      <dt>Company</dt><dd>{{ v.company }}</dd>
      <dt>Phone</dt><dd>{{ v.phone }}</dd>
      <dt>Email</dt><dd>{{ v.email }}</dd>
      <dt>Date of issue</dt><dd>{{ v.issue_date|d }}</dd>
      <dt>Expiry date</dt><dd>{{ v.expiry_date|d }}</dd>
      <dt>Issued by</dt><dd>{{ v.issued_by }}</dd>
      <dt>HR email</dt><dd>{{ v.hr_email or '-' }}</dd>
      <dt>Security email</dt><dd>{{ v.security_email or '-' }}</dd>
      <dt>Email status</dt><dd>{{ v.email_status or 'Not sent' }}</dd>
      <dt>Created</dt><dd>{{ v.created_at|dt }} by {{ v.created_by }}</dd>
    </dl>
  </div>
  <div class="card" style="text-align:center">
    <h2>QR pass</h2>
    <img src="{{ url_for('qr_image', pass_id=v.pass_id) }}" alt="QR" width="220" height="220" style="border:1px solid var(--line);border-radius:8px">
    <p class="mono">{{ v.pass_id }}</p>
    <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
      <a class="icon-btn ghost" href="{{ url_for('qr_image', pass_id=v.pass_id, download=1) }}" title="Download QR" aria-label="Download QR">
        <svg viewBox="0 0 24 24"><path d="M12 3v12m0 0-5-5m5 5 5-5M4 19h16"/></svg>
      </a>
      <form method="post" action="{{ url_for('resend_email', vid=v.id) }}" class="inline">{{ csrf() }}
        <button class="icon-btn" title="Resend email" aria-label="Resend email">
          <svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>
        </button>
      </form>
      <form method="post" action="{{ url_for('toggle_revoke', vid=v.id) }}" class="inline">{{ csrf() }}
        {% if v.revoked %}
        <button class="icon-btn ok" title="Restore pass" aria-label="Restore pass">
          <svg viewBox="0 0 24 24"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.5-2"/></svg>
        </button>
        {% else %}
        <button class="icon-btn bad" title="Revoke pass" aria-label="Revoke pass" onclick="return confirm('Revoke this pass? The visitor will not be able to log in.')">
          <svg viewBox="0 0 24 24"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
        </button>
        {% endif %}
      </form>
      <form method="post" action="{{ url_for('delete_visitor', vid=v.id) }}" class="inline">{{ csrf() }}
        <button class="icon-btn bad" title="Delete visitor" aria-label="Delete visitor" onclick="return confirm('Permanently delete {{ v.name }} and all their visit history? This cannot be undone.')">
          <svg viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
        </button>
      </form>
    </div>
  </div>
</div>

{% endblock %}
"""

TEMPLATES["history.html"] = r"""{% extends "base.html" %}
{% block title %}Visitor history{% endblock %}
{% block content %}
<h1>Visitor history</h1><p class="sub">Every log-in / log-out with devices carried.</p>
<div class="card">
  <form method="get" class="toolbar">
    <div style="flex:1;min-width:220px"><label>Search</label><input name="q" value="{{ q }}" placeholder="Name, company, phone, pass ID"></div>
    <div><label>From</label><input type="date" name="from" value="{{ dfrom }}"></div>
    <div><label>To</label><input type="date" name="to" value="{{ dto }}"></div>
    <div><button class="btn">Filter</button></div>
    <div><a class="btn ghost" href="{{ url_for('history_csv', panel=g.role, q=q, **{'from': dfrom, 'to': dto}) }}">Export CSV</a></div>
  </form>
  <div class="tbl"><table>
    <tr><th>Pass ID</th><th>Visitor</th><th>Company</th><th>Phone</th><th>Date</th><th>Log in time</th><th>Log out time</th><th>Duration</th><th>Devices</th><th>Security</th></tr>
    {% for r in rows %}
    <tr>
      <td class="mono">{{ r.pass_id }}</td><td>{{ r.name }}</td><td>{{ r.company }}</td><td>{{ r.phone }}</td>
      <td>{{ r.check_in|dt('%d-%m-%y')}}</td><td>{{ r.check_in|dt('%I:%M %p') }}</td>
      <td>{% if r.check_out %}{{ r.check_out|dt('%I:%M %p')}}{% else %}<span class="badge b-in">Inside</span>{% endif %}</td>
      <td>{{ duration(r.check_in, r.check_out) }}</td>
      <td>{{ r.devices or '-' }}</td>
      <td>In: {{ r.checked_in_by or '-' }}<br>Out: {{ r.checked_out_by or '-' }}</td>
    </tr>
    {% else %}<tr><td colspan="10" class="muted">No records found.</td></tr>{% endfor %}
  </table></div>
  {% if rows|length >= 1000 %}<p class="muted">Showing the latest 1000 records — narrow the filter or export CSV.</p>{% endif %}
</div>
{% endblock %}
"""

TEMPLATES["settings.html"] = r"""{% extends "base.html" %}{% from "macros.html" import csrf, pwd_toggle %}
{% block title %}Settings{% endblock %}
{% block content %}
<h1>Settings</h1><p class="sub">Email delivery, default recipients and user accounts.</p>
<div class="grid g2">
<div class="card">
  <h2>General &amp; email</h2>
  <form method="post">{{ csrf() }}
    <div style="margin-bottom:10px"><label>Company name</label><input name="company_name" value="{{ s.company_name }}"></div>
    <div class="row">
      <div><label>Default HR email</label><input type="email" name="hr_email" value="{{ s.hr_email }}"></div>
      <div><label>Default Security email</label><input type="email" name="security_email" value="{{ s.security_email }}"></div>
    </div>
    <div class="row">
      <div><label>SMTP host</label><input name="smtp_host" value="{{ s.smtp_host }}" placeholder="smtp.gmail.com"></div>
      <div><label>SMTP port</label><input name="smtp_port" value="{{ s.smtp_port }}" placeholder="587 (TLS) or 465 (SSL)"></div>
    </div>
    <div class="row">
      <div><label>SMTP username</label><input name="smtp_user" value="{{ s.smtp_user }}" autocomplete="off"></div>
      <div class="pwd-wrap"><label>SMTP password {% if s.smtp_password %}(saved){% endif %}</label><input type="password" name="smtp_password" placeholder="Leave blank to keep" autocomplete="new-password">{{ pwd_toggle() }}</div>
    </div>
    <div style="margin-bottom:14px"><label>Sender address (optional)</label><input name="smtp_sender" value="{{ s.smtp_sender }}" placeholder="Defaults to SMTP username"></div>
    <button class="btn">Save settings</button>
  </form>
  <hr style="border:0;border-top:1px solid var(--line);margin:18px 0">
  <form method="post" action="{{ url_for('test_email') }}" class="toolbar">{{ csrf() }}
    <div style="flex:1"><label>Send a test email to</label><input type="email" name="to" value="{{ s.security_email or s.hr_email }}" required></div>
    <div><button class="btn ghost">Send test</button></div>
  </form>
  <p class="muted" style="font-size:13px">Gmail: turn on 2-step verification and use an <b>App Password</b> (not your normal password), host smtp.gmail.com, port 587.</p>
</div>
<div class="card">
  <h2>User accounts</h2>
  <div class="tbl"><table>
    <tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr>
    {% for u in users %}
    <tr><td>{{ u.username }}</td><td>{{ u.role|capitalize }}</td><td>{{ u.created_at|dt }}</td>
      <td class="right">{% if u.id != g.user_id %}
        <form method="post" action="{{ url_for('delete_user', uid=u.id) }}" class="inline">{{ csrf() }}
          <button class="btn sm bad" onclick="return confirm('Delete user {{ u.username }}?')">Delete</button></form>{% endif %}</td></tr>
    {% endfor %}
  </table></div>
  <h2 style="margin-top:18px">Add user</h2>
  <form method="post" action="{{ url_for('add_user') }}">{{ csrf() }}
    <div class="row">
      <div><label>Username</label><input name="username" required></div>
      <div class="pwd-wrap"><label>Password (min 6)</label><input type="password" name="password" minlength="6" required>{{ pwd_toggle() }}</div>
      <div><label>Role</label><select name="role"><option value="security">Security</option><option value="admin">Admin</option></select></div>
    </div>
    <button class="btn">Add user</button>
  </form>
</div>
</div>
{% endblock %}
"""

TEMPLATES["security_dashboard.html"] = r"""{% extends "base.html" %}{% from "macros.html" import csrf %}
{% block title %}Security Panel{% endblock %}
{% block head %}<script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>{% endblock %}
{% block content %}
<h1>Security Panel</h1><p class="sub">Scan the visitor's QR pass to log them in or out.</p>
<div class="stats">
  <a class="stat" href="#inside-list"><b>{{ inside|length }}</b><span>Inside right now</span></a>
  <a class="stat" href="#today-activity"><b>{{ today_ins }}</b><span>Log-ins today</span></a>
  <a class="stat" href="#today-activity"><b>{{ today_outs }}</b><span>Log-outs today</span></a>
</div>
<div class="grid g2">
  <div class="card">
    <h2>Scan QR pass</h2>
    <div id="reader" style="width:100%;max-width:420px;margin:0 auto"></div>
    <p id="scanmsg" class="muted" style="text-align:center;font-size:13px"></p>
    <div style="text-align:center"><button type="button" class="btn" id="scanbtn">Start camera</button></div>
  </div>
  <div class="card">
    <h2>Enter pass manually</h2>
    <form method="post" action="{{ url_for('security_lookup') }}">{{ csrf() }}
      <div style="margin-bottom:12px"><label>Pass ID or phone number</label><input name="code" placeholder="VIS-XXXXXXXX" autofocus required></div>
      <button class="btn">Find visitor</button>
    </form>
    <p class="muted" style="font-size:13px;margin-top:14px">A USB/Bluetooth QR scanner also works here: click the box and scan — it types the pass ID and presses Enter.</p>
  </div>
</div>

<div class="card" id="inside-list">
  <h2>Currently inside ({{ inside|length }})</h2>
  <div class="tbl"><table>
    <tr><th>Visitor</th><th>Company</th><th>Phone</th><th>Logged in</th><th>Time inside</th><th>Devices</th><th></th></tr>
    {% for r in inside %}
    <tr>
      <td>{{ r.name }}<div class="mono muted">{{ r.pass_id }}</div></td><td>{{ r.company }}</td><td>{{ r.phone }}</td>
      <td>{{ r.check_in|dt }}</td><td>{{ duration(r.check_in) }}</td><td>{{ r.devices or '-' }}</td>
      <td class="right" style="white-space:nowrap">
        <a class="btn sm ghost" href="{{ url_for('security_visitor', pass_id=r.pass_id) }}">Open</a>
        <form method="post" action="{{ url_for('checkout', pass_id=r.pass_id) }}" class="inline">{{ csrf() }}
          <input type="hidden" name="next" value="{{ url_for('security_dashboard') }}">
          <button class="btn sm bad">Log out</button></form>
      </td>
    </tr>
    {% else %}<tr><td colspan="7" class="muted">Nobody is inside.</td></tr>{% endfor %}
  </table></div>
</div>

{% endblock %}
{% block scripts %}
<script>
(function(){
  var btn = document.getElementById('scanbtn'), msg = document.getElementById('scanmsg'), scanner = null, running = false;
  var base = "{{ url_for('scan_visitor', pass_id='__ID__') }}";
  function stop(){ if(scanner && running){ scanner.stop().catch(function(){}); } running=false; btn.textContent='Start camera'; }
  btn.addEventListener('click', function(){
    if(running){ stop(); return; }
    if(typeof Html5Qrcode === 'undefined'){ msg.textContent='Scanner library failed to load (no internet?). Use manual entry.'; return; }
    scanner = scanner || new Html5Qrcode('reader');
    msg.textContent='Point the camera at the QR code…';
    scanner.start({facingMode:'environment'}, {fps:10, qrbox:{width:230,height:230}}, function(text){
      stop(); msg.textContent='Found ' + text + ' — opening…';
      window.location = base.replace('__ID__', encodeURIComponent(text.trim()));
    }, function(){}).then(function(){ running=true; btn.textContent='Stop camera'; })
    .catch(function(err){ msg.textContent='Camera unavailable: ' + err + '. Camera needs https or localhost.'; });
  });
})();
</script>
{% endblock %}
"""

TEMPLATES["security_visitor.html"] = r"""{% extends "base.html" %}{% from "macros.html" import badge, csrf %}
{% block title %}{{ v.name }}{% endblock %}
{% block content %}
<p><a href="{{ url_for('security_dashboard') }}">← Security Panel</a></p>
{% set st = pass_status(v) %}
<div class="card">
  <div style="display:flex;flex-wrap:wrap;gap:18px;justify-content:space-between;align-items:center">
    <div>
      <h1>{{ v.name }} {{ badge(v) }}</h1>
      <p class="sub" style="margin:0">{{ v.company }} · {{ v.phone }} · Pass <span class="mono">{{ v.pass_id }}</span></p>
      <p class="muted" style="margin:6px 0 0">Valid {{ v.issue_date|d }} → {{ v.expiry_date|d }} · Issued by {{ v.issued_by }}</p>
    </div>
    <div style="text-align:right">
      {% if current %}
        <p style="margin:0 0 8px"><span class="badge b-in">Inside since {{ current.check_in|dt }} ({{ duration(current.check_in) }})</span></p>
        <form method="post" action="{{ url_for('checkout', pass_id=v.pass_id) }}">{{ csrf() }}
          <button class="btn bad big">Log OUT</button></form>
      {% else %}
        <form method="post" action="{{ url_for('checkin', pass_id=v.pass_id) }}">{{ csrf() }}
          <button class="btn ok big" {% if st != 'valid' %}disabled{% endif %}>Log IN</button></form>
        {% if st != 'valid' %}<p class="badge b-bad" style="margin-top:8px">
          {% if st == 'expired' %}Pass expired on {{ v.expiry_date|d }}{% elif st == 'revoked' %}Pass revoked by admin{% else %}Pass valid from {{ v.issue_date|d }}{% endif %}</p>{% endif %}
      {% endif %}
    </div>
  </div>
</div>

{% if current %}
<div class="card">
  <h2>Devices carried on this visit</h2>
  <div class="tbl"><table>
    <tr><th>Device name</th><th>Model name</th><th>Quantity</th><th>Added</th><th></th></tr>
    {% for d in cur_devices %}
    <tr><td>{{ d.device_name }}</td><td>{{ d.model_name or '-' }}</td><td>{{ d.quantity }}</td><td>{{ d.added_at|dt }} · {{ d.added_by }}</td>
      <td class="right"><form method="post" action="{{ url_for('delete_device', did=d.id) }}" class="inline">{{ csrf() }}
        <button class="btn sm ghost" onclick="return confirm('Remove this device?')">Remove</button></form></td></tr>
    {% else %}<tr><td colspan="5" class="muted">No devices recorded.</td></tr>{% endfor %}
  </table></div>
  <form method="post" action="{{ url_for('add_device', pass_id=v.pass_id) }}" style="margin-top:14px">{{ csrf() }}
    <div class="row">
      <div><label>Device name *</label><input name="device_name" placeholder="Laptop" list="devlist" required></div>
      <div><label>Model name</label><input name="model_name" placeholder="Dell Latitude 5440"></div>
      <div><label>Quantity *</label><input type="number" name="quantity" value="1" min="1" max="999" required></div>
    </div>
    <datalist id="devlist"><option>Laptop</option><option>Mobile phone</option><option>Tablet</option><option>Camera</option>
      <option>Pen drive</option><option>External hard disk</option><option>Charger</option><option>Tools</option></datalist>
    <button class="btn">Add device</button>
  </form>
</div>
{% else %}
<p class="muted">Log the visitor in to record the devices they are carrying.</p>
{% endif %}

<div class="card">
  <h2>Previous visits</h2>
  <div class="tbl"><table>
    <tr><th>Log in</th><th>Log out</th><th>Duration</th><th>Devices</th></tr>
    {% for vs in past %}
    <tr><td>{{ vs.check_in|dt }}</td><td>{{ vs.check_out|dt }}</td><td>{{ duration(vs.check_in, vs.check_out) }}</td><td>{{ vs.devices or '-' }}</td></tr>
    {% else %}<tr><td colspan="4" class="muted">No previous visits.</td></tr>{% endfor %}
  </table></div>
</div>
{% endblock %}
"""

app.jinja_loader = DictLoader(TEMPLATES)

DEVICES_SQL = ("(SELECT GROUP_CONCAT(d.device_name || CASE WHEN d.model_name <> '' THEN ' (' || d.model_name || ')' ELSE '' END"
               " || ' x' || d.quantity, '; ') FROM devices d WHERE d.visit_id = vs.id) AS devices")


# --------------------------------------------------------------------------- #
# Routes: auth
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    identities = session.get("identities", {})
    if len(identities) == 1:
        only_role = next(iter(identities))
        return redirect(url_for("admin_dashboard" if only_role == "admin" else "security_dashboard"))
    return render_template("home.html", identities=identities)


def _role_login(role, template, dashboard_endpoint, other_login_endpoint, other_label):
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            if user["role"] != role:
                flash(f"That account is not a {role} account. Use the {other_label} login.", "error")
                return redirect(url_for(other_login_endpoint))
            nxt = safe_next(url_for(dashboard_endpoint))
            set_identity(role, user)
            return redirect(nxt)
        flash("Invalid username or password.", "error")
    return render_template(template)


@app.route("/login", methods=["GET", "POST"])
def login():
    return _role_login("admin", "login.html", "admin_dashboard", "security_login", "Security")


@app.route("/security/login", methods=["GET", "POST"])
def security_login():
    return _role_login("security", "security_login.html", "security_dashboard", "login", "Admin")


@app.route("/logout/<panel>")
@panel_required
def logout(panel):
    clear_identity(panel)
    return redirect(url_for("index"))


@app.route("/change-password/<panel>", methods=["GET", "POST"])
@panel_required
def change_password(panel):
    if request.method == "POST":
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (g.user_id,)).fetchone()
        new, confirm = request.form.get("new", ""), request.form.get("confirm", "")
        if not check_password_hash(user["password_hash"], request.form.get("current", "")):
            flash("Current password is wrong.", "error")
        elif len(new) < 6:
            flash("New password must be at least 6 characters.", "error")
        elif new != confirm:
            flash("New passwords do not match.", "error")
        else:
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), user["id"]))
            db.commit()
            flash("Password updated.", "success")
            return redirect(url_for("admin_dashboard" if panel == "admin" else "security_dashboard"))
    return render_template("change_password.html")


# --------------------------------------------------------------------------- #
# Routes: admin panel
# --------------------------------------------------------------------------- #
def render_admin_dashboard(form=None):
    db = get_db()
    today = today_str()
    stats = {
        "total": db.execute("SELECT COUNT(*) FROM visitors").fetchone()[0],
        "active": db.execute("SELECT COUNT(*) FROM visitors WHERE revoked=0 AND issue_date<=? AND expiry_date>=?",
                             (today, today)).fetchone()[0],
        "inside": db.execute("SELECT COUNT(*) FROM visits WHERE check_out IS NULL").fetchone()[0],
        "today": db.execute("SELECT COUNT(*) FROM visits WHERE date(check_in)=?", (today,)).fetchone()[0],
    }
    form = form or {k: None for k in ("name", "company", "phone", "email", "issue_date", "expiry_date",
                                       "issued_by", "hr_email", "security_email")}
    for k in ("name", "company", "phone", "email", "issue_date", "expiry_date", "issued_by"):
        form[k] = form.get(k) or ""
    return render_template("admin_dashboard.html", stats=stats,
                           form=form, settings=get_settings(), today_date=today)


@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    return render_admin_dashboard()


@app.route("/admin/visitors")
@login_required("admin")
def admin_visitors_list():
    db = get_db()
    q = request.args.get("q", "").strip()
    sql = ("SELECT v.*, EXISTS(SELECT 1 FROM visits x WHERE x.visitor_id=v.id AND x.check_out IS NULL) AS inside,"
           " (SELECT MAX(check_in) FROM visits x WHERE x.visitor_id=v.id) AS last_visit FROM visitors v")
    params = []
    if q:
        sql += " WHERE v.name LIKE ? OR v.company LIKE ? OR v.phone LIKE ? OR v.pass_id LIKE ? OR v.email LIKE ?"
        params = [f"%{q}%"] * 5
    sql += " ORDER BY v.id DESC LIMIT 300"
    visitors = db.execute(sql, params).fetchall()
    return render_template("admin_visitors_list.html", visitors=visitors, q=q)


@app.post("/admin/visitors")
@login_required("admin")
def create_visitor():
    f = request.form
    fields = ("name", "company", "phone", "email", "issue_date", "expiry_date", "issued_by",
              "hr_email", "security_email")
    data = {k: f.get(k, "").strip() for k in fields}
    labels = {"name": "Visitor name", "company": "Company name", "phone": "Phone no.",
              "email": "Visitor email", "issue_date": "Date of issue", "expiry_date": "Expiry date",
              "issued_by": "Issued by"}
    errors = [f"{label} is required." for key, label in labels.items() if not data[key]]
    if data["phone"] and not PHONE_RE.match(data["phone"]):
        errors.append("Phone number looks invalid.")
    for key, label in (("email", "Visitor email"), ("hr_email", "HR email"), ("security_email", "Security email")):
        if data[key] and not EMAIL_RE.match(data[key]):
            errors.append(f"{label} is not a valid email address.")
    d_issue, d_exp = parse_date(data["issue_date"]), parse_date(data["expiry_date"])
    if data["issue_date"] and not d_issue:
        errors.append("Date of issue is invalid.")
    if data["expiry_date"] and not d_exp:
        errors.append("Expiry date is invalid.")
    if d_issue and d_exp and d_exp < d_issue:
        errors.append("Expiry date cannot be before the date of issue.")
    if errors:
        for e in errors:
            flash(e, "error")
        return render_admin_dashboard(form=data)

    db = get_db()
    pass_id = new_pass_id()
    cur = db.execute(
        "INSERT INTO visitors (pass_id, name, company, phone, email, issue_date, expiry_date, issued_by,"
        " hr_email, security_email, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (pass_id, data["name"], data["company"], data["phone"], data["email"], data["issue_date"],
         data["expiry_date"], data["issued_by"], data["hr_email"], data["security_email"],
         g.username, now_str()))
    db.commit()
    vid = cur.lastrowid
    make_qr(pass_id)
    flash(f"Pass {pass_id} created for {data['name']}.", "success")

    if f.get("send_email"):
        v = db.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone()
        ok, info = send_qr_email(v)
        db.execute("UPDATE visitors SET email_status=? WHERE id=?",
                   (f"{'Sent' if ok else 'Failed'} {now_str()} - {info}", vid))
        db.commit()
        flash(info if ok else f"QR created but email failed: {info}", "success" if ok else "error")
    return redirect(url_for("admin_visitor", vid=vid))


@app.route("/admin/visitor/<int:vid>")
@login_required("admin")
def admin_visitor(vid):
    db = get_db()
    v = db.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone() or abort(404)
    visits = db.execute("SELECT * FROM visits WHERE visitor_id=? ORDER BY check_in DESC", (vid,)).fetchall()
    devices = {}
    for d in db.execute("SELECT d.* FROM devices d JOIN visits vs ON vs.id=d.visit_id WHERE vs.visitor_id=?"
                        " ORDER BY d.id", (vid,)):
        devices.setdefault(d["visit_id"], []).append(d)
    return render_template("admin_visitor.html", v=v, visits=visits, devices=devices, current=open_visit(vid))


@app.post("/admin/visitor/<int:vid>/resend")
@login_required("admin")
def resend_email(vid):
    db = get_db()
    v = db.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone() or abort(404)
    ok, info = send_qr_email(v)
    db.execute("UPDATE visitors SET email_status=? WHERE id=?",
               (f"{'Sent' if ok else 'Failed'} {now_str()} - {info}", vid))
    db.commit()
    flash(info if ok else f"Email failed: {info}", "success" if ok else "error")
    return redirect(url_for("admin_visitor", vid=vid))


@app.post("/admin/visitor/<int:vid>/revoke")
@login_required("admin")
def toggle_revoke(vid):
    db = get_db()
    v = db.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone() or abort(404)
    db.execute("UPDATE visitors SET revoked=? WHERE id=?", (0 if v["revoked"] else 1, vid))
    db.commit()
    flash("Pass restored." if v["revoked"] else "Pass revoked.", "info")
    return redirect(url_for("admin_visitor", vid=vid))


@app.post("/admin/visitor/<int:vid>/delete")
@login_required("admin")
def delete_visitor(vid):
    db = get_db()
    v = db.execute("SELECT * FROM visitors WHERE id=?", (vid,)).fetchone() or abort(404)
    if open_visit(vid):
        flash("Cannot delete: visitor is currently logged in. Log them out first.", "error")
        return redirect(url_for("admin_visitor", vid=vid))
    db.execute("DELETE FROM visitors WHERE id=?", (vid,))
    db.commit()
    path = qr_path(v["pass_id"])
    if os.path.exists(path):
        os.remove(path)
    flash(f"Visitor {v['name']} deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/settings", methods=["GET", "POST"])
@login_required("admin")
def settings_page():
    if request.method == "POST":
        f = request.form
        values = {k: f.get(k, "").strip() for k in ("company_name", "hr_email", "security_email",
                                                    "smtp_host", "smtp_port", "smtp_user", "smtp_sender")}
        bad = [k for k in ("hr_email", "security_email") if values[k] and not EMAIL_RE.match(values[k])]
        if values["smtp_port"] and not values["smtp_port"].isdigit():
            bad.append("smtp_port")
        if bad:
            flash("Please fix: " + ", ".join(b.replace("_", " ") for b in bad), "error")
        else:
            if f.get("smtp_password"):
                values["smtp_password"] = f.get("smtp_password")
            values["company_name"] = values["company_name"] or "My Company"
            save_settings(values)
            flash("Settings saved.", "success")
        return redirect(url_for("settings_page"))
    users = get_db().execute("SELECT id, username, role, created_at FROM users ORDER BY role, username").fetchall()
    return render_template("settings.html", s=get_settings(), users=users)


@app.post("/admin/settings/test-email")
@login_required("admin")
def test_email():
    to = request.form.get("to", "").strip()
    if not EMAIL_RE.match(to):
        flash("Enter a valid email address.", "error")
        return redirect(url_for("settings_page"))
    msg = EmailMessage()
    msg["Subject"] = "VMS test email"
    msg["To"] = to
    msg.set_content("This is a test email from the Visitor Management System. Email delivery works.")
    ok, info = smtp_send(msg)
    flash(f"Test email sent to {to}." if ok else f"Test failed: {info}", "success" if ok else "error")
    return redirect(url_for("settings_page"))


@app.post("/admin/users")
@login_required("admin")
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "security")
    if not username or len(password) < 6 or role not in ("admin", "security"):
        flash("Username, a password of 6+ characters and a valid role are required.", "error")
    else:
        try:
            db = get_db()
            db.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                       (username, generate_password_hash(password), role, now_str()))
            db.commit()
            flash(f"User {username} added.", "success")
        except sqlite3.IntegrityError:
            flash("That username already exists.", "error")
    return redirect(url_for("settings_page"))


@app.post("/admin/users/<int:uid>/delete")
@login_required("admin")
def delete_user(uid):
    db = get_db()
    if uid == g.user_id:
        flash("You cannot delete your own account.", "error")
    else:
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.commit()
        flash("User deleted.", "info")
    return redirect(url_for("settings_page"))


@app.route("/qr/<pass_id>.png")
@login_required()
def qr_image(pass_id):
    v = find_visitor(pass_id) or abort(404)
    path = qr_path(v["pass_id"])
    if not os.path.exists(path):
        make_qr(v["pass_id"])
    return send_file(path, mimetype="image/png", download_name=f"{v['pass_id']}.png",
                     as_attachment=request.args.get("download") == "1")


# --------------------------------------------------------------------------- #
# Routes: history (admin + security)
# --------------------------------------------------------------------------- #
def history_rows(limit=1000):
    q = request.args.get("q", "").strip()
    dfrom = request.args.get("from", "").strip()
    dto = request.args.get("to", "").strip()
    sql = ("SELECT vs.id, vs.check_in, vs.check_out, vs.checked_in_by, vs.checked_out_by,"
           " v.pass_id, v.name, v.company, v.phone, v.email, v.issued_by, " + DEVICES_SQL +
           " FROM visits vs JOIN visitors v ON v.id = vs.visitor_id WHERE 1=1")
    params = []
    if q:
        sql += " AND (v.name LIKE ? OR v.company LIKE ? OR v.phone LIKE ? OR v.pass_id LIKE ?)"
        params += [f"%{q}%"] * 4
    if parse_date(dfrom):
        sql += " AND date(vs.check_in) >= ?"
        params.append(dfrom)
    if parse_date(dto):
        sql += " AND date(vs.check_in) <= ?"
        params.append(dto)
    sql += " ORDER BY vs.check_in DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return get_db().execute(sql, params).fetchall(), q, dfrom, dto


@app.route("/history/<panel>")
@panel_required
def history(panel):
    rows, q, dfrom, dto = history_rows()
    return render_template("history.html", rows=rows, q=q, dfrom=dfrom, dto=dto)


@app.route("/history/<panel>/export.csv")
@panel_required
def history_csv(panel):
    rows, *_ = history_rows(limit=None)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Pass ID", "Visitor", "Company", "Phone", "Email", "Issued by", "Log in", "Log out",
                "Duration", "Devices", "Logged in by", "Logged out by"])
    for r in rows:
        w.writerow([r["pass_id"], r["name"], r["company"], r["phone"], r["email"], r["issued_by"],
                    r["check_in"], r["check_out"] or "", duration(r["check_in"], r["check_out"]),
                    r["devices"] or "", r["checked_in_by"] or "", r["checked_out_by"] or ""])
    fname = f"visitor_history_{datetime.now():%Y%m%d_%H%M}.csv"
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


# --------------------------------------------------------------------------- #
# Routes: security panel
# --------------------------------------------------------------------------- #
@app.route("/security")
@login_required("security")
def security_dashboard():
    db = get_db()
    today = today_str()
    base = ("SELECT vs.*, v.pass_id, v.name, v.company, v.phone, " + DEVICES_SQL +
            " FROM visits vs JOIN visitors v ON v.id = vs.visitor_id ")
    inside = db.execute(base + "WHERE vs.check_out IS NULL ORDER BY vs.check_in").fetchall()
    today_rows = db.execute(base + "WHERE date(vs.check_in)=? OR date(vs.check_out)=? ORDER BY vs.check_in DESC",
                            (today, today)).fetchall()
    today_ins = db.execute("SELECT COUNT(*) FROM visits WHERE date(check_in)=?", (today,)).fetchone()[0]
    today_outs = db.execute("SELECT COUNT(*) FROM visits WHERE date(check_out)=?", (today,)).fetchone()[0]
    return render_template("security_dashboard.html", inside=inside, today_rows=today_rows,
                           today_ins=today_ins, today_outs=today_outs)


@app.post("/security/lookup")
@login_required("security")
def security_lookup():
    code = request.form.get("code", "").strip()
    if not code:
        return redirect(url_for("security_dashboard"))
    v = find_visitor(code)
    if not v:
        digits = re.sub(r"\D", "", code)
        if len(digits) >= 7:
            matches = [r for r in get_db().execute("SELECT * FROM visitors ORDER BY id DESC")
                       if re.sub(r"\D", "", r["phone"]).endswith(digits[-10:])]
            if matches:
                valid = [m for m in matches if pass_status(m) == "valid"]
                v = (valid or matches)[0]
    if not v:
        flash(f"No visitor pass found for '{code}'.", "error")
        return redirect(url_for("security_dashboard"))
    return redirect(url_for("security_visitor", pass_id=v["pass_id"]))


@app.route("/security/visitor/<pass_id>")
@login_required("security")
def security_visitor(pass_id):
    v = find_visitor(pass_id)
    if not v:
        flash(f"Invalid pass: '{pass_id}' is not registered.", "error")
        return redirect(url_for("security_dashboard"))
    db = get_db()
    current = open_visit(v["id"])
    cur_devices = db.execute("SELECT * FROM devices WHERE visit_id=? ORDER BY id",
                             (current["id"],)).fetchall() if current else []
    past = db.execute("SELECT vs.*, " + DEVICES_SQL + " FROM visits vs WHERE vs.visitor_id=? AND vs.check_out IS NOT NULL"
                      " ORDER BY vs.check_in DESC LIMIT 50", (v["id"],)).fetchall()
    return render_template("security_visitor.html", v=v, current=current, cur_devices=cur_devices, past=past)


def perform_checkin(v):
    st = pass_status(v)
    if st != "valid":
        flash({"expired": "Pass has expired - log in refused.",
               "revoked": "Pass has been revoked - log in refused.",
               "not_yet_valid": "Pass is not valid yet - log in refused."}[st], "error")
    elif open_visit(v["id"]):
        flash(f"{v['name']} is already logged in.", "info")
    else:
        t = now_str()
        db = get_db()
        db.execute("INSERT INTO visits (visitor_id, check_in, checked_in_by) VALUES (?,?,?)",
                   (v["id"], t, g.username))
        db.commit()
        flash(f"{v['name']} logged IN at {fmt_dt(t)}. Add any devices they carry below.", "success")


def perform_checkout(v, current):
    t = now_str()
    db = get_db()
    db.execute("UPDATE visits SET check_out=?, checked_out_by=? WHERE id=?", (t, g.username, current["id"]))
    db.commit()
    flash(f"{v['name']} logged OUT at {fmt_dt(t)} (inside {duration(current['check_in'], t)}).", "success")


@app.post("/security/visitor/<pass_id>/checkin")
@login_required("security")
def checkin(pass_id):
    v = find_visitor(pass_id) or abort(404)
    perform_checkin(v)
    return redirect(url_for("security_visitor", pass_id=v["pass_id"]))


@app.post("/security/visitor/<pass_id>/checkout")
@login_required("security")
def checkout(pass_id):
    v = find_visitor(pass_id) or abort(404)
    current = open_visit(v["id"])
    if not current:
        flash(f"{v['name']} is not logged in.", "info")
    else:
        perform_checkout(v, current)
    return redirect(safe_next(url_for("security_visitor", pass_id=v["pass_id"])))


@app.route("/security/scan/<pass_id>")
@login_required("security")
def scan_visitor(pass_id):
    """Scanning a QR auto-logs the visitor in or out, so the guard doesn't have to click
    Log IN / Log OUT by hand - scan once to check in, scan again to check out."""
    v = find_visitor(pass_id)
    if not v:
        flash(f"Invalid pass: '{pass_id}' is not registered.", "error")
        return redirect(url_for("security_dashboard"))
    current = open_visit(v["id"])
    if current:
        perform_checkout(v, current)
    else:
        perform_checkin(v)
    return redirect(url_for("security_visitor", pass_id=v["pass_id"]))


@app.post("/security/visitor/<pass_id>/device")
@login_required("security")
def add_device(pass_id):
    v = find_visitor(pass_id) or abort(404)
    current = open_visit(v["id"])
    name = request.form.get("device_name", "").strip()
    model = request.form.get("model_name", "").strip()
    try:
        qty = int(request.form.get("quantity", "1"))
    except ValueError:
        qty = 0
    if not current:
        flash("Log the visitor in before adding devices.", "error")
    elif not name:
        flash("Device name is required.", "error")
    elif not 1 <= qty <= 999:
        flash("Quantity must be between 1 and 999.", "error")
    else:
        db = get_db()
        db.execute("INSERT INTO devices (visit_id, device_name, model_name, quantity, added_by, added_at)"
                   " VALUES (?,?,?,?,?,?)", (current["id"], name, model, qty, g.username, now_str()))
        db.commit()
        flash(f"Device added: {name}{' (' + model + ')' if model else ''} × {qty}.", "success")
    return redirect(url_for("security_visitor", pass_id=v["pass_id"]))


@app.post("/security/device/<int:did>/delete")
@login_required("security")
def delete_device(did):
    db = get_db()
    row = db.execute("SELECT d.id, v.pass_id FROM devices d JOIN visits vs ON vs.id=d.visit_id"
                     " JOIN visitors v ON v.id=vs.visitor_id WHERE d.id=?", (did,)).fetchone() or abort(404)
    db.execute("DELETE FROM devices WHERE id=?", (did,))
    db.commit()
    flash("Device removed.", "info")
    return redirect(url_for("security_visitor", pass_id=row["pass_id"]))


@app.errorhandler(400)
def bad_request(err):
    return render_template_safe(err.description or "Bad request", 400)


@app.errorhandler(404)
def not_found(_err):
    return render_template_safe("Page not found.", 404)


def render_template_safe(message, code):
    html = ('{% extends "base.html" %}{% block content %}<div class="card"><h2>Error ' + str(code) +
            '</h2><p>{{ message }}</p><a class="btn ghost" href="{{ url_for(\'index\') }}">Home</a></div>{% endblock %}')
    return render_template_string(html, message=message), code


# --------------------------------------------------------------------------- #
init_db()

if __name__ == "__main__":
    host = os.environ.get("VMS_HOST", "0.0.0.0")
    port = int(os.environ.get("VMS_PORT", "5000"))
    ssl_ctx = "adhoc" if os.environ.get("VMS_HTTPS") == "1" else None  # needs: pip install pyopenssl
    print(f"\n  Visitor Management System running on {'https' if ssl_ctx else 'http'}://127.0.0.1:{port}")
    print("  Default logins -> admin / admin123   |   security / security123\n")
    app.run(host=host, port=port, debug=False, ssl_context=ssl_ctx)

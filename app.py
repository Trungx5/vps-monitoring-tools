"""
Custom VPS Monitoring Tool
A lightweight Prometheus + Grafana alternative built from scratch.

What it does:
  1. Scrapes one or more node_exporter /metrics endpoints on a timer (like Prometheus does)
  2. Parses the raw Prometheus text format
  3. Computes CPU / memory / disk / network / disk I/O usage (including live bandwidth/sec)
  4. Stores history in SQLite (like Prometheus's TSDB, simplified)
  5. Serves a live-updating web dashboard with support for multiple VPS instances,
     Good/Warn/Critical alert thresholds per metric, and email notifications on
     severity changes

Run with:  python app.py
Then open: http://localhost:5000

Email alerts need an SMTP relay to send through - set these environment
variables before starting the app (see README for a Gmail App Password example):
  SMTP_HOST, SMTP_PORT (default 587), SMTP_USER, SMTP_PASSWORD, ALERT_FROM_EMAIL (optional)
If they're not set, alerts are just logged to the console instead of emailed.

The whole dashboard sits behind a login. Set APP_USERNAME / APP_PASSWORD env
vars for a fixed account; if you don't, a random password is generated and
printed to the console each time you start the app.
"""

import logging
import math
import os
import re
import secrets
import smtplib
import socket
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler
from urllib.parse import urlsplit

import requests
from flask import (Flask, g, has_request_context, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Used only to seed the first ("Default") instance the very first time the
# app runs. After that, instances live in the `instances` table and are
# managed from the dashboard's sidebar.
DEFAULT_TARGET_URL = os.environ.get("DEFAULT_TARGET_URL", "")
SCRAPE_INTERVAL_SECONDS = 10
HEARTBEAT_INTERVAL_SECONDS = 30
# Websites are checked from the outside and are far less volatile than a
# server's CPU, so they get a slower cadence - and hammering someone else's
# site every 10 seconds would be rude at best.
WEB_CHECK_INTERVAL_SECONDS = int(os.environ.get("WEB_CHECK_INTERVAL_SECONDS", "60"))
WEB_CHECK_TIMEOUT_SECONDS = 15
WEB_CHECK_RETENTION_DAYS = 30
EVENT_LOG_RETENTION_DAYS = 3
AUDIT_LOG_RETENTION_DAYS = 90
DB_PATH = os.environ.get("DB_PATH", "metrics.db")
LOG_FILE_PATH = os.environ.get("LOG_FILE_PATH", "vps_monitor.log")
SQLITE_TIMEOUT_SECONDS = 30

# A real log file (rotates at ~2MB, keeps 3 backups) plus console output -
# every scrape, error, and status change goes through this instead of bare
# print(). The DB-backed event_log table (below) is a curated subset of this
# for the dashboard's Logs view; this file has everything, for when you need
# to dig deeper than the UI shows.
logger = logging.getLogger("vps_monitor")
logger.setLevel(logging.INFO)
_log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
_file_handler = RotatingFileHandler(LOG_FILE_PATH, maxBytes=2_000_000, backupCount=3)
_file_handler.setFormatter(_log_formatter)
logger.addHandler(_file_handler)
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_log_formatter)
logger.addHandler(_console_handler)


def utcnow():
    """Naive UTC 'now'. utcnow() is deprecated, but every timestamp
    already stored in the database - and the format the dashboard parses - is
    naive UTC, so this keeps the exact same string format without the warning."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
ALERT_FROM_EMAIL = os.environ.get("ALERT_FROM_EMAIL", SMTP_USER)

# Metrics that get a Good/Warn/Critical evaluation, and how to read each
# one's current value off a `metrics` row.
METRIC_DEFS = {
    "cpu": ("CPU", "%", lambda m: m.get("cpu_percent")),
    "mem": ("Memory", "%", lambda m: m.get("mem_percent")),
    "disk": ("Disk", "%", lambda m: m.get("disk_percent")),
    "net": ("Bandwidth", "B/s", lambda m: max(
        [v for v in (m.get("net_rx_bps"), m.get("net_tx_bps")) if v is not None], default=None)),
    "diskio": ("Disk I/O", "B/s", lambda m: max(
        [v for v in (m.get("disk_read_bps"), m.get("disk_write_bps")) if v is not None], default=None)),
}
SEVERITY_RANK = {"good": 0, "warn": 1, "critical": 2}

# Pass/fail health checklist - the "is this box actually okay" questions an
# enterprise monitoring tool asks alongside the numeric gauges above. Each
# evaluates to True (pass), False (fail), or None (not enough data / metric
# not exposed by this node_exporter build).
HEALTH_CHECK_DEFS = {
    "reachable": "Host reachable",
    "net_ifaces": "Network interfaces up",
    "fs_writable": "Root filesystem writable",
    "load": "System load normal",
    "swap": "Swap not exhausted",
    "reboot": "No unexpected reboot",
    "traffic": "No traffic anomaly",
}
LOAD_WARN_MULTIPLIER = 2.0     # load1 > this * cpu_count = fail
SWAP_WARN_PERCENT = 90.0       # swap used % >= this = fail
TRAFFIC_ANOMALY_MULTIPLIER = 5.0     # current bandwidth > this * recent baseline = fail
TRAFFIC_ANOMALY_MIN_SAMPLES = 5      # need this many history rows to trust a baseline
TRAFFIC_ANOMALY_FLOOR_BPS = 5000     # ignore spikes below this - idle noise, not an anomaly
REBOOT_JITTER_SECONDS = 60           # allow boot_time to wobble this much before calling it a reboot

# Every alert condition a subscription row can point at - the 5 graduated
# metrics plus the 7 pass/fail health checks, in one flat namespace so a
# recipient can be wired to exactly the conditions they care about.
ALERT_TYPE_LABELS = {
    "cpu": "CPU usage",
    "mem": "Memory usage",
    "disk": "Disk usage",
    "net": "Network bandwidth high",
    "diskio": "Disk I/O high",
    "reachable": "System down / unreachable",
    "net_ifaces": "Network interface down",
    "fs_writable": "Filesystem read-only",
    "load": "System overloaded",
    "swap": "Swap exhausted",
    "reboot": "Unexpected reboot",
    "traffic": "Traffic anomaly (possible attack)",
}

# Website checks. Kept in their own namespace so a subscription row always
# says which kind of monitor it belongs to.
WEB_ALERT_TYPE_LABELS = {
    "web_down": "Website down / unreachable",
    "web_slow": "Website slow to respond",
    "web_status": "Unexpected HTTP status code",
    "web_cert_expiring": "TLS certificate expiring soon",
    "web_cert_invalid": "TLS certificate invalid",
    "web_ip_changed": "Resolved IP address changed",
    "web_keyword_missing": "Expected text missing from page",
}

# Pass/fail checks shown per website, mirroring the VPS health checklist.
WEB_CHECK_DEFS = {
    "reachable": "Site responding",
    "status": "Expected HTTP status",
    "speed": "Response time acceptable",
    "cert_valid": "TLS certificate valid",
    "cert_fresh": "TLS certificate not expiring soon",
    "ip_stable": "Resolved IP unchanged",
    "keyword": "Expected text present",
}

WEB_CERT_WARN_DAYS = 21        # cert_fresh fails below this
WEB_SLOW_MS_DEFAULT = 5000     # speed fails above this unless overridden

app = Flask(__name__)
# A per-process random fallback is fine for single-process development, but
# fatal with multiple workers: each would sign cookies with a different key and
# users would appear randomly logged out. wsgi.py refuses to start without a
# configured key for exactly that reason.
SECRET_KEY_CONFIGURED = bool(os.environ.get("SECRET_KEY"))
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Set SECURE_COOKIES=1 once the app is served over HTTPS so the session cookie
# is never sent over plaintext. Left off by default because switching it on
# while serving plain HTTP silently breaks login (the browser withholds the
# cookie and every request looks logged-out).
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SECURE_COOKIES", "") == "1"

# ---------------------------------------------------------------------------
# Accounts, roles and sessions
#
# Every account lives in the `users` table (see init_db). Two roles:
#   admin  - full control: instances, thresholds, alerts, users, everything
#   viewer - read-only: dashboards, health checks and logs, nothing mutating
# All accounts see the same fleet of VPS instances; the role decides what
# they're allowed to change, not what they're allowed to see.
#
# There is no public signup. The first admin is created at setup (from
# APP_USERNAME/APP_PASSWORD, or a generated password printed once), and that
# admin creates every other account.
# ---------------------------------------------------------------------------
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ROLES = (ROLE_ADMIN, ROLE_VIEWER)

PUBLIC_ENDPOINTS = {"login", "static"}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
SESSION_LIFETIME_HOURS = int(os.environ.get("SESSION_LIFETIME_HOURS", "12"))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=SESSION_LIFETIME_HOURS)

# Endpoints a signed-in *viewer* may call with a mutating HTTP verb. Everything
# else that isn't a GET requires admin - deny-by-default, so a new endpoint
# added later is admin-only until deliberately listed here.
VIEWER_WRITE_ENDPOINTS = {"logout", "api_change_own_password"}


def db():
    """Every DB connection goes through here. The busy timeout matters once
    there is more than one process touching the file (gunicorn workers plus
    the separate scraper): without it, two concurrent writes raise
    'database is locked' immediately instead of waiting their turn."""
    conn = sqlite3.connect(DB_PATH, timeout=SQLITE_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {SQLITE_TIMEOUT_SECONDS * 1000}")
    return conn


def get_app_state(key, default=None):
    conn = db()
    row = conn.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_app_state(key, value):
    conn = db()
    conn.execute(
        "INSERT INTO app_state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value)
    )
    conn.commit()
    conn.close()


def mark_server_start():
    """Rotate the boot id so sessions issued before this restart stop being
    accepted. Lives in the DB rather than a module-level constant so that it
    stays consistent across multiple gunicorn workers - each worker reads the
    same value instead of inventing its own (which would log users out at
    random as requests bounced between workers)."""
    set_app_state("boot_id", secrets.token_hex(8))


def current_boot_id():
    return get_app_state("boot_id", "")


# ---------------------------------------------------------------------------
# User records
# ---------------------------------------------------------------------------
def get_user_by_username(username):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user(user_id):
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_users():
    conn = db()
    rows = conn.execute(
        "SELECT id, username, role, is_active, created_at, last_login_at "
        "FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_admins(exclude_user_id=None):
    conn = db()
    if exclude_user_id is None:
        row = conn.execute(
            "SELECT COUNT(*) c FROM users WHERE role = ? AND is_active = 1", (ROLE_ADMIN,)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) c FROM users WHERE role = ? AND is_active = 1 AND id != ?",
            (ROLE_ADMIN, exclude_user_id)
        ).fetchone()
    conn.close()
    return row["c"]


def create_user(username, password, role=ROLE_VIEWER):
    conn = db()
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, is_active, created_at) "
        "VALUES (?, ?, ?, 1, ?)",
        (username, generate_password_hash(password), role, utcnow().isoformat())
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def update_user_password(user_id, password):
    conn = db()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                 (generate_password_hash(password), user_id))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Audit log - who did what. Distinct from event_log, which records what the
# monitored machines did.
# ---------------------------------------------------------------------------
def log_audit(action, target=None, details=None, username=None, user_id=None, ip=None):
    if username is None or user_id is None:
        user = current_user()
        if user:
            username = username if username is not None else user["username"]
            user_id = user_id if user_id is not None else user["id"]
    if ip is None:
        ip = request.remote_addr if request else None

    conn = db()
    conn.execute(
        "INSERT INTO audit_log (timestamp, user_id, username, action, target, details, ip_address) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (utcnow().isoformat(), user_id, username, action, target, details, ip)
    )
    conn.commit()
    conn.close()
    logger.info(f"AUDIT {username or '-'}@{ip or '-'} {action}"
                f"{' ' + target if target else ''}{' (' + details + ')' if details else ''}")


def get_audit_log(limit=200, username=None, action=None):
    limit = max(1, min(limit, 500))
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    if username:
        query += " AND username = ?"
        params.append(username)
    if action:
        query += " AND action = ?"
        params.append(action)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    conn = db()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def trim_audit_log():
    cutoff = (utcnow() - timedelta(days=AUDIT_LOG_RETENTION_DAYS)).isoformat()
    conn = db()
    conn.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Login throttling - DB-backed so the limit holds across gunicorn workers
# rather than being counted separately inside each one.
# ---------------------------------------------------------------------------
def _too_many_attempts(ip):
    cutoff = (utcnow() - timedelta(seconds=LOGIN_WINDOW_SECONDS)).isoformat()
    conn = db()
    conn.execute("DELETE FROM login_attempts WHERE timestamp < ?", (cutoff,))
    conn.commit()
    row = conn.execute(
        "SELECT COUNT(*) c FROM login_attempts WHERE ip_address = ? AND timestamp >= ?",
        (ip, cutoff)
    ).fetchone()
    conn.close()
    return row["c"] >= LOGIN_MAX_ATTEMPTS


def _record_failed_attempt(ip, username):
    conn = db()
    conn.execute(
        "INSERT INTO login_attempts (ip_address, username, timestamp) VALUES (?, ?, ?)",
        (ip, username, utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def _clear_attempts(ip):
    conn = db()
    conn.execute("DELETE FROM login_attempts WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Request gating
# ---------------------------------------------------------------------------
def current_user():
    """The signed-in user for this request, or None. Cached on `g` so a single
    request doesn't re-query the users table for every permission check."""
    if not has_request_context():
        return None
    if "cached_user" in g:
        return g.cached_user

    user = None
    user_id = session.get("user_id")
    if user_id and session.get("boot_id") == current_boot_id():
        candidate = get_user(user_id)
        if candidate and candidate["is_active"]:
            user = candidate
    g.cached_user = user
    return user


def is_admin():
    user = current_user()
    return bool(user and user["role"] == ROLE_ADMIN)


@app.before_request
def require_login():
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return

    user = current_user()
    if not user:
        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication required"}), 401
        return redirect(url_for("login", next=request.path))

    session.permanent = True
    # Deny-by-default: anything that isn't a plain read needs admin, unless
    # the endpoint is explicitly listed as viewer-writable.
    if request.method not in ("GET", "HEAD", "OPTIONS") \
            and request.endpoint not in VIEWER_WRITE_ENDPOINTS \
            and user["role"] != ROLE_ADMIN:
        if request.path.startswith("/api/"):
            return jsonify({"error": "admin role required for this action"}), 403
        return jsonify({"error": "admin role required for this action"}), 403


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if _too_many_attempts(ip):
            error = "Too many failed attempts. Try again in a few minutes."
            log_audit("login.throttled", target=username or None,
                      username=username or None, user_id=None, ip=ip)
        else:
            user = get_user_by_username(username)
            if user and user["is_active"] and check_password_hash(user["password_hash"], password):
                _clear_attempts(ip)
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["boot_id"] = current_boot_id()

                conn = db()
                conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?",
                             (utcnow().isoformat(), user["id"]))
                conn.commit()
                conn.close()

                log_audit("login.success", username=user["username"], user_id=user["id"], ip=ip)
                next_path = request.args.get("next") or "/"
                if not next_path.startswith("/"):
                    next_path = "/"
                return redirect(next_path)

            _record_failed_attempt(ip, username)
            reason = "disabled account" if (user and not user["is_active"]) else "bad credentials"
            log_audit("login.failed", target=username or None, details=reason,
                      username=username or None, user_id=None, ip=ip)
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    user = current_user()
    if user:
        log_audit("logout", username=user["username"], user_id=user["id"])
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Database (SQLite acts as our mini time-series store)
# ---------------------------------------------------------------------------
def init_db(_attempt=0):
    """Create or upgrade the schema. Safe to call from several processes at
    once: on a fresh install the web and scraper services start together and
    both land here, and switching the journal mode needs a brief exclusive
    lock, so a loser can see SQLITE_BUSY. Retry rather than crash the service."""
    try:
        return _init_db_once()
    except sqlite3.OperationalError as e:
        if "locked" not in str(e).lower() or _attempt >= 5:
            raise
        time.sleep(0.5 * (_attempt + 1))
        return init_db(_attempt + 1)


def _init_db_once():
    conn = db()
    # WAL lets the web workers keep reading while the scraper writes, instead
    # of the two blocking each other on every sample.
    conn.execute("PRAGMA journal_mode = WAL")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS instances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_url TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_status TEXT,
            last_error TEXT,
            last_checked_at TEXT,
            auth_username TEXT,
            auth_password TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instance_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            cpu_percent REAL,
            mem_percent REAL,
            mem_used_mb REAL,
            mem_total_mb REAL,
            disk_percent REAL,
            disk_used_gb REAL,
            disk_total_gb REAL,
            net_rx_bytes REAL,
            net_tx_bytes REAL,
            net_rx_bps REAL,
            net_tx_bps REAL,
            disk_read_bps REAL,
            disk_write_bps REAL,
            load1 REAL,
            cpu_count INTEGER,
            swap_percent REAL,
            fs_readonly INTEGER,
            net_ifaces_down INTEGER,
            boot_time REAL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_thresholds (
            instance_id INTEGER PRIMARY KEY,
            alert_email TEXT,
            cpu_warn REAL, cpu_crit REAL,
            mem_warn REAL, mem_crit REAL,
            disk_warn REAL, disk_crit REAL,
            net_warn REAL, net_crit REAL,
            diskio_warn REAL, diskio_crit REAL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instance_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(instance_id, email, alert_type)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            instance_id INTEGER,
            instance_name TEXT,
            level TEXT NOT NULL,
            category TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_log_timestamp ON event_log(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_event_log_instance ON event_log(instance_id)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login_at TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT,
            ip_address TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # --- website monitoring -------------------------------------------------
    conn.execute("""
        CREATE TABLE IF NOT EXISTS web_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL UNIQUE,
            expected_status INTEGER,
            keyword TEXT,
            slow_ms INTEGER,
            cert_warn_days INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_status TEXT,
            last_error TEXT,
            last_checked_at TEXT,
            last_ip TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS web_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            ok INTEGER,
            status_code INTEGER,
            response_ms REAL,
            resolved_ip TEXT,
            cert_days REAL,
            cert_valid INTEGER,
            keyword_ok INTEGER,
            final_url TEXT,
            error TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_web_checks_target ON web_checks(target_id, id)")
    conn.commit()

    # INSERT OR IGNORE rather than check-then-insert: two services starting
    # together can both see the row missing and race to create it.
    conn.execute("INSERT OR IGNORE INTO app_state (key, value) VALUES ('boot_id', ?)",
                 (secrets.token_hex(8),))
    conn.commit()

    # --- migrate a pre-multi-instance / pre-severity-tier metrics.db in place ---
    cols = [r[1] for r in conn.execute("PRAGMA table_info(metrics)").fetchall()]
    if "instance_id" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN instance_id INTEGER")
    if "net_rx_bps" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN net_rx_bps REAL")
    if "net_tx_bps" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN net_tx_bps REAL")
    if "disk_read_bps" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN disk_read_bps REAL")
    if "disk_write_bps" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN disk_write_bps REAL")
    if "cpu_count" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN cpu_count INTEGER")
    if "swap_percent" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN swap_percent REAL")
    if "fs_readonly" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN fs_readonly INTEGER")
    if "net_ifaces_down" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN net_ifaces_down INTEGER")
    if "boot_time" not in cols:
        conn.execute("ALTER TABLE metrics ADD COLUMN boot_time REAL")

    inst_cols = [r[1] for r in conn.execute("PRAGMA table_info(instances)").fetchall()]
    if "last_status" not in inst_cols:
        conn.execute("ALTER TABLE instances ADD COLUMN last_status TEXT")
    if "last_error" not in inst_cols:
        conn.execute("ALTER TABLE instances ADD COLUMN last_error TEXT")
    if "last_checked_at" not in inst_cols:
        conn.execute("ALTER TABLE instances ADD COLUMN last_checked_at TEXT")
    if "auth_username" not in inst_cols:
        conn.execute("ALTER TABLE instances ADD COLUMN auth_username TEXT")
    if "auth_password" not in inst_cols:
        conn.execute("ALTER TABLE instances ADD COLUMN auth_password TEXT")

    sub_cols = [r[1] for r in conn.execute("PRAGMA table_info(alert_subscriptions)").fetchall()]
    if "monitor_type" not in sub_cols:
        # Existing rows all predate website monitoring, so they are VPS alerts.
        conn.execute("ALTER TABLE alert_subscriptions ADD COLUMN monitor_type TEXT NOT NULL DEFAULT 'vps'")
        conn.commit()

    thresh_cols = [r[1] for r in conn.execute("PRAGMA table_info(alert_thresholds)").fetchall()]
    legacy_map = {"cpu_max": "cpu_crit", "mem_max": "mem_crit",
                  "disk_max": "disk_crit", "net_bps_max": "net_crit"}
    for new_col in ("alert_email TEXT", "cpu_warn REAL", "cpu_crit REAL", "mem_warn REAL",
                     "mem_crit REAL", "disk_warn REAL", "disk_crit REAL", "net_warn REAL",
                     "net_crit REAL", "diskio_warn REAL", "diskio_crit REAL"):
        col_name = new_col.split()[0]
        if col_name not in thresh_cols:
            conn.execute(f"ALTER TABLE alert_thresholds ADD COLUMN {new_col}")
    conn.commit()
    if any(legacy in thresh_cols for legacy in legacy_map):
        for legacy_col, new_col in legacy_map.items():
            if legacy_col in thresh_cols:
                conn.execute(
                    f"UPDATE alert_thresholds SET {new_col} = {legacy_col} "
                    f"WHERE {new_col} IS NULL AND {legacy_col} IS NOT NULL"
                )
        conn.commit()

    # --- one-time migration: the old single alert_email-per-instance model
    # becomes explicit (instance, email, alert_type) subscription rows, one
    # per alert type, so nobody who'd already set an email loses their
    # notifications when this table replaces it ---
    if conn.execute("SELECT COUNT(*) FROM alert_subscriptions").fetchone()[0] == 0:
        old_emails = conn.execute(
            "SELECT instance_id, alert_email FROM alert_thresholds "
            "WHERE alert_email IS NOT NULL AND alert_email != ''"
        ).fetchall()
        for instance_id, email in old_emails:
            for alert_type in ALERT_TYPE_LABELS:
                conn.execute(
                    "INSERT OR IGNORE INTO alert_subscriptions "
                    "(instance_id, email, alert_type, created_at) VALUES (?, ?, ?, ?)",
                    (instance_id, email, alert_type, utcnow().isoformat())
                )
        conn.commit()

    # Seed a first instance only when DEFAULT_TARGET_URL is explicitly set -
    # a fresh install on someone else's server should start empty, not
    # pre-pointed at a hard-coded address.
    if DEFAULT_TARGET_URL and conn.execute("SELECT id FROM instances LIMIT 1").fetchone() is None:
        try:
            cur = conn.execute(
                "INSERT INTO instances (name, target_url, created_at) VALUES (?, ?, ?)",
                ("Default", DEFAULT_TARGET_URL, utcnow().isoformat())
            )
            conn.execute("UPDATE metrics SET instance_id = ? WHERE instance_id IS NULL",
                         (cur.lastrowid,))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()  # another starting process seeded it first

    conn.close()
    bootstrap_admin_user()


def bootstrap_admin_user():
    """Create the first admin account if the users table is empty. Uses
    APP_USERNAME/APP_PASSWORD when provided (so existing setups keep their
    credentials), otherwise generates a password and prints it once."""
    conn = db()
    existing = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    conn.close()
    if existing:
        return None

    username = os.environ.get("APP_USERNAME", "admin")
    password = os.environ.get("APP_PASSWORD")
    generated = not password
    if generated:
        password = secrets.token_urlsafe(12)

    try:
        create_user(username, password, ROLE_ADMIN)
    except sqlite3.IntegrityError:
        # The web and scraper services start at the same time and both call
        # init_db(). Both can see an empty users table and race to create the
        # first admin; the loser must not crash, the account exists either way.
        logger.info(f"First admin {username!r} was created concurrently - nothing to do")
        return None

    log_audit("user.bootstrap", target=username, details="initial admin account",
              username="system", user_id=None, ip=None)

    if generated:
        print("=" * 68)
        print("No APP_PASSWORD set - created the first admin account with a")
        print("generated password. Save it now, it is not shown again:")
        print(f"    username: {username}")
        print(f"    password: {password}")
        print("Change it from the Users panel, or set APP_USERNAME/APP_PASSWORD")
        print("before first run to choose your own.")
        print("=" * 68)
    else:
        logger.info(f"Created first admin account '{username}' from APP_USERNAME/APP_PASSWORD")
    return username


def get_instances(include_secrets=False):
    """include_secrets=True returns auth_password in the clear - only for the
    scrape loop's own use. Every API-facing caller gets include_secrets=False
    (the default), so the password never round-trips into a browser response;
    `has_auth` tells the UI whether one is set without revealing it."""
    conn = db()
    rows = conn.execute("SELECT * FROM instances ORDER BY id").fetchall()
    conn.close()
    instances = [dict(r) for r in rows]
    for inst in instances:
        inst["has_auth"] = bool(inst.get("auth_username"))
        if not include_secrets:
            inst.pop("auth_password", None)
        latest = get_latest(inst["id"])
        thresholds = get_thresholds(inst["id"])
        inst["severity"] = evaluate_severity(latest, thresholds)
        inst["health"] = evaluate_health(inst, get_history(inst["id"], limit=30))
    return instances


def save_metrics(instance_id, m):
    conn = db()
    conn.execute("""
        INSERT INTO metrics
        (instance_id, timestamp, cpu_percent, mem_percent, mem_used_mb, mem_total_mb,
         disk_percent, disk_used_gb, disk_total_gb, net_rx_bytes, net_tx_bytes,
         net_rx_bps, net_tx_bps, disk_read_bps, disk_write_bps, load1,
         cpu_count, swap_percent, fs_readonly, net_ifaces_down, boot_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        instance_id, m["timestamp"], m["cpu_percent"], m["mem_percent"], m["mem_used_mb"],
        m["mem_total_mb"], m["disk_percent"], m["disk_used_gb"], m["disk_total_gb"],
        m["net_rx_bytes"], m["net_tx_bytes"], m["net_rx_bps"], m["net_tx_bps"],
        m["disk_read_bps"], m["disk_write_bps"], m["load1"],
        m["cpu_count"], m["swap_percent"], m["fs_readonly"], m["net_ifaces_down"], m["boot_time"]
    ))
    conn.commit()
    conn.close()


def get_latest(instance_id):
    conn = db()
    row = conn.execute(
        "SELECT * FROM metrics WHERE instance_id = ? ORDER BY id DESC LIMIT 1", (instance_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_history(instance_id, limit=60):
    conn = db()
    rows = conn.execute(
        "SELECT * FROM metrics WHERE instance_id = ? ORDER BY id DESC LIMIT ?", (instance_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in reversed(rows)]


# Numeric columns worth averaging when a requested time range has more raw
# samples than we want to ship to the browser and plot.
HISTORY_NUMERIC_FIELDS = [
    "cpu_percent", "mem_percent", "mem_used_mb", "mem_total_mb",
    "disk_percent", "disk_used_gb", "disk_total_gb",
    "net_rx_bytes", "net_tx_bytes", "net_rx_bps", "net_tx_bps",
    "disk_read_bps", "disk_write_bps", "load1",
]


def _downsample_history(rows, max_points):
    bucket_size = math.ceil(len(rows) / max_points)
    result = []
    for i in range(0, len(rows), bucket_size):
        chunk = rows[i:i + bucket_size]
        bucket = {"timestamp": chunk[-1]["timestamp"], "id": chunk[-1]["id"],
                  "instance_id": chunk[-1]["instance_id"]}
        for field in HISTORY_NUMERIC_FIELDS:
            values = [r[field] for r in chunk if r.get(field) is not None]
            bucket[field] = round(sum(values) / len(values), 2) if values else None
        result.append(bucket)
    return result


def get_history_range(instance_id, seconds, max_points=300):
    """Everything since `seconds` ago, for the dashboard's time-range picker.
    Downsamples (bucket-averaged) to at most `max_points` rows so a 7-day
    view doesn't ship tens of thousands of points to the browser."""
    cutoff = (utcnow() - timedelta(seconds=seconds)).isoformat()
    conn = db()
    rows = conn.execute(
        "SELECT * FROM metrics WHERE instance_id = ? AND timestamp >= ? ORDER BY id ASC",
        (instance_id, cutoff)
    ).fetchall()
    conn.close()
    rows = [dict(r) for r in rows]
    if len(rows) <= max_points:
        return rows
    return _downsample_history(rows, max_points)


def get_thresholds(instance_id):
    conn = db()
    row = conn.execute(
        "SELECT * FROM alert_thresholds WHERE instance_id = ?", (instance_id,)
    ).fetchone()
    conn.close()
    if row:
        return dict(row)
    return {"instance_id": instance_id, "alert_email": None,
            "cpu_warn": None, "cpu_crit": None, "mem_warn": None, "mem_crit": None,
            "disk_warn": None, "disk_crit": None, "net_warn": None, "net_crit": None,
            "diskio_warn": None, "diskio_crit": None}


def alert_label_for(alert_type):
    return ALERT_TYPE_LABELS.get(alert_type) or WEB_ALERT_TYPE_LABELS.get(alert_type) or alert_type


def get_subscriptions(instance_id):
    """VPS subscriptions for one instance."""
    conn = db()
    rows = conn.execute(
        "SELECT * FROM alert_subscriptions WHERE instance_id = ? AND monitor_type = 'vps' ORDER BY id",
        (instance_id,)
    ).fetchall()
    conn.close()
    subs = [dict(r) for r in rows]
    for s in subs:
        s["alert_type_label"] = alert_label_for(s["alert_type"])
    return subs


def get_subscriptions_for_web(target_id):
    conn = db()
    rows = conn.execute(
        "SELECT * FROM alert_subscriptions WHERE instance_id = ? AND monitor_type = 'web' ORDER BY id",
        (target_id,)
    ).fetchall()
    conn.close()
    subs = [dict(r) for r in rows]
    for s in subs:
        s["alert_type_label"] = alert_label_for(s["alert_type"])
    return subs


def get_all_subscriptions():
    """Every subscription of every monitor type, with the target's name resolved.
    A LEFT JOIN against each table so a row is never dropped just because it
    points at the other kind of monitor."""
    conn = db()
    rows = conn.execute("""
        SELECT s.*,
               i.name AS vps_name, i.target_url AS vps_url,
               w.name AS web_name, w.url AS web_url
        FROM alert_subscriptions s
        LEFT JOIN instances   i ON i.id = s.instance_id AND s.monitor_type = 'vps'
        LEFT JOIN web_targets w ON w.id = s.instance_id AND s.monitor_type = 'web'
        ORDER BY s.id
    """).fetchall()
    conn.close()
    subs = []
    for r in rows:
        s = dict(r)
        is_web = s.get("monitor_type") == "web"
        s["target_name"] = (s.pop("web_name") if is_web else s.pop("vps_name")) or f"#{s['instance_id']}"
        s["target_url"] = (s.pop("web_url") if is_web else s.pop("vps_url")) or ""
        s.pop("web_name", None); s.pop("vps_name", None)
        s.pop("web_url", None); s.pop("vps_url", None)
        s["instance_name"] = s["target_name"]          # kept for the existing UI
        s["alert_type_label"] = alert_label_for(s["alert_type"])
        subs.append(s)
    return subs


def emails_for_alert_type(subscriptions, alert_type):
    return sorted({s["email"] for s in subscriptions if s["alert_type"] == alert_type})


# ---------------------------------------------------------------------------
# Event log - a curated, DB-backed trail of what happened (scrape failures,
# severity/health transitions, and a heartbeat every 30s), shown in the
# dashboard's Logs view. Everything here also goes through `logger` above,
# so the full detail (including routine successful scrapes) lives in
# vps_monitor.log even though only the noteworthy stuff is stored here.
# ---------------------------------------------------------------------------
def log_event(level, category, message, instance_id=None, instance_name=None):
    conn = db()
    conn.execute(
        "INSERT INTO event_log (timestamp, instance_id, instance_name, level, category, message) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (utcnow().isoformat(), instance_id, instance_name, level, category, message)
    )
    conn.commit()
    conn.close()

    prefix = f"[{instance_name}] " if instance_name else ""
    {"info": logger.info, "warn": logger.warning, "error": logger.error}[level](f"{prefix}{message}")


def trim_event_log():
    cutoff = (utcnow() - timedelta(days=EVENT_LOG_RETENTION_DAYS)).isoformat()
    conn = db()
    conn.execute("DELETE FROM event_log WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()


def get_logs(instance_id=None, level=None, limit=200):
    limit = max(1, min(limit, 500))
    conn = db()
    query = "SELECT * FROM event_log WHERE 1=1"
    params = []
    if instance_id is not None:
        query += " AND instance_id = ?"
        params.append(instance_id)
    if level:
        query += " AND level = ?"
        params.append(level)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Minimal Prometheus text-format parser
# (node_exporter output looks like: metric_name{label="val"} 123.45)
# ---------------------------------------------------------------------------
def parse_metrics_text(text):
    data = {}
    line_re = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+([-\d.eE+]+)$')
    label_re = re.compile(r'(\w+)="([^"]*)"')

    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = line_re.match(line)
        if not match:
            continue
        name, _, labels_str, value = match.groups()
        labels = dict(label_re.findall(labels_str)) if labels_str else {}
        data.setdefault(name, []).append((labels, float(value)))
    return data


# Per-instance scrape state, keyed by instance_id. CPU, network, and disk I/O
# readings are cumulative counters, so usage %, bandwidth/sec, and disk
# throughput/sec all need the delta between two scrapes.
_prev_state = {}


def compute_rates(parsed, prev, now_mono):
    cpu_lines = parsed.get("node_cpu_seconds_total", [])
    totals, idles = {}, {}
    for labels, value in cpu_lines:
        cpu = labels.get("cpu")
        totals[cpu] = totals.get(cpu, 0) + value
        if labels.get("mode") == "idle":
            idles[cpu] = idles.get(cpu, 0) + value
    total_sum = sum(totals.values())
    idle_sum = sum(idles.values())
    cpu_count = len(totals) or None

    net_rx = sum(v for l, v in parsed.get("node_network_receive_bytes_total", [])
                 if l.get("device") != "lo")
    net_tx = sum(v for l, v in parsed.get("node_network_transmit_bytes_total", [])
                 if l.get("device") != "lo")

    disk_read = sum(v for l, v in parsed.get("node_disk_read_bytes_total", []))
    disk_write = sum(v for l, v in parsed.get("node_disk_written_bytes_total", []))

    cpu_percent = None
    if prev.get("cpu_total") is not None:
        d_total = total_sum - prev["cpu_total"]
        d_idle = idle_sum - prev["cpu_idle"]
        if d_total > 0:
            cpu_percent = round((1 - d_idle / d_total) * 100, 2)

    def rate(curr, prev_val, dt):
        if prev_val is None or dt is None or dt <= 0:
            return None
        d = curr - prev_val
        return round(d / dt, 1) if d >= 0 else None

    dt = (now_mono - prev["net_time"]) if prev.get("net_time") is not None else None
    net_rx_bps = rate(net_rx, prev.get("net_rx"), dt)
    net_tx_bps = rate(net_tx, prev.get("net_tx"), dt)
    disk_read_bps = rate(disk_read, prev.get("disk_read"), dt)
    disk_write_bps = rate(disk_write, prev.get("disk_write"), dt)

    new_state = {
        "cpu_total": total_sum, "cpu_idle": idle_sum,
        "net_rx": net_rx, "net_tx": net_tx,
        "disk_read": disk_read, "disk_write": disk_write,
        "net_time": now_mono,
    }
    return {
        "cpu_percent": cpu_percent,
        "cpu_count": cpu_count,
        "net_rx": net_rx, "net_tx": net_tx,
        "net_rx_bps": net_rx_bps, "net_tx_bps": net_tx_bps,
        "disk_read_bps": disk_read_bps, "disk_write_bps": disk_write_bps,
    }, new_state


def extract_metrics(text, prev, now_mono):
    parsed = parse_metrics_text(text)

    def scalar(name, label_filter=None):
        for labels, value in parsed.get(name, []):
            if label_filter is None or all(labels.get(k) == v for k, v in label_filter.items()):
                return value
        return None

    mem_total = scalar("node_memory_MemTotal_bytes") or 0
    mem_avail = scalar("node_memory_MemAvailable_bytes") or 0
    mem_used = mem_total - mem_avail
    mem_percent = round((mem_used / mem_total) * 100, 2) if mem_total else None

    disk_size = scalar("node_filesystem_size_bytes", {"mountpoint": "/"}) or 0
    disk_avail = scalar("node_filesystem_avail_bytes", {"mountpoint": "/"}) or 0
    disk_used = disk_size - disk_avail
    disk_percent = round((disk_used / disk_size) * 100, 2) if disk_size else None

    swap_total = scalar("node_memory_SwapTotal_bytes")
    swap_free = scalar("node_memory_SwapFree_bytes")
    if swap_total:
        swap_percent = round(((swap_total - (swap_free or 0)) / swap_total) * 100, 2)
    elif swap_total == 0:
        swap_percent = 0.0  # no swap configured - nothing to exhaust
    else:
        swap_percent = None  # metric not exposed at all

    fs_readonly = scalar("node_filesystem_readonly", {"mountpoint": "/"})
    fs_readonly = int(fs_readonly) if fs_readonly is not None else None

    iface_up = parsed.get("node_network_up", [])
    non_loopback = [v for l, v in iface_up if l.get("device") != "lo"]
    net_ifaces_down = sum(1 for v in non_loopback if v == 0) if non_loopback else None

    boot_time = scalar("node_boot_time_seconds")

    rates, new_state = compute_rates(parsed, prev, now_mono)

    metrics = {
        "timestamp": utcnow().isoformat(),
        "cpu_percent": rates["cpu_percent"],
        "cpu_count": rates["cpu_count"],
        "mem_percent": mem_percent,
        "mem_used_mb": round(mem_used / (1024 ** 2), 1) if mem_total else None,
        "mem_total_mb": round(mem_total / (1024 ** 2), 1) if mem_total else None,
        "disk_percent": disk_percent,
        "disk_used_gb": round(disk_used / (1024 ** 3), 2) if disk_size else None,
        "disk_total_gb": round(disk_size / (1024 ** 3), 2) if disk_size else None,
        "net_rx_bytes": rates["net_rx"],
        "net_tx_bytes": rates["net_tx"],
        "net_rx_bps": rates["net_rx_bps"],
        "net_tx_bps": rates["net_tx_bps"],
        "disk_read_bps": rates["disk_read_bps"],
        "disk_write_bps": rates["disk_write_bps"],
        "load1": scalar("node_load1"),
        "swap_percent": swap_percent,
        "fs_readonly": fs_readonly,
        "net_ifaces_down": net_ifaces_down,
        "boot_time": boot_time,
    }
    return metrics, new_state


def set_instance_status(instance_id, status, error=None):
    conn = db()
    conn.execute(
        "UPDATE instances SET last_status = ?, last_error = ?, last_checked_at = ? WHERE id = ?",
        (status, error, utcnow().isoformat(), instance_id)
    )
    conn.commit()
    conn.close()


def normalize_target_url(url):
    """node_exporter serves metrics at /metrics - if the user only gave a
    host:port, fill in the path for them instead of silently collecting
    nothing."""
    parts = urlsplit(url)
    if parts.path in ("", "/"):
        parts = parts._replace(path="/metrics")
    return parts.geturl()


# ---------------------------------------------------------------------------
# Good / Warn / Critical evaluation
# ---------------------------------------------------------------------------
def severity_for(value, warn, crit):
    if value is None:
        return None
    if crit is not None and value >= crit:
        return "critical"
    if warn is not None and value >= warn:
        return "warn"
    return "good"


def evaluate_severity(latest, thresholds):
    """Returns {"overall": ..., "metrics": {cpu: ..., mem: ..., ...}}.
    A metric with no threshold configured (or no data yet) is left out of
    both the per-metric map's contribution to `overall` and doesn't count
    against the instance."""
    per_metric = {}
    worst = None
    for key, (label, unit, getter) in METRIC_DEFS.items():
        value = getter(latest) if latest else None
        sev = severity_for(value, thresholds.get(f"{key}_warn"), thresholds.get(f"{key}_crit"))
        per_metric[key] = sev
        if sev is not None and (worst is None or SEVERITY_RANK[sev] > SEVERITY_RANK[worst]):
            worst = sev
    return {"overall": worst, "metrics": per_metric}


# ---------------------------------------------------------------------------
# Health checklist - pass/fail questions, as distinct from the graduated
# Warn/Critical thresholds above.
# ---------------------------------------------------------------------------
def evaluate_health(inst, history):
    """history is get_history()'s ascending list (oldest..newest) for one
    instance. Returns {check_id: True/False/None} - None means we don't have
    enough data (or this node_exporter build doesn't expose that metric) to
    say either way, so it's excluded from alerting rather than guessed at."""
    checks = {key: None for key in HEALTH_CHECK_DEFS}

    if inst.get("last_status") == "error":
        checks["reachable"] = False
        return checks
    checks["reachable"] = True if inst.get("last_status") == "ok" else None

    if not history:
        return checks
    latest = history[-1]

    if latest.get("net_ifaces_down") is not None:
        checks["net_ifaces"] = latest["net_ifaces_down"] == 0

    if latest.get("fs_readonly") is not None:
        checks["fs_writable"] = latest["fs_readonly"] == 0

    cpu_count, load1 = latest.get("cpu_count"), latest.get("load1")
    if cpu_count and load1 is not None:
        checks["load"] = load1 <= LOAD_WARN_MULTIPLIER * cpu_count

    if latest.get("swap_percent") is not None:
        checks["swap"] = latest["swap_percent"] < SWAP_WARN_PERCENT

    if len(history) >= 2 and latest.get("boot_time") is not None:
        prev_boot = history[-2].get("boot_time")
        if prev_boot is not None:
            checks["reboot"] = abs(latest["boot_time"] - prev_boot) < REBOOT_JITTER_SECONDS

    baseline_rows = history[:-1]
    baseline_samples = [
        r["net_rx_bps"] + r["net_tx_bps"] for r in baseline_rows
        if r.get("net_rx_bps") is not None and r.get("net_tx_bps") is not None
    ]
    if (latest.get("net_rx_bps") is not None and latest.get("net_tx_bps") is not None
            and len(baseline_samples) >= TRAFFIC_ANOMALY_MIN_SAMPLES):
        bw_now = latest["net_rx_bps"] + latest["net_tx_bps"]
        baseline_avg = sum(baseline_samples) / len(baseline_samples)
        limit = max(baseline_avg * TRAFFIC_ANOMALY_MULTIPLIER, TRAFFIC_ANOMALY_FLOOR_BPS)
        checks["traffic"] = bw_now <= limit

    return checks


# Last known health checklist per instance, so we only email on transitions
# (a check newly failing, or newly recovering) rather than every scrape.
_prev_health = {}


def maybe_alert_health(inst, health, subscriptions):
    iid = inst["id"]
    previous = _prev_health.get(iid, {})
    _prev_health[iid] = dict(health)

    for key, val in health.items():
        old = previous.get(key)
        if val is None or old == val:
            continue
        if old is None and val is True:
            continue  # first real reading being healthy isn't a "transition"

        label = ALERT_TYPE_LABELS[key]
        log_event("info" if val else "error", "health",
                  f"{HEALTH_CHECK_DEFS[key]}: {'OK' if val else 'FAILING'}", iid, inst["name"])

        for email in emails_for_alert_type(subscriptions, key):
            if val:
                subject = f"[VPS Monitor] {inst['name']}: {label} - recovered"
                body = f"{inst['name']} ({inst['target_url']}): {HEALTH_CHECK_DEFS[key]} is now OK."
            else:
                subject = f"[VPS Monitor] {inst['name']}: {label} - FAILING"
                body = f"{inst['name']} ({inst['target_url']}): {HEALTH_CHECK_DEFS[key]} is FAILING."
            send_alert_email(email, subject, body)


def send_alert_email(to_addr, subject, body):
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD and to_addr):
        logger.info(f"[alert email skipped - SMTP not configured] {subject}")
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = ALERT_FROM_EMAIL
    msg["To"] = to_addr
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_FROM_EMAIL, [to_addr], msg.as_string())
        logger.info(f"Alert email sent to {to_addr}: {subject}")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")


# Last known per-metric severity per instance, so we email on *transitions*
# (e.g. good -> warn, warn -> critical, critical -> good) instead of every
# single scrape while a problem is ongoing.
_prev_severity = {}


def maybe_alert(inst, metrics, thresholds, subscriptions):
    result = evaluate_severity(metrics, thresholds)
    iid = inst["id"]
    previous = _prev_severity.get(iid, {})
    _prev_severity[iid] = dict(result["metrics"])

    for key, (label, unit, getter) in METRIC_DEFS.items():
        sev = result["metrics"].get(key)
        old = previous.get(key)
        if sev is None or sev == old:
            continue
        if old is None and sev == "good":
            continue  # first real reading being fine isn't a "transition"

        value = getter(metrics)
        alert_label = ALERT_TYPE_LABELS[key]
        log_level = {"good": "info", "warn": "warn", "critical": "error"}[sev]
        log_event(log_level, "severity", f"{label}: {sev.upper()} ({value}{unit})", iid, inst["name"])

        for email in emails_for_alert_type(subscriptions, key):
            if sev == "good":
                subject = f"[VPS Monitor] {inst['name']}: {alert_label} - recovered"
                body = f"{inst['name']} ({inst['target_url']}): {label} is back to normal ({value}{unit})."
            else:
                subject = f"[VPS Monitor] {inst['name']}: {alert_label} - {sev.upper()}"
                body = (f"{inst['name']} ({inst['target_url']}): {label} is {sev.upper()} "
                        f"at {value}{unit} (warn={thresholds.get(key + '_warn')}, "
                        f"crit={thresholds.get(key + '_crit')}).")
            send_alert_email(email, subject, body)


# ---------------------------------------------------------------------------
# Website monitoring
#
# Unlike the VPS side there is no agent on the far end - everything is
# observed from outside, the same way an ordinary visitor sees the site.
# ---------------------------------------------------------------------------
def get_web_targets():
    conn = db()
    rows = conn.execute("SELECT * FROM web_targets ORDER BY id").fetchall()
    conn.close()
    targets = [dict(r) for r in rows]
    for t in targets:
        t["health"] = evaluate_web_health(t, get_web_latest(t["id"]))
        t["severity"] = {"overall": web_overall_severity(t)}
    return targets


def get_web_target(target_id):
    conn = db()
    row = conn.execute("SELECT * FROM web_targets WHERE id = ?", (target_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_web_latest(target_id):
    conn = db()
    row = conn.execute(
        "SELECT * FROM web_checks WHERE target_id = ? ORDER BY id DESC LIMIT 1", (target_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_web_history(target_id, seconds=None, limit=200):
    conn = db()
    if seconds:
        cutoff = (utcnow() - timedelta(seconds=seconds)).isoformat()
        rows = conn.execute(
            "SELECT * FROM web_checks WHERE target_id = ? AND timestamp >= ? ORDER BY id ASC",
            (target_id, cutoff)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM web_checks WHERE target_id = ? ORDER BY id DESC LIMIT ?",
            (target_id, limit)
        ).fetchall()
        rows = list(reversed(rows))
    conn.close()
    return [dict(r) for r in rows]


def normalize_web_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    if not re.match(r'^https?://', url, re.I):
        url = "https://" + url          # default to HTTPS, not HTTP
    return url


def _ca_bundle():
    """Verify against the same CA bundle requests uses. Relying on the OS trust
    store instead makes cert_valid disagree with the HTTP check on any machine
    whose root store is behind - which shows up as phantom 'invalid
    certificate' alerts for sites that are actually fine."""
    try:
        import certifi
        return certifi.where()
    except Exception:
        return None


def _tls_info(hostname, port=443):
    """(days_until_expiry, is_valid). Falls back to an unverified handshake so
    an expired or self-signed certificate still reports its dates instead of
    just failing - that distinction is the whole point of the check."""
    try:
        ctx = ssl.create_default_context(cafile=_ca_bundle())
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10),
                             server_hostname=hostname) as s:
            der = s.getpeercert(binary_form=True)
        valid = True
    except Exception:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10),
                                 server_hostname=hostname) as s:
                der = s.getpeercert(binary_form=True)
            valid = False
        except Exception:
            return None, None
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        days = (cert.not_valid_after_utc.replace(tzinfo=None) - utcnow()).total_seconds() / 86400
        return round(days, 1), valid
    except Exception:
        return None, valid


def check_web_target(target):
    """One pass over a single website. Never raises - a failure is a result."""
    url = target["url"]
    parts = urlsplit(url)
    host = parts.hostname or ""
    result = {"target_id": target["id"], "timestamp": utcnow().isoformat(), "ok": 0,
              "status_code": None, "response_ms": None, "resolved_ip": None,
              "cert_days": None, "cert_valid": None, "keyword_ok": None,
              "final_url": None, "error": None}

    try:
        result["resolved_ip"] = socket.gethostbyname(host)
    except Exception as e:
        result["error"] = f"DNS lookup failed: {e}"
        return result

    started = time.monotonic()
    try:
        resp = requests.get(url, timeout=WEB_CHECK_TIMEOUT_SECONDS, allow_redirects=True,
                            headers={"User-Agent": "vpsmon-uptime/1.0 (+website monitoring)"})
        result["response_ms"] = round((time.monotonic() - started) * 1000, 1)
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        expected = target.get("expected_status")
        result["ok"] = 1 if (resp.status_code == expected if expected else resp.status_code < 400) else 0
        if target.get("keyword"):
            result["keyword_ok"] = 1 if target["keyword"].lower() in resp.text.lower() else 0
        if not result["ok"]:
            result["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        result["response_ms"] = round((time.monotonic() - started) * 1000, 1)
        result["error"] = f"{type(e).__name__}: {e}"

    if parts.scheme == "https":
        days, valid = _tls_info(host, parts.port or 443)
        result["cert_days"] = days
        result["cert_valid"] = None if valid is None else (1 if valid else 0)
    return result


def save_web_check(result):
    conn = db()
    conn.execute("""
        INSERT INTO web_checks (target_id, timestamp, ok, status_code, response_ms,
                                resolved_ip, cert_days, cert_valid, keyword_ok, final_url, error)
        VALUES (:target_id, :timestamp, :ok, :status_code, :response_ms,
                :resolved_ip, :cert_days, :cert_valid, :keyword_ok, :final_url, :error)
    """, result)
    conn.commit()
    conn.close()


def evaluate_web_health(target, latest):
    """True / False / None per check, same convention as the VPS checklist:
    None means we cannot say yet, and never counts against the target."""
    checks = {k: None for k in WEB_CHECK_DEFS}
    if not latest:
        return checks

    checks["reachable"] = bool(latest.get("status_code")) and not latest.get("error", "").startswith("DNS") \
        if latest.get("error") else bool(latest.get("status_code"))
    if latest.get("status_code") is None:
        checks["reachable"] = False

    if latest.get("status_code") is not None:
        checks["status"] = bool(latest.get("ok"))

    slow_ms = target.get("slow_ms") or WEB_SLOW_MS_DEFAULT
    if latest.get("response_ms") is not None and latest.get("status_code") is not None:
        checks["speed"] = latest["response_ms"] <= slow_ms

    if latest.get("cert_valid") is not None:
        checks["cert_valid"] = bool(latest["cert_valid"])
    if latest.get("cert_days") is not None:
        warn = target.get("cert_warn_days") or WEB_CERT_WARN_DAYS
        checks["cert_fresh"] = latest["cert_days"] >= warn

    if target.get("last_ip") and latest.get("resolved_ip"):
        checks["ip_stable"] = target["last_ip"] == latest["resolved_ip"]

    if latest.get("keyword_ok") is not None:
        checks["keyword"] = bool(latest["keyword_ok"])
    return checks


def web_overall_severity(target):
    h = target.get("health") or {}
    if h.get("reachable") is False or h.get("status") is False or h.get("cert_valid") is False:
        return "critical"
    if False in (h.get("speed"), h.get("cert_fresh"), h.get("ip_stable"), h.get("keyword")):
        return "warn"
    if any(v is True for v in h.values()):
        return "good"
    return None


# Previous per-check state, so website alerts are edge-triggered like the rest.
_prev_web_health = {}

# Which alert type corresponds to each failing website check.
WEB_CHECK_ALERT = {
    "reachable": "web_down",
    "status": "web_status",
    "speed": "web_slow",
    "cert_valid": "web_cert_invalid",
    "cert_fresh": "web_cert_expiring",
    "ip_stable": "web_ip_changed",
    "keyword": "web_keyword_missing",
}


def maybe_alert_web(target, health, subscriptions, latest):
    tid = target["id"]
    previous = _prev_web_health.get(tid, {})
    _prev_web_health[tid] = dict(health)

    for key, val in health.items():
        old = previous.get(key)
        if val is None or old == val:
            continue
        if old is None and val is True:
            continue

        alert_type = WEB_CHECK_ALERT[key]
        label = WEB_ALERT_TYPE_LABELS[alert_type]
        log_event("info" if val else "error", "web",
                  f"{WEB_CHECK_DEFS[key]}: {'OK' if val else 'FAILING'}", None, target["name"])

        detail = ""
        if key == "ip_stable" and latest:
            detail = f" ({target.get('last_ip')} -> {latest.get('resolved_ip')})"
        elif key == "cert_fresh" and latest and latest.get("cert_days") is not None:
            detail = f" ({latest['cert_days']:.0f} days left)"
        elif key == "speed" and latest and latest.get("response_ms") is not None:
            detail = f" ({latest['response_ms']:.0f} ms)"
        elif key in ("status", "reachable") and latest:
            detail = f" ({latest.get('error') or 'HTTP ' + str(latest.get('status_code'))})"

        for email in emails_for_alert_type(subscriptions, alert_type):
            if val:
                subject = f"[VPS Monitor] {target['name']}: {label} - recovered"
                body = f"{target['name']} ({target['url']}): {WEB_CHECK_DEFS[key]} is OK again{detail}."
            else:
                subject = f"[VPS Monitor] {target['name']}: {label}"
                body = f"{target['name']} ({target['url']}): {WEB_CHECK_DEFS[key]} is FAILING{detail}."
            send_alert_email(email, subject, body)


def trim_web_checks():
    cutoff = (utcnow() - timedelta(days=WEB_CHECK_RETENTION_DAYS)).isoformat()
    conn = db()
    conn.execute("DELETE FROM web_checks WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()


def web_check_loop():
    while True:
        for target in get_web_targets():
            if not target.get("enabled"):
                continue
            tid = target["id"]
            try:
                result = check_web_target(target)
                save_web_check(result)

                status = "ok" if result["ok"] else "error"
                conn = db()
                conn.execute(
                    "UPDATE web_targets SET last_status=?, last_error=?, last_checked_at=?, last_ip=? "
                    "WHERE id=?",
                    (status, result["error"], result["timestamp"], result["resolved_ip"], tid)
                )
                conn.commit()
                conn.close()

                logger.info(
                    f"[web:{target['name']}] {result['status_code'] or '-'} "
                    f"{result['response_ms'] or '-'}ms ip={result['resolved_ip'] or '-'} "
                    f"cert={result['cert_days'] or '-'}d"
                )

                fresh = get_web_target(tid)
                fresh["health"] = evaluate_web_health(target, result)
                maybe_alert_web(fresh, fresh["health"], get_subscriptions_for_web(tid), result)
            except Exception as e:
                logger.error(f"web check failed for {target['name']}: {e}")
        trim_web_checks()
        time.sleep(WEB_CHECK_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Background scraper thread (this is your "Prometheus scrape loop")
# Loops over every configured instance each cycle.
# ---------------------------------------------------------------------------
def scrape_loop():
    while True:
        for inst in get_instances(include_secrets=True):
            iid = inst["id"]
            try:
                auth = (inst["auth_username"], inst["auth_password"]) if inst.get("auth_username") else None
                resp = requests.get(inst["target_url"], timeout=5, auth=auth)
                resp.raise_for_status()
                prev = _prev_state.get(iid, {})
                metrics, new_state = extract_metrics(resp.text, prev, time.monotonic())
                _prev_state[iid] = new_state
                if metrics["cpu_percent"] is not None:  # skip first sample (no delta yet)
                    save_metrics(iid, metrics)
                    logger.info(f"[{inst['name']}] CPU {metrics['cpu_percent']}% | "
                                f"MEM {metrics['mem_percent']}% | DISK {metrics['disk_percent']}% | "
                                f"NET {metrics['net_rx_bps']}/{metrics['net_tx_bps']} B/s | "
                                f"DISKIO {metrics['disk_read_bps']}/{metrics['disk_write_bps']} B/s")
                    set_instance_status(iid, "ok")
                    thresholds = get_thresholds(iid)
                    subscriptions = get_subscriptions(iid)
                    maybe_alert(inst, metrics, thresholds, subscriptions)
                    inst["last_status"] = "ok"
                    health = evaluate_health(inst, get_history(iid, limit=30))
                    maybe_alert_health(inst, health, subscriptions)
                else:
                    set_instance_status(iid, "pending")
            except Exception as e:
                log_event("error", "scrape", f"Scrape failed: {e}", iid, inst["name"])
                set_instance_status(iid, "error", str(e))
                inst["last_status"] = "error"
                health = evaluate_health(inst, [])
                maybe_alert_health(inst, health, get_subscriptions(iid))
        time.sleep(SCRAPE_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Heartbeat thread - independent of the 10s scrape cycle, this checks every
# HEARTBEAT_INTERVAL_SECONDS whether things are still okay and writes one
# log line per instance either way, so "is it actually working" has a
# continuous trail instead of only showing up when something changes.
# ---------------------------------------------------------------------------
def heartbeat_loop():
    while True:
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)
        for inst in get_instances():
            iid = inst["id"]
            severity = inst["severity"]["overall"]
            health = inst["health"]
            failing = [HEALTH_CHECK_DEFS[k] for k, v in health.items() if v is False]
            known = sum(1 for v in health.values() if v is not None)

            if inst["last_status"] == "error":
                level = "error"
                message = f"Heartbeat: unreachable ({inst.get('last_error') or 'unknown error'})"
            elif failing:
                level = "error" if severity == "critical" else "warn"
                message = f"Heartbeat: {severity or 'unknown'} - failing: {', '.join(failing)}"
            elif severity == "critical":
                level = "error"
                message = "Heartbeat: critical"
            elif severity == "warn":
                level = "warn"
                message = "Heartbeat: warn"
            else:
                level = "info"
                message = f"Heartbeat: good ({known}/{len(HEALTH_CHECK_DEFS)} health checks known, all passing)"

            log_event(level, "heartbeat", message, iid, inst["name"])
        trim_event_log()
        trim_audit_log()


# ---------------------------------------------------------------------------
# Web routes (this is your "Grafana")
# ---------------------------------------------------------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/instances", methods=["GET"])
def api_instances_list():
    return jsonify(get_instances())


@app.route("/api/instances", methods=["POST"])
def api_instances_create():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    url = (data.get("target_url") or "").strip()
    auth_username = (data.get("auth_username") or "").strip() or None
    auth_password = (data.get("auth_password") or "").strip() or None

    if not name or not url:
        return jsonify({"error": "name and target_url are required"}), 400
    if not re.match(r'^https?://', url):
        return jsonify({"error": "target_url must start with http:// or https://"}), 400

    url = normalize_target_url(url)

    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO instances (name, target_url, created_at, auth_username, auth_password) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, url, utcnow().isoformat(), auth_username, auth_password)
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "an instance with this target_url already exists"}), 409
    conn.close()
    log_audit("instance.create", target=name,
              details=f"{url}{' (basic auth)' if auth_username else ''}")
    return jsonify({"id": new_id, "name": name, "target_url": url}), 201


@app.route("/api/instances/<int:instance_id>", methods=["PATCH"])
def api_instances_update(instance_id):
    data = request.get_json(force=True, silent=True) or {}
    conn = db()
    row = conn.execute("SELECT * FROM instances WHERE id = ?", (instance_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "instance not found"}), 404

    name = (data.get("name") or "").strip() or row["name"]

    url = row["target_url"]
    if (data.get("target_url") or "").strip():
        url = data["target_url"].strip()
        if not re.match(r'^https?://', url):
            conn.close()
            return jsonify({"error": "target_url must start with http:// or https://"}), 400
        url = normalize_target_url(url)

    # auth_username absent from the payload = leave auth untouched. Present
    # but empty = clear it. Present and non-empty = set/replace it; a blank
    # auth_password alongside a *changed* username still just keeps whatever
    # password was already there (there's no separate "change password only"
    # affordance - re-entering the username is enough to also require the
    # password if the goal is actually to change it).
    auth_username, auth_password = row["auth_username"], row["auth_password"]
    if "auth_username" in data:
        new_username = (data.get("auth_username") or "").strip()
        if not new_username:
            auth_username, auth_password = None, None
        else:
            auth_username = new_username
            new_password = (data.get("auth_password") or "").strip()
            if new_password:
                auth_password = new_password

    try:
        conn.execute(
            "UPDATE instances SET name = ?, target_url = ?, auth_username = ?, auth_password = ? WHERE id = ?",
            (name, url, auth_username, auth_password, instance_id)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "an instance with this target_url already exists"}), 409
    conn.close()

    changed = []
    if name != row["name"]:
        changed.append(f"name: {row['name']} -> {name}")
    if url != row["target_url"]:
        changed.append(f"url: {row['target_url']} -> {url}")
    if auth_username != row["auth_username"]:
        changed.append(f"basic auth user: {row['auth_username'] or 'none'} -> {auth_username or 'none'}")
    elif auth_password != row["auth_password"]:
        changed.append("basic auth password changed")
    log_audit("instance.update", target=name, details="; ".join(changed) or "no effective change")
    return jsonify({"ok": True})


@app.route("/api/instances/<int:instance_id>", methods=["DELETE"])
def api_instances_delete(instance_id):
    doomed = next((i for i in get_instances() if i["id"] == instance_id), None)
    conn = db()
    conn.execute("DELETE FROM instances WHERE id = ?", (instance_id,))
    conn.execute("DELETE FROM metrics WHERE instance_id = ?", (instance_id,))
    conn.execute("DELETE FROM alert_thresholds WHERE instance_id = ?", (instance_id,))
    conn.execute("DELETE FROM alert_subscriptions WHERE instance_id = ?", (instance_id,))
    conn.commit()
    conn.close()
    _prev_state.pop(instance_id, None)
    _prev_severity.pop(instance_id, None)
    _prev_health.pop(instance_id, None)
    log_audit("instance.delete", target=doomed["name"] if doomed else f"id={instance_id}",
              details="instance and all of its history removed")
    return jsonify({"ok": True})


@app.route("/api/metrics/latest")
def api_latest():
    instance_id = request.args.get("instance_id", type=int)
    if instance_id is None:
        return jsonify(None)
    return jsonify(get_latest(instance_id))


@app.route("/api/metrics/history")
def api_history():
    instance_id = request.args.get("instance_id", type=int)
    if instance_id is None:
        return jsonify([])
    range_seconds = request.args.get("range_seconds", type=int)
    if range_seconds:
        return jsonify(get_history_range(instance_id, range_seconds))
    return jsonify(get_history(instance_id, limit=60))


@app.route("/api/thresholds")
def api_thresholds_get():
    instance_id = request.args.get("instance_id", type=int)
    return jsonify(get_thresholds(instance_id))


@app.route("/api/thresholds", methods=["POST"])
def api_thresholds_set():
    data = request.get_json(force=True, silent=True) or {}
    instance_id = data.get("instance_id")
    if not instance_id:
        return jsonify({"error": "instance_id is required"}), 400

    def clean(v):
        return float(v) if v not in (None, "") else None

    values = {"instance_id": instance_id}
    for key in METRIC_DEFS:
        values[f"{key}_warn"] = clean(data.get(f"{key}_warn"))
        values[f"{key}_crit"] = clean(data.get(f"{key}_crit"))

    conn = db()
    conn.execute("""
        INSERT INTO alert_thresholds
            (instance_id, cpu_warn, cpu_crit, mem_warn, mem_crit,
             disk_warn, disk_crit, net_warn, net_crit, diskio_warn, diskio_crit)
        VALUES (:instance_id, :cpu_warn, :cpu_crit, :mem_warn, :mem_crit,
                :disk_warn, :disk_crit, :net_warn, :net_crit, :diskio_warn, :diskio_crit)
        ON CONFLICT(instance_id) DO UPDATE SET
            cpu_warn = excluded.cpu_warn, cpu_crit = excluded.cpu_crit,
            mem_warn = excluded.mem_warn, mem_crit = excluded.mem_crit,
            disk_warn = excluded.disk_warn, disk_crit = excluded.disk_crit,
            net_warn = excluded.net_warn, net_crit = excluded.net_crit,
            diskio_warn = excluded.diskio_warn, diskio_crit = excluded.diskio_crit
    """, values)
    conn.commit()
    conn.close()

    inst = next((i for i in get_instances() if i["id"] == instance_id), None)
    summary = ", ".join(
        f"{key}={values[f'{key}_warn'] if values[f'{key}_warn'] is not None else '-'}"
        f"/{values[f'{key}_crit'] if values[f'{key}_crit'] is not None else '-'}"
        for key in METRIC_DEFS
    )
    log_audit("thresholds.update", target=inst["name"] if inst else f"instance {instance_id}",
              details=f"warn/crit -> {summary}")
    return jsonify({"ok": True})


@app.route("/api/alert-types")
def api_alert_types():
    monitor_type = request.args.get("monitor_type", "vps")
    table = WEB_ALERT_TYPE_LABELS if monitor_type == "web" else ALERT_TYPE_LABELS
    return jsonify([{"key": k, "label": v} for k, v in table.items()])


# ---------------------------------------------------------------------------
# Website monitoring
# ---------------------------------------------------------------------------
@app.route("/api/web-targets")
def api_web_targets_list():
    targets = get_web_targets()
    for t in targets:
        t["latest"] = get_web_latest(t["id"])
    return jsonify(targets)


@app.route("/api/web-targets", methods=["POST"])
def api_web_targets_create():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    url = normalize_web_url(data.get("url"))

    if not name or not url:
        return jsonify({"error": "name and url are required"}), 400
    if not urlsplit(url).hostname:
        return jsonify({"error": "that does not look like a valid URL"}), 400

    def opt_int(key):
        v = data.get(key)
        try:
            return int(v) if v not in (None, "") else None
        except (TypeError, ValueError):
            return None

    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO web_targets (name, url, expected_status, keyword, slow_ms, "
            "cert_warn_days, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (name, url, opt_int("expected_status"), (data.get("keyword") or "").strip() or None,
             opt_int("slow_ms"), opt_int("cert_warn_days"), utcnow().isoformat())
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "that URL is already being monitored"}), 409
    conn.close()
    log_audit("web.create", target=name, details=url)
    return jsonify({"id": new_id, "name": name, "url": url}), 201


@app.route("/api/web-targets/<int:target_id>", methods=["PATCH"])
def api_web_targets_update(target_id):
    data = request.get_json(force=True, silent=True) or {}
    row = get_web_target(target_id)
    if not row:
        return jsonify({"error": "website not found"}), 404

    name = (data.get("name") or "").strip() or row["name"]
    url = normalize_web_url(data.get("url")) or row["url"]
    enabled = 1 if data.get("enabled", row["enabled"]) else 0

    def pick(key):
        if key not in data:
            return row[key]
        v = data.get(key)
        try:
            return int(v) if v not in (None, "") else None
        except (TypeError, ValueError):
            return None

    keyword = (data.get("keyword") if "keyword" in data else row["keyword"]) or None
    conn = db()
    try:
        conn.execute(
            "UPDATE web_targets SET name=?, url=?, expected_status=?, keyword=?, slow_ms=?, "
            "cert_warn_days=?, enabled=? WHERE id=?",
            (name, url, pick("expected_status"), keyword, pick("slow_ms"),
             pick("cert_warn_days"), enabled, target_id)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "another website already uses that URL"}), 409
    conn.close()
    log_audit("web.update", target=name, details=url)
    return jsonify({"ok": True})


@app.route("/api/web-targets/<int:target_id>", methods=["DELETE"])
def api_web_targets_delete(target_id):
    row = get_web_target(target_id)
    conn = db()
    conn.execute("DELETE FROM web_targets WHERE id = ?", (target_id,))
    conn.execute("DELETE FROM web_checks WHERE target_id = ?", (target_id,))
    conn.execute("DELETE FROM alert_subscriptions WHERE instance_id = ? AND monitor_type = 'web'",
                 (target_id,))
    conn.commit()
    conn.close()
    _prev_web_health.pop(target_id, None)
    log_audit("web.delete", target=row["name"] if row else f"id={target_id}")
    return jsonify({"ok": True})


@app.route("/api/web-checks/latest")
def api_web_latest():
    target_id = request.args.get("target_id", type=int)
    if target_id is None:
        return jsonify(None)
    return jsonify(get_web_latest(target_id))


@app.route("/api/web-checks/history")
def api_web_history():
    target_id = request.args.get("target_id", type=int)
    if target_id is None:
        return jsonify([])
    return jsonify(get_web_history(target_id,
                                    seconds=request.args.get("range_seconds", type=int),
                                    limit=request.args.get("limit", default=200, type=int)))


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------
@app.route("/api/me")
def api_me():
    user = current_user()
    return jsonify({"id": user["id"], "username": user["username"],
                     "role": user["role"], "is_admin": user["role"] == ROLE_ADMIN})


@app.route("/api/users")
def api_users_list():
    if not is_admin():
        return jsonify({"error": "admin role required"}), 403
    return jsonify(list_users())


@app.route("/api/users", methods=["POST"])
def api_users_create():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or ROLE_VIEWER).strip()

    if not username or not re.match(r'^[A-Za-z0-9._-]{3,32}$', username):
        return jsonify({"error": "username must be 3-32 chars (letters, digits, . _ -)"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if role not in ROLES:
        return jsonify({"error": f"role must be one of: {', '.join(ROLES)}"}), 400

    try:
        new_id = create_user(username, password, role)
    except sqlite3.IntegrityError:
        return jsonify({"error": "that username is already taken"}), 409

    log_audit("user.create", target=username, details=f"role={role}")
    return jsonify({"id": new_id, "username": username, "role": role}), 201


@app.route("/api/users/<int:user_id>", methods=["PATCH"])
def api_users_update(user_id):
    data = request.get_json(force=True, silent=True) or {}
    target = get_user(user_id)
    if not target:
        return jsonify({"error": "user not found"}), 404

    changes = []

    if "role" in data:
        role = (data.get("role") or "").strip()
        if role not in ROLES:
            return jsonify({"error": f"role must be one of: {', '.join(ROLES)}"}), 400
        # Don't allow demoting the last remaining admin - that would lock
        # everyone out of user management with no way back in.
        if target["role"] == ROLE_ADMIN and role != ROLE_ADMIN and count_admins(user_id) == 0:
            return jsonify({"error": "cannot demote the last admin account"}), 400
        conn = db()
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
        conn.close()
        changes.append(f"role={role}")

    if "is_active" in data:
        active = 1 if data.get("is_active") else 0
        if not active and target["role"] == ROLE_ADMIN and count_admins(user_id) == 0:
            return jsonify({"error": "cannot disable the last admin account"}), 400
        conn = db()
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (active, user_id))
        conn.commit()
        conn.close()
        changes.append("enabled" if active else "disabled")

    if data.get("password"):
        if len(data["password"]) < 8:
            return jsonify({"error": "password must be at least 8 characters"}), 400
        update_user_password(user_id, data["password"])
        changes.append("password reset")

    if not changes:
        return jsonify({"error": "nothing to update"}), 400

    log_audit("user.update", target=target["username"], details=", ".join(changes))
    return jsonify({"ok": True})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def api_users_delete(user_id):
    target = get_user(user_id)
    if not target:
        return jsonify({"error": "user not found"}), 404

    me = current_user()
    if me and me["id"] == user_id:
        return jsonify({"error": "you cannot delete your own account"}), 400
    if target["role"] == ROLE_ADMIN and count_admins(user_id) == 0:
        return jsonify({"error": "cannot delete the last admin account"}), 400

    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    log_audit("user.delete", target=target["username"])
    return jsonify({"ok": True})


@app.route("/api/users/me/password", methods=["POST"])
def api_change_own_password():
    data = request.get_json(force=True, silent=True) or {}
    user = current_user()
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""

    if not check_password_hash(user["password_hash"], current_password):
        log_audit("password.change_failed", target=user["username"],
                   details="current password incorrect")
        return jsonify({"error": "current password is incorrect"}), 403
    if len(new_password) < 8:
        return jsonify({"error": "new password must be at least 8 characters"}), 400

    update_user_password(user["id"], new_password)
    log_audit("password.changed", target=user["username"])
    return jsonify({"ok": True})


@app.route("/api/audit")
def api_audit():
    if not is_admin():
        return jsonify({"error": "admin role required"}), 403
    return jsonify(get_audit_log(
        limit=request.args.get("limit", default=200, type=int),
        username=request.args.get("username") or None,
        action=request.args.get("action") or None,
    ))


@app.route("/api/logs")
def api_logs():
    instance_id = request.args.get("instance_id", type=int)
    level = request.args.get("level") or None
    limit = request.args.get("limit", default=200, type=int)
    return jsonify(get_logs(instance_id=instance_id, level=level, limit=limit))


@app.route("/api/subscriptions")
def api_subscriptions_list():
    instance_id = request.args.get("instance_id", type=int)
    if instance_id is not None:
        return jsonify(get_subscriptions(instance_id))
    return jsonify(get_all_subscriptions())


@app.route("/api/subscriptions", methods=["POST"])
def api_subscriptions_create():
    data = request.get_json(force=True, silent=True) or {}
    instance_id = data.get("instance_id")
    email = (data.get("email") or "").strip()
    alert_type = (data.get("alert_type") or "").strip()

    monitor_type = (data.get("monitor_type") or "vps").strip()

    if not instance_id:
        return jsonify({"error": "a target is required"}), 400
    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({"error": "a valid email is required"}), 400
    if monitor_type not in ("vps", "web"):
        return jsonify({"error": "monitor_type must be vps or web"}), 400

    valid_types = WEB_ALERT_TYPE_LABELS if monitor_type == "web" else ALERT_TYPE_LABELS
    if alert_type not in valid_types:
        return jsonify({"error": f"unknown alert_type for a {monitor_type} monitor"}), 400

    if monitor_type == "web":
        target = get_web_target(instance_id)
        target_name = target["name"] if target else None
    else:
        target = next((i for i in get_instances() if i["id"] == instance_id), None)
        target_name = target["name"] if target else None
    if not target:
        return jsonify({"error": "that target does not exist"}), 404

    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO alert_subscriptions (instance_id, email, alert_type, created_at, monitor_type) "
            "VALUES (?, ?, ?, ?, ?)",
            (instance_id, email, alert_type, utcnow().isoformat(), monitor_type)
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "that email is already subscribed to this alert"}), 409
    conn.close()
    log_audit("subscription.create", target=email,
              details=f"{valid_types[alert_type]} on {target_name} ({monitor_type})")
    return jsonify({"id": new_id, "instance_id": instance_id, "email": email,
                     "monitor_type": monitor_type, "alert_type": alert_type,
                     "alert_type_label": valid_types[alert_type]}), 201


@app.route("/api/subscriptions/<int:sub_id>", methods=["DELETE"])
def api_subscriptions_delete(sub_id):
    conn = db()
    row = conn.execute("SELECT * FROM alert_subscriptions WHERE id = ?", (sub_id,)).fetchone()
    conn.execute("DELETE FROM alert_subscriptions WHERE id = ?", (sub_id,))
    conn.commit()
    conn.close()
    if row:
        log_audit("subscription.delete", target=row["email"],
                  details=ALERT_TYPE_LABELS.get(row["alert_type"], row["alert_type"]))
    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    mark_server_start()
    threading.Thread(target=scrape_loop, daemon=True).start()
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    threading.Thread(target=web_check_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)

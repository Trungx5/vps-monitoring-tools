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
import sqlite3
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


def get_subscriptions(instance_id):
    conn = db()
    rows = conn.execute(
        "SELECT * FROM alert_subscriptions WHERE instance_id = ? ORDER BY id", (instance_id,)
    ).fetchall()
    conn.close()
    subs = [dict(r) for r in rows]
    for s in subs:
        s["alert_type_label"] = ALERT_TYPE_LABELS.get(s["alert_type"], s["alert_type"])
    return subs


def get_all_subscriptions():
    """Every subscription across every instance, with the instance's name
    joined in - the data behind the Alerts page's global recipients table."""
    conn = db()
    rows = conn.execute("""
        SELECT s.*, i.name AS instance_name, i.target_url AS instance_url
        FROM alert_subscriptions s
        JOIN instances i ON i.id = s.instance_id
        ORDER BY s.id
    """).fetchall()
    conn.close()
    subs = [dict(r) for r in rows]
    for s in subs:
        s["alert_type_label"] = ALERT_TYPE_LABELS.get(s["alert_type"], s["alert_type"])
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
    return jsonify([{"key": k, "label": v} for k, v in ALERT_TYPE_LABELS.items()])


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

    if not instance_id:
        return jsonify({"error": "instance_id is required"}), 400
    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({"error": "a valid email is required"}), 400
    if alert_type not in ALERT_TYPE_LABELS:
        return jsonify({"error": "unknown alert_type"}), 400

    conn = db()
    try:
        cur = conn.execute(
            "INSERT INTO alert_subscriptions (instance_id, email, alert_type, created_at) "
            "VALUES (?, ?, ?, ?)",
            (instance_id, email, alert_type, utcnow().isoformat())
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "that email is already subscribed to this alert"}), 409
    conn.close()
    inst = next((i for i in get_instances() if i["id"] == instance_id), None)
    log_audit("subscription.create", target=email,
              details=f"{ALERT_TYPE_LABELS[alert_type]} on {inst['name'] if inst else instance_id}")
    return jsonify({"id": new_id, "instance_id": instance_id, "email": email,
                     "alert_type": alert_type, "alert_type_label": ALERT_TYPE_LABELS[alert_type]}), 201


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
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)

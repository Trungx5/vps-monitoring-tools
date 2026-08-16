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
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler
from urllib.parse import urlsplit

import requests
from flask import Flask, jsonify, redirect, render_template, request, session, url_for

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Used only to seed the first ("Default") instance the very first time the
# app runs. After that, instances live in the `instances` table and are
# managed from the dashboard's sidebar.
DEFAULT_TARGET_URL = "http://54.90.214.41:9100/metrics"
SCRAPE_INTERVAL_SECONDS = 10
HEARTBEAT_INTERVAL_SECONDS = 30
EVENT_LOG_RETENTION_DAYS = 3
DB_PATH = "metrics.db"
LOG_FILE_PATH = "vps_monitor.log"

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
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ---------------------------------------------------------------------------
# Login - gates the whole app (dashboard + every /api/* route) behind a
# single admin account. No user database: credentials come from environment
# variables, or a random one-off password printed at startup.
# ---------------------------------------------------------------------------
APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD")
if not APP_PASSWORD:
    APP_PASSWORD = secrets.token_urlsafe(9)
    print("=" * 64)
    print("No APP_PASSWORD set - generated a login for this run only:")
    print(f"    username: {APP_USERNAME}")
    print(f"    password: {APP_PASSWORD}")
    print("Set APP_USERNAME / APP_PASSWORD env vars for a fixed login that")
    print("survives restarts.")
    print("=" * 64)

# Regenerated every time the process starts, and required (alongside
# "logged_in") for a session to be considered valid. This forces everyone to
# sign in again after every restart, even if SECRET_KEY is fixed and would
# otherwise let old session cookies keep working.
BOOT_ID = secrets.token_hex(8)

PUBLIC_ENDPOINTS = {"login", "static"}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
_login_attempts = {}  # ip -> [failure timestamps]


def _too_many_attempts(ip):
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def _record_failed_attempt(ip):
    _login_attempts.setdefault(ip, []).append(time.time())


@app.before_request
def require_login():
    if request.endpoint in PUBLIC_ENDPOINTS or request.endpoint is None:
        return
    if session.get("logged_in") and session.get("boot_id") == BOOT_ID:
        return
    if request.path.startswith("/api/"):
        return jsonify({"error": "authentication required"}), 401
    return redirect(url_for("login", next=request.path))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        if _too_many_attempts(ip):
            error = "Too many failed attempts. Try again in a few minutes."
        else:
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if username == APP_USERNAME and secrets.compare_digest(password, APP_PASSWORD):
                session.clear()
                session["logged_in"] = True
                session["username"] = username
                session["boot_id"] = BOOT_ID
                next_path = request.args.get("next") or "/"
                if not next_path.startswith("/"):
                    next_path = "/"
                return redirect(next_path)
            _record_failed_attempt(ip)
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Database (SQLite acts as our mini time-series store)
# ---------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)

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
                    (instance_id, email, alert_type, datetime.utcnow().isoformat())
                )
        conn.commit()

    if conn.execute("SELECT id FROM instances LIMIT 1").fetchone() is None:
        cur = conn.execute(
            "INSERT INTO instances (name, target_url, created_at) VALUES (?, ?, ?)",
            ("Default", DEFAULT_TARGET_URL, datetime.utcnow().isoformat())
        )
        default_id = cur.lastrowid
        conn.execute("UPDATE metrics SET instance_id = ? WHERE instance_id IS NULL", (default_id,))
        conn.commit()

    conn.close()


def get_instances(include_secrets=False):
    """include_secrets=True returns auth_password in the clear - only for the
    scrape loop's own use. Every API-facing caller gets include_secrets=False
    (the default), so the password never round-trips into a browser response;
    `has_auth` tells the UI whether one is set without revealing it."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    conn = sqlite3.connect(DB_PATH)
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM metrics WHERE instance_id = ? ORDER BY id DESC LIMIT 1", (instance_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_history(instance_id, limit=60):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    cutoff = (datetime.utcnow() - timedelta(seconds=seconds)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO event_log (timestamp, instance_id, instance_name, level, category, message) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (datetime.utcnow().isoformat(), instance_id, instance_name, level, category, message)
    )
    conn.commit()
    conn.close()

    prefix = f"[{instance_name}] " if instance_name else ""
    {"info": logger.info, "warn": logger.warning, "error": logger.error}[level](f"{prefix}{message}")


def trim_event_log():
    cutoff = (datetime.utcnow() - timedelta(days=EVENT_LOG_RETENTION_DAYS)).isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM event_log WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()


def get_logs(instance_id=None, level=None, limit=200):
    limit = max(1, min(limit, 500))
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
        "timestamp": datetime.utcnow().isoformat(),
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
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE instances SET last_status = ?, last_error = ?, last_checked_at = ? WHERE id = ?",
        (status, error, datetime.utcnow().isoformat(), instance_id)
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

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            "INSERT INTO instances (name, target_url, created_at, auth_username, auth_password) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, url, datetime.utcnow().isoformat(), auth_username, auth_password)
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "an instance with this target_url already exists"}), 409
    conn.close()
    return jsonify({"id": new_id, "name": name, "target_url": url}), 201


@app.route("/api/instances/<int:instance_id>", methods=["PATCH"])
def api_instances_update(instance_id):
    data = request.get_json(force=True, silent=True) or {}
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    return jsonify({"ok": True})


@app.route("/api/instances/<int:instance_id>", methods=["DELETE"])
def api_instances_delete(instance_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM instances WHERE id = ?", (instance_id,))
    conn.execute("DELETE FROM metrics WHERE instance_id = ?", (instance_id,))
    conn.execute("DELETE FROM alert_thresholds WHERE instance_id = ?", (instance_id,))
    conn.execute("DELETE FROM alert_subscriptions WHERE instance_id = ?", (instance_id,))
    conn.commit()
    conn.close()
    _prev_state.pop(instance_id, None)
    _prev_severity.pop(instance_id, None)
    _prev_health.pop(instance_id, None)
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

    conn = sqlite3.connect(DB_PATH)
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
    return jsonify({"ok": True})


@app.route("/api/alert-types")
def api_alert_types():
    return jsonify([{"key": k, "label": v} for k, v in ALERT_TYPE_LABELS.items()])


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

    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            "INSERT INTO alert_subscriptions (instance_id, email, alert_type, created_at) "
            "VALUES (?, ?, ?, ?)",
            (instance_id, email, alert_type, datetime.utcnow().isoformat())
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "that email is already subscribed to this alert"}), 409
    conn.close()
    return jsonify({"id": new_id, "instance_id": instance_id, "email": email,
                     "alert_type": alert_type, "alert_type_label": ALERT_TYPE_LABELS[alert_type]}), 201


@app.route("/api/subscriptions/<int:sub_id>", methods=["DELETE"])
def api_subscriptions_delete(sub_id):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM alert_subscriptions WHERE id = ?", (sub_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    threading.Thread(target=scrape_loop, daemon=True).start()
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)

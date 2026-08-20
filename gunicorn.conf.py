"""
gunicorn configuration for the VPS monitor web service.

Sessions are signed cookies and the login throttle, session epoch and all
application state live in SQLite, so multiple workers are safe here - there is
no per-worker memory that a request depends on. The scraper is a separate
service (scraper.py), so no worker ever scrapes anything.
"""

import multiprocessing
import os

bind = os.environ.get("BIND", "127.0.0.1:5000")

# Modest worker count: this app is I/O-light and SQLite is the shared
# bottleneck, so a large pool buys nothing and only increases write contention.
workers = int(os.environ.get("WEB_WORKERS", min(4, multiprocessing.cpu_count() * 2 + 1)))
threads = int(os.environ.get("WEB_THREADS", "2"))
worker_class = "gthread"

timeout = 60
graceful_timeout = 30
keepalive = 5

accesslog = os.environ.get("ACCESS_LOG", "-")
errorlog = os.environ.get("ERROR_LOG", "-")
loglevel = os.environ.get("LOG_LEVEL", "info")

# Behind a reverse proxy, trust its forwarded headers so the audit log records
# the real client IP rather than 127.0.0.1 for every single request.
forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1")
proxy_protocol = False

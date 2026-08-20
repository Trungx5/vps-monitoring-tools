"""
WSGI entry point for gunicorn.

    gunicorn -c gunicorn.conf.py wsgi:application

Deliberately does NOT start the scrape or heartbeat threads - those belong to
the separate scraper process (scraper.py). Importing this module only prepares
the database and exposes the Flask app, so it is safe to load in as many
workers as you like.
"""

import os

from werkzeug.middleware.proxy_fix import ProxyFix

import app

# Refuse to start rather than fail mysteriously later. Without a shared
# SECRET_KEY each gunicorn worker signs session cookies with its own random
# key, so a user logged in on one worker looks logged out on the next - which
# surfaces as random, intermittent logouts that are painful to diagnose.
if not app.SECRET_KEY_CONFIGURED:
    raise RuntimeError(
        "SECRET_KEY is not set. Multiple workers must share one signing key, "
        "or logins will appear to drop at random. Generate one with:\n"
        "    python -c \"import secrets; print(secrets.token_hex(32))\"\n"
        "and set it in the service environment (see deploy/vpsmon.env.example)."
    )

app.init_db()

application = app.app

# Behind nginx/Caddy every request arrives from 127.0.0.1, which would make the
# audit log useless ("who signed in?" -> always localhost). ProxyFix reads the
# X-Forwarded-* headers the proxy sets so request.remote_addr is the real
# client. Only enable it when there genuinely is a trusted proxy in front,
# otherwise a client could spoof the header and forge audit entries.
if os.environ.get("BEHIND_PROXY", "") == "1":
    application.wsgi_app = ProxyFix(
        application.wsgi_app,
        x_for=int(os.environ.get("PROXY_HOPS", "1")),
        x_proto=int(os.environ.get("PROXY_HOPS", "1")),
        x_host=0, x_prefix=0,
    )

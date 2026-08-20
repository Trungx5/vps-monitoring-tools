#!/usr/bin/env bash
#
# Install the VPS monitor as a systemd service on Debian/Ubuntu.
#
#   sudo ./deploy/install.sh
#
# Idempotent: safe to re-run to upgrade an existing install. It never
# overwrites /etc/vpsmon/vpsmon.env or the database.
set -euo pipefail

APP_USER=vpsmon
BASE=/opt/vpsmon
APP_DIR="$BASE/app"
DATA_DIR="$BASE/data"
VENV="$BASE/venv"
ENV_FILE=/etc/vpsmon/vpsmon.env
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0" >&2
    exit 1
fi

echo "==> Installing system packages"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip

echo "==> Creating service account and directories"
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --home "$BASE" --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR" "$DATA_DIR" /etc/vpsmon

echo "==> Copying application files"
install -m 644 "$SRC_DIR"/app.py "$SRC_DIR"/cli.py "$SRC_DIR"/scraper.py \
               "$SRC_DIR"/wsgi.py "$SRC_DIR"/gunicorn.conf.py \
               "$SRC_DIR"/requirements.txt "$APP_DIR"/
mkdir -p "$APP_DIR/templates"
install -m 644 "$SRC_DIR"/templates/*.html "$APP_DIR/templates/"

echo "==> Setting up the Python environment"
[[ -d "$VENV" ]] || python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt"

FIRST_RUN=false
if [[ ! -f "$ENV_FILE" ]]; then
    FIRST_RUN=true
    echo "==> Creating $ENV_FILE"
    install -m 640 "$SRC_DIR/deploy/vpsmon.env.example" "$ENV_FILE"
    # Generate a real signing key so nobody ships the placeholder to production.
    SECRET=$("$VENV/bin/python" -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$SECRET|" "$ENV_FILE"
    # Plain HTTP until a proxy with TLS is configured; see deploy/Caddyfile.
    sed -i "s|^SECURE_COOKIES=.*|SECURE_COOKIES=0|" "$ENV_FILE"
    sed -i "s|^BEHIND_PROXY=.*|BEHIND_PROXY=0|" "$ENV_FILE"
fi

echo "==> Installing the vpsmon command"
cat > /usr/local/bin/vpsmon <<EOF
#!/usr/bin/env bash
set -a; . $ENV_FILE; set +a
cd $APP_DIR && exec $VENV/bin/python cli.py "\$@"
EOF
chmod 755 /usr/local/bin/vpsmon

echo "==> Setting ownership"
chown -R "$APP_USER:$APP_USER" "$BASE"
chown root:"$APP_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

echo "==> Installing systemd units"
install -m 644 "$SRC_DIR"/deploy/vpsmon-web.service "$SRC_DIR"/deploy/vpsmon-scraper.service \
        /etc/systemd/system/
systemctl daemon-reload

if [[ "$FIRST_RUN" == true ]]; then
    cat <<EOF

============================================================================
Installed, but NOT started yet.

1. Edit the configuration - at minimum set APP_PASSWORD:
       sudo nano $ENV_FILE

2. Start both services:
       sudo systemctl enable --now vpsmon-scraper vpsmon-web

3. Confirm they are healthy:
       systemctl status vpsmon-web vpsmon-scraper --no-pager
       curl -I http://127.0.0.1:5000/login

4. It is listening on localhost only. To reach it from a browser, put a
   reverse proxy with HTTPS in front - see deploy/Caddyfile - then set
   SECURE_COOKIES=1 and BEHIND_PROXY=1 in $ENV_FILE and restart.

Manage it from the terminal with:  vpsmon --help
============================================================================
EOF
else
    echo "==> Restarting services"
    systemctl restart vpsmon-scraper vpsmon-web || true
    echo "Upgrade complete. Existing configuration and data were left alone."
fi

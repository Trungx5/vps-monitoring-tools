# Custom VPS Monitor (DIY Prometheus + Grafana)

A minimal, from-scratch monitoring tool that scrapes one or more `node_exporter`
endpoints, stores history in SQLite, and shows a live dashboard in the browser —
built to demonstrate what Prometheus + Grafana are actually doing under the hood.

## What it replaces

| Component  | Real tool     | This project                          |
|------------|---------------|----------------------------------------|
| Scraper    | Prometheus    | `scrape_loop()` in `app.py`            |
| Storage    | Prometheus TSDB | SQLite (`metrics.db`)                |
| Query lang | PromQL        | Plain SQL / Python                     |
| Dashboard  | Grafana       | Flask + Chart.js (`templates/dashboard.html`) |
| Alerting   | Alertmanager  | Good/Warn/Critical thresholds + email  |

## Requirements

- Python 3.9+
- A reachable `node_exporter` endpoint on each VPS you want to monitor (default
  port 9100). See "Running node_exporter on a VPS" below if you need to set one up.

## Setup

```bash
cd vps-monitor
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

Then open: **http://localhost:5000**

The first VPS instance ("Default") is seeded automatically on first run. Add more
from the dashboard's hamburger menu (top-left, ☰) → **Add Monitoring Instance**.
Just give it a name and `http://<ip>:9100` — the app fills in the `/metrics` path
for you if you leave it off.

The first scrape of any instance has no delta yet (CPU %, bandwidth, and disk I/O
all need two samples to compute a rate), so its stats fill in after ~10-20 seconds.
While an instance has no data yet, or a scrape is failing, its status shows up in
the "Choose a VPS" / "Add Monitoring Instance" panels (green OK / amber waiting /
red with the actual error, e.g. connection refused).

## Running node_exporter on a VPS

SSH into the box you want to monitor:

```bash
cd /tmp
curl -LO https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz
tar xvfz node_exporter-1.8.2.linux-amd64.tar.gz
sudo mv node_exporter-1.8.2.linux-amd64/node_exporter /usr/local/bin/
sudo useradd -rs /bin/false node_exporter 2>/dev/null

sudo tee /etc/systemd/system/node_exporter.service > /dev/null <<'EOF'
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter
curl -s http://localhost:9100/metrics | head -5
```

Then open port 9100 to wherever this app runs from in that VPS's firewall /
cloud security group (e.g. AWS EC2 Security Group inbound rule, Custom TCP 9100).
node_exporter has no built-in auth, so scope the source IP as tightly as you can.

## Login

The whole dashboard (viewing *and* adding/deleting instances or thresholds) sits
behind a single login. Set a fixed account with environment variables before
starting the app. First generate a `SECRET_KEY` value:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Then, **Command Prompt (cmd.exe)** — the `set` lines only apply to that window,
so run them again first if you open a new one:

```bat
set APP_USERNAME=admin
set APP_PASSWORD=choose-a-real-password
set SECRET_KEY=paste-the-generated-value-here
python app.py
```

**PowerShell:**

```powershell
$env:APP_USERNAME = "admin"
$env:APP_PASSWORD = "choose-a-real-password"
$env:SECRET_KEY = "paste-the-generated-value-here"
python app.py
```

**macOS/Linux:**

```bash
export APP_USERNAME=admin
export APP_PASSWORD=choose-a-real-password
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python app.py
```

`SECRET_KEY` signs the session cookie so it can't be forged — set it if you
want its format to be predictable across restarts, though it doesn't change
this: **every restart forces everyone to sign in again, on purpose**, so an
old browser tab left open never keeps working against a server you just
relaunched. If you skip `APP_PASSWORD`, the app generates a random one-off
password and prints it to the console each time it starts (fine for quick
local testing, not for anything left running).

Failed logins are throttled (5 attempts per 5 minutes per IP). There's no
per-user accounts or CSRF tokens — it's a single shared login meant to keep
random people on your network (or the internet, if you expose this beyond
localhost) from adding scrape targets, not a multi-tenant auth system.

## Alerts: recipients list + Good / Warn / Critical thresholds

The **Alerts** panel (hamburger menu) has two parts per VPS instance:

**Alert Recipients** — a list of subscriptions, each one `(email, alert type)`.
Click **+ Add Subscription**, pick an email and one of 12 alert types (the 5
graduated metrics — CPU, Memory, Disk, Bandwidth, Disk I/O — plus the 7 Health
Checks — System down, Network interface down, Filesystem read-only, System
overloaded, Swap exhausted, Unexpected reboot, Traffic anomaly), and save. The
same email can appear in multiple rows if they should hear about several
things; different emails can be wired to different alerts (e.g. the network
team only gets "Network bandwidth high", oncall gets "System down"). Remove
any row with its **×** button. Nothing sends unless a row exists for that
specific alert type — no row, no email, regardless of thresholds.

**Thresholds** — a Warn and/or Critical numeric value per graduated metric.
Leave a field blank to skip that tier. Crossing a threshold highlights the
matching stat card amber (warn) or red (critical) on the dashboard, shows a
GOOD/WARN/CRITICAL pill next to the instance everywhere it's listed, and
emails everyone subscribed to that specific metric above.

Every alert (threshold or health check) is edge-triggered per recipient — one
email when that specific condition changes state (fires *or* recovers), never
one per scrape.

Sending mail requires an SMTP relay. Set these environment variables before
starting `app.py` (a Gmail example, using an
[App Password](https://myaccount.google.com/apppasswords) rather than your real
password) — combine with the login variables above using whichever syntax
matches your shell (`set` in cmd.exe, `$env:X = "..."` in PowerShell, `export`
on macOS/Linux/bash):

```bat
set SMTP_HOST=smtp.gmail.com
set SMTP_PORT=587
set SMTP_USER=you@gmail.com
set SMTP_PASSWORD=your-16-char-app-password
python app.py
```

If these aren't set, alerts are just logged to the console instead of emailed —
the rest of the app (thresholds, colored cards, severity pills) still works.

## Logs

The **Logs** panel (hamburger menu) is a live trail of what happened, across
every instance, filterable by instance and by level (Error/Warn/Info):

- Every scrape failure, with the actual error.
- Every severity or health-check transition (a metric crossing Warn/Critical,
  a health check starting or stopping failing) — edge-triggered, same as the
  emails, so this doesn't fill up with a duplicate line every 10 seconds
  while a problem is ongoing.
- A **heartbeat** every 30 seconds per instance, logging its current
  Good/Warn/Critical status and any failing health checks, whether or not
  anything changed — this is the "confirm it's still actually working" trail,
  separate from the edge-triggered entries above.

Kept for 3 days, then trimmed automatically. The full detail — including
routine successful scrapes, which are deliberately left out of this list to
keep it readable — also goes to `vps_monitor.log` in the project directory
(rotates at ~2MB, keeps 3 backups), if you need to dig deeper than the UI
shows.

## Health Checks: pass/fail, not just gauges

The **Health Checks** panel (hamburger menu) is a checklist alongside the
Warn/Critical gauges — the "is this box actually okay" questions an enterprise
tool like Datadog or Nagios asks, built from metrics `node_exporter` already
exposes by default:

| Check | Fails when | Source metric |
|---|---|---|
| Host reachable | Last scrape errored (timeout, refused, DNS, etc.) | scrape itself |
| Network interfaces up | Any non-loopback interface reports down | `node_network_up` |
| Root filesystem writable | `/` is mounted read-only (common sign of disk corruption) | `node_filesystem_readonly` |
| System load normal | `load1` > 2× CPU core count | `node_load1`, `node_cpu_seconds_total` |
| Swap not exhausted | Swap usage ≥ 90% | `node_memory_Swap*_bytes` |
| No unexpected reboot | Uptime didn't reset since the last scrape | `node_boot_time_seconds` |
| No traffic anomaly | Current bandwidth > 5× its own recent baseline | `node_network_*_bytes_total` |

Each shows ✓ OK, ✗ FAILING, or **?** Unknown — Unknown means not enough
history yet, or this node_exporter build doesn't expose that metric; checks
are never guessed into a false pass or fail. Same edge-triggered email as the
threshold alerts above (same `alert_email` field): you get one when a check
*changes* state, not one per scrape.

**Read "No traffic anomaly" for what it is** — a rough heuristic comparing
current bandwidth against its own recent average, not real intrusion
detection. It'll catch a sudden bandwidth spike (which could be a DDoS, a
runaway backup job, or someone's rsync); it won't catch a stealthy attacker
who never generates unusual traffic. For anything resembling real security
monitoring, this is a monitoring dashboard, not a substitute for `fail2ban`,
a WAF, or actual log analysis.

## Notes for your report

- `parse_metrics_text()` shows you understand the Prometheus exposition
  format (the same plain-text format `node_exporter`, `/metrics` endpoints,
  and Prometheus itself all speak).
- `compute_rates()` shows the delta-based calculation Prometheus does
  internally for every counter metric (CPU time, network bytes, disk bytes are
  all *counters*, not gauges, so usage %, bandwidth/sec, and disk I/O/sec all
  require comparing two points in time).
- SQLite here is a simplified stand-in for Prometheus's real TSDB (which
  uses a custom on-disk format optimized for time-series compression).
- The dashboard polls the Flask API every 5-10s — a simplified version of
  how Grafana queries its data source on an interval.
- `evaluate_severity()` / `maybe_alert()` are a minimal stand-in for
  Alertmanager: thresholds evaluated per scrape, edge-triggered notifications
  on state transitions instead of paging on every sample.

## Extending it (optional)

- Swap email for a Discord/Slack/Telegram webhook in `send_alert_email()`.
- Add authentication if exposing this dashboard beyond localhost.
- Track more node_exporter metrics (e.g. per-core CPU, swap, inode usage).

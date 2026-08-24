#!/usr/bin/env python3
"""
vpsmon - command line administration for the VPS monitor.

Talks straight to the same SQLite database the web app uses, so it works
whether or not the web service is running. Point it at a different database
with the DB_PATH environment variable.

    vpsmon status
    vpsmon instance add --name "Web 1" --url http://10.0.0.5:9100
    vpsmon threshold set "Web 1" --cpu-warn 70 --cpu-crit 90
    vpsmon alert add "Web 1" --email ops@example.com --type cpu
    vpsmon user add alice --role viewer
    vpsmon logs --level error
    vpsmon audit

Run `vpsmon <command> --help` for the options of any single command.
"""

import argparse
import getpass
import os
import sqlite3
import sys

import app


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def die(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def ok(message):
    print(message)


def table(headers, rows):
    if not rows:
        print("(none)")
        return
    cols = [[str(h)] + [str(r[i]) for r in rows] for i, h in enumerate(headers)]
    widths = [min(max(len(v) for v in col), 48) for col in cols]
    line = "  ".join(h.ljust(w)[:w] for h, w in zip(headers, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(v).ljust(w)[:w] for v, w in zip(row, widths)))


def cli_actor():
    """Recorded in the audit log so CLI changes are attributable too."""
    return f"cli:{os.environ.get('SUDO_USER') or getpass.getuser()}"


def audit(action, target=None, details=None):
    app.log_audit(action, target=target, details=details,
                  username=cli_actor(), user_id=None, ip="local")


def resolve_instance(ref):
    """Accept either an instance id or a name, so you don't have to look up
    numeric ids for everyday commands."""
    instances = app.get_instances()
    if ref.isdigit():
        match = next((i for i in instances if i["id"] == int(ref)), None)
        if match:
            return match
    matches = [i for i in instances if i["name"].lower() == ref.lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        die(f"several instances are named {ref!r}; use the numeric id instead")
    die(f"no instance matching {ref!r} (try: vpsmon instance list)")


def fmt(value, dash="-"):
    return dash if value is None else str(value)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
def cmd_status(args):
    instances = app.get_instances()
    if not instances:
        ok("No instances configured. Add one with: vpsmon instance add --name NAME --url URL")
        return
    rows = []
    for inst in instances:
        latest = app.get_latest(inst["id"]) or {}
        failing = [k for k, v in (inst.get("health") or {}).items() if v is False]
        rows.append([
            inst["id"], inst["name"],
            inst.get("last_status") or "-",
            (inst.get("severity") or {}).get("overall") or "-",
            fmt(latest.get("cpu_percent")), fmt(latest.get("mem_percent")),
            fmt(latest.get("disk_percent")),
            ", ".join(app.HEALTH_CHECK_DEFS[k] for k in failing) or "-",
        ])
    table(["ID", "NAME", "SCRAPE", "STATUS", "CPU%", "MEM%", "DISK%", "FAILING CHECKS"], rows)


# ---------------------------------------------------------------------------
# instance
# ---------------------------------------------------------------------------
def cmd_instance_list(args):
    rows = [[i["id"], i["name"], i["target_url"],
             "yes" if i.get("has_auth") else "no",
             i.get("last_status") or "-"]
            for i in app.get_instances()]
    table(["ID", "NAME", "URL", "AUTH", "SCRAPE"], rows)


def cmd_instance_add(args):
    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        die("--url must start with http:// or https://")
    url = app.normalize_target_url(url)

    auth_user = args.auth_user
    auth_pass = args.auth_pass
    if auth_user and not auth_pass:
        auth_pass = getpass.getpass(f"Basic Auth password for {auth_user}: ")

    conn = app.db()
    try:
        cur = conn.execute(
            "INSERT INTO instances (name, target_url, created_at, auth_username, auth_password) "
            "VALUES (?, ?, ?, ?, ?)",
            (args.name, url, app.utcnow().isoformat(), auth_user or None, auth_pass or None)
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        die("an instance with that URL already exists")
    finally:
        conn.close()

    audit("instance.create", args.name, f"{url}{' (basic auth)' if auth_user else ''}")
    ok(f"Added instance {new_id}: {args.name} -> {url}")
    ok("Metrics appear after the first two scrapes (~20s).")


def cmd_instance_edit(args):
    inst = resolve_instance(args.instance)
    conn = app.db()
    row = conn.execute("SELECT * FROM instances WHERE id = ?", (inst["id"],)).fetchone()

    name = args.name or row["name"]
    url = row["target_url"]
    if args.url:
        if not args.url.startswith(("http://", "https://")):
            conn.close()
            die("--url must start with http:// or https://")
        url = app.normalize_target_url(args.url)

    auth_user, auth_pass = row["auth_username"], row["auth_password"]
    if args.clear_auth:
        auth_user, auth_pass = None, None
    elif args.auth_user:
        auth_user = args.auth_user
        auth_pass = args.auth_pass or getpass.getpass(f"Basic Auth password for {auth_user}: ")

    try:
        conn.execute(
            "UPDATE instances SET name = ?, target_url = ?, auth_username = ?, auth_password = ? "
            "WHERE id = ?", (name, url, auth_user, auth_pass, inst["id"])
        )
        conn.commit()
    except sqlite3.IntegrityError:
        die("another instance already uses that URL")
    finally:
        conn.close()

    audit("instance.update", name, "edited from cli")
    ok(f"Updated instance {inst['id']}: {name} -> {url}")


def cmd_instance_remove(args):
    inst = resolve_instance(args.instance)
    if not args.yes:
        answer = input(f"Delete {inst['name']!r} and all of its history? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            ok("Cancelled.")
            return
    conn = app.db()
    for tbl in ("instances", "metrics", "alert_thresholds", "alert_subscriptions"):
        column = "id" if tbl == "instances" else "instance_id"
        conn.execute(f"DELETE FROM {tbl} WHERE {column} = ?", (inst["id"],))
    conn.commit()
    conn.close()
    audit("instance.delete", inst["name"], "removed from cli")
    ok(f"Deleted instance {inst['id']} ({inst['name']}).")


# ---------------------------------------------------------------------------
# threshold
# ---------------------------------------------------------------------------
def cmd_threshold_show(args):
    inst = resolve_instance(args.instance)
    th = app.get_thresholds(inst["id"])
    rows = [[key, app.METRIC_DEFS[key][0], app.METRIC_DEFS[key][1],
             fmt(th.get(f"{key}_warn")), fmt(th.get(f"{key}_crit"))]
            for key in app.METRIC_DEFS]
    ok(f"Thresholds for {inst['name']}:")
    table(["KEY", "METRIC", "UNIT", "WARN", "CRIT"], rows)


def cmd_threshold_set(args):
    inst = resolve_instance(args.instance)
    th = app.get_thresholds(inst["id"])
    values = {"instance_id": inst["id"]}
    changed = []

    for key in app.METRIC_DEFS:
        for tier in ("warn", "crit"):
            attr = f"{key}_{tier}"
            supplied = getattr(args, attr)
            if supplied is None:
                values[attr] = th.get(attr)
            elif supplied.lower() in ("none", "off", ""):
                values[attr] = None
                changed.append(f"{attr}=off")
            else:
                try:
                    values[attr] = float(supplied)
                except ValueError:
                    die(f"--{attr.replace('_', '-')} must be a number or 'none'")
                changed.append(f"{attr}={values[attr]}")

    if not changed:
        die("nothing to set; pass at least one threshold, e.g. --cpu-warn 70")

    conn = app.db()
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

    audit("thresholds.update", inst["name"], ", ".join(changed))
    ok(f"Updated thresholds for {inst['name']}: {', '.join(changed)}")


# ---------------------------------------------------------------------------
# alert (email subscriptions)
# ---------------------------------------------------------------------------
def cmd_alert_types(args):
    table(["KEY", "DESCRIPTION"], [[k, v] for k, v in app.ALERT_TYPE_LABELS.items()])


def cmd_alert_list(args):
    subs = app.get_all_subscriptions()
    if args.instance:
        inst = resolve_instance(args.instance)
        subs = [s for s in subs if s["instance_id"] == inst["id"]]
    rows = [[s["id"], s["instance_name"], s["email"], s["alert_type"], s["alert_type_label"]]
            for s in subs]
    table(["ID", "INSTANCE", "EMAIL", "TYPE", "ALERT"], rows)


def cmd_alert_add(args):
    inst = resolve_instance(args.instance)
    types = args.type
    if "all" in types:
        types = list(app.ALERT_TYPE_LABELS)

    added = 0
    for alert_type in types:
        if alert_type not in app.ALERT_TYPE_LABELS:
            die(f"unknown alert type {alert_type!r} (try: vpsmon alert types)")
        conn = app.db()
        try:
            conn.execute(
                "INSERT INTO alert_subscriptions (instance_id, email, alert_type, created_at) "
                "VALUES (?, ?, ?, ?)",
                (inst["id"], args.email, alert_type, app.utcnow().isoformat())
            )
            conn.commit()
            added += 1
            audit("subscription.create", args.email,
                  f"{app.ALERT_TYPE_LABELS[alert_type]} on {inst['name']}")
        except sqlite3.IntegrityError:
            ok(f"  already subscribed: {alert_type}")
        finally:
            conn.close()

    ok(f"Subscribed {args.email} to {added} alert type(s) on {inst['name']}.")
    if not (app.SMTP_HOST and app.SMTP_USER and app.SMTP_PASSWORD):
        ok("note: SMTP is not configured, so alerts will only be logged, not emailed.")


def cmd_alert_remove(args):
    conn = app.db()
    row = conn.execute("SELECT * FROM alert_subscriptions WHERE id = ?", (args.id,)).fetchone()
    if not row:
        conn.close()
        die(f"no subscription with id {args.id} (try: vpsmon alert list)")
    conn.execute("DELETE FROM alert_subscriptions WHERE id = ?", (args.id,))
    conn.commit()
    conn.close()
    audit("subscription.delete", row["email"],
          app.ALERT_TYPE_LABELS.get(row["alert_type"], row["alert_type"]))
    ok(f"Removed subscription {args.id} ({row['email']} / {row['alert_type']}).")


# ---------------------------------------------------------------------------
# web (website monitoring)
# ---------------------------------------------------------------------------
def resolve_web(ref):
    targets = app.get_web_targets()
    if ref.isdigit():
        m = next((t for t in targets if t['id'] == int(ref)), None)
        if m:
            return m
    matches = [t for t in targets if t['name'].lower() == ref.lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        die(f"several websites are named {ref!r}; use the numeric id instead")
    die(f"no website matching {ref!r} (try: vpsmon web list)")


def cmd_web_list(args):
    rows = []
    for t in app.get_web_targets():
        latest = app.get_web_latest(t['id']) or {}
        failing = [app.WEB_CHECK_DEFS[k] for k, v in (t.get('health') or {}).items() if v is False]
        rows.append([
            t['id'], t['name'], t['url'],
            fmt(latest.get('status_code')),
            f"{latest['response_ms']:.0f}" if latest.get('response_ms') is not None else '-',
            fmt(latest.get('resolved_ip')),
            f"{latest['cert_days']:.0f}" if latest.get('cert_days') is not None else '-',
            ', '.join(failing) or 'ok',
        ])
    table(["ID", "NAME", "URL", "CODE", "MS", "IP", "CERTd", "FAILING"], rows)


def cmd_web_add(args):
    url = app.normalize_web_url(args.url)
    conn = app.db()
    try:
        cur = conn.execute(
            "INSERT INTO web_targets (name, url, expected_status, keyword, slow_ms, "
            "cert_warn_days, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (args.name, url, args.expect_status, args.keyword, args.slow_ms,
             args.cert_warn_days, app.utcnow().isoformat())
        )
        conn.commit()
        new_id = cur.lastrowid
    except sqlite3.IntegrityError:
        die(f"{url} is already being monitored")
    finally:
        conn.close()
    audit("web.create", args.name, url)
    ok(f"Added website {new_id}: {args.name} -> {url}")


def cmd_web_remove(args):
    t = resolve_web(args.target)
    if not args.yes:
        if input(f"Delete website {t['name']!r} and its history? [y/N] ").strip().lower() not in ('y', 'yes'):
            ok("Cancelled."); return
    conn = app.db()
    conn.execute("DELETE FROM web_targets WHERE id = ?", (t['id'],))
    conn.execute("DELETE FROM web_checks WHERE target_id = ?", (t['id'],))
    conn.execute("DELETE FROM alert_subscriptions WHERE instance_id = ? AND monitor_type = 'web'", (t['id'],))
    conn.commit(); conn.close()
    audit("web.delete", t['name'])
    ok(f"Deleted website {t['id']} ({t['name']}).")


def cmd_web_check(args):
    """Run a check right now instead of waiting for the next cycle."""
    targets = [resolve_web(args.target)] if args.target else app.get_web_targets()
    rows = []
    for t in targets:
        r = app.check_web_target(t)
        app.save_web_check(r)
        conn = app.db()
        conn.execute("UPDATE web_targets SET last_status=?, last_error=?, last_checked_at=?, last_ip=? WHERE id=?",
                     ('ok' if r['ok'] else 'error', r['error'], r['timestamp'], r['resolved_ip'], t['id']))
        conn.commit(); conn.close()
        rows.append([t['name'], 'OK' if r['ok'] else 'FAIL', fmt(r['status_code']),
                     f"{r['response_ms']:.0f}" if r['response_ms'] is not None else '-',
                     fmt(r['resolved_ip']),
                     f"{r['cert_days']:.0f}" if r['cert_days'] is not None else '-',
                     {1: 'yes', 0: 'NO', None: '-'}[r['cert_valid']],
                     (r['error'] or '')[:40]])
    table(["NAME", "RESULT", "CODE", "MS", "IP", "CERTd", "CERT OK", "ERROR"], rows)


def cmd_web_import(args):
    """Bulk-add websites from a CSV with 'name'/'company' and 'domain'/'url' columns."""
    import csv
    added = skipped = 0
    with open(args.file, encoding='utf-8-sig', newline='') as fh:
        for row in csv.DictReader(fh):
            keys = {k.lower().strip(): (v or '').strip() for k, v in row.items() if k}
            name = keys.get('name') or keys.get('company') or ''
            url = keys.get('url') or keys.get('domain') or ''
            if not name or not url or url.upper().startswith('UNCONFIRMED') or not any(c.isalpha() for c in url):
                skipped += 1
                continue
            url = app.normalize_web_url(url)
            conn = app.db()
            try:
                conn.execute(
                    "INSERT INTO web_targets (name, url, enabled, created_at) VALUES (?, ?, 1, ?)",
                    (name[:80], url, app.utcnow().isoformat())
                )
                conn.commit(); added += 1
            except sqlite3.IntegrityError:
                skipped += 1
            finally:
                conn.close()
    audit("web.import", args.file, f"{added} added, {skipped} skipped")
    ok(f"Imported {added} website(s); skipped {skipped} (duplicates or missing/unconfirmed URL).")
    ok("Run 'vpsmon web check' to test them all immediately.")


# ---------------------------------------------------------------------------
# user
# ---------------------------------------------------------------------------
def prompt_password(label="Password"):
    first = getpass.getpass(f"{label}: ")
    if len(first) < 8:
        die("password must be at least 8 characters")
    if first != getpass.getpass(f"{label} (again): "):
        die("passwords did not match")
    return first


def cmd_user_list(args):
    rows = [[u["id"], u["username"], u["role"],
             "active" if u["is_active"] else "disabled",
             u["last_login_at"] or "never"]
            for u in app.list_users()]
    table(["ID", "USERNAME", "ROLE", "STATE", "LAST LOGIN"], rows)


def find_user(name):
    user = app.get_user_by_username(name)
    if not user:
        die(f"no user named {name!r} (try: vpsmon user list)")
    return user


def cmd_user_add(args):
    password = args.password or prompt_password(f"Password for {args.username}")
    if len(password) < 8:
        die("password must be at least 8 characters")
    try:
        app.create_user(args.username, password, args.role)
    except sqlite3.IntegrityError:
        die(f"user {args.username!r} already exists")
    audit("user.create", args.username, f"role={args.role}")
    ok(f"Created {args.role} account {args.username!r}.")


def cmd_user_passwd(args):
    user = find_user(args.username)
    password = args.password or prompt_password(f"New password for {args.username}")
    if len(password) < 8:
        die("password must be at least 8 characters")
    app.update_user_password(user["id"], password)
    audit("user.update", args.username, "password reset")
    ok(f"Password updated for {args.username!r}.")


def cmd_user_role(args):
    user = find_user(args.username)
    if user["role"] == app.ROLE_ADMIN and args.role != app.ROLE_ADMIN \
            and app.count_admins(user["id"]) == 0:
        die("that is the last admin account - promote someone else first")
    conn = app.db()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (args.role, user["id"]))
    conn.commit()
    conn.close()
    audit("user.update", args.username, f"role={args.role}")
    ok(f"{args.username!r} is now {args.role}.")


def cmd_user_enable(args):
    _set_user_active(args.username, True)


def cmd_user_disable(args):
    _set_user_active(args.username, False)


def _set_user_active(username, active):
    user = find_user(username)
    if not active and user["role"] == app.ROLE_ADMIN and app.count_admins(user["id"]) == 0:
        die("that is the last admin account - promote someone else first")
    conn = app.db()
    conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, user["id"]))
    conn.commit()
    conn.close()
    audit("user.update", username, "enabled" if active else "disabled")
    ok(f"{username!r} {'enabled' if active else 'disabled'}.")


def cmd_user_remove(args):
    user = find_user(args.username)
    if user["role"] == app.ROLE_ADMIN and app.count_admins(user["id"]) == 0:
        die("that is the last admin account - promote someone else first")
    if not args.yes:
        answer = input(f"Delete user {user['username']!r}? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            ok("Cancelled.")
            return
    conn = app.db()
    conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()
    audit("user.delete", user["username"])
    ok(f"Deleted user {user['username']!r}.")


# ---------------------------------------------------------------------------
# logs
# ---------------------------------------------------------------------------
def cmd_logs(args):
    instance_id = resolve_instance(args.instance)["id"] if args.instance else None
    entries = app.get_logs(instance_id=instance_id, level=args.level, limit=args.limit)
    rows = [[e["timestamp"][:19].replace("T", " "), e["level"], e["category"],
             e["instance_name"] or "-", e["message"]]
            for e in reversed(entries)]
    table(["TIME", "LEVEL", "CATEGORY", "INSTANCE", "MESSAGE"], rows)


def cmd_audit(args):
    entries = app.get_audit_log(limit=args.limit, username=args.user, action=args.action)
    rows = [[e["timestamp"][:19].replace("T", " "), e["username"] or "-", e["action"],
             e["target"] or "-", e["details"] or "", e["ip_address"] or "-"]
            for e in reversed(entries)]
    table(["TIME", "USER", "ACTION", "TARGET", "DETAILS", "IP"], rows)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------
def cmd_init(args):
    # init_db() creates the schema and bootstraps the first admin itself, so
    # count accounts beforehand to report accurately rather than calling the
    # bootstrap twice (which would always look like "already exists").
    try:
        users_before = len(app.list_users())
    except sqlite3.OperationalError:
        users_before = 0  # database or users table does not exist yet

    app.init_db()
    ok(f"Database ready at {app.DB_PATH}")

    users_after = app.list_users()
    if users_before == 0 and users_after:
        ok(f"Created first admin account: {users_after[0]['username']!r}")
    else:
        ok(f"{len(users_after)} account(s) already exist - left untouched.")

    if args.rotate_sessions:
        app.mark_server_start()
        ok("Rotated the session epoch - everyone must sign in again.")


# ---------------------------------------------------------------------------
# Argument wiring
# ---------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog="vpsmon", description="Administer the VPS monitor from the command line.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create/upgrade the database and first admin")
    p.add_argument("--rotate-sessions", action="store_true",
                   help="also invalidate every existing login session")
    p.set_defaults(func=cmd_init)
    sub.add_parser("status", help="one-line health summary of every instance").set_defaults(func=cmd_status)

    # --- instance ---
    inst = sub.add_parser("instance", help="add, edit, list or remove monitored servers")
    inst_sub = inst.add_subparsers(dest="sub", required=True)
    inst_sub.add_parser("list", help="list instances").set_defaults(func=cmd_instance_list)

    p = inst_sub.add_parser("add", help="add an instance")
    p.add_argument("--name", required=True)
    p.add_argument("--url", required=True, help="node_exporter URL, e.g. http://10.0.0.5:9100")
    p.add_argument("--auth-user", dest="auth_user", help="Basic Auth username, if node_exporter requires one")
    p.add_argument("--auth-pass", dest="auth_pass", help="Basic Auth password (prompted if omitted)")
    p.set_defaults(func=cmd_instance_add)

    p = inst_sub.add_parser("edit", help="edit an instance")
    p.add_argument("instance", help="instance name or id")
    p.add_argument("--name")
    p.add_argument("--url")
    p.add_argument("--auth-user", dest="auth_user")
    p.add_argument("--auth-pass", dest="auth_pass")
    p.add_argument("--clear-auth", action="store_true", help="remove Basic Auth credentials")
    p.set_defaults(func=cmd_instance_edit)

    p = inst_sub.add_parser("remove", help="delete an instance and its history")
    p.add_argument("instance", help="instance name or id")
    p.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    p.set_defaults(func=cmd_instance_remove)

    # --- threshold ---
    th = sub.add_parser("threshold", help="set Warn/Critical levels")
    th_sub = th.add_subparsers(dest="sub", required=True)

    p = th_sub.add_parser("show", help="show thresholds for an instance")
    p.add_argument("instance")
    p.set_defaults(func=cmd_threshold_show)

    p = th_sub.add_parser("set", help="set thresholds ('none' clears one)")
    p.add_argument("instance")
    for key, (label, unit, _) in app.METRIC_DEFS.items():
        # argparse runs help through %-formatting, so a literal % (the unit
        # for CPU/memory/disk) has to be escaped or it blows up at parse time.
        safe_unit = unit.replace("%", "%%")
        p.add_argument(f"--{key}-warn", dest=f"{key}_warn", metavar="N",
                       help=f"{label} warn level ({safe_unit})")
        p.add_argument(f"--{key}-crit", dest=f"{key}_crit", metavar="N",
                       help=f"{label} critical level ({safe_unit})")
    p.set_defaults(func=cmd_threshold_set)

    # --- alert ---
    al = sub.add_parser("alert", help="manage who gets emailed about what")
    al_sub = al.add_subparsers(dest="sub", required=True)
    al_sub.add_parser("types", help="list valid alert types").set_defaults(func=cmd_alert_types)

    p = al_sub.add_parser("list", help="list alert recipients")
    p.add_argument("instance", nargs="?", help="optional: filter to one instance")
    p.set_defaults(func=cmd_alert_list)

    p = al_sub.add_parser("add", help="subscribe an email to alerts")
    p.add_argument("instance")
    p.add_argument("--email", required=True)
    p.add_argument("--type", required=True, nargs="+",
                   help="one or more alert types, or 'all' (see: vpsmon alert types)")
    p.set_defaults(func=cmd_alert_add)

    p = al_sub.add_parser("remove", help="remove a subscription by id")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_alert_remove)

    # --- web ---
    web = sub.add_parser("web", help="monitor websites (uptime, speed, TLS, IP changes)")
    web_sub = web.add_subparsers(dest="sub", required=True)
    web_sub.add_parser("list", help="list monitored websites").set_defaults(func=cmd_web_list)

    p = web_sub.add_parser("add", help="add a website")
    p.add_argument("--name", required=True)
    p.add_argument("--url", required=True, help="https:// is assumed if no scheme is given")
    p.add_argument("--keyword", help="text that must appear on the page")
    p.add_argument("--expect-status", dest="expect_status", type=int,
                   help="require this exact HTTP code (default: any 2xx/3xx)")
    p.add_argument("--slow-ms", dest="slow_ms", type=int,
                   help="flag as slow above this many milliseconds")
    p.add_argument("--cert-warn-days", dest="cert_warn_days", type=int,
                   help="warn when the TLS certificate has fewer days left than this")
    p.set_defaults(func=cmd_web_add)

    p = web_sub.add_parser("remove", help="stop monitoring a website")
    p.add_argument("target", help="website name or id")
    p.add_argument("-y", "--yes", action="store_true")
    p.set_defaults(func=cmd_web_remove)

    p = web_sub.add_parser("check", help="run a check now rather than waiting")
    p.add_argument("target", nargs="?", help="website name or id (default: all)")
    p.set_defaults(func=cmd_web_check)

    p = web_sub.add_parser("import", help="bulk add from a CSV (name/company + url/domain columns)")
    p.add_argument("file")
    p.set_defaults(func=cmd_web_import)

    # --- user ---
    us = sub.add_parser("user", help="manage dashboard accounts")
    us_sub = us.add_subparsers(dest="sub", required=True)
    us_sub.add_parser("list", help="list accounts").set_defaults(func=cmd_user_list)

    p = us_sub.add_parser("add", help="create an account")
    p.add_argument("username")
    p.add_argument("--role", choices=app.ROLES, default=app.ROLE_VIEWER)
    p.add_argument("--password", help="prompted securely if omitted")
    p.set_defaults(func=cmd_user_add)

    p = us_sub.add_parser("passwd", help="reset an account password")
    p.add_argument("username")
    p.add_argument("--password", help="prompted securely if omitted")
    p.set_defaults(func=cmd_user_passwd)

    p = us_sub.add_parser("role", help="change an account role")
    p.add_argument("username")
    p.add_argument("role", choices=app.ROLES)
    p.set_defaults(func=cmd_user_role)

    p = us_sub.add_parser("enable", help="re-enable an account")
    p.add_argument("username")
    p.set_defaults(func=cmd_user_enable)

    p = us_sub.add_parser("disable", help="disable an account without deleting it")
    p.add_argument("username")
    p.set_defaults(func=cmd_user_disable)

    p = us_sub.add_parser("remove", help="delete an account")
    p.add_argument("username")
    p.add_argument("-y", "--yes", action="store_true")
    p.set_defaults(func=cmd_user_remove)

    # --- logs ---
    p = sub.add_parser("logs", help="monitoring events (scrapes, alerts, heartbeats)")
    p.add_argument("--instance")
    p.add_argument("--level", choices=("info", "warn", "error"))
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("audit", help="who signed in and what they changed")
    p.add_argument("--user")
    p.add_argument("--action")
    p.add_argument("--limit", type=int, default=50)
    p.set_defaults(func=cmd_audit)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command != "init" and not os.path.exists(app.DB_PATH):
        die(f"no database at {app.DB_PATH} - run 'vpsmon init' first "
            f"(or set DB_PATH to point at an existing one)")
    try:
        args.func(args)
    except KeyboardInterrupt:
        print()
        sys.exit(130)


if __name__ == "__main__":
    main()

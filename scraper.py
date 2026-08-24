#!/usr/bin/env python3
"""
vpsmon scraper daemon.

In production the scraper runs as its own process, separate from the web
workers. That split matters:

  * The scrape loop keeps per-instance counter state in memory (previous CPU
    ticks, network and disk byte counters) to turn counters into rates. If it
    ran inside each gunicorn worker, every worker would scrape every target
    independently - duplicate load on the monitored machines, duplicate
    alert emails, and each worker computing rates from its own partial view.
  * Exactly one process writes samples, so the web side can scale to as many
    workers as it likes without coordinating.

Run directly:   python scraper.py
Under systemd:  see deploy/vpsmon-scraper.service
"""

import threading

import app


def main():
    app.init_db()
    app.logger.info(
        f"scraper starting: db={app.DB_PATH} "
        f"scrape_interval={app.SCRAPE_INTERVAL_SECONDS}s "
        f"heartbeat_interval={app.HEARTBEAT_INTERVAL_SECONDS}s"
    )

    threading.Thread(target=app.heartbeat_loop, daemon=True).start()
    threading.Thread(target=app.web_check_loop, daemon=True).start()
    threading.Thread(target=app.ip_check_loop, daemon=True).start()

    # Runs forever in the foreground so systemd can supervise it directly.
    app.scrape_loop()


if __name__ == "__main__":
    main()

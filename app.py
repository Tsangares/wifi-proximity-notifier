#!/usr/bin/env python3
"""WiFi Proximity Notifier — monitors network for device connections."""

import signal
import sys
import threading
import logging
import argparse

import scanner
import manufacturer as mfr
from dashboard import app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("wifi-notifier")


def main():
    parser = argparse.ArgumentParser(description="WiFi Proximity Notifier")
    parser.add_argument("--port", type=int, default=5555, help="Dashboard port (default: 5555)")
    parser.add_argument("--host", default="0.0.0.0", help="Dashboard bind address")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-dashboard", action="store_true", help="Run scanner only, no web UI")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Pre-initialize vendor DB so first scan has it ready
    log.info("Initializing vendor database...")
    mfr.init()

    def shutdown(sig, frame):
        log.info("Shutting down...")
        scanner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Start scanner in background thread
    scan_thread = threading.Thread(target=scanner.scan_loop, daemon=True)
    scan_thread.start()
    log.info("Scanner started")

    if args.no_dashboard:
        log.info("Running in scanner-only mode (no dashboard)")
        scan_thread.join()
    else:
        log.info("Dashboard at http://%s:%d", args.host, args.port)
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

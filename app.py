#!/usr/bin/env python3
"""WiFi Proximity Notifier — monitors network for device connections."""

import os
import signal
import sys
import threading
import logging
import argparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("wifi-notifier")


def main():
    parser = argparse.ArgumentParser(description="WiFi Proximity Notifier")
    # Bind address/port: flags win, then WIFI_NOTIFIER_HOST/PORT env vars,
    # then defaults. 0.0.0.0 exposes the dashboard on LAN + Tailscale
    # (see README for the tradeoff).
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("WIFI_NOTIFIER_PORT", 5555)),
                        help="Dashboard port (default: 5555, env WIFI_NOTIFIER_PORT)")
    parser.add_argument("--host",
                        default=os.environ.get("WIFI_NOTIFIER_HOST", "0.0.0.0"),
                        help="Dashboard bind address (default: 0.0.0.0, env WIFI_NOTIFIER_HOST)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-dashboard", action="store_true", help="Run scanner only, no web UI")
    parser.add_argument("--mock", action="store_true", help="Seed fake data and run dashboard without scanning (no root needed)")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.mock:
        # Mock mode uses a SEPARATE database file (mock.db) so wiping and
        # re-seeding fake devices can never destroy real device history.
        import device_db
        device_db.use_mock_db()
        from mock_data import seed_mock_data
        import resolver
        from dashboard import app
        log.info("Mock mode — seeding fake devices into %s...", device_db.DB_PATH)
        seed_mock_data()
        resolver.backfill()  # run the identity engine over the fake devices
        log.info("Dashboard at http://%s:%d", args.host, args.port)
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
        return

    from dashboard import app
    import scanner
    import manufacturer as mfr
    import resolver

    # Re-resolve identities for devices whose labels predate the current
    # identity engine version (additive — user overrides are never touched).
    log.info("Running identity backfill...")
    resolver.backfill()

    # Pre-initialize vendor DB so first scan has it ready
    log.info("Initializing vendor database...")
    mfr.init()

    def shutdown(sig, frame):
        log.info("Shutting down...")
        scanner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Start scanner in background thread with auto-restart
    def scanner_wrapper():
        while True:
            try:
                scanner.scan_loop()
            except Exception as e:
                log.error("Scanner crashed: %s — restarting in 3s", e, exc_info=True)
                import time
                time.sleep(3)

    scan_thread = threading.Thread(target=scanner_wrapper, daemon=True)
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

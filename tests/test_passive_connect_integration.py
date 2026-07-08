"""Integration test: a passive `ip monitor neigh` REACHABLE event should
flow through scanner._process_scan_results exactly like a poller-detected
device — new device row created, activity logged, notification fired —
without touching the real device DB or sending real desktop notifications.
"""

import os
import sys
import shutil
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestPassiveConnectIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="wifi-notifier-test-")

        import device_db
        self.device_db = device_db
        # Point the DB at a throwaway location so we never touch the real one.
        self._orig_dir = device_db.DB_DIR
        self._orig_path = device_db.DB_PATH
        device_db.DB_DIR = self.tmpdir
        device_db.DB_PATH = os.path.join(self.tmpdir, "devices.db")
        device_db._local = threading.local()  # drop cached connection

        import scanner
        self.scanner = scanner
        # Reset in-memory scanner state between tests.
        scanner._last_seen.clear()
        scanner._last_reachable.clear()
        scanner._disconnect_ts.clear()
        scanner._notified_new.clear()
        scanner._flap_history.clear()

        import manufacturer
        import notifier
        import fingerprint
        self._patches = [
            mock.patch.object(manufacturer, "lookup", return_value=("TestVendor", "Test Device")),
            mock.patch.object(notifier, "notify_new_device"),
            mock.patch.object(fingerprint, "queue_probe"),
        ]
        self.mocks = [p.start() for p in self._patches]
        self.notify_new_device = self.mocks[1]

    def tearDown(self):
        for p in self._patches:
            p.stop()
        import device_db
        device_db.DB_DIR = self._orig_dir
        device_db.DB_PATH = self._orig_path
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_passive_reachable_event_creates_and_notifies_new_device(self):
        # NOTE: first octet must NOT have the locally-administered bit set
        # (mac & 0x02 on the first byte) — that would make this a private/
        # randomized MAC and, with no hostname, trip the new-device
        # notification suppression covered separately below.
        mac, ip = "10:bb:cc:dd:ee:01", "10.0.0.201"

        self.assertIsNone(self.scanner.device_db.get_device(mac))

        # Simulate what _passive_monitor_loop does for a REACHABLE line.
        self.scanner._process_scan_results(
            {(mac, ip)}, hostnames={}, alive_macs={mac}, reachable_macs={mac},
        )

        device = self.scanner.device_db.get_device(mac)
        self.assertIsNotNone(device)
        self.assertEqual(device["ip"], ip)
        self.assertTrue(device["is_active"])
        self.notify_new_device.assert_called_once()

        activity = self.scanner.device_db.get_activity_log(limit=10)
        events = [a["event"] for a in activity if a["mac"] == mac]
        self.assertIn("connect", events)

    def test_passive_event_reconnects_inactive_device(self):
        mac, ip = "10:bb:cc:dd:ee:02", "10.0.0.202"

        # First contact: creates the device.
        self.scanner._process_scan_results(
            {(mac, ip)}, hostnames={}, alive_macs={mac}, reachable_macs={mac},
        )
        self.notify_new_device.reset_mock()

        # Device goes inactive (as if the arping-confirmation path declared it gone).
        self.scanner.device_db.mark_inactive(mac)
        # Force reconnect past the quick-reconnect grace window.
        self.scanner._disconnect_ts[mac] = datetime.now() - timedelta(seconds=1000)

        # Passive monitor sees it REACHABLE again.
        self.scanner._process_scan_results(
            {(mac, ip)}, hostnames={}, alive_macs={mac}, reachable_macs={mac},
        )

        device = self.scanner.device_db.get_device(mac)
        self.assertTrue(device["is_active"])
        self.notify_new_device.assert_called_once()
        call_kwargs = self.notify_new_device.call_args.kwargs
        self.assertTrue(call_kwargs.get("is_returning"))

    def test_stale_only_event_does_not_reconnect_inactive_device(self):
        """A STALE-state passive line (alive_macs empty) must not resurrect
        an inactive device — mirrors the poller's existing safety check."""
        mac, ip = "10:bb:cc:dd:ee:03", "10.0.0.203"
        self.scanner._process_scan_results(
            {(mac, ip)}, hostnames={}, alive_macs={mac}, reachable_macs={mac},
        )
        self.scanner.device_db.mark_inactive(mac)
        self.notify_new_device.reset_mock()

        # Simulate a passive STALE line: found but not in alive_macs.
        self.scanner._process_scan_results(
            {(mac, ip)}, hostnames={}, alive_macs=set(), reachable_macs=set(),
        )

        device = self.scanner.device_db.get_device(mac)
        self.assertFalse(device["is_active"])
        self.notify_new_device.assert_not_called()

    def test_private_mac_without_identity_does_not_notify(self):
        """A brand-new randomized/private MAC with no hostname yet looks
        like a phone that just rotated its MAC — it should be tracked
        (device row + activity log) but not spam a desktop notification."""
        mac, ip = "e2:4a:71:b3:f8:10", "10.0.0.210"
        self.assertTrue(self.scanner.identity.is_private_mac(mac))

        self.scanner._process_scan_results(
            {(mac, ip)}, hostnames={}, alive_macs={mac}, reachable_macs={mac},
        )

        device = self.scanner.device_db.get_device(mac)
        self.assertIsNotNone(device)
        self.assertTrue(device["is_active"])
        self.notify_new_device.assert_not_called()

        activity = self.scanner.device_db.get_activity_log(limit=10)
        events = [a["event"] for a in activity if a["mac"] == mac]
        self.assertIn("connect", events)

    def test_private_mac_with_hostname_still_notifies(self):
        """A private MAC that already resolved a hostname (e.g. DHCP/DNS
        gave it away) is treated as identified and still notifies."""
        mac, ip = "e2:4a:71:b3:f8:11", "10.0.0.211"
        self.assertTrue(self.scanner.identity.is_private_mac(mac))

        self.scanner._process_scan_results(
            {(mac, ip)}, hostnames={mac: "Wils-iPhone"},
            alive_macs={mac}, reachable_macs={mac},
        )

        self.notify_new_device.assert_called_once()


if __name__ == "__main__":
    unittest.main()

"""Offline unit tests for the pure decision logic in scanner.py:

- Type-aware absence/stale grace periods (_absent_timeout / _stale_timeout),
  which give power-saving phones/tablets/watches/laptops a longer grace
  before we start arping-probing them for disconnect.
- The chronic-flapper classifier (_prune_flap_times / _is_chronic_flapper),
  which suppresses connect/disconnect notification spam for devices that
  bounce off the ARP table repeatedly.

All tests are fully offline: no network, no subprocess, no root, no live
DB access — these functions operate purely on device dicts / datetime
lists passed in by the test.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scanner


class TestAbsentTimeout(unittest.TestCase):
    def test_phone_gets_extended_timeout(self):
        device = {"resolved_type": "phone"}
        self.assertEqual(scanner._absent_timeout(device), 300)

    def test_tablet_gets_extended_timeout(self):
        device = {"custom_type": "Tablet"}
        self.assertEqual(scanner._absent_timeout(device), 300)

    def test_watch_gets_extended_timeout(self):
        device = {"device_type": "Smart Watch"}
        self.assertEqual(scanner._absent_timeout(device), 300)

    def test_laptop_gets_medium_timeout(self):
        device = {"resolved_type": "laptop"}
        self.assertEqual(scanner._absent_timeout(device), 180)

    def test_desktop_keeps_default_timeout(self):
        device = {"resolved_type": "desktop"}
        self.assertEqual(scanner._absent_timeout(device), scanner.ABSENT_TIMEOUT)

    def test_unknown_type_keeps_default_timeout(self):
        device = {}
        self.assertEqual(scanner._absent_timeout(device), scanner.ABSENT_TIMEOUT)

    def test_iot_console_tv_network_printer_keep_default(self):
        for t in ("iot", "console", "tv", "network device", "printer", "unknown"):
            device = {"resolved_type": t}
            self.assertEqual(scanner._absent_timeout(device), scanner.ABSENT_TIMEOUT, t)

    def test_custom_type_wins_over_resolved_type(self):
        # custom_type ("laptop") should win over resolved_type ("desktop")
        device = {"custom_type": "laptop", "resolved_type": "desktop"}
        self.assertEqual(scanner._absent_timeout(device), 180)

    def test_case_insensitive_match(self):
        device = {"resolved_type": "PHONE/TABLET (MAC RANDOMIZED)"}
        self.assertEqual(scanner._absent_timeout(device), 300)

    def test_substring_match_on_composite_type_string(self):
        # e.g. "Android (Samsung) Phone" style composite strings
        device = {"device_type": "Android (Samsung) Phone"}
        self.assertEqual(scanner._absent_timeout(device), 300)


class TestStaleTimeout(unittest.TestCase):
    def test_phone_stale_timeout(self):
        device = {"resolved_type": "phone"}
        self.assertEqual(scanner._stale_timeout(device), 150)

    def test_laptop_stale_timeout(self):
        device = {"resolved_type": "laptop"}
        self.assertEqual(scanner._stale_timeout(device), 90)

    def test_default_stale_timeout(self):
        device = {"resolved_type": "desktop"}
        self.assertEqual(scanner._stale_timeout(device), scanner.STALE_TIMEOUT)

    def test_missing_device_fields_default(self):
        self.assertEqual(scanner._stale_timeout({}), scanner.STALE_TIMEOUT)


class TestFlapTimePruning(unittest.TestCase):
    def test_prune_drops_entries_older_than_window(self):
        now = datetime.now()
        old = now - timedelta(seconds=scanner.CHRONIC_FLAP_WINDOW + 1)
        recent = now - timedelta(seconds=10)
        pruned = scanner._prune_flap_times([old, recent], now)
        self.assertEqual(pruned, [recent])

    def test_prune_keeps_entries_within_window(self):
        now = datetime.now()
        times = [now - timedelta(seconds=s) for s in (10, 100, 1000)]
        pruned = scanner._prune_flap_times(times, now)
        self.assertEqual(len(pruned), 3)

    def test_prune_empty_list(self):
        self.assertEqual(scanner._prune_flap_times([], datetime.now()), [])

    def test_prune_boundary_entry_dropped(self):
        # Entry exactly at (or past) the window edge should not survive.
        now = datetime.now()
        edge = now - timedelta(seconds=scanner.CHRONIC_FLAP_WINDOW)
        pruned = scanner._prune_flap_times([edge], now)
        self.assertEqual(pruned, [])


class TestChronicFlapperClassifier(unittest.TestCase):
    def test_below_threshold_not_chronic(self):
        now = datetime.now()
        times = [now - timedelta(seconds=s) for s in (10, 20)]
        self.assertEqual(len(times), scanner.CHRONIC_FLAP_THRESHOLD - 1)
        self.assertFalse(scanner._is_chronic_flapper(times, now))

    def test_at_threshold_is_chronic(self):
        now = datetime.now()
        times = [now - timedelta(seconds=s) for s in range(scanner.CHRONIC_FLAP_THRESHOLD)]
        self.assertTrue(scanner._is_chronic_flapper(times, now))

    def test_above_threshold_is_chronic(self):
        now = datetime.now()
        times = [now - timedelta(seconds=s) for s in range(scanner.CHRONIC_FLAP_THRESHOLD + 5)]
        self.assertTrue(scanner._is_chronic_flapper(times, now))

    def test_old_disconnects_outside_window_dont_count(self):
        # Enough disconnects to hit the threshold, but all outside the
        # trailing window -> should NOT be classified as chronic.
        now = datetime.now()
        far_past = scanner.CHRONIC_FLAP_WINDOW + 100
        times = [now - timedelta(seconds=far_past + s) for s in range(scanner.CHRONIC_FLAP_THRESHOLD + 2)]
        self.assertFalse(scanner._is_chronic_flapper(times, now))

    def test_mixed_old_and_recent_only_recent_count(self):
        now = datetime.now()
        old = [now - timedelta(seconds=scanner.CHRONIC_FLAP_WINDOW + 500) for _ in range(5)]
        recent = [now - timedelta(seconds=s) for s in (10, 20)]  # below threshold alone
        self.assertFalse(scanner._is_chronic_flapper(old + recent, now))
        recent.append(now - timedelta(seconds=30))  # now at threshold
        self.assertTrue(scanner._is_chronic_flapper(old + recent, now))

    def test_no_reset_bug_long_absence_does_not_wipe_history(self):
        """Regression test for the old FLAP_SUPPRESS_TIME bug: a device
        that's been away for a long time (but still within the 1h chronic
        window) must keep its flap count instead of silently resetting."""
        now = datetime.now()
        # 3 disconnects, oldest 50 minutes ago (well within the 1h window,
        # but well past the old 300s FLAP_SUPPRESS_TIME that used to wipe
        # history after this much absence).
        times = [now - timedelta(minutes=m) for m in (50, 30, 10)]
        self.assertTrue(scanner._is_chronic_flapper(times, now))
        # Pruning (the "on every touch" step used instead of a hard reset)
        # must not have dropped any of them, since all are inside the window.
        self.assertEqual(len(scanner._prune_flap_times(times, now)), 3)


if __name__ == "__main__":
    unittest.main()

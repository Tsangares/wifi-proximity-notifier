"""Offline tests for passive connect detection (net.parse_neigh_line, net.NeighMonitor).

Sample lines below were captured live with `ip monitor neigh` while pinging
known and unknown hosts on the LAN (see plans/scan-optimizations.md). The
"Deleted " prefix case is synthetic — documented iproute2 behavior for
removed neighbor entries, not something we could trigger without root on
this machine (ip neigh del needs CAP_NET_ADMIN).
"""

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import net


# Real captured `ip monitor neigh` output (see capture session in task notes).
CAPTURED_LINES = [
    "10.0.0.23 dev wlan0 lladdr c2:85:82:c2:44:e2 REACHABLE \n",
    "10.0.0.111 dev wlan0 lladdr 4c:49:6c:f0:4f:fb REACHABLE \n",
    "10.0.0.77 dev wlan0 FAILED \n",
    "10.0.0.50 dev wlan0 FAILED \n",
    "10.0.0.13 dev wlan0 lladdr e4:ce:8f:66:4f:c0 STALE \n",
    "10.0.0.13 dev wlan0 lladdr e4:ce:8f:66:4f:c0 DELAY \n",
]


class TestParseNeighLine(unittest.TestCase):
    def test_reachable_line(self):
        parsed = net.parse_neigh_line(CAPTURED_LINES[0])
        self.assertEqual(parsed, {
            "mac": "c2:85:82:c2:44:e2", "ip": "10.0.0.23",
            "state": "REACHABLE", "deleted": False,
        })

    def test_second_reachable_line(self):
        parsed = net.parse_neigh_line(CAPTURED_LINES[1])
        self.assertEqual(parsed["mac"], "4c:49:6c:f0:4f:fb")
        self.assertEqual(parsed["ip"], "10.0.0.111")
        self.assertEqual(parsed["state"], "REACHABLE")

    def test_failed_line_with_no_mac_is_ignored(self):
        # FAILED entries for unresponsive IPs carry no lladdr — not usable.
        self.assertIsNone(net.parse_neigh_line(CAPTURED_LINES[2]))
        self.assertIsNone(net.parse_neigh_line(CAPTURED_LINES[3]))

    def test_stale_line(self):
        parsed = net.parse_neigh_line(CAPTURED_LINES[4])
        self.assertEqual(parsed["state"], "STALE")
        self.assertFalse(parsed["deleted"])

    def test_delay_line(self):
        parsed = net.parse_neigh_line(CAPTURED_LINES[5])
        self.assertEqual(parsed["state"], "DELAY")

    def test_deleted_prefix(self):
        line = "Deleted 10.0.0.50 dev wlan0 lladdr aa:bb:cc:dd:ee:ff STALE\n"
        parsed = net.parse_neigh_line(line)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed["deleted"])
        self.assertEqual(parsed["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed["ip"], "10.0.0.50")

    def test_mac_is_lowercased(self):
        line = "10.0.0.5 dev wlan0 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n"
        parsed = net.parse_neigh_line(line)
        self.assertEqual(parsed["mac"], "aa:bb:cc:dd:ee:ff")

    def test_ipv6_link_local_ignored(self):
        line = "fe80::1234 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        self.assertIsNone(net.parse_neigh_line(line))

    def test_incomplete_ignored(self):
        line = "10.0.0.99 dev wlan0  INCOMPLETE\n"
        self.assertIsNone(net.parse_neigh_line(line))

    def test_blank_line_ignored(self):
        self.assertIsNone(net.parse_neigh_line(""))
        self.assertIsNone(net.parse_neigh_line("   \n"))

    def test_garbage_line_ignored(self):
        self.assertIsNone(net.parse_neigh_line("not a neigh line at all"))

    def test_all_captured_lines_parse_without_exception(self):
        for line in CAPTURED_LINES:
            net.parse_neigh_line(line)  # must not raise


class _FakeProc:
    """Stand-in for subprocess.Popen — yields a fixed set of lines from
    .stdout then closes, simulating `ip monitor neigh` exiting."""

    def __init__(self, lines, returncode=1):
        self._lines = list(lines)
        self.stdout = iter(self._lines)
        self._returncode = returncode
        self.terminated = False

    def poll(self):
        return self._returncode

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return self._returncode


class TestNeighMonitorRestart(unittest.TestCase):
    def test_restarts_after_process_exit(self):
        """If the `ip monitor neigh` subprocess dies, NeighMonitor should
        spawn a new one rather than silently going quiet."""
        batches = [
            ["10.0.0.23 dev wlan0 lladdr c2:85:82:c2:44:e2 REACHABLE\n"],
            ["10.0.0.111 dev wlan0 lladdr 4c:49:6c:f0:4f:fb REACHABLE\n"],
        ]
        call_count = {"n": 0}

        def fake_popen(*args, **kwargs):
            i = call_count["n"]
            call_count["n"] += 1
            return _FakeProc(batches[i] if i < len(batches) else [])

        monitor = net.NeighMonitor(restart_delay=0)
        seen = []
        with mock.patch("subprocess.Popen", side_effect=fake_popen), \
             mock.patch("time.sleep", return_value=None):
            for line in monitor.lines():
                seen.append(line)
                if len(seen) >= 2:
                    monitor.stop()
                    break

        self.assertEqual(seen, [
            "10.0.0.23 dev wlan0 lladdr c2:85:82:c2:44:e2 REACHABLE\n",
            "10.0.0.111 dev wlan0 lladdr 4c:49:6c:f0:4f:fb REACHABLE\n",
        ])
        # First process's single line exhausted, monitor restarted the
        # subprocess (2 Popen calls) to keep receiving lines.
        self.assertEqual(call_count["n"], 2)

    def test_missing_ip_binary_exits_cleanly(self):
        """If `ip` isn't installed, the generator should end instead of
        busy-looping or raising out of the consumer thread."""
        monitor = net.NeighMonitor(restart_delay=0)
        with mock.patch("subprocess.Popen", side_effect=FileNotFoundError()):
            lines = list(monitor.lines())
        self.assertEqual(lines, [])

    def test_stop_prevents_further_restarts(self):
        def fake_popen(*args, **kwargs):
            return _FakeProc([])  # immediately "exits" with no lines

        monitor = net.NeighMonitor(restart_delay=0)
        with mock.patch("subprocess.Popen", side_effect=fake_popen), \
             mock.patch("time.sleep", side_effect=lambda s: monitor.stop()):
            lines = list(monitor.lines())
        self.assertEqual(lines, [])


if __name__ == "__main__":
    unittest.main()

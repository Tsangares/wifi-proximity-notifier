"""Offline tests for notifier._send_notification's gdbus-unavailable
deduplication (see notifier.py's _dbus_session_down flag): repeated
"no DBUS session" failures should log INFO once (not WARNING every time),
and recovery should log once too. Fully offline — _run_as_user is mocked
so no real subprocess/gdbus/DBUS call happens.
"""

import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import notifier


def _completed(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestGdbusUnavailableDedup(unittest.TestCase):
    def setUp(self):
        # Reset module-level dedup state between tests.
        notifier._dbus_session_down = False
        self._patch = mock.patch.object(notifier, "_run_as_user")
        self.mock_run = self._patch.start()

    def tearDown(self):
        self._patch.stop()
        notifier._dbus_session_down = False

    def _dbus_down_result(self):
        return _completed(
            returncode=1,
            stderr="Error connecting: Could not connect: No such file or directory",
        )

    def test_first_failure_logs_info_and_sets_flag(self):
        self.mock_run.return_value = self._dbus_down_result()
        with self.assertLogs(notifier.log, level="INFO") as cm:
            notifier._send_notification("title", "body")
        self.assertTrue(notifier._dbus_session_down)
        self.assertTrue(any("No desktop session DBUS" in m for m in cm.output))

    def test_repeated_failures_do_not_spam_logs(self):
        self.mock_run.return_value = self._dbus_down_result()
        notifier._send_notification("title", "body")  # first failure, sets flag
        self.assertTrue(notifier._dbus_session_down)

        # Second and third failures while already "down" should produce no
        # further logging at all from _send_notification.
        with self.assertNoLogs(notifier.log):
            notifier._send_notification("title", "body")
            notifier._send_notification("title", "body")
        self.assertTrue(notifier._dbus_session_down)

    def test_recovery_logs_info_once_and_clears_flag(self):
        self.mock_run.return_value = self._dbus_down_result()
        notifier._send_notification("title", "body")
        self.assertTrue(notifier._dbus_session_down)

        self.mock_run.return_value = _completed(returncode=0, stdout="(uint32 1,)")
        with self.assertLogs(notifier.log, level="INFO") as cm:
            notifier._send_notification("title", "body")
        self.assertFalse(notifier._dbus_session_down)
        self.assertTrue(any("recovered" in m for m in cm.output))

    def test_unrelated_gdbus_failure_still_warns_every_time(self):
        """A different gdbus failure (not the DBUS-unavailable signature)
        must keep warning normally — only the specific known failure mode
        is deduplicated."""
        self.mock_run.return_value = _completed(returncode=1, stderr="some other error")
        with self.assertLogs(notifier.log, level="WARNING") as cm:
            notifier._send_notification("title", "body")
        self.assertFalse(notifier._dbus_session_down)
        self.assertTrue(any("gdbus failed" in m for m in cm.output))

    def test_happy_path_when_never_down_logs_nothing(self):
        self.mock_run.return_value = _completed(returncode=0, stdout="(uint32 1,)")
        with self.assertNoLogs(notifier.log):
            notifier._send_notification("title", "body")


if __name__ == "__main__":
    unittest.main()

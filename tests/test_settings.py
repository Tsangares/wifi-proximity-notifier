import os
import shutil
import tempfile
import threading
import unittest


class SettingsTest(unittest.TestCase):
    def setUp(self):
        import device_db
        self.device_db = device_db
        self.tmpdir = tempfile.mkdtemp()
        self._orig_dir = device_db.DB_DIR
        self._orig_path = device_db.DB_PATH
        device_db.DB_DIR = self.tmpdir
        device_db.DB_PATH = os.path.join(self.tmpdir, "devices.db")
        device_db._local = threading.local()  # drop cached connection

    def tearDown(self):
        self.device_db.DB_DIR = self._orig_dir
        self.device_db.DB_PATH = self._orig_path
        self.device_db._local = threading.local()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_default_when_unset(self):
        self.assertEqual(self.device_db.get_setting("sound_enabled", "1"), "1")

    def test_set_get_roundtrip(self):
        self.device_db.set_setting("sound_enabled", "0")
        self.assertEqual(self.device_db.get_setting("sound_enabled", "1"), "0")
        self.device_db.set_setting("sound_enabled", "1")
        self.assertEqual(self.device_db.get_setting("sound_enabled", "0"), "1")

    def test_notifier_honors_setting(self):
        import notifier
        self.device_db.set_setting("sound_enabled", "0")
        self.assertFalse(notifier.sound_enabled())
        self.device_db.set_setting("sound_enabled", "1")
        self.assertTrue(notifier.sound_enabled())

    def test_notifier_defaults_on(self):
        import notifier
        self.assertTrue(notifier.sound_enabled())


if __name__ == "__main__":
    unittest.main()

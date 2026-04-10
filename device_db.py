import sqlite3
import os
import threading
from datetime import datetime

DB_DIR = os.path.expanduser("~/.local/share/wifi-notifier")
DB_PATH = os.path.join(DB_DIR, "devices.db")

_local = threading.local()


def _get_conn():
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(DB_DIR, exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _init_tables(_local.conn)
    return _local.conn


def _init_tables(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT DEFAULT '',
            custom_name TEXT DEFAULT '',
            manufacturer TEXT DEFAULT 'Unknown',
            device_type TEXT DEFAULT 'Unknown',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            event TEXT NOT NULL,
            ip TEXT,
            timestamp TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity_log(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_activity_mac ON activity_log(mac);
    """)
    # Migrate: add columns if missing
    cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
    if "hostname" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN hostname TEXT DEFAULT ''")
        conn.commit()
    if "last_probed" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN last_probed TEXT DEFAULT ''")
        conn.commit()
    if "fingerprint_data" not in cols:
        conn.execute("ALTER TABLE devices ADD COLUMN fingerprint_data TEXT DEFAULT ''")
        conn.commit()
    # Clean up bad data from nmap parsing bug (hostname="1", ip="0.0.0.x")
    conn.execute("UPDATE devices SET hostname = '' WHERE hostname = '1'")
    conn.execute("UPDATE devices SET ip = '' WHERE ip LIKE '0.0.0.%'")
    conn.commit()


def upsert_device(mac, ip, manufacturer="Unknown", device_type="Unknown", hostname=""):
    conn = _get_conn()
    now = datetime.now().isoformat()
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO devices (mac, ip, hostname, manufacturer, device_type, first_seen, last_seen, is_active) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            (mac, ip, hostname, manufacturer, device_type, now, now),
        )
        conn.commit()
        return True  # new device
    else:
        conn.execute(
            "UPDATE devices SET "
            "ip = CASE WHEN ? NOT LIKE '0.%' THEN ? ELSE ip END, "
            "hostname = CASE WHEN ? != '' THEN ? ELSE hostname END, "
            "manufacturer = CASE WHEN ? != 'Unknown' THEN ? ELSE manufacturer END, "
            "device_type = CASE WHEN ? != 'Unknown' THEN ? ELSE device_type END, "
            "last_seen = ?, is_active = 1 WHERE mac = ?",
            (ip, ip, hostname, hostname, manufacturer, manufacturer, device_type, device_type, now, mac),
        )
        conn.commit()
        return False  # existing device


def mark_inactive(mac):
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute("UPDATE devices SET is_active = 0, last_seen = ? WHERE mac = ?", (now, mac))
    conn.commit()


def mark_all_inactive():
    conn = _get_conn()
    conn.execute("UPDATE devices SET is_active = 0")
    conn.commit()


def get_active_devices():
    conn = _get_conn()
    return [dict(r) for r in conn.execute(
        "SELECT * FROM devices WHERE is_active = 1 ORDER BY last_seen DESC"
    ).fetchall()]


def get_inactive_devices():
    conn = _get_conn()
    return [dict(r) for r in conn.execute(
        "SELECT * FROM devices WHERE is_active = 0 ORDER BY last_seen DESC"
    ).fetchall()]


def get_all_devices():
    conn = _get_conn()
    return [dict(r) for r in conn.execute(
        "SELECT * FROM devices ORDER BY is_active DESC, last_seen DESC"
    ).fetchall()]


def rename_device(mac, name):
    conn = _get_conn()
    conn.execute("UPDATE devices SET custom_name = ? WHERE mac = ?", (name, mac))
    conn.commit()


def log_event(mac, event, ip=""):
    conn = _get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        "INSERT INTO activity_log (mac, event, ip, timestamp) VALUES (?, ?, ?, ?)",
        (mac, event, ip, now),
    )
    conn.commit()


def get_activity_log(limit=100):
    conn = _get_conn()
    rows = conn.execute(
        "SELECT a.*, d.custom_name, d.manufacturer, d.device_type "
        "FROM activity_log a LEFT JOIN devices d ON a.mac = d.mac "
        "ORDER BY a.timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_device(mac):
    conn = _get_conn()
    row = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    return dict(row) if row else None


def update_fingerprint(mac, device_type=None, extra_info="", fingerprint_data=""):
    """Update a device's identification from deep probing results."""
    conn = _get_conn()
    now = datetime.now().isoformat()
    if device_type:
        conn.execute(
            "UPDATE devices SET device_type = ?, last_probed = ?, fingerprint_data = ? WHERE mac = ?",
            (device_type, now, fingerprint_data, mac),
        )
    else:
        conn.execute(
            "UPDATE devices SET last_probed = ?, fingerprint_data = ? WHERE mac = ?",
            (now, fingerprint_data, mac),
        )
    conn.commit()


def clear_last_probed(mac):
    """Clear last_probed so device can be re-fingerprinted."""
    conn = _get_conn()
    conn.execute("UPDATE devices SET last_probed = '' WHERE mac = ?", (mac,))
    conn.commit()

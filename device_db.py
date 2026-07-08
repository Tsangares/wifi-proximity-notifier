import sqlite3
import os
import json
import threading
from datetime import datetime, timedelta

DB_DIR = os.path.expanduser("~/.local/share/wifi-notifier")
# WIFI_NOTIFIER_DB env var overrides the DB location (used by tests / mock mode)
DB_PATH = os.environ.get("WIFI_NOTIFIER_DB") or os.path.join(DB_DIR, "devices.db")

_local = threading.local()


def use_mock_db():
    """Switch to a separate mock database file. MUST be called before any
    DB access. Mock mode wipes and re-seeds its DB, so it must never point
    at the real devices.db (that would destroy accumulated device history)."""
    global DB_PATH
    DB_PATH = os.path.join(DB_DIR, "mock.db")
    # Drop any existing per-thread connection so it reopens on the new path
    if getattr(_local, "conn", None) is not None:
        _local.conn.close()
        _local.conn = None


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
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
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
    # Identity-engine columns (additive migration — existing data untouched).
    # Resolved fields are written by identity.resolve() via set_identity();
    # custom_* and owner are user-set and never touched by automatic code.
    for col, decl in [
        ("display_name", "TEXT DEFAULT ''"),      # resolved best name (auto)
        ("resolved_type", "TEXT DEFAULT 'unknown'"),  # canonical device type (auto)
        ("os_guess", "TEXT DEFAULT ''"),          # resolved OS (auto)
        ("identity_meta", "TEXT DEFAULT ''"),     # JSON: per-field confidence + provenance
        ("identity_version", "INTEGER DEFAULT 0"),  # engine version that last resolved
        ("is_private_mac", "INTEGER DEFAULT 0"),  # locally-administered (randomized) MAC
        ("custom_type", "TEXT DEFAULT ''"),       # user override — sacred
        ("owner", "TEXT DEFAULT ''"),             # user-set owner — sacred
        ("muted", "INTEGER DEFAULT 0"),           # user-set notify-suppress — sacred
    ]:
        if col not in cols:
            conn.execute(f"ALTER TABLE devices ADD COLUMN {col} {decl}")
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


def get_setting(key, default=""):
    conn = _get_conn()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    conn = _get_conn()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )
    conn.commit()


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
        "SELECT a.*, d.custom_name, d.display_name, d.hostname, d.manufacturer, "
        "d.device_type, d.resolved_type, d.custom_type, d.is_private_mac "
        "FROM activity_log a LEFT JOIN devices d ON a.mac = d.mac "
        "ORDER BY a.timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_device_presence(mac, hours=24):
    """Connect/disconnect events for one device within the last `hours`,
    oldest first. Client derives online/offline spans from this raw stream
    (kept simple here — no interval math server-side)."""
    conn = _get_conn()
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    rows = conn.execute(
        "SELECT timestamp AS ts, event FROM activity_log "
        "WHERE mac = ? AND timestamp >= ? AND event IN ('connect', 'disconnect') "
        "ORDER BY timestamp ASC",
        (mac, cutoff),
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


# ---------------------------------------------------------------------------
# Identity engine persistence
# ---------------------------------------------------------------------------

def set_identity(mac, display_name, resolved_type, os_guess, manufacturer,
                 identity_meta, is_private_mac, engine_version):
    """Persist resolved identity fields. NEVER touches custom_name,
    custom_type, or owner — those are user-set and sacred."""
    conn = _get_conn()
    conn.execute(
        "UPDATE devices SET display_name = ?, resolved_type = ?, os_guess = ?, "
        "manufacturer = ?, identity_meta = ?, is_private_mac = ?, identity_version = ? "
        "WHERE mac = ?",
        (display_name, resolved_type, os_guess, manufacturer, identity_meta,
         1 if is_private_mac else 0, engine_version, mac),
    )
    conn.commit()


def update_device_user_fields(mac, name=None, dtype=None, owner=None, muted=None):
    """Set user-controlled fields (pass None to leave a field unchanged;
    pass '' to explicitly clear an override). `muted` is a bool/int flag —
    also user-set and sacred; only this function (and callers of it) ever
    write it."""
    conn = _get_conn()
    sets, args = [], []
    if name is not None:
        sets.append("custom_name = ?")
        args.append(name)
    if dtype is not None:
        sets.append("custom_type = ?")
        args.append(dtype)
    if owner is not None:
        sets.append("owner = ?")
        args.append(owner)
    if muted is not None:
        sets.append("muted = ?")
        args.append(1 if muted else 0)
    if not sets:
        return
    args.append(mac)
    conn.execute(f"UPDATE devices SET {', '.join(sets)} WHERE mac = ?", args)
    conn.commit()


def get_devices_view(new_window_hours=24):
    """All devices enriched for the dashboard:
    - name: custom_name > display_name > hostname > mac (user override wins)
    - type: custom_type > resolved_type
    - identity: parsed identity_meta JSON (confidence + provenance) or None
    - connection_count: number of 'connect' events in the activity log
    - is_new: first_seen within new_window_hours
    """
    conn = _get_conn()
    counts = {r[0]: r[1] for r in conn.execute(
        "SELECT mac, COUNT(*) FROM activity_log WHERE event = 'connect' GROUP BY mac"
    ).fetchall()}
    cutoff = (datetime.now() - timedelta(hours=new_window_hours)).isoformat()
    out = []
    for r in conn.execute(
        "SELECT * FROM devices ORDER BY is_active DESC, last_seen DESC"
    ).fetchall():
        d = dict(r)
        d["name"] = (d.get("custom_name") or d.get("display_name")
                     or d.get("hostname") or d["mac"])
        d["type"] = d.get("custom_type") or d.get("resolved_type") or "unknown"
        try:
            d["identity"] = json.loads(d["identity_meta"]) if d.get("identity_meta") else None
        except (json.JSONDecodeError, TypeError):
            d["identity"] = None
        d["connection_count"] = counts.get(d["mac"], 0)
        d["is_new"] = bool(d.get("first_seen") and d["first_seen"] >= cutoff)
        out.append(d)
    return out


def devices_needing_identity(engine_version):
    """Devices whose identity was resolved by an older engine version
    (or never resolved). Used for startup backfill."""
    conn = _get_conn()
    return [dict(r) for r in conn.execute(
        "SELECT * FROM devices WHERE identity_version != ? OR identity_meta = ''",
        (engine_version,),
    ).fetchall()]

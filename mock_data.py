"""Seed the database with fake devices for demo/screenshot purposes."""

from datetime import datetime, timedelta
import device_db

MOCK_DEVICES = [
    {
        "mac": "e2:4a:71:b3:f8:01",
        "ip": "10.0.0.42",
        "manufacturer": "Randomized MAC",
        "device_type": "iPhone/iPad",
        "hostname": "Wils-iPhone",
        "custom_name": "Wil's iPhone",
        "is_active": True,
        "hours_ago": 0.01,
    },
    {
        "mac": "a4:83:e7:2d:c1:09",
        "ip": "10.0.0.15",
        "manufacturer": "Apple, Inc.",
        "device_type": "Apple (Mac/TV/HomePod)",
        "hostname": "Wils-MacBook-Pro.local",
        "custom_name": "Wil's MacBook",
        "is_active": True,
        "hours_ago": 0.05,
    },
    {
        "mac": "d4:ae:05:7f:22:b4",
        "ip": "10.0.0.88",
        "manufacturer": "Vizio, Inc",
        "device_type": "TV (Vizio)",
        "hostname": "",
        "custom_name": "Living Room TV",
        "is_active": True,
        "hours_ago": 0.2,
    },
    {
        "mac": "8c:f5:a3:91:de:47",
        "ip": "10.0.0.31",
        "manufacturer": "Samsung Electronics Co.,Ltd",
        "device_type": "Android (Samsung)",
        "hostname": "Galaxy-S24",
        "custom_name": "",
        "is_active": True,
        "hours_ago": 0.1,
    },
    {
        "mac": "fc:a1:83:0a:ee:5c",
        "ip": "10.0.0.102",
        "manufacturer": "Amazon Technologies Inc.",
        "device_type": "Smart Device (Amazon)",
        "hostname": "",
        "custom_name": "Ring Doorbell",
        "is_active": True,
        "hours_ago": 0.3,
    },
    {
        "mac": "f4:f5:d8:3b:77:a0",
        "ip": "10.0.0.55",
        "manufacturer": "Google LLC",
        "device_type": "Smart Device (Google/Nest)",
        "hostname": "",
        "custom_name": "Nest Thermostat",
        "is_active": True,
        "hours_ago": 0.5,
    },
    {
        "mac": "48:a6:b8:c2:44:19",
        "ip": "10.0.0.67",
        "manufacturer": "Sonos, Inc.",
        "device_type": "Smart Speaker (Sonos)",
        "hostname": "Sonos-Living-Room.local",
        "custom_name": "Sonos Speaker",
        "is_active": True,
        "hours_ago": 1.0,
    },
    {
        "mac": "24:0a:c4:88:f3:2e",
        "ip": "10.0.0.120",
        "manufacturer": "Espressif Inc.",
        "device_type": "IoT Device (ESP)",
        "hostname": "esp32-sensor",
        "custom_name": "",
        "is_active": True,
        "hours_ago": 0.8,
    },
    {
        "mac": "3c:2a:f4:5d:01:bb",
        "ip": "10.0.0.200",
        "manufacturer": "Hewlett Packard",
        "device_type": "PC/Laptop (HP)",
        "hostname": "BRWF45D01BB.local",
        "custom_name": "Office Printer",
        "is_active": False,
        "hours_ago": 6.0,
    },
    {
        "mac": "e6:9c:22:d1:ab:03",
        "ip": "10.0.0.78",
        "manufacturer": "Randomized MAC",
        "device_type": "iPhone/iPad",
        "hostname": "Jens-iPad",
        "custom_name": "Jen's iPad",
        "is_active": False,
        "hours_ago": 3.5,
    },
    {
        "mac": "a0:36:9f:e4:c7:55",
        "ip": "10.0.0.22",
        "manufacturer": "Intel Corporate",
        "device_type": "PC/Laptop (Intel)",
        "hostname": "DESKTOP-GAMING",
        "custom_name": "Gaming PC",
        "is_active": False,
        "hours_ago": 12.0,
    },
    {
        "mac": "da:77:01:f8:6e:c2",
        "ip": "10.0.0.91",
        "manufacturer": "Randomized MAC",
        "device_type": "Android Phone (Cast)",
        "hostname": "",
        "custom_name": "Guest's Pixel",
        "is_active": False,
        "hours_ago": 26.0,
    },
]

# Activity log: (device_index, event, hours_ago)
MOCK_ACTIVITY = [
    (0, "connect", 0.01),
    (3, "connect", 0.1),
    (1, "connect", 0.05),
    (2, "connect", 0.2),
    (4, "connect", 0.3),
    (5, "connect", 0.5),
    (7, "connect", 0.8),
    (6, "connect", 1.0),
    (9, "disconnect", 3.5),
    (9, "connect", 5.0),
    (8, "disconnect", 6.0),
    (8, "connect", 8.0),
    (10, "disconnect", 12.0),
    (10, "connect", 14.0),
    (11, "disconnect", 26.0),
    (11, "connect", 30.0),
    (0, "disconnect", 2.0),
    (0, "connect", 2.5),
    (3, "disconnect", 4.0),
    (3, "connect", 4.5),
]


def seed_mock_data():
    """Clear the DB and insert fake devices + activity for demo purposes."""
    conn = device_db._get_conn()
    conn.execute("DELETE FROM activity_log")
    conn.execute("DELETE FROM devices")
    conn.commit()

    now = datetime.now()

    for dev in MOCK_DEVICES:
        last_seen = now - timedelta(hours=dev["hours_ago"])
        first_seen = now - timedelta(hours=dev["hours_ago"] + 48)

        device_db.upsert_device(
            dev["mac"], dev["ip"],
            dev["manufacturer"], dev["device_type"],
            dev["hostname"],
        )
        # Set custom_name, first_seen, last_seen, and is_active directly
        conn.execute(
            "UPDATE devices SET custom_name = ?, first_seen = ?, last_seen = ?, is_active = ? WHERE mac = ?",
            (dev["custom_name"], first_seen.isoformat(), last_seen.isoformat(),
             1 if dev["is_active"] else 0, dev["mac"]),
        )

    conn.commit()

    # Insert activity log entries
    for dev_idx, event, hours_ago in sorted(MOCK_ACTIVITY, key=lambda x: x[2], reverse=True):
        dev = MOCK_DEVICES[dev_idx]
        ts = now - timedelta(hours=hours_ago)
        conn.execute(
            "INSERT INTO activity_log (mac, event, ip, timestamp) VALUES (?, ?, ?, ?)",
            (dev["mac"], event, dev["ip"], ts.isoformat()),
        )

    conn.commit()


# Mock mDNS services — what avahi-browse would return on a real network
MOCK_MDNS_SERVICES = {
    "10.0.0.42": [
        {"type": "_companion-link._tcp", "name": "Wil\u2019s iPhone", "hostname": "Wils-iPhone.local", "txt": ""},
        {"type": "_airplay._tcp", "name": "Wil\u2019s iPhone", "hostname": "Wils-iPhone.local", "txt": ""},
    ],
    "10.0.0.15": [
        {"type": "_airplay._tcp", "name": "Wil\u2019s MacBook Pro", "hostname": "Wils-MacBook-Pro.local", "txt": ""},
        {"type": "_smb._tcp", "name": "Wil\u2019s MacBook Pro", "hostname": "Wils-MacBook-Pro.local", "txt": ""},
        {"type": "_afpovertcp._tcp", "name": "Wil\u2019s MacBook Pro", "hostname": "Wils-MacBook-Pro.local", "txt": ""},
    ],
    "10.0.0.78": [
        {"type": "_companion-link._tcp", "name": "Jen\u2019s iPad", "hostname": "Jens-iPad.local", "txt": ""},
        {"type": "_airplay._tcp", "name": "Jen\u2019s iPad", "hostname": "Jens-iPad.local", "txt": ""},
    ],
    "10.0.0.67": [
        {"type": "_sonos._tcp", "name": "Sonos Living Room", "hostname": "Sonos-Living-Room.local", "txt": ""},
        {"type": "_spotify-connect._tcp", "name": "Sonos Living Room", "hostname": "Sonos-Living-Room.local", "txt": ""},
    ],
    "10.0.0.91": [
        {"type": "_googlecast._tcp", "name": "Guest\u2019s Pixel", "hostname": "android-pixel.local", "txt": ""},
    ],
}

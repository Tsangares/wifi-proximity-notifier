"""Seed the database with fake devices for demo/screenshot purposes.

Seeds both the legacy columns (manufacturer, device_type, hostname) via the
normal upsert path AND the identity-engine columns (display_name,
resolved_type, os_guess, is_private_mac, custom_type, owner, identity_meta)
directly via SQL, so --mock looks right even before identity.py ever runs.
This module must NOT import identity or resolver — it stands on its own.
"""

from datetime import datetime, timedelta
import json
import device_db

MOCK_DEVICES = [
    {
        "mac": "e2:4a:71:b3:f8:01",
        "ip": "10.0.0.42",
        "manufacturer": "Apple Inc.",
        "device_type": "iPhone/iPad",
        "hostname": "Wils-iPhone",
        "custom_name": "Wil's iPhone",
        "is_active": True,
        "hours_ago": 0.01,
        "display_name": "Wil's iPhone",
        "resolved_type": "phone",
        "os_guess": "iOS",
        "is_private_mac": True,
        "owner": "Wil",
        "identity_meta": {
            "display_name": {"value": "Wil's iPhone", "confidence": 0.9, "source": "mdns_services"},
            "device_type": {"value": "phone", "confidence": 0.9, "source": "mdns_services"},
            "os_guess": {"value": "iOS", "confidence": 0.9, "source": "mdns_services"},
            "manufacturer": {"value": "Apple Inc.", "confidence": 0.85, "source": "mdns_services"},
            "is_private_mac": True,
            "engine_version": 1,
        },
    },
    {
        "mac": "a4:83:e7:2d:c1:09",
        "ip": "10.0.0.15",
        "manufacturer": "Apple Inc.",
        "device_type": "Apple (Mac/TV/HomePod)",
        "hostname": "Wils-MacBook-Pro.local",
        "custom_name": "Wil's MacBook",
        "is_active": True,
        "hours_ago": 0.05,
        "display_name": "Wil's MacBook Pro",
        "resolved_type": "laptop",
        "os_guess": "macOS",
        "is_private_mac": False,
        "owner": "Wil",
        "identity_meta": {
            "display_name": {"value": "Wil's MacBook Pro", "confidence": 0.95, "source": "mdns_services"},
            "device_type": {"value": "laptop", "confidence": 0.9, "source": "mdns_services"},
            "os_guess": {"value": "macOS", "confidence": 0.9, "source": "mdns_services"},
            "manufacturer": {"value": "Apple Inc.", "confidence": 0.95, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
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
        "display_name": "",
        "resolved_type": "tv",
        "os_guess": "",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "device_type": {"value": "tv", "confidence": 0.6, "source": "mac_vendor"},
            "manufacturer": {"value": "Vizio, Inc", "confidence": 0.95, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
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
        "display_name": "Galaxy-S24",
        "resolved_type": "phone",
        "os_guess": "Android",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "display_name": {"value": "Galaxy-S24", "confidence": 0.5, "source": "hostname_pattern"},
            "device_type": {"value": "phone", "confidence": 0.7, "source": "mac_vendor"},
            "os_guess": {"value": "Android", "confidence": 0.6, "source": "mac_vendor"},
            "manufacturer": {"value": "Samsung Electronics Co.,Ltd", "confidence": 0.95, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
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
        "display_name": "",
        "resolved_type": "camera",
        "os_guess": "embedded",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "device_type": {"value": "camera", "confidence": 0.8, "source": "mac_vendor+mdns"},
            "os_guess": {"value": "embedded", "confidence": 0.6, "source": "mac_vendor"},
            "manufacturer": {"value": "Amazon Technologies Inc.", "confidence": 0.95, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
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
        "display_name": "",
        "resolved_type": "iot",
        "os_guess": "embedded",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "device_type": {"value": "iot", "confidence": 0.75, "source": "mac_vendor+mdns"},
            "os_guess": {"value": "embedded", "confidence": 0.6, "source": "mac_vendor"},
            "manufacturer": {"value": "Google LLC", "confidence": 0.95, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
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
        "display_name": "Sonos Living Room",
        "resolved_type": "speaker",
        "os_guess": "embedded",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "display_name": {"value": "Sonos Living Room", "confidence": 0.9, "source": "mdns_services"},
            "device_type": {"value": "speaker", "confidence": 0.9, "source": "mdns_services"},
            "os_guess": {"value": "embedded", "confidence": 0.6, "source": "mac_vendor"},
            "manufacturer": {"value": "Sonos, Inc.", "confidence": 0.95, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
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
        "display_name": "esp32-sensor",
        "resolved_type": "iot",
        "os_guess": "embedded",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "display_name": {"value": "esp32-sensor", "confidence": 0.4, "source": "hostname"},
            "device_type": {"value": "iot", "confidence": 0.4, "source": "mac_vendor"},
            "manufacturer": {"value": "Espressif Inc.", "confidence": 0.9, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
    },
    {
        "mac": "3c:2a:f4:5d:01:bb",
        "ip": "10.0.0.200",
        "manufacturer": "Brother Industries, Ltd.",
        "device_type": "Printer (Brother)",
        "hostname": "BRWF45D01BB.local",
        "custom_name": "Office Printer",
        "is_active": False,
        "hours_ago": 6.0,
        "display_name": "Brother Printer",
        "resolved_type": "printer",
        "os_guess": "embedded",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "display_name": {"value": "Brother Printer", "confidence": 0.85, "source": "hostname_pattern"},
            "device_type": {"value": "printer", "confidence": 0.9, "source": "hostname_pattern"},
            "os_guess": {"value": "embedded", "confidence": 0.6, "source": "hostname_pattern"},
            "manufacturer": {"value": "Brother Industries, Ltd.", "confidence": 0.9, "source": "hostname_pattern"},
            "is_private_mac": False,
            "engine_version": 1,
        },
    },
    {
        "mac": "e6:9c:22:d1:ab:03",
        "ip": "10.0.0.78",
        "manufacturer": "Apple Inc.",
        "device_type": "iPhone/iPad",
        "hostname": "Jens-iPad",
        "custom_name": "Jen's iPad",
        "is_active": False,
        "hours_ago": 3.5,
        "display_name": "Jen's iPad",
        "resolved_type": "tablet",
        "os_guess": "iOS",
        "is_private_mac": True,
        "owner": "Jen",
        "identity_meta": {
            "display_name": {"value": "Jen's iPad", "confidence": 0.9, "source": "mdns_services"},
            "device_type": {"value": "tablet", "confidence": 0.9, "source": "mdns_services"},
            "os_guess": {"value": "iOS", "confidence": 0.9, "source": "mdns_services"},
            "manufacturer": {"value": "Apple Inc.", "confidence": 0.8, "source": "mdns_services"},
            "is_private_mac": True,
            "engine_version": 1,
        },
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
        "display_name": "DESKTOP-GAMING",
        "resolved_type": "desktop",
        "os_guess": "Windows",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "display_name": {"value": "DESKTOP-GAMING", "confidence": 0.7, "source": "netbios"},
            "device_type": {"value": "desktop", "confidence": 0.6, "source": "hostname_pattern"},
            "os_guess": {"value": "Windows", "confidence": 0.7, "source": "netbios"},
            "manufacturer": {"value": "Intel Corporate", "confidence": 0.7, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
    },
    {
        "mac": "da:77:01:f8:6e:c2",
        "ip": "10.0.0.91",
        "manufacturer": "Google Inc.",
        "device_type": "Android Phone (Cast)",
        "hostname": "",
        "custom_name": "Guest's Pixel",
        "is_active": False,
        "hours_ago": 26.0,
        "display_name": "",
        "resolved_type": "phone",
        "os_guess": "Android",
        "is_private_mac": True,
        "owner": "Guest",
        "identity_meta": {
            "device_type": {"value": "phone", "confidence": 0.6, "source": "mdns_services"},
            "os_guess": {"value": "Android", "confidence": 0.6, "source": "mdns_services"},
            "manufacturer": {"value": "Google Inc.", "confidence": 0.5, "source": "mdns_services"},
            "is_private_mac": True,
            "engine_version": 1,
        },
    },
    # --- Additional devices to exercise the identity-engine UI ---
    {
        # No custom_name and effectively no identity — sits in "Needs labeling"
        # with a user-applied type override (custom_type) to show that type
        # correction and name-labeling are independent.
        "mac": "b2:1c:44:90:aa:11",
        "ip": "10.0.0.150",
        "manufacturer": "Unknown",
        "device_type": "Unknown",
        "hostname": "",
        "custom_name": "",
        "is_active": True,
        "hours_ago": 0.1,
        "display_name": "",
        "resolved_type": "unknown",
        "os_guess": "",
        "is_private_mac": False,
        "owner": "",
        "custom_type": "network",
        "identity_meta": None,
    },
    {
        # Brand-new device — first_seen ~1h ago, triggers the NEW badge.
        "mac": "56:7a:19:2c:8e:40",
        "ip": "10.0.0.175",
        "manufacturer": "Unknown",
        "device_type": "Android Phone",
        "hostname": "OnePlus-9",
        "custom_name": "",
        "is_active": True,
        "hours_ago": 0.02,
        "first_seen_hours_ago": 1.0,
        "display_name": "OnePlus-9",
        "resolved_type": "phone",
        "os_guess": "Android",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "display_name": {"value": "OnePlus-9", "confidence": 0.55, "source": "hostname_pattern"},
            "device_type": {"value": "phone", "confidence": 0.55, "source": "hostname_pattern"},
            "os_guess": {"value": "Android", "confidence": 0.55, "source": "hostname_pattern"},
            "is_private_mac": False,
            "engine_version": 1,
        },
    },
    {
        # Private-MAC device with no resolvable hostname.
        "mac": "7a:3c:91:af:20:15",
        "ip": "10.0.0.190",
        "manufacturer": "Unknown",
        "device_type": "Unknown",
        "hostname": "",
        "custom_name": "",
        "is_active": False,
        "hours_ago": 4.0,
        "display_name": "Private device 20:15",
        "resolved_type": "phone",
        "os_guess": "",
        "is_private_mac": True,
        "owner": "",
        "identity_meta": {
            "display_name": {"value": "Private device 20:15", "confidence": 0.3, "source": "mac_heuristic"},
            "device_type": {"value": "phone", "confidence": 0.3, "source": "mac_heuristic"},
            "is_private_mac": True,
            "engine_version": 1,
        },
    },
    {
        # Another IoT device — Tuya smart plug.
        "mac": "68:57:2d:11:9c:44",
        "ip": "10.0.0.210",
        "manufacturer": "Shenzhen Tuya Technology Co., Ltd",
        "device_type": "Smart Plug (Tuya)",
        "hostname": "tuya-smartplug-01",
        "custom_name": "",
        "is_active": True,
        "hours_ago": 0.4,
        "display_name": "tuya-smartplug-01",
        "resolved_type": "iot",
        "os_guess": "embedded",
        "is_private_mac": False,
        "owner": "",
        "identity_meta": {
            "display_name": {"value": "tuya-smartplug-01", "confidence": 0.85, "source": "hostname_pattern"},
            "device_type": {"value": "iot", "confidence": 0.85, "source": "hostname_pattern"},
            "os_guess": {"value": "embedded", "confidence": 0.6, "source": "hostname_pattern"},
            "manufacturer": {"value": "Shenzhen Tuya Technology Co., Ltd", "confidence": 0.8, "source": "mac_vendor"},
            "is_private_mac": False,
            "engine_version": 1,
        },
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
    (12, "connect", 0.1),
    (13, "connect", 1.0),
    (14, "connect", 6.0),
    (14, "disconnect", 4.0),
    (15, "connect", 0.4),
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
        first_seen_hours_ago = dev.get("first_seen_hours_ago", dev["hours_ago"] + 48)
        first_seen = now - timedelta(hours=first_seen_hours_ago)

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
        # Seed identity-engine columns directly (no identity.py dependency).
        identity_meta_json = json.dumps(dev["identity_meta"]) if dev.get("identity_meta") else ""
        conn.execute(
            "UPDATE devices SET display_name = ?, resolved_type = ?, os_guess = ?, "
            "is_private_mac = ?, owner = ?, custom_type = ?, identity_meta = ?, manufacturer = ? "
            "WHERE mac = ?",
            (
                dev.get("display_name", ""),
                dev.get("resolved_type", "unknown"),
                dev.get("os_guess", ""),
                1 if dev.get("is_private_mac") else 0,
                dev.get("owner", ""),
                dev.get("custom_type", ""),
                identity_meta_json,
                dev["manufacturer"],
                dev["mac"],
            ),
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
        {"type": "_companion-link._tcp", "name": "Wil’s iPhone", "hostname": "Wils-iPhone.local", "txt": ""},
        {"type": "_airplay._tcp", "name": "Wil’s iPhone", "hostname": "Wils-iPhone.local", "txt": ""},
    ],
    "10.0.0.15": [
        {"type": "_airplay._tcp", "name": "Wil’s MacBook Pro", "hostname": "Wils-MacBook-Pro.local", "txt": ""},
        {"type": "_smb._tcp", "name": "Wil’s MacBook Pro", "hostname": "Wils-MacBook-Pro.local", "txt": ""},
        {"type": "_afpovertcp._tcp", "name": "Wil’s MacBook Pro", "hostname": "Wils-MacBook-Pro.local", "txt": ""},
    ],
    "10.0.0.78": [
        {"type": "_companion-link._tcp", "name": "Jen’s iPad", "hostname": "Jens-iPad.local", "txt": ""},
        {"type": "_airplay._tcp", "name": "Jen’s iPad", "hostname": "Jens-iPad.local", "txt": ""},
    ],
    "10.0.0.67": [
        {"type": "_sonos._tcp", "name": "Sonos Living Room", "hostname": "Sonos-Living-Room.local", "txt": ""},
        {"type": "_spotify-connect._tcp", "name": "Sonos Living Room", "hostname": "Sonos-Living-Room.local", "txt": ""},
    ],
    "10.0.0.91": [
        {"type": "_googlecast._tcp", "name": "Guest’s Pixel", "hostname": "android-pixel.local", "txt": ""},
    ],
}

# WiFi Proximity Notifier

## What this is
A daemon that monitors the local WiFi network for device connections/disconnections. Sends desktop notifications with sound and provides a web dashboard at `http://localhost:5555`.

## Architecture
- `app.py` — entry point. Starts scanner thread + Flask dashboard. Scanner auto-restarts on crash.
- `scanner.py` — network scanning loop. Fast loop (3s) reads ARP table + arp-scan. Detail thread (30s) runs nmap for hostname discovery. Disconnect detection uses arping probes after device goes missing.
- `device_db.py` — SQLite database at `~/.local/share/wifi-notifier/devices.db`. Stores devices, custom names, activity log. Thread-local connections.
- `manufacturer.py` — MAC vendor lookup via `mac-vendor-lookup`. Maps vendors to device types. Detects randomized MACs (locally administered bit).
- `notifier.py` — sends notifications via `gdbus` as user `wil` (service runs as root). Plays connect/disconnect chirp sounds via `paplay`.
- `dashboard.py` — Flask routes. API at `/api/devices`, `/api/activity`, `/api/devices/<mac>/rename`.
- `templates/index.html` — single-page dashboard. Glassmorphism dark theme. Phones panel at top. DOM-diffing refresh (no flashing). Colorblind-friendly: uses text labels (ONLINE/OFFLINE), solid/dashed borders, brightness contrast instead of color.

## Key design decisions
- **ARP table (`ip neigh`) is source of truth** for device presence. arp-scan is used for discovery (connect detection) but NOT for keepalive (router ARP proxy responds for gone devices).
- **Kernel ARP timers are tuned on startup**: `gc_stale_time=5`, `base_reachable_time_ms=10000` on wlan0. This makes disconnect detection faster.
- **Disconnect uses active arping probes**: after a device is missing from ARP for 5s, 3 rapid arping probes confirm it's gone. Sleeping devices (iPad/iPhone) respond to arping so they don't false-disconnect.
- **On startup, all devices are marked inactive** and silently rediscovered on first scan (no notification spam).
- **Notifications run as user `wil`** via `sudo -u wil` with DBUS/DISPLAY env vars so they appear on the GNOME desktop from the root service.

## Running
```bash
# Service management
sudo systemctl start|stop|restart|status wifi-notifier

# Logs
journalctl -u wifi-notifier -f

# Manual run (for debugging)
sudo ./venv/bin/python3 app.py --debug
```

## Systemd
- Service file: `wifi-notifier.service` (symlinked to `/etc/systemd/system/`)
- Runs as root (needed for arp-scan, nmap, arping, sysctl)
- sudoers entry at `/etc/sudoers.d/wifi-notifier` allows `wil` to restart without password

## Common issues
- **Scanner not detecting anything**: check `journalctl -u wifi-notifier -f` for crashes. The scanner auto-restarts but logs the error.
- **No notifications appearing**: the service runs as root but notifications need the user's DBUS session. Check that `DBUS_SESSION_BUS_ADDRESS` and `DISPLAY` are set in the service file.
- **Slow disconnect**: the kernel ARP stale time should be set to 5s on startup. Check logs for "Set ARP stale time" message.
- **False disconnects for sleeping devices**: iPad/iPhone sleep aggressively and don't respond to ICMP ping, but DO respond to arping. The arping probe before disconnect should catch this.
- **Dashboard shows wrong device count after restart**: normal — devices are marked inactive on startup and rediscovered within ~30s.

## Git
- Author: `Tsangares <Tsangares@gmail.com>`
- No co-author lines
- DB file (`.db`) is gitignored — contains MAC addresses and device names

## Network
- Subnet auto-detected from `ip route`
- Dashboard on port 5555 (all interfaces)
- Scans: `ip neigh` (passive ARP), `arp-scan --localnet` (active L2), `nmap -sn` (ping sweep + hostname)

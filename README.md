# WiFi Proximity Notifier

Real-time WiFi device monitoring with desktop notifications and a web dashboard. Detects when devices connect or disconnect from your network within seconds.

![Dashboard](https://img.shields.io/badge/dashboard-localhost:5555-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-gray)

## Features

- **Fast detection** — new devices detected in ~10s, disconnects in ~15s
- **Desktop notifications** with distinct connect/disconnect sounds
- **Device identification** — manufacturer lookup, hostname resolution, randomized MAC detection
- **Web dashboard** at `localhost:5555` with live updates
  - Phones & tablets panel at the top
  - Online/offline status with colorblind-friendly indicators
  - Editable device names
  - Activity log
- **Systemd service** — runs on boot, auto-restarts on crash

## How it works

```
  arp-scan (every 3s)  ──┐
                         ├──> Process ──> Notify + Dashboard
  ip neigh (ARP table) ──┘       │
                                 ├── New device? → notification + chirp
  nmap (every 30s) ──────────────┤── Device gone? → arping probes → confirm → notify
                                 └── Update dashboard + SQLite DB
```

- **Connect detection**: `arp-scan` sends ARP probes every 3 seconds. New devices appear in the kernel ARP table and are picked up immediately.
- **Disconnect detection**: when a device drops from the ARP table, 3 rapid `arping` probes verify it's truly gone before notifying. Sleeping devices (iPhones, iPads) still respond to ARP so they won't false-disconnect.
- **Identification**: MAC vendor database, mDNS/DNS hostname resolution, randomized MAC detection (locally administered bit).

## Install

### Requirements

- Arch Linux (tested), should work on any systemd Linux
- Python 3.10+
- `nmap`, `arp-scan` (installed automatically)

### Quick start

```bash
git clone https://github.com/Tsangares/wifi-proximity-notifier.git
cd wifi-proximity-notifier
chmod +x install.sh
./install.sh
```

### Manual setup

```bash
# Install system deps
sudo pacman -S --needed nmap arp-scan

# Create venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run manually
sudo ./venv/bin/python3 app.py

# Or install as service
sudo ln -sf "$(pwd)/wifi-notifier.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-notifier
```

### Passwordless restart (optional)

To allow your user to restart the service without sudo password:

```bash
echo 'YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart wifi-notifier
YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop wifi-notifier
YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl start wifi-notifier
YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl status wifi-notifier' | sudo tee /etc/sudoers.d/wifi-notifier
```

## Usage

```bash
# Service management
sudo systemctl start wifi-notifier
sudo systemctl stop wifi-notifier
sudo systemctl restart wifi-notifier

# View logs
journalctl -u wifi-notifier -f

# Debug mode (manual)
sudo ./venv/bin/python3 app.py --debug

# Scanner only (no dashboard)
sudo ./venv/bin/python3 app.py --no-dashboard
```

## Dashboard

Open `http://localhost:5555` in your browser.

- **Phones & Tablets** — top panel showing all mobile devices with online/offline status
- **Other Devices** — everything else on the network
- **Offline Devices** — devices that have disconnected
- **Activity** — recent connect/disconnect events
- Click any device name to rename it

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | All devices (active + inactive) |
| `/api/devices/<mac>/rename` | POST | Rename a device `{"name": "My Phone"}` |
| `/api/activity?limit=50` | GET | Recent activity log |

## Configuration

Edit the timing constants at the top of `scanner.py`:

```python
FAST_SCAN_INTERVAL = 3       # seconds between ARP sweeps
DETAIL_SCAN_INTERVAL = 30    # seconds between nmap hostname sweeps
MISSING_PROBE_AFTER = 5      # seconds before arping probe starts
DISCONNECT_PROBE_COUNT = 3   # failed probes before declaring gone
```

## Data

Device data is stored in `~/.local/share/wifi-notifier/devices.db` (SQLite). This file contains MAC addresses, IPs, and device names and is excluded from git.

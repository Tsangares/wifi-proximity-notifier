# WiFi Proximity Notifier

A daemon that watches your local network and tells you when devices show up or leave. Sends desktop notifications with sound and runs a live dashboard.

![Dashboard](docs/dashboard.png)

![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-gray)

## How it works

```
  arp-scan (every 3s)  ──┐
                         ├──> Process ──> Notify + Dashboard
  ip neigh (ARP table) ──┘       │
                                 ├── New device? → notification + chirp
  nmap (every 30s) ──────────────┤── Device gone? → arping probes → confirm → notify
                                 └── Update dashboard + SQLite DB
```

Every 3 seconds, `arp-scan` and the kernel ARP table are checked for new MACs. When a device drops out of the ARP table, 3 rapid `arping` probes confirm it's actually gone before sending a disconnect notification. This avoids false alarms for sleeping phones — iPhones and iPads ignore ICMP pings but still respond to ARP.

Device identification comes from the MAC vendor database, mDNS/DNS hostname lookups, and randomized-MAC detection (the locally-administered bit).

## Install

Tested on Arch Linux. Should work on anything with systemd.

Needs Python 3.10+, `nmap`, and `arp-scan`.

### Quick start

```bash
git clone https://github.com/Tsangares/wifi-proximity-notifier.git
cd wifi-proximity-notifier
chmod +x install.sh
./install.sh
```

### Manual setup

```bash
sudo pacman -S --needed nmap arp-scan

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run manually (needs root for arp-scan, nmap, arping, sysctl)
sudo ./venv/bin/python3 app.py

# Or install as a service
sudo ln -sf "$(pwd)/wifi-notifier.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-notifier
```

### Passwordless restart (optional)

Let your user restart the service without a sudo password:

```bash
echo 'YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart wifi-notifier
YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop wifi-notifier
YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl start wifi-notifier
YOUR_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl status wifi-notifier' | sudo tee /etc/sudoers.d/wifi-notifier
```

## Usage

```bash
sudo systemctl start wifi-notifier
sudo systemctl stop wifi-notifier
sudo systemctl restart wifi-notifier

# View logs
journalctl -u wifi-notifier -f

# Debug mode (verbose logging)
sudo ./venv/bin/python3 app.py --debug

# Scanner only, no web UI
sudo ./venv/bin/python3 app.py --no-dashboard

# Demo mode — fake devices, no root needed
python3 app.py --mock
```

## Dashboard

Open `http://localhost:5555`.

The top panel shows phones and tablets. Below that, a bento grid splits other online devices from offline ones, with stats and an activity feed on the right. Click any device name to rename it. Everything refreshes every 5 seconds without page flicker (DOM diffing).

The UI uses text labels (ONLINE/OFFLINE), solid vs dashed borders, and brightness differences instead of relying on color alone.

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | All devices (active + inactive) |
| `/api/devices/<mac>/rename` | POST | Rename a device `{"name": "My Phone"}` |
| `/api/activity?limit=50` | GET | Recent activity log |

## Tuning

Edit the timing constants at the top of `scanner.py`:

```python
FAST_SCAN_INTERVAL = 3       # seconds between ARP sweeps
DETAIL_SCAN_INTERVAL = 30    # seconds between nmap hostname sweeps
DISCONNECT_PROBE_COUNT = 2   # failed arping probes before declaring gone
DISCONNECT_PROBE_SLEEP = 0.1 # seconds between probes
RECONNECT_GRACE = 15         # suppress re-notification if gone < this long
```

## Mock mode

`python3 app.py --mock` seeds the database with a dozen fake devices and starts the dashboard without scanning. No root needed. Useful for trying out the UI or regenerating the screenshot:

```bash
pip install playwright && playwright install chromium
python3 app.py --mock --port 5556 &
python3 ~/.claude/skills/screenshot/capture.py \
    --url http://localhost:5556 \
    --output docs/dashboard.png \
    --width 1280 --height 1200 \
    --wait-selector ".device-row" \
    --wait-seconds 3 \
    --full-page
kill %1
```

## Project layout

```
app.py              Entry point. Starts scanner thread + Flask dashboard.
scanner.py          Scan loop, state tracking, disconnect detection.
net.py              Network tool wrappers (arp-scan, nmap, arping, ip neigh).
fingerprint.py      Background device probing (TLS certs, HTTP banners, mDNS, NetBIOS).
device_db.py        SQLite database (~/.local/share/wifi-notifier/devices.db).
manufacturer.py     MAC vendor lookup and device type inference.
notifier.py         Desktop notifications via gdbus + sound via paplay.
dashboard.py        Flask routes.
mock_data.py        Fake device data for --mock mode.
templates/          Dashboard HTML.
static/             Connect/disconnect sound files.
```

## Data

Device data lives in `~/.local/share/wifi-notifier/devices.db` (SQLite). It contains MAC addresses, IPs, and device names. This file is gitignored.

#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== WiFi Proximity Notifier Installer ==="

# Install system dependencies
echo "[1/4] Installing system packages..."
sudo pacman -S --needed --noconfirm nmap arp-scan

# Set up Python venv
echo "[2/4] Setting up Python virtual environment..."
cd "$SCRIPT_DIR"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install systemd service
echo "[3/4] Installing systemd service..."
sudo ln -sf "$SCRIPT_DIR/wifi-notifier.service" /etc/systemd/system/wifi-notifier.service
sudo systemctl daemon-reload

# Enable service
echo "[4/4] Enabling service..."
sudo systemctl enable wifi-notifier

echo ""
echo "=== Installation complete ==="
echo "Start now:     sudo systemctl start wifi-notifier"
echo "Check status:  sudo systemctl status wifi-notifier"
echo "View logs:     journalctl -u wifi-notifier -f"
echo "Dashboard:     http://localhost:5555"

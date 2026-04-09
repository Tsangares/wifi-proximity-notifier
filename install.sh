#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
USER_ID="$(id -u "${SUDO_USER:-$USER}")"

echo "=== WiFi Proximity Notifier Installer ==="

# Install system dependencies
echo "[1/5] Installing system packages..."
sudo pacman -S --needed --noconfirm nmap arp-scan

# Set up Python venv
echo "[2/5] Setting up Python virtual environment..."
cd "$SCRIPT_DIR"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Generate service file from template
echo "[3/5] Generating systemd service..."
sed -e "s|__INSTALL_DIR__|$SCRIPT_DIR|g" \
    -e "s|__UID__|$USER_ID|g" \
    "$SCRIPT_DIR/wifi-notifier.service.template" > "$SCRIPT_DIR/wifi-notifier.service"

# Install systemd service
echo "[4/5] Installing systemd service..."
sudo ln -sf "$SCRIPT_DIR/wifi-notifier.service" /etc/systemd/system/wifi-notifier.service
sudo systemctl daemon-reload

# Enable service
echo "[5/5] Enabling service..."
sudo systemctl enable wifi-notifier

echo ""
echo "=== Installation complete ==="
echo "Start now:     sudo systemctl start wifi-notifier"
echo "Check status:  sudo systemctl status wifi-notifier"
echo "View logs:     journalctl -u wifi-notifier -f"
echo "Dashboard:     http://localhost:5555"

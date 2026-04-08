import subprocess
import re
import time
import logging
import threading
from datetime import datetime, timedelta

import device_db
import manufacturer as mfr
import notifier

log = logging.getLogger(__name__)

# Timing config
FAST_SCAN_INTERVAL = 10      # seconds between arp scans
NMAP_SCAN_INTERVAL = 30      # seconds between nmap sweeps
DISCONNECT_TIMEOUT = 90      # seconds before declaring device gone
NEW_DEVICE_WINDOW = 300      # seconds — if unseen for this long, treat as "new" again
RECONNECT_GRACE = 30         # seconds — suppress re-notification if device was gone < this

# State tracking
_last_seen = {}       # mac -> datetime of last scan that saw it
_disconnect_ts = {}   # mac -> datetime when we marked it disconnected
_notified_new = {}    # mac -> datetime of last "new device" notification
_lock = threading.Lock()
_running = False


def _parse_ip_neigh():
    """Parse 'ip neigh' for MAC/IP pairs."""
    devices = set()
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True, timeout=5)
        for line in out.strip().split("\n"):
            if not line:
                continue
            # 10.0.0.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            parts = line.split()
            ip = parts[0]
            # Skip IPv6 link-local to avoid duplicate MACs
            if ip.startswith("fe80:") or ip.startswith("ff"):
                continue
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                mac = parts[idx + 1].lower()
                state = parts[-1] if len(parts) > idx + 2 else ""
                # Skip FAILED entries
                if state not in ("FAILED", "INCOMPLETE"):
                    devices.add((mac, ip))
    except Exception as e:
        log.warning("ip neigh failed: %s", e)
    return devices


def _parse_arp_scan():
    """Run arp-scan --localnet and parse output."""
    devices = set()
    try:
        out = subprocess.check_output(
            ["arp-scan", "--localnet", "--retry=1", "--timeout=500"],
            text=True, timeout=15, stderr=subprocess.DEVNULL,
        )
        for line in out.strip().split("\n"):
            match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", line, re.I)
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()
                devices.add((mac, ip))
    except FileNotFoundError:
        log.debug("arp-scan not installed, skipping")
    except Exception as e:
        log.warning("arp-scan failed: %s", e)
    return devices


def _parse_nmap_scan(subnet="10.0.0.0/24"):
    """Run nmap ping sweep and parse output."""
    devices = set()
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", subnet, "--host-timeout", "5s"],
            text=True, timeout=30, stderr=subprocess.DEVNULL,
        )
        current_ip = None
        for line in out.strip().split("\n"):
            ip_match = re.search(r"Nmap scan report for\s+\S*\s*\(?(\d+\.\d+\.\d+\.\d+)\)?", line)
            if ip_match:
                current_ip = ip_match.group(1)
            mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]{17})", line)
            if mac_match and current_ip:
                mac = mac_match.group(1).lower()
                devices.add((mac, current_ip))
                current_ip = None
    except FileNotFoundError:
        log.debug("nmap not installed, skipping")
    except Exception as e:
        log.warning("nmap scan failed: %s", e)
    return devices


def _detect_subnet():
    """Detect the local subnet from ip route."""
    try:
        out = subprocess.check_output(["ip", "route"], text=True, timeout=5)
        for line in out.split("\n"):
            if "scope link" in line and "/" in line.split()[0]:
                return line.split()[0]
    except Exception:
        pass
    return "10.0.0.0/24"


def _get_own_mac():
    """Get our own MAC so we can skip it."""
    try:
        out = subprocess.check_output(["ip", "link", "show"], text=True, timeout=5)
        macs = set()
        for line in out.split("\n"):
            m = re.search(r"link/ether\s+([0-9a-f:]{17})", line)
            if m:
                macs.add(m.group(1).lower())
        return macs
    except Exception:
        return set()


def _process_scan_results(found_devices):
    """Process a set of (mac, ip) from scanning. Handle connect/disconnect logic."""
    now = datetime.now()
    own_macs = _get_own_mac()

    with _lock:
        seen_macs = set()

        for mac, ip in found_devices:
            if mac in own_macs:
                continue
            if mac == "ff:ff:ff:ff:ff:ff":
                continue

            seen_macs.add(mac)
            _last_seen[mac] = now

            # Check if device is in DB
            device = device_db.get_device(mac)

            if device is None:
                # Brand new device never seen before
                vendor, dtype = mfr.lookup(mac)
                device_db.upsert_device(mac, ip, vendor, dtype)
                device_db.log_event(mac, "connect", ip)
                _notified_new[mac] = now
                log.info("NEW DEVICE: %s (%s) %s - %s", mac, ip, vendor, dtype)
                notifier.notify_new_device(mac, ip, vendor, dtype)

            elif not device["is_active"]:
                # Device returning after being marked inactive
                vendor, dtype = mfr.lookup(mac)
                device_db.upsert_device(mac, ip, vendor, dtype)
                device_db.log_event(mac, "connect", ip)

                # Check if it was gone long enough to warrant notification
                disc_time = _disconnect_ts.get(mac)
                last_notif = _notified_new.get(mac)

                if disc_time and (now - disc_time).total_seconds() < RECONNECT_GRACE:
                    # Quick reconnect — suppress notification
                    log.debug("Quick reconnect (< %ds), suppressing notification for %s",
                              RECONNECT_GRACE, mac)
                elif last_notif and (now - last_notif).total_seconds() < NEW_DEVICE_WINDOW:
                    # Recently notified about this device
                    log.debug("Recently notified about %s, suppressing", mac)
                else:
                    _notified_new[mac] = now
                    is_returning = device["first_seen"] != device["last_seen"]
                    notifier.notify_new_device(mac, ip,
                                               device.get("manufacturer", vendor),
                                               device.get("device_type", dtype),
                                               is_returning=is_returning)
            else:
                # Device still active, just update last_seen
                device_db.upsert_device(mac, ip,
                                        device.get("manufacturer", "Unknown"),
                                        device.get("device_type", "Unknown"))

        # Check for disconnections
        for mac in list(_last_seen.keys()):
            if mac in seen_macs:
                # Remove from disconnect tracking if it's back
                _disconnect_ts.pop(mac, None)
                continue

            elapsed = (now - _last_seen[mac]).total_seconds()
            if elapsed >= DISCONNECT_TIMEOUT:
                device = device_db.get_device(mac)
                if device and device["is_active"]:
                    device_db.mark_inactive(mac)
                    device_db.log_event(mac, "disconnect", device.get("ip", ""))
                    _disconnect_ts[mac] = now
                    log.info("DISCONNECT: %s (%s) after %ds",
                             mac, device.get("manufacturer", ""), int(elapsed))
                    notifier.notify_device_left(
                        mac, device.get("ip", ""),
                        device.get("manufacturer", "Unknown"),
                        device.get("device_type", "Unknown"),
                        device.get("custom_name", ""),
                    )


def scan_loop():
    """Main scanning loop."""
    global _running
    _running = True
    subnet = _detect_subnet()
    log.info("Starting scanner on subnet %s", subnet)
    log.info("Timings: scan=%ds, nmap=%ds, disconnect=%ds, new_window=%ds, grace=%ds",
             FAST_SCAN_INTERVAL, NMAP_SCAN_INTERVAL, DISCONNECT_TIMEOUT,
             NEW_DEVICE_WINDOW, RECONNECT_GRACE)

    last_nmap = 0

    while _running:
        try:
            # Always do fast scans
            devices = _parse_ip_neigh()
            arp_devices = _parse_arp_scan()
            devices.update(arp_devices)

            # Periodic nmap sweep
            if time.time() - last_nmap >= NMAP_SCAN_INTERVAL:
                nmap_devices = _parse_nmap_scan(subnet)
                devices.update(nmap_devices)
                last_nmap = time.time()

            log.debug("Scan found %d devices", len(devices))
            _process_scan_results(devices)

        except Exception as e:
            log.error("Scan loop error: %s", e, exc_info=True)

        time.sleep(FAST_SCAN_INTERVAL)


def stop():
    global _running
    _running = False

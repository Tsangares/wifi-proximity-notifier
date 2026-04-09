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
FAST_SCAN_INTERVAL = 2       # seconds between fast ARP checks
DETAIL_SCAN_INTERVAL = 20    # seconds between full nmap/arp-scan sweeps
DISCONNECT_TIMEOUT = 12      # seconds before declaring device gone
NEW_DEVICE_WINDOW = 30       # seconds — if unseen for this long, treat as "new" again
RECONNECT_GRACE = 5          # seconds — suppress re-notification if device was gone < this

# State tracking
_last_seen = {}       # mac -> datetime of last scan that saw it
_disconnect_ts = {}   # mac -> datetime when we marked it disconnected
_notified_new = {}    # mac -> datetime of last "new device" notification
_lock = threading.Lock()
_running = False


def _quick_ping(ip):
    """Quick single ping to verify device is alive. Returns True if responds."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


def _parallel_ping(ips):
    """Ping multiple IPs in parallel using both ICMP and ARP. Return set of alive IPs."""
    if not ips:
        return set()
    procs = {}
    for ip in ips:
        try:
            # ARP ping — works even when phones block ICMP
            procs[("arp", ip)] = subprocess.Popen(
                ["arping", "-c", "1", "-w", "1", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            # ICMP ping — catches devices that respond to ping
            procs[("icmp", ip)] = subprocess.Popen(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass
    alive = set()
    for (kind, ip), proc in procs.items():
        try:
            proc.wait(timeout=2)
            if proc.returncode == 0:
                alive.add(ip)
        except Exception:
            proc.kill()
    return alive


def _parse_ip_neigh():
    """Parse 'ip neigh' for MAC/IP pairs. Only REACHABLE entries — stale ones are unreliable."""
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
                # Only trust REACHABLE — STALE entries linger after device leaves
                if state == "REACHABLE":
                    devices.add((mac, ip))
    except Exception as e:
        log.warning("ip neigh failed: %s", e)
    return devices


def _parse_arp_scan():
    """Run arp-scan --localnet and parse output."""
    # Flush stale ARP cache first so we only get live responses
    subprocess.run(["ip", "neigh", "flush", "nud", "stale"], capture_output=True, timeout=3)
    devices = set()
    try:
        out = subprocess.check_output(
            ["arp-scan", "--localnet", "--retry=1", "--timeout=200", "--plain"],
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
    """Run nmap ping sweep and parse output. Returns set of (mac, ip) and dict of ip->hostname."""
    devices = set()
    hostnames = {}
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", subnet, "--host-timeout", "5s"],
            text=True, timeout=30, stderr=subprocess.DEVNULL,
        )
        current_ip = None
        current_hostname = ""
        for line in out.strip().split("\n"):
            ip_match = re.search(r"Nmap scan report for\s+(\S+)\s*\(?(\d+\.\d+\.\d+\.\d+)\)?", line)
            if ip_match:
                hostname_or_ip = ip_match.group(1)
                current_ip = ip_match.group(2)
                # If the first capture is not the IP itself, it's a hostname
                if hostname_or_ip != current_ip:
                    current_hostname = hostname_or_ip.rstrip(".")
                else:
                    current_hostname = ""
            mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]{17})", line)
            if mac_match and current_ip:
                mac = mac_match.group(1).lower()
                devices.add((mac, current_ip))
                if current_hostname:
                    hostnames[mac] = current_hostname
                current_ip = None
                current_hostname = ""
    except FileNotFoundError:
        log.debug("nmap not installed, skipping")
    except Exception as e:
        log.warning("nmap scan failed: %s", e)
    return devices, hostnames


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


def _resolve_hostname(ip):
    """Try DNS reverse lookup for an IP."""
    try:
        import socket
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not hostname.startswith(ip):
            return hostname
    except Exception:
        pass
    return ""


def _identify_by_hostname(hostname):
    """Identify device type from hostname string."""
    if not hostname:
        return None
    h = hostname.lower()
    # iPhone patterns: "iPhone-de-Juan.local", "Juans-iPhone.local", "iPhone.local"
    if "iphone" in h:
        return "iPhone"
    if "ipad" in h:
        return "iPad"
    if "macbook" in h:
        return "MacBook"
    if "imac" in h:
        return "iMac"
    if "appletv" in h or "apple-tv" in h:
        return "Apple TV"
    if "android" in h:
        return "Android"
    if "galaxy" in h:
        return "Android (Samsung Galaxy)"
    if "pixel" in h:
        return "Android (Pixel)"
    if "windows" in h or "desktop-" in h or "laptop-" in h:
        return "Windows Desktop"
    if "raspberrypi" in h:
        return "Raspberry Pi"
    if "tasmota" in h or "esp8266" in h or "esp32" in h:
        return "IoT (Tasmota)"
    if "onn" in h or "streaming" in h:
        return "Android TV"
    if "vizio" in h or "casttv" in h or "smartcast" in h:
        return "TV (Vizio)"
    if "brw" in h and h.startswith("brw"):
        return "Printer"
    return None


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


def _process_scan_results(found_devices, hostnames=None):
    """Process a set of (mac, ip) from scanning. Handle connect/disconnect logic."""
    if hostnames is None:
        hostnames = {}
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

            # Resolve hostname
            hostname = hostnames.get(mac, "")
            if not hostname:
                hostname = _resolve_hostname(ip)

            # Get manufacturer info
            vendor, dtype = mfr.lookup(mac)

            # Override device type if hostname gives us better info
            hostname_type = _identify_by_hostname(hostname)
            if hostname_type:
                dtype = hostname_type

            # Check if device is in DB
            device = device_db.get_device(mac)

            if device is None:
                # Brand new device never seen before
                device_db.upsert_device(mac, ip, vendor, dtype, hostname)
                device_db.log_event(mac, "connect", ip)
                _notified_new[mac] = now
                log.info("NEW DEVICE: %s (%s) [%s] %s - %s", mac, ip, hostname, vendor, dtype)
                notifier.notify_new_device(mac, ip, vendor, dtype)

            elif not device["is_active"]:
                # Device returning after being marked inactive
                device_db.upsert_device(mac, ip, vendor, dtype, hostname)
                device_db.log_event(mac, "connect", ip)

                # Check if it was gone long enough to warrant notification
                disc_time = _disconnect_ts.get(mac)

                if disc_time and (now - disc_time).total_seconds() < RECONNECT_GRACE:
                    # Quick reconnect — suppress notification
                    log.debug("Quick reconnect (< %ds), suppressing notification for %s",
                              RECONNECT_GRACE, mac)
                else:
                    # Always notify on reconnect
                    _notified_new[mac] = now
                    notifier.notify_new_device(mac, ip,
                                               device.get("manufacturer", vendor),
                                               device.get("device_type", dtype),
                                               is_returning=True)
            else:
                # Device still active, just update last_seen
                device_db.upsert_device(mac, ip,
                                        device.get("manufacturer", "Unknown"),
                                        device.get("device_type", "Unknown"),
                                        hostname)

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
                    # Quick ping to confirm device is really gone
                    ip = device.get("ip", "")
                    if ip and _quick_ping(ip):
                        _last_seen[mac] = now
                        log.debug("Ping confirmed %s still alive", mac)
                        continue
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
    log.info("Timings: fast=%ds, detail=%ds, disconnect=%ds, new_window=%ds, grace=%ds",
             FAST_SCAN_INTERVAL, DETAIL_SCAN_INTERVAL, DISCONNECT_TIMEOUT,
             NEW_DEVICE_WINDOW, RECONNECT_GRACE)

    last_detail = 0

    # Start detail scanner in separate thread so it doesn't block fast scans
    detail_results = {"devices": set(), "hostnames": {}, "time": 0}
    detail_lock = threading.Lock()

    def detail_loop():
        while _running:
            try:
                arp_devices = _parse_arp_scan()
                nmap_devices, hostnames = _parse_nmap_scan(subnet)
                with detail_lock:
                    detail_results["devices"] = arp_devices | nmap_devices
                    detail_results["hostnames"] = hostnames
                    detail_results["time"] = time.time()
            except Exception as e:
                log.error("Detail scan error: %s", e, exc_info=True)
            time.sleep(DETAIL_SCAN_INTERVAL)

    detail_thread = threading.Thread(target=detail_loop, daemon=True)
    detail_thread.start()

    while _running:
        try:
            # Fast scan: ARP table + quick arping of recently-seen IPs
            devices = _parse_ip_neigh()

            # Parallel ping all known device IPs for fast connect/disconnect detection
            all_known = device_db.get_all_devices()
            ip_to_mac = {}
            ping_ips = set()
            for d in all_known:
                ip = d.get("ip", "")
                mac = d.get("mac", "")
                if ip and mac:
                    ip_to_mac[ip] = mac
                    ping_ips.add(ip)

            alive_ips = _parallel_ping(ping_ips)
            for ip in alive_ips:
                mac = ip_to_mac.get(ip)
                if mac:
                    devices.add((mac, ip))

            # Only merge detail results if they're fresh (< 10s old)
            with detail_lock:
                detail_age = time.time() - detail_results["time"]
                if detail_age < 10:
                    devices.update(detail_results["devices"])
                hostnames = dict(detail_results["hostnames"])

            log.debug("Scan found %d devices", len(devices))
            _process_scan_results(devices, hostnames)

        except Exception as e:
            log.error("Scan loop error: %s", e, exc_info=True)

        time.sleep(FAST_SCAN_INTERVAL)


def stop():
    global _running
    _running = False

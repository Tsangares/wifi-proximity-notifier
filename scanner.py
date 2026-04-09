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
FAST_SCAN_INTERVAL = 3       # seconds between fast ARP sweeps
DETAIL_SCAN_INTERVAL = 30    # seconds between nmap sweeps (hostnames)
MISSING_PROBE_AFTER = 5      # seconds — start active probing after not REACHABLE this long
DISCONNECT_PROBE_COUNT = 3   # number of failed arping probes before declaring gone
NEW_DEVICE_WINDOW = 120      # seconds — if unseen for this long, treat as "new" again
RECONNECT_GRACE = 15         # seconds — suppress re-notification if device was gone < this

# State tracking
_last_seen = {}       # mac -> datetime of last scan that saw it (any ARP state)
_last_reachable = {}  # mac -> datetime of last REACHABLE state
_disconnect_ts = {}   # mac -> datetime when we marked it disconnected
_notified_new = {}    # mac -> datetime of last "new device" notification
_lock = threading.Lock()
_running = False


def _arping_check(ip):
    """Single ARP probe — layer 2, works even on sleeping devices."""
    try:
        result = subprocess.run(
            ["arping", "-c", "1", "-w", "1", ip],
            capture_output=True, timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def _parse_arp_scan_fast():
    """Quick arp-scan for connect detection. Returns set of (mac, ip)."""
    devices = set()
    try:
        out = subprocess.check_output(
            ["arp-scan", "--localnet", "--retry=1", "--timeout=100"],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        for line in out.strip().split("\n"):
            match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})", line, re.I)
            if match:
                devices.add((match.group(2).lower(), match.group(1)))
    except Exception:
        pass
    return devices


def _arp_sweep():
    """Quick arp-scan to populate ARP table with all live devices. Blocks until done."""
    try:
        subprocess.run(
            ["arp-scan", "--localnet", "--retry=1", "--timeout=200"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except Exception:
        pass


def _parse_ip_neigh():
    """Parse 'ip neigh' for MAC/IP pairs. Returns (all_devices, reachable_devices)."""
    all_devices = set()
    reachable = set()
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True, timeout=5)
        for line in out.strip().split("\n"):
            if not line:
                continue
            parts = line.split()
            ip = parts[0]
            if ip.startswith("fe80:") or ip.startswith("ff"):
                continue
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                mac = parts[idx + 1].lower()
                state = parts[-1] if len(parts) > idx + 2 else ""
                if state not in ("FAILED", "INCOMPLETE"):
                    all_devices.add((mac, ip))
                if state == "REACHABLE":
                    reachable.add((mac, ip))
    except Exception as e:
        log.warning("ip neigh failed: %s", e)
    return all_devices, reachable


def _parse_arp_scan():
    """Run arp-scan --localnet. Layer 2 — all devices MUST respond."""
    devices = set()
    try:
        out = subprocess.check_output(
            ["arp-scan", "--localnet", "--retry=2", "--timeout=300"],
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
    """Run nmap ping sweep. Returns set of (mac, ip) and dict of mac->hostname."""
    devices = set()
    hostnames = {}
    try:
        out = subprocess.check_output(
            ["nmap", "-sn", subnet, "--host-timeout", "5s"],
            text=True, timeout=45, stderr=subprocess.DEVNULL,
        )
        current_ip = None
        current_hostname = ""
        for line in out.strip().split("\n"):
            ip_match = re.search(r"Nmap scan report for\s+(\S+)\s*\(?(\d+\.\d+\.\d+\.\d+)\)?", line)
            if ip_match:
                hostname_or_ip = ip_match.group(1)
                current_ip = ip_match.group(2)
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


def _process_scan_results(found_devices, hostnames=None, alive_macs=None, reachable_macs=None, silent=False):
    """Process scan results.
    alive_macs = MACs in ARP table (any state, refresh last_seen).
    reachable_macs = MACs that are REACHABLE (confirmed alive).
    """
    if hostnames is None:
        hostnames = {}
    if alive_macs is None:
        alive_macs = {m for m, _ in found_devices}
    if reachable_macs is None:
        reachable_macs = alive_macs
    now = datetime.now()
    own_macs = _get_own_mac()

    with _lock:
        seen_macs = set()

        for mac, ip in found_devices:
            if mac in own_macs:
                continue
            if mac == "ff:ff:ff:ff:ff:ff":
                continue
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                continue

            seen_macs.add(mac)
            # Only refresh last_seen for devices confirmed in ARP table
            if mac in alive_macs:
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
                device_db.upsert_device(mac, ip, vendor, dtype, hostname)
                device_db.log_event(mac, "connect", ip)
                _notified_new[mac] = now
                log.info("NEW DEVICE: %s (%s) [%s] %s - %s", mac, ip, hostname, vendor, dtype)
                if not silent:
                    notifier.notify_new_device(mac, ip, vendor, dtype)

            elif not device["is_active"]:
                device_db.upsert_device(mac, ip, vendor, dtype, hostname)
                device_db.log_event(mac, "connect", ip)

                disc_time = _disconnect_ts.get(mac)
                if disc_time and (now - disc_time).total_seconds() < RECONNECT_GRACE:
                    log.debug("Quick reconnect (< %ds), suppressing notification for %s",
                              RECONNECT_GRACE, mac)
                else:
                    _notified_new[mac] = now
                    if not silent:
                        notifier.notify_new_device(mac, ip,
                                                   device.get("manufacturer", vendor),
                                                   device.get("device_type", dtype),
                                                   is_returning=True)
            else:
                device_db.upsert_device(mac, ip,
                                        device.get("manufacturer", "Unknown"),
                                        device.get("device_type", "Unknown"),
                                        hostname)

        # Check for disconnections
        db_active = {d["mac"]: d for d in device_db.get_active_devices()}
        all_tracked = set(_last_seen.keys()) | set(db_active.keys())

        for mac in all_tracked:
            if mac in seen_macs:
                # Device is in ARP table (any state) or found by arp-scan — alive
                _disconnect_ts.pop(mac, None)
                continue

            # Seed _last_seen from DB for devices we haven't seen since restart
            if mac not in _last_seen:
                device = db_active.get(mac) or device_db.get_device(mac)
                if device:
                    try:
                        _last_seen[mac] = datetime.fromisoformat(device["last_seen"])
                    except Exception:
                        _last_seen[mac] = now
                else:
                    continue

            device = db_active.get(mac) or device_db.get_device(mac)
            if not device or not device["is_active"]:
                continue

            ip = device.get("ip", "")
            elapsed = (now - _last_seen[mac]).total_seconds()

            if ip:
                # Device missing — rapid-fire arping to confirm
                alive = False
                for probe in range(DISCONNECT_PROBE_COUNT):
                    if _arping_check(ip):
                        alive = True
                        break
                    time.sleep(1)

                if alive:
                    _last_seen[mac] = now
                    log.debug("arping confirmed %s (%s) still alive", mac, ip)
                else:
                    # All probes failed — device is gone
                    device_db.mark_inactive(mac)
                    device_db.log_event(mac, "disconnect", ip)
                    _disconnect_ts[mac] = now
                    log.info("DISCONNECT: %s (%s) confirmed gone after %d probes, %ds",
                             mac, device.get("manufacturer", ""), DISCONNECT_PROBE_COUNT, int(elapsed))
                    if not silent:
                        notifier.notify_device_left(
                            mac, ip,
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
    log.info("Timings: fast=%ds, detail=%ds, probe_after=%ds, probe_count=%d, new_window=%ds, grace=%ds",
             FAST_SCAN_INTERVAL, DETAIL_SCAN_INTERVAL, MISSING_PROBE_AFTER,
             DISCONNECT_PROBE_COUNT, NEW_DEVICE_WINDOW, RECONNECT_GRACE)

    # Shorten ARP stale time so disconnects are detected faster
    try:
        subprocess.run(["sysctl", "-w", "net.ipv4.neigh.wlan0.gc_stale_time=5"],
                       capture_output=True, timeout=3)
        subprocess.run(["sysctl", "-w", "net.ipv4.neigh.wlan0.base_reachable_time_ms=10000"],
                       capture_output=True, timeout=3)
        log.info("Set ARP stale time to 5s, reachable time to 10s")
    except Exception as e:
        log.warning("Could not tune ARP timers: %s", e)

    # On startup, mark all devices inactive so we get a clean state
    # First scan will re-discover everything (without spamming notifications)
    log.info("Resetting device states for fresh discovery...")
    device_db.mark_all_inactive()
    first_scan = True

    # Detail scanner thread: arp-scan + nmap (slow but thorough)
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
            # 1. Read passive ARP table (no probing)
            arp_all, arp_reachable = _parse_ip_neigh()

            # 2. Quick arp-scan for CONNECT detection (finds new devices)
            fast_arp = _parse_arp_scan_fast()

            # 3. Track reachable state (only from passive ARP, not from our probes)
            now = datetime.now()
            for mac, ip in arp_reachable:
                _last_reachable[mac] = now

            # 4. Detail results for discovery
            with detail_lock:
                hostnames = dict(detail_results["hostnames"])

            # All devices seen this cycle (for connect detection)
            all_devices = arp_all | fast_arp | detail_results.get("devices", set())

            # Only passive ARP counts for "alive" (disconnect detection)
            log.debug("Scan: %d passive (%d reachable) + %d fast_arp = %d total",
                      len(arp_all), len(arp_reachable), len(fast_arp), len(all_devices))
            _process_scan_results(all_devices, hostnames,
                                  alive_macs={m for m, _ in arp_all},
                                  reachable_macs={m for m, _ in arp_reachable},
                                  silent=first_scan)
            first_scan = False

        except Exception as e:
            log.error("Scan loop error: %s", e, exc_info=True)

        time.sleep(FAST_SCAN_INTERVAL)


def stop():
    global _running
    _running = False

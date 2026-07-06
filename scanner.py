"""Network scanner — orchestrates device discovery and disconnect detection."""

import subprocess
import re
import time
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import device_db
import manufacturer as mfr
import notifier
import net
import fingerprint

log = logging.getLogger(__name__)

# Timing config
# Connect detection is now primarily passive (see NeighMonitor / _passive_monitor_loop
# below): `ip monitor neigh` streams kernel ARP transitions live, so new/REACHABLE
# devices are picked up in near real time instead of waiting for the next poll.
# FAST_SCAN_INTERVAL is now a fallback/reconcile rate — it covers the startup
# snapshot, catches anything the passive monitor misses (e.g. a dropped netlink
# message or a restart gap), and still drives disconnect-probing (see
# _queue_disconnect_checks / _check_stale_devices). Was 3s pre-passive-detection.
FAST_SCAN_INTERVAL = 10      # seconds between fallback/reconcile ARP sweeps
DETAIL_SCAN_INTERVAL = 30    # seconds between nmap sweeps (hostnames)
DISCONNECT_PROBE_COUNT = 5   # number of failed arping probes before declaring gone
DISCONNECT_PROBE_SLEEP = 0.3 # seconds between arping probes
STALE_TIMEOUT = 60           # seconds in STALE (not REACHABLE) before probing
ABSENT_TIMEOUT = 120         # seconds absent from ARP before probing (sleeping device grace)
NEW_DEVICE_WINDOW = 120      # seconds — if unseen for this long, treat as "new" again
RECONNECT_GRACE = 90         # seconds — suppress re-notification if device was gone < this

# Flap dampening — suppress notifications for devices that keep bouncing
FLAP_WINDOW = 600            # track disconnects within this many seconds
FLAP_THRESHOLD = 2           # disconnects in window before suppressing
FLAP_SUPPRESS_TIME = 300     # seconds — clear flap history after genuine absence this long

# State tracking
_last_seen = {}       # mac -> datetime of last scan that saw it (REACHABLE only)
_last_reachable = {}  # mac -> datetime of last REACHABLE state (same as _last_seen now)
_disconnect_ts = {}   # mac -> datetime when we marked it disconnected
_notified_new = {}    # mac -> datetime of last "new device" notification
_flap_history = {}    # mac -> list of recent disconnect datetimes
_lock = threading.Lock()
_running = False

# Passive connect detection (ip monitor neigh)
_neigh_monitor = None       # net.NeighMonitor instance, owned by scan_loop()
_startup_done = threading.Event()  # gates passive notifications until the silent first scan finishes


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
    own_macs = net.get_own_mac()
    own_ips = net.get_own_ip()

    with _lock:
        seen_macs = set()

        for mac, ip in found_devices:
            if mac in own_macs:
                continue
            if ip in own_ips:
                continue
            if mac == "ff:ff:ff:ff:ff:ff":
                continue
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                continue

            seen_macs.add(mac)
            # Only refresh last_seen for devices confirmed in ARP table
            if mac in alive_macs:
                _last_seen[mac] = now

            # Use cached hostname from detail scan; skip blocking DNS in fast loop
            hostname = hostnames.get(mac, "")

            # Get manufacturer info
            vendor, dtype = mfr.lookup(mac)

            # Override device type if hostname gives us better info
            hostname_type = mfr.identify_by_hostname(hostname)
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
                fingerprint.queue_probe(mac, ip)

            elif not device["is_active"]:
                # Only reconnect if device is confirmed alive (REACHABLE or arp-scan),
                # not just lingering as STALE in the ARP cache.
                # Exception: silent (first) scan re-activates everything without notifications.
                if not silent and mac not in alive_macs:
                    continue

                device_db.upsert_device(mac, ip, vendor, dtype, hostname)
                device_db.log_event(mac, "connect", ip)

                # Re-probe if device was never fingerprinted
                if not device.get("last_probed"):
                    fingerprint.queue_probe(mac, ip)

                disc_time = _disconnect_ts.get(mac)
                if disc_time and (now - disc_time).total_seconds() < RECONNECT_GRACE:
                    log.debug("Quick reconnect (< %ds), suppressing notification for %s",
                              RECONNECT_GRACE, mac)
                else:
                    # Clear flap history if device was gone long enough (genuine return)
                    if disc_time and (now - disc_time).total_seconds() >= FLAP_SUPPRESS_TIME:
                        _flap_history.pop(mac, None)

                    # Suppress reconnect notification for flapping devices
                    flap_times = _flap_history.get(mac, [])
                    recent_flaps = [t for t in flap_times
                                    if (now - t).total_seconds() < FLAP_WINDOW]
                    if len(recent_flaps) >= FLAP_THRESHOLD:
                        log.debug("Suppressing reconnect notification for flapping device %s", mac)
                    else:
                        _notified_new[mac] = now
                        if not silent:
                            notifier.notify_new_device(mac, ip,
                                                       device.get("manufacturer", vendor),
                                                       device.get("device_type", dtype),
                                                       is_returning=True,
                                                       custom_name=device.get("custom_name", ""))
            else:
                device_db.upsert_device(mac, ip,
                                        device.get("manufacturer", "Unknown"),
                                        device.get("device_type", "Unknown"),
                                        hostname)

        # Mark seen devices as not-disconnecting
        for mac in seen_macs:
            _disconnect_ts.pop(mac, None)

    # Queue disconnect checks OUTSIDE the lock (does DB queries, runs async)
    if not silent:
        _queue_disconnect_checks(seen_macs, now)


_disconnect_executor = ThreadPoolExecutor(max_workers=8)
_disconnect_pending = set()  # MACs currently being probed
_pending_lock = threading.Lock()


def _queue_disconnect_checks(seen_macs, now):
    """Find missing devices and probe them in background threads."""
    db_active = {d["mac"]: d for d in device_db.get_active_devices()}
    with _lock:
        all_tracked = set(_last_seen.keys()) | set(db_active.keys())

    for mac in all_tracked:
        if mac in seen_macs:
            continue
        with _pending_lock:
            if mac in _disconnect_pending:
                continue

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

        # Grace period: don't probe until device has been absent long enough.
        # Sleeping phones drop from ARP quickly (gc_stale_time=5s) but wake up
        # within a couple minutes — wait before declaring them gone.
        with _lock:
            last = _last_seen.get(mac)
        if last and (now - last).total_seconds() < ABSENT_TIMEOUT:
            continue

        ip = device.get("ip", "")
        if ip:
            with _pending_lock:
                _disconnect_pending.add(mac)
            _disconnect_executor.submit(_probe_disconnect, mac, ip, device)


def _probe_disconnect(mac, ip, device):
    """Probe a single device for disconnect (runs in thread pool)."""
    try:
        for probe in range(DISCONNECT_PROBE_COUNT):
            if net.arping_check(ip):
                with _lock:
                    _last_seen[mac] = datetime.now()
                log.debug("arping confirmed %s (%s) still alive", mac, ip)
                return

            time.sleep(DISCONNECT_PROBE_SLEEP)

        # Device is gone — mark inactive BEFORE clearing pending flag
        # so the next scan cycle can't submit a duplicate probe
        now = datetime.now()
        with _lock:
            elapsed = (now - _last_seen.get(mac, now)).total_seconds()
            _disconnect_ts[mac] = now

        device_db.mark_inactive(mac)
        device_db.log_event(mac, "disconnect", ip)
        log.info("DISCONNECT: %s (%s) confirmed gone after %d probes, %ds",
                 mac, device.get("manufacturer", ""), DISCONNECT_PROBE_COUNT, int(elapsed))

        # Flap dampening — track recent disconnects and suppress if flapping
        with _lock:
            if mac not in _flap_history:
                _flap_history[mac] = []
            _flap_history[mac] = [t for t in _flap_history[mac]
                                  if (now - t).total_seconds() < FLAP_WINDOW]
            _flap_history[mac].append(now)
            is_flapping = len(_flap_history[mac]) >= FLAP_THRESHOLD

        if is_flapping:
            log.info("Suppressing disconnect notification for flapping device %s "
                     "(%d disconnects in %ds)", mac, len(_flap_history[mac]), FLAP_WINDOW)
        else:
            notifier.notify_device_left(
                mac, ip,
                device.get("manufacturer", "Unknown"),
                device.get("device_type", "Unknown"),
                device.get("custom_name", ""),
            )
    except Exception as e:
        log.error("Disconnect probe error for %s: %s", mac, e)
    finally:
        with _pending_lock:
            _disconnect_pending.discard(mac)


def _check_stale_devices(stale_devices):
    """Probe devices stuck in STALE that haven't been REACHABLE recently."""
    now = datetime.now()
    for mac, ip in stale_devices:
        with _lock:
            last = _last_seen.get(mac)
            if not last:
                # Never been REACHABLE since startup — seed from DB so timeout can start
                device = device_db.get_device(mac)
                if device and device.get("last_seen"):
                    try:
                        last = datetime.fromisoformat(device["last_seen"])
                    except Exception:
                        last = now
                else:
                    last = now
                _last_seen[mac] = last
        elapsed = (now - last).total_seconds()
        if elapsed < STALE_TIMEOUT:
            continue
        device = device_db.get_device(mac)
        if not device or not device["is_active"]:
            continue
        with _pending_lock:
            if mac in _disconnect_pending:
                continue
            _disconnect_pending.add(mac)
        log.debug("Device %s STALE for %ds, probing...", mac, int(elapsed))
        _disconnect_executor.submit(_probe_disconnect, mac, ip, device)


_WEAK_DEVICE_TYPES = {
    "Phone/Tablet (MAC Randomized)", "Unknown", "Other",
    "Randomized MAC",
}


def _update_from_mdns_services(mdns_results):
    """Improve identification of poorly-identified active devices using mDNS services."""
    if not mdns_results:
        return
    for device in device_db.get_active_devices():
        if device["device_type"] not in _WEAK_DEVICE_TYPES:
            continue
        ip = device.get("ip", "")
        if not ip or ip not in mdns_results:
            continue
        services = mdns_results[ip]
        dtype, name, svc_list = fingerprint.identify_from_mdns_services(
            services, device["mac"]
        )
        if dtype:
            log.info("mDNS identified %s (%s) as %s [%s]",
                     device["mac"], ip, dtype, name)
            device_db.update_fingerprint(
                device["mac"], dtype, name,
                json.dumps({"mdns_services": svc_list}, default=str),
            )


def _passive_monitor_loop(monitor):
    """Consume `ip monitor neigh` events and feed connect signals into the
    same processing path the poller uses (_process_scan_results), so new or
    reconnecting devices are notified as soon as the kernel sees them instead
    of waiting for the next fallback poll.

    Only REACHABLE lines are treated as "alive" (mirrors the poller's
    reachable_macs semantics — confirmed alive, not just lingering STALE).
    Deletions are intentionally ignored here: disconnect still goes through
    the arping-confirmation path (_queue_disconnect_checks / _probe_disconnect)
    because sleeping devices produce spurious absence that would otherwise
    cause false disconnects.
    """
    _startup_done.wait()  # don't fire notifications during the silent startup scan
    log.info("Passive neigh monitor loop starting")
    try:
        for line in monitor.lines():
            if not _running:
                break
            try:
                parsed = net.parse_neigh_line(line)
            except Exception as e:
                log.debug("Failed to parse neigh monitor line %r: %s", line, e)
                continue
            if not parsed or parsed["deleted"]:
                continue

            mac, ip, state = parsed["mac"], parsed["ip"], parsed["state"]
            alive = {mac} if state == "REACHABLE" else set()
            try:
                _process_scan_results(
                    {(mac, ip)}, hostnames={}, alive_macs=alive, reachable_macs=alive,
                )
            except Exception as e:
                log.error("Passive monitor processing error for %s (%s): %s", mac, ip, e)
    except Exception as e:
        log.error("Passive neigh monitor loop crashed: %s", e, exc_info=True)
    log.info("Passive neigh monitor loop exiting")


def scan_loop():
    """Main scanning loop."""
    global _running, _neigh_monitor
    _running = True
    _startup_done.clear()
    subnet = net.detect_subnet()
    log.info("Starting scanner on subnet %s", subnet)
    log.info("Timings: fast=%ds, detail=%ds, probe_count=%d, probe_sleep=%.1fs, stale_timeout=%ds, grace=%ds",
             FAST_SCAN_INTERVAL, DETAIL_SCAN_INTERVAL,
             DISCONNECT_PROBE_COUNT, DISCONNECT_PROBE_SLEEP, STALE_TIMEOUT, RECONNECT_GRACE)

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
    FULL_SWEEP_INTERVAL = 300  # full /24 nmap every 5 minutes for new device discovery

    def detail_loop():
        last_full_sweep = 0
        while _running:
            start = time.time()
            try:
                arp_devices = net.parse_arp_scan()

                # Targeted nmap: scan only known device IPs for hostname refresh
                # Full /24 sweep every 5 minutes for new device discovery
                known_ips = list({d["ip"] for d in device_db.get_all_devices()
                                  if d["ip"] and not d["ip"].startswith("0.")})
                if time.time() - last_full_sweep >= FULL_SWEEP_INTERVAL:
                    log.debug("Running full /24 nmap sweep for discovery")
                    nmap_devices, hostnames = net.parse_nmap_scan(subnet)
                    last_full_sweep = time.time()
                elif known_ips:
                    nmap_devices, hostnames = net.parse_nmap_scan(targets=known_ips)
                else:
                    nmap_devices, hostnames = set(), {}

                # mDNS service browsing — identifies phones and smart devices
                mdns_services = net.mdns_browse(timeout=10)

                with detail_lock:
                    detail_results["devices"] = arp_devices | nmap_devices
                    detail_results["hostnames"] = hostnames
                    detail_results["mdns_services"] = mdns_services
                    detail_results["time"] = time.time()
            except Exception as e:
                log.error("Detail scan error: %s", e, exc_info=True)
            elapsed = time.time() - start
            remaining = max(0, DETAIL_SCAN_INTERVAL - elapsed)
            time.sleep(remaining)

    detail_thread = threading.Thread(target=detail_loop, daemon=True)
    detail_thread.start()

    # Passive connect detection: `ip monitor neigh` streams kernel ARP
    # transitions live. Feeds _process_scan_results directly, in parallel
    # with the fallback poll below.
    _neigh_monitor = net.NeighMonitor(restart_delay=2)
    passive_thread = threading.Thread(
        target=_passive_monitor_loop, args=(_neigh_monitor,), daemon=True,
    )
    passive_thread.start()

    fingerprint.start()

    while _running:
        try:
            # 1. Read passive ARP table (no probing)
            arp_all, arp_reachable, arp_stale = net.parse_ip_neigh()

            # 2. Quick arp-scan for CONNECT detection (finds new devices)
            fast_arp = net.parse_arp_scan_fast()

            # 3. Track reachable state (only from passive ARP, not from our probes)
            now = datetime.now()
            for mac, ip in arp_reachable:
                _last_reachable[mac] = now

            # 4. Detail results for discovery
            with detail_lock:
                hostnames = dict(detail_results["hostnames"])

            # All devices seen this cycle (for connect detection + DB updates)
            all_devices = arp_all | fast_arp | detail_results.get("devices", set())

            # Only REACHABLE refreshes _last_seen (not STALE — STALE is unconfirmed)
            log.debug("Scan: %d passive (%d reachable, %d stale) + %d fast_arp = %d total",
                      len(arp_all), len(arp_reachable), len(arp_stale), len(fast_arp), len(all_devices))
            _process_scan_results(all_devices, hostnames,
                                  alive_macs={m for m, _ in arp_reachable},
                                  reachable_macs={m for m, _ in arp_reachable},
                                  silent=first_scan)

            # Probe stale devices that haven't been REACHABLE for STALE_TIMEOUT
            if not first_scan:
                _check_stale_devices(arp_stale)

            # Try to improve identification of poorly-identified devices via mDNS
            with detail_lock:
                mdns_services = detail_results.get("mdns_services", {})
            if mdns_services and not first_scan:
                _update_from_mdns_services(mdns_services)

            first_scan = False
            _startup_done.set()  # let the passive monitor start firing notifications

        except Exception as e:
            log.error("Scan loop error: %s", e, exc_info=True)

        time.sleep(FAST_SCAN_INTERVAL)


def stop():
    global _running
    _running = False
    if _neigh_monitor is not None:
        _neigh_monitor.stop()
    fingerprint.stop()

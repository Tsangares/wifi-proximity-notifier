"""Network utility functions — subprocess wrappers for ARP, nmap, and IP tools."""

import subprocess
import re
import socket
import logging
import threading
import time

log = logging.getLogger(__name__)


def arping_check(ip):
    """Single ARP probe — layer 2, works even on sleeping devices.
    1s deadline — a normal ARP response is sub-millisecond on LAN, but
    power-saving phones/tablets can take noticeably longer to wake their
    radio and answer, so a too-tight deadline (previously 300ms) makes a
    merely-sleeping device look gone. The overall subprocess timeout has
    matching headroom above the arping deadline."""
    try:
        result = subprocess.run(
            ["arping", "-c", "1", "-W", "1", ip],
            capture_output=True, timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def parse_arp_scan_fast():
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


def arp_sweep():
    """Quick arp-scan to populate ARP table with all live devices. Blocks until done."""
    try:
        subprocess.run(
            ["arp-scan", "--localnet", "--retry=1", "--timeout=200"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except Exception:
        pass


def parse_ip_neigh():
    """Parse 'ip neigh' for MAC/IP pairs.
    Returns (all_devices, reachable_devices, stale_devices).
    all_devices includes everything except FAILED/INCOMPLETE.
    reachable = REACHABLE only. stale = STALE only."""
    all_devices = set()
    reachable = set()
    stale = set()
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
                elif state == "STALE":
                    stale.add((mac, ip))
    except Exception as e:
        log.warning("ip neigh failed: %s", e)
    return all_devices, reachable, stale


def parse_neigh_line(line):
    """Parse a single line of `ip neigh` / `ip monitor neigh` output.

    Same line format as `ip neigh show`, e.g.:
        10.0.0.23 dev wlan0 lladdr c2:85:82:c2:44:e2 REACHABLE
        10.0.0.77 dev wlan0 FAILED
    `ip monitor neigh` additionally prefixes removed entries with "Deleted ":
        Deleted 10.0.0.23 dev wlan0 lladdr c2:85:82:c2:44:e2 STALE

    Returns a dict {"mac", "ip", "state", "deleted"} or None if the line has
    no usable MAC (FAILED/INCOMPLETE entries have none), is IPv6 link-local,
    or is otherwise blank/unparsable.
    """
    line = line.strip()
    if not line:
        return None
    deleted = line.startswith("Deleted ")
    if deleted:
        line = line[len("Deleted "):]
    parts = line.split()
    if not parts:
        return None
    ip = parts[0]
    if ip.startswith("fe80:") or ip.startswith("ff"):
        return None
    if "lladdr" not in parts:
        return None
    idx = parts.index("lladdr")
    if idx + 1 >= len(parts):
        return None
    mac = parts[idx + 1].lower()
    state = parts[-1] if len(parts) > idx + 2 else ""
    if state in ("FAILED", "INCOMPLETE"):
        return None
    return {"mac": mac, "ip": ip, "state": state, "deleted": deleted}


class NeighMonitor:
    """Wraps a persistent `ip monitor neigh` subprocess.

    `ip monitor neigh` streams kernel ARP table transitions live (no polling
    needed), giving near-instant connect signals. It's a plain line stream —
    no initial dump — so it complements rather than replaces the periodic
    poll (which still covers the startup snapshot and reconciles anything
    the monitor misses, e.g. a dropped netlink message).

    Call `.lines()` from a single consumer thread to get an infinite
    generator of raw stdout lines; the subprocess is restarted automatically
    (after `restart_delay` seconds) if it exits or errors. Call `.stop()` to
    shut it down.
    """

    def __init__(self, restart_delay=2):
        self.restart_delay = restart_delay
        self._proc = None
        self._stopped = threading.Event()

    def stop(self):
        self._stopped.set()
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass

    def lines(self):
        """Yield raw lines from `ip monitor neigh`, restarting on crash.
        Runs until stop() is called."""
        while not self._stopped.is_set():
            try:
                self._proc = subprocess.Popen(
                    ["ip", "monitor", "neigh"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, bufsize=1,
                )
                for line in self._proc.stdout:
                    if self._stopped.is_set():
                        break
                    yield line
                if self._stopped.is_set():
                    break
                ret = self._proc.poll()
                log.warning("ip monitor neigh exited unexpectedly (code %s); restarting in %ds",
                            ret, self.restart_delay)
            except FileNotFoundError:
                log.error("`ip` binary not found; passive neigh monitor disabled")
                return
            except Exception as e:
                log.warning("ip monitor neigh error: %s; restarting in %ds", e, self.restart_delay)
            finally:
                proc = self._proc
                if proc and proc.poll() is None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=2)
                    except Exception:
                        pass
            if self._stopped.is_set():
                break
            time.sleep(self.restart_delay)


def parse_arp_scan():
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


def parse_nmap_scan(subnet="10.0.0.0/24", targets=None):
    """Run nmap ping sweep. If targets (list of IPs) is given, scan only those.
    Returns set of (mac, ip) and dict of mac->hostname."""
    devices = set()
    hostnames = {}
    try:
        cmd = ["nmap", "-sn", "-T4", "--max-retries", "1", "--host-timeout", "5s"]
        if targets:
            cmd.extend(targets)
        else:
            cmd.append(subnet)
        out = subprocess.check_output(
            cmd, text=True, timeout=90, stderr=subprocess.DEVNULL,
        )
        current_ip = None
        current_hostname = ""
        for line in out.strip().split("\n"):
            # "Nmap scan report for hostname (10.0.0.1)" — with DNS name
            ip_match = re.search(r"Nmap scan report for\s+(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)", line)
            if ip_match:
                current_hostname = ip_match.group(1).rstrip(".")
                current_ip = ip_match.group(2)
            else:
                # "Nmap scan report for 10.0.0.1" — bare IP, no hostname
                ip_match = re.search(r"Nmap scan report for\s+(\d+\.\d+\.\d+\.\d+)\s*$", line)
                if ip_match:
                    current_ip = ip_match.group(1)
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


def detect_subnet():
    """Detect the local subnet from ip route."""
    try:
        out = subprocess.check_output(["ip", "route"], text=True, timeout=5)
        for line in out.split("\n"):
            if "scope link" in line and "/" in line.split()[0]:
                return line.split()[0]
    except Exception:
        pass
    return "10.0.0.0/24"


def resolve_hostname(ip):
    """Try DNS reverse lookup for an IP. 1s timeout to avoid stalling scan loop."""
    try:
        socket.setdefaulttimeout(1)
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and not hostname.startswith(ip):
            return hostname
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(None)
    return ""


def mdns_browse(timeout=8):
    """Browse all mDNS services on the network via avahi-browse.
    Returns {ip: [{"type": str, "name": str, "hostname": str, "txt": str}]}."""
    results = {}
    try:
        out = subprocess.check_output(
            ["avahi-browse", "-a", "-t", "-p", "-r"],
            text=True, timeout=timeout, stderr=subprocess.DEVNULL,
        )
        for line in out.strip().split("\n"):
            if not line.startswith("="):
                continue
            # Parsable format: =;iface;proto;name;type;domain;hostname;address;port;txt
            parts = line.split(";")
            if len(parts) < 10:
                continue
            name = parts[3]
            stype = parts[4]
            hostname = parts[6].rstrip(".")
            address = parts[7]
            txt = parts[9] if len(parts) > 9 else ""
            # Skip IPv6 link-local
            if ":" in address:
                continue
            if address not in results:
                results[address] = []
            results[address].append({
                "type": stype,
                "name": name,
                "hostname": hostname,
                "txt": txt,
            })
    except FileNotFoundError:
        log.debug("avahi-browse not installed, skipping mDNS browse")
    except subprocess.TimeoutExpired:
        log.debug("avahi-browse timed out after %ds", timeout)
    except Exception as e:
        log.warning("mDNS browse failed: %s", e)
    return results


def get_own_mac():
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


def get_own_ip():
    """Get our own IPs so we can skip ourselves in scan results."""
    try:
        out = subprocess.check_output(["ip", "-4", "addr", "show"], text=True, timeout=5)
        ips = set()
        for line in out.split("\n"):
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", line)
            if m:
                ips.add(m.group(1))
        return ips
    except Exception:
        return set()

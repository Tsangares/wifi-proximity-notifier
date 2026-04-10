"""Network utility functions — subprocess wrappers for ARP, nmap, and IP tools."""

import subprocess
import re
import socket
import logging

log = logging.getLogger(__name__)


def arping_check(ip):
    """Single ARP probe — layer 2, works even on sleeping devices.
    300ms deadline — ARP responses are sub-millisecond on LAN."""
    try:
        result = subprocess.run(
            ["arping", "-c", "1", "-W", "0.3", ip],
            capture_output=True, timeout=2,
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

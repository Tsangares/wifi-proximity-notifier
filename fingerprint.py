"""Deep device identification via TLS certs, HTTP banners, mDNS, and NetBIOS.

Runs as a background worker thread. The scanner queues (mac, ip) pairs and
this module probes them without blocking the fast scan loop.
"""

import subprocess
import re
import ssl
import socket
import json
import logging
import threading
import queue
from datetime import datetime

import device_db
import net as net_mod
from manufacturer import _is_randomized_mac

log = logging.getLogger(__name__)

_probe_queue = queue.Queue(maxsize=200)
_running = False

# Ports to check for TLS certs and HTTP banners
TLS_PORTS = (443, 8443, 4443, 7443)
HTTP_PORTS = (80, 8008, 8060, 8080)
SCAN_PORTS = TLS_PORTS + HTTP_PORTS + (548, 9100)  # 548=AFP, 9100=printer


# ---------------------------------------------------------------------------
# mDNS service-based identification
# ---------------------------------------------------------------------------

# Service type → (device_type, is_phone_indicator)
_MDNS_SERVICE_MAP = [
    # Apple mobile — _companion-link is the key signal (only iPhones/iPads)
    ("_companion-link._tcp", "iPhone/iPad", True),
    # Apple general
    ("_airplay._tcp", "Apple Device (AirPlay)", False),
    ("_raop._tcp", "Apple AirPlay Speaker", False),
    ("_airprint._tcp", "AirPrint Printer", False),
    # Google / Android
    ("_googlecast._tcp", "Google Cast Device", False),
    ("_android-tv-remote._tcp", "Android TV", False),
    # Media
    ("_spotify-connect._tcp", "Spotify Connect Device", False),
    ("_sonos._tcp", "Sonos Speaker", False),
    # Printers
    ("_ipp._tcp", "Network Printer", False),
    ("_printer._tcp", "Network Printer", False),
    # Smart home
    ("_hap._tcp", "HomeKit Accessory", False),
    ("_matter._tcp", "Matter Smart Device", False),
    # File sharing
    ("_smb._tcp", "File Server (SMB)", False),
    ("_afpovertcp._tcp", "File Server (AFP/Mac)", False),
]


def identify_from_mdns_services(services, mac=None):
    """Identify device from mDNS service list.

    Args:
        services: list of dicts with 'type', 'name', 'hostname', 'txt' keys
        mac: optional MAC — if randomized, affects identification logic

    Returns:
        (device_type, device_name, raw_services) or (None, None, services)
    """
    if not services:
        return None, None, services

    is_randomized = _is_randomized_mac(mac) if mac else False
    service_types = {s["type"] for s in services}

    # Extract best device name from service name fields
    device_name = ""
    for s in services:
        if s.get("name") and s["name"] not in ("", "local"):
            device_name = s["name"]
            break

    # Combinatorial logic for phones
    has_companion = "_companion-link._tcp" in service_types
    has_airplay = "_airplay._tcp" in service_types
    has_googlecast = "_googlecast._tcp" in service_types

    if is_randomized:
        if has_companion:
            # _companion-link is only advertised by iPhones/iPads
            return "iPhone/iPad", device_name, services
        if has_airplay and not has_companion:
            # Randomized MAC + AirPlay but no companion-link — likely iPhone with
            # companion-link filtered, still most likely an Apple mobile device
            return "iPhone/iPad (AirPlay)", device_name, services
        if has_googlecast:
            return "Android Phone (Cast)", device_name, services

    # Non-randomized or no phone-specific match — use the mapping table
    for stype, dtype, _ in _MDNS_SERVICE_MAP:
        if stype in service_types:
            return dtype, device_name, services

    return None, device_name, services


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

def _scan_ports(ip):
    """Quick nmap port scan. Returns set of open port numbers."""
    ports_str = ",".join(str(p) for p in SCAN_PORTS)
    try:
        out = subprocess.check_output(
            ["nmap", "-sS", "-p", ports_str, "--host-timeout", "3s", "-T4", ip],
            text=True, timeout=15, stderr=subprocess.DEVNULL,
        )
        open_ports = set()
        for line in out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open", line)
            if m:
                open_ports.add(int(m.group(1)))
        return open_ports
    except Exception as e:
        log.debug("Port scan failed for %s: %s", ip, e)
        return set()


# ---------------------------------------------------------------------------
# TLS certificate harvesting
# ---------------------------------------------------------------------------

def _grab_tls_cert(ip, port):
    """Connect to a TLS port and return the subject + issuer text."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer"],
            input=cert_bin, capture_output=True, timeout=5,
        )
        return proc.stdout.decode().strip()
    except Exception:
        return ""


# Patterns in TLS cert subject/issuer → friendly device type
_CERT_PATTERNS = [
    (r"Onn.TV|Onn.*Amlogic", "Onn TV (Google TV)"),
    (r"Chromecast", "Google Chromecast"),
    (r"Roku", "Roku Streaming Device"),
    (r"Fire.?TV|Amazon.*Fire", "Amazon Fire TV"),
    (r"webOS.*LG|LG.*webOS", "LG Smart TV (webOS)"),
    (r"Tizen.*Samsung|Samsung.*Tizen", "Samsung Smart TV (Tizen)"),
    (r"Sony.*Bravia|Bravia", "Sony Bravia TV"),
    (r"Vizio|SmartCast", "Vizio Smart TV"),
    (r"Widevine", "Streaming Device (Widevine DRM)"),
    (r"Apple\s*TV", "Apple TV"),
    (r"HomePod", "Apple HomePod"),
]


def _identify_from_cert(cert_text):
    """Try to identify device type from TLS certificate text."""
    if not cert_text:
        return None, None
    for pattern, dtype in _CERT_PATTERNS:
        if re.search(pattern, cert_text, re.IGNORECASE):
            return dtype, cert_text
    return None, cert_text


# ---------------------------------------------------------------------------
# HTTP banner grabbing
# ---------------------------------------------------------------------------

def _http_get(ip, port, path="/", timeout=3):
    """Fetch an HTTP URL and return the response body."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", str(timeout),
             f"http://{ip}:{port}{path}"],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        return result.stdout
    except Exception:
        return ""


def _identify_from_http(ip, open_ports):
    """Try HTTP-based identification on open ports."""
    # Chromecast / Google TV — port 8008
    if 8008 in open_ports:
        body = _http_get(ip, 8008, "/setup/eureka_info")
        if body.strip().startswith("{"):
            try:
                info = json.loads(body)
                name = info.get("name", "")
                model = info.get("model_name", "")
                dtype = f"Google Cast ({model})" if model else "Google Cast"
                return dtype, name
            except json.JSONDecodeError:
                pass

    # Roku — port 8060
    if 8060 in open_ports:
        body = _http_get(ip, 8060, "/")
        if "<root" in body.lower():
            m = re.search(r"<friendlyDeviceName>(.*?)</friendlyDeviceName>", body)
            model_m = re.search(r"<modelName>(.*?)</modelName>", body)
            name = m.group(1) if m else ""
            model = model_m.group(1) if model_m else "Roku"
            return f"Roku ({model})", name

    # Generic HTTP — port 80 (Tasmota, routers, printers, Pi-hole, etc.)
    if 80 in open_ports:
        body = _http_get(ip, 80, "/")
        if body:
            dtype = _identify_from_html(body)
            if dtype:
                return dtype, ""

        # UPnP description.xml
        body = _http_get(ip, 80, "/description.xml")
        if "<root" in body.lower():
            m = re.search(r"<friendlyName>(.*?)</friendlyName>", body, re.I)
            model_m = re.search(r"<modelDescription>(.*?)</modelDescription>", body, re.I)
            mfr_m = re.search(r"<manufacturer>(.*?)</manufacturer>", body, re.I)
            if m:
                parts = []
                if mfr_m:
                    parts.append(mfr_m.group(1))
                if model_m:
                    parts.append(model_m.group(1))
                dtype = " ".join(parts) if parts else m.group(1)
                return dtype, m.group(1)

    return None, None


# Patterns in HTML page content → device type
_HTML_PATTERNS = [
    (r"Tasmota", r"<h3>(.*?)</h3>", "IoT (Tasmota {match})"),
    (r"Pi-hole", None, "Raspberry Pi (Pi-hole)"),
    (r"NETGEAR", None, "Router (NETGEAR)"),
    (r"TP-LINK|TP-Link", None, "Router (TP-Link)"),
    (r"OpenWrt", None, "Router (OpenWrt)"),
    (r"DD-WRT", None, "Router (DD-WRT)"),
    (r"Synology", None, "NAS (Synology)"),
    (r"QNAP", None, "NAS (QNAP)"),
    (r"OctoPrint", None, "3D Printer (OctoPrint)"),
    (r"Home\s*Assistant", None, "Home Assistant"),
    (r"UniFi", None, "Network Device (UniFi)"),
]


def _identify_from_html(body):
    """Try to identify a device from its HTTP homepage HTML."""
    for keyword, detail_re, template in _HTML_PATTERNS:
        if re.search(keyword, body, re.IGNORECASE):
            detail = ""
            if detail_re:
                m = re.search(detail_re, body)
                if m:
                    detail = m.group(1).strip()
            return template.replace("{match}", detail) if detail else template.replace(" {match}", "")
    return None


# ---------------------------------------------------------------------------
# mDNS lookup
# ---------------------------------------------------------------------------

def _mdns_resolve(ip):
    """Resolve IP to mDNS hostname via avahi-resolve."""
    try:
        result = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True, text=True, timeout=5,
        )
        # Output format: "10.0.0.5\tdevice-name.local"
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split("\t")
            if len(parts) >= 2:
                return parts[1].rstrip(".")
    except FileNotFoundError:
        log.debug("avahi-resolve not available, skipping mDNS")
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# NetBIOS lookup
# ---------------------------------------------------------------------------

def _netbios_lookup(ip):
    """Try NetBIOS name lookup for Windows/Samba devices."""
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and "No reply" not in result.stdout:
            # Parse first name entry that isn't a group
            for line in result.stdout.splitlines():
                m = re.match(r"\s+(\S+)\s+<[0-9a-f]+>\s+-\s+", line, re.I)
                if m and "<GROUP>" not in line:
                    return m.group(1)
    except FileNotFoundError:
        log.debug("nmblookup not available, skipping NetBIOS")
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Main probe orchestration
# ---------------------------------------------------------------------------

def _deep_probe(mac, ip):
    """Run all identification probes on a single device. Returns (device_type, extra_info, results_dict)."""
    log.debug("Deep probe starting for %s (%s)", mac, ip)

    # Accumulate all probe results for the identification breakdown
    results = {
        "probed_at": datetime.now().isoformat(),
        "ip": ip,
        "mdns_services": None,
        "port_scan": None,
        "tls_cert": None,
        "http_banner": None,
        "mdns": None,
        "netbios": None,
        "identified_by": None,
        "final_type": None,
    }

    identified_type = None
    extra_info = ""

    # 0. mDNS service browsing (best signal for phones — try first)
    mdns_all = net_mod.mdns_browse(timeout=10)
    ip_services = mdns_all.get(ip, [])
    results["mdns_services"] = ip_services
    if ip_services:
        dtype, name, _ = identify_from_mdns_services(ip_services, mac)
        if dtype:
            identified_type = dtype
            extra_info = name or ""
            results["identified_by"] = "mdns_services"
            log.debug("  mDNS services identified %s as %s (%s)", ip, dtype, name)

    # If identified via mDNS, skip slow port scan / TLS / HTTP probes
    if identified_type:
        results["final_type"] = identified_type
        return identified_type, extra_info, results

    # 1. Port scan
    open_ports = _scan_ports(ip)
    log.debug("  Open ports on %s: %s", ip, open_ports or "none")
    results["port_scan"] = {
        "ports_checked": sorted(SCAN_PORTS),
        "open": sorted(open_ports),
    }

    # 2. TLS certs on open TLS ports
    for port in TLS_PORTS:
        if port in open_ports:
            cert_text = _grab_tls_cert(ip, port)
            tls_result = {"port": port, "cert_text": cert_text or "", "identified_as": None}
            if cert_text:
                dtype, info = _identify_from_cert(cert_text)
                if dtype:
                    tls_result["identified_as"] = dtype
                    identified_type = dtype
                    extra_info = info or ""
                    log.debug("  TLS cert on :%d identified %s as %s", port, ip, dtype)
            results["tls_cert"] = tls_result
            if identified_type:
                results["identified_by"] = "tls_cert"
                break

    # 3. HTTP banners
    http_result = {"ports_checked": [], "identified_as": None, "detail": ""}
    if not identified_type:
        # Check which HTTP ports are open
        http_result["ports_checked"] = [p for p in HTTP_PORTS if p in open_ports]
        dtype, name = _identify_from_http(ip, open_ports)
        if dtype:
            identified_type = dtype
            extra_info = name or ""
            http_result["identified_as"] = dtype
            http_result["detail"] = name or ""
            results["identified_by"] = "http_banner"
            log.debug("  HTTP identified %s as %s", ip, dtype)
    results["http_banner"] = http_result

    # 4. mDNS
    mdns_name = _mdns_resolve(ip)
    mdns_result = {"hostname": mdns_name or "", "identified_as": None}
    if mdns_name:
        log.debug("  mDNS: %s → %s", ip, mdns_name)
        if not identified_type:
            from manufacturer import identify_by_hostname
            hostname_type = identify_by_hostname(mdns_name)
            if hostname_type:
                identified_type = hostname_type
                extra_info = mdns_name
                mdns_result["identified_as"] = hostname_type
                results["identified_by"] = "mdns"
    results["mdns"] = mdns_result

    # 5. NetBIOS
    nb_name = _netbios_lookup(ip)
    netbios_result = {"name": nb_name or "", "identified_as": None}
    if not identified_type and nb_name:
        log.debug("  NetBIOS: %s → %s", ip, nb_name)
        extra_info = nb_name
    results["netbios"] = netbios_result

    results["final_type"] = identified_type
    return identified_type, extra_info, results


def _worker():
    """Background worker that processes the probe queue."""
    while _running:
        try:
            mac, ip = _probe_queue.get(timeout=5)
        except queue.Empty:
            continue

        try:
            # Check if already probed recently
            device = device_db.get_device(mac)
            if device and device.get("last_probed"):
                log.debug("Skipping probe for %s — already probed", mac)
                continue

            dtype, extra, probe_results = _deep_probe(mac, ip)
            fp_json = json.dumps(probe_results)

            if dtype:
                log.info("FINGERPRINT: %s (%s) identified as %s%s",
                         mac, ip, dtype, f" [{extra}]" if extra else "")
                device_db.update_fingerprint(mac, dtype, extra, fp_json)
            else:
                log.debug("FINGERPRINT: %s (%s) — no identification from deep probe", mac, ip)
                # Mark as probed even if we didn't find anything, so we don't retry
                device_db.update_fingerprint(mac, None, "", fp_json)

            # Fold the fresh probe evidence into the canonical identity
            import resolver
            resolver.resolve_mac(mac)

        except Exception as e:
            log.error("Deep probe error for %s: %s", mac, e, exc_info=True)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def queue_probe(mac, ip):
    """Queue a device for background deep probing. Non-blocking."""
    try:
        _probe_queue.put_nowait((mac, ip))
    except queue.Full:
        log.warning("Fingerprint queue full, dropping probe for %s", mac)


def start():
    """Start the background probe worker thread."""
    global _running
    _running = True
    t = threading.Thread(target=_worker, daemon=True, name="fingerprint-worker")
    t.start()
    log.info("Fingerprint worker started")


def stop():
    """Signal the worker to stop."""
    global _running
    _running = False

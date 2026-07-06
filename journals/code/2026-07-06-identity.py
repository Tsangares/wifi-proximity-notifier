"""Device identity-resolution engine.

Pure logic, stdlib only. Takes a normalized "evidence" dict describing
everything we've learned about a device (MAC, vendor OUI, hostnames, mDNS
services, TLS certs, HTTP banners, legacy free-text type strings, user
overrides) and resolves it into a canonical identity: display name, device
type, OS guess, and manufacturer, each tagged with a confidence and a
source.

No network calls, no subprocess, no randomness, no datetime-dependent
output. Same evidence in -> byte-identical output, always.
"""

import json
import re

ENGINE_VERSION = 1  # bump when rules change; DB backfill triggers on mismatch

CANONICAL_TYPES = [
    "phone", "tablet", "laptop", "desktop", "tv", "console", "iot",
    "network", "printer", "speaker", "watch", "camera", "unknown",
]

OS_VALUES = ["iOS", "Android", "Windows", "macOS", "Linux", "tvOS", "embedded", ""]

# Fixed priority ranking used ONLY to break ties when two candidates share
# the same confidence. Confidence tiers do almost all of the real work.
_SOURCE_PRIORITY = [
    "user", "mdns_services", "tls_cert", "http", "mdns_hostname",
    "netbios", "hostname", "vendor", "legacy", "private_mac", "fallback", "none",
]


# ---------------------------------------------------------------------------
# MAC helpers
# ---------------------------------------------------------------------------

def is_private_mac(mac: str) -> bool:
    """True if the MAC has the locally-administered bit set (second-least
    significant bit of the first octet) — i.e. it's a randomized/private MAC
    handed out by iOS/Android privacy features, not a real OUI-assigned MAC.
    """
    if not mac:
        return False
    try:
        first_octet = mac.strip().replace("-", ":").split(":")[0]
        first_byte = int(first_octet, 16)
        return bool(first_byte & 0x02)
    except (ValueError, AttributeError, IndexError):
        return False


def _last_two_octets(mac):
    if not mac:
        return "??:??"
    parts = mac.strip().replace("-", ":").split(":")
    if len(parts) >= 2:
        return f"{parts[-2]}:{parts[-1]}"
    return mac


# ---------------------------------------------------------------------------
# Hostname cleaning
# ---------------------------------------------------------------------------

_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".localdomain")


def _clean_hostname(name):
    """Strip trailing mDNS/LAN suffixes and generic DNS domain suffixes,
    keeping original casing/hyphens of the first label.
    """
    if not name:
        return ""
    n = name.strip()
    low = n.lower()
    for suf in _LOCAL_SUFFIXES:
        if low.endswith(suf):
            return n[: -len(suf)]
    if "." in n:
        return n.split(".")[0]
    return n


# ---------------------------------------------------------------------------
# Hostname / mdns_hostname / netbios_name -> (device_type, os) pattern table
# ---------------------------------------------------------------------------

def _kw(substrings, dtype, osv):
    def fn(h):
        for s in substrings:
            if s in h:
                return (dtype, osv)
        return None
    return fn


def _prefix(prefixes, dtype, osv):
    def fn(h):
        for p in prefixes:
            if h.startswith(p):
                return (dtype, osv)
        return None
    return fn


def _watch_pattern(h):
    if "watch" in h:
        return ("watch", "iOS" if "apple" in h else None)
    return None


def _desktop_laptop_windows(h):
    if "desktop-" in h:
        return ("desktop", "Windows")
    if "laptop-" in h:
        return ("laptop", "Windows")
    if "windows" in h:
        return ("desktop", "Windows")
    return None


_HOSTNAME_PATTERNS = [
    _kw(["iphone"], "phone", "iOS"),
    _kw(["ipad"], "tablet", "iOS"),
    _watch_pattern,
    _kw(["macbook"], "laptop", "macOS"),
    _kw(["imac", "mac-mini", "macmini", "mac-pro"], "desktop", "macOS"),
    _kw(["appletv", "apple-tv"], "tv", "tvOS"),
    _kw(["android-"], "phone", "Android"),
    _kw(["galaxy", "pixel", "oneplus", "redmi"], "phone", "Android"),
    _desktop_laptop_windows,
    _kw(["raspberrypi", "rpi", "raspberry"], "iot", "Linux"),
    _kw(["esp32", "esp8266", "espressif", "tasmota", "sonoff", "shelly", "tuya"], "iot", "embedded"),
    _prefix(["brw"], "printer", None),
    _kw(["printer", "officejet", "deskjet", "envy", "laserjet", "epson", "canon"], "printer", None),
    _kw(["chromecast", "googletv", "onn"], "tv", "Android"),
    _kw(["roku"], "tv", None),
    _kw(["firetv", "fire-tv"], "tv", "Android"),
    _kw(["ps3", "ps4", "ps5", "playstation"], "console", None),
    _kw(["xbox"], "console", "Windows"),
    _kw(["nintendo", "switch"], "console", None),
    _kw(["steamdeck", "steam-deck"], "console", "Linux"),
    _kw(["kindle", "fire-tablet"], "tablet", "Android"),
    _kw(["nest", "ecobee", "ring", "wyze", "roomba", "irobot"], "iot", None),
    _kw(["ubuntu", "debian", "arch", "fedora", "-linux"], None, "Linux"),
    _kw(["vacuum"], "iot", None),
    _kw(["camera", "cam-"], "camera", None),
]


def _match_hostname_patterns(text):
    """Scan all patterns (not short-circuiting) so a type match earlier in
    the list and an OS-only match later in the list (e.g. "-linux") can
    both contribute. First match wins per-field, independent of the other.
    """
    if not text:
        return None, None
    h = text.lower()
    dtype = None
    osv = None
    for pat in _HOSTNAME_PATTERNS:
        res = pat(h)
        if res is None:
            continue
        d, o = res
        if dtype is None and d is not None:
            dtype = d
        if osv is None and o is not None:
            osv = o
    return dtype, osv


# ---------------------------------------------------------------------------
# Vendor OUI keyword -> (device_type, os, confidence)
# ---------------------------------------------------------------------------

_VENDOR_MAP = [
    (["espressif", "tuya", "sonoff", "itead", "shelly", "allterco", "wemo",
      "ifit", "wyze", "ecobee", "tado"], "iot", "embedded", 0.5),
    (["raspberry"], "iot", "Linux", 0.5),
    (["samsung", "xiaomi", "huawei", "oneplus", "oppo", "bbk", "vivo",
      "realme", "zte", "htc", "nothing", "motorola mobility"], "phone", "Android", 0.4),
    (["intel", "realtek", "dell", "hewlett packard", "hp inc", "lenovo",
      "asus", "msi", "gigabyte", "micro-star"], "laptop", "Windows", 0.4),
    (["microsoft"], "laptop", "Windows", 0.4),
    (["tp-link", "netgear", "linksys", "belkin", "ubiquiti", "cisco",
      "arris", "aruba", "mikrotik", "d-link", "zyxel"], "network", "embedded", 0.4),
    (["sonos", "bose", "denon", "yamaha", "harman", "jbl"], "speaker", "embedded", 0.4),
    (["roku"], "tv", "embedded", 0.4),
    (["vizio", "tcl", "hisense", "lg electronics"], "tv", "embedded", 0.4),
    (["nintendo"], "console", "embedded", 0.4),
    (["sony interactive"], "console", "embedded", 0.4),
    (["valve"], "console", "Linux", 0.4),
    (["amazon"], "iot", "embedded", 0.4),
    (["brother", "canon", "epson", "lexmark", "kyocera"], "printer", "embedded", 0.4),
    (["hikvision", "dahua", "reolink", "axis", "gopro"], "camera", "embedded", 0.4),
    (["garmin", "fitbit"], "watch", "embedded", 0.4),
    (["nvidia"], "desktop", "Linux", 0.3),
    (["apple"], "unknown", "macOS", 0.3),
    (["google"], "unknown", "Android", 0.3),
]


def _match_vendor(vendor):
    if not vendor:
        return None
    v = vendor.lower()
    for keywords, dtype, osv, conf in _VENDOR_MAP:
        for kw in keywords:
            if kw in v:
                return dtype, osv, conf
    return None


def _short_vendor(vendor):
    v = vendor.split(",")[0].split(" ")[0]
    return v.strip()


def _vendor_type_composite(vendor, dtype):
    short = _short_vendor(vendor)
    if not short:
        return ""
    if dtype in ("unknown", ""):
        return short
    if dtype == "iot":
        return f"{short} IoT device"
    return f"{short} {dtype}"


# ---------------------------------------------------------------------------
# legacy_device_type free-text parsing
# ---------------------------------------------------------------------------

def _parse_legacy(text):
    if not text:
        return None, None
    t = text.lower()
    if "iphone" in t:
        return "phone", "iOS"
    if "ipad" in t:
        return "tablet", "iOS"
    if "randomized" in t:
        # legacy "Phone/Tablet (MAC Randomized)" marker — phone guess, no OS
        return "phone", None
    if "android" in t:
        return "phone", "Android"
    if "mac/tv/homepod" in t:
        # legacy "Apple (Mac/TV/HomePod)" — ambiguous Apple wired device
        return "unknown", "macOS"
    if "tv" in t:
        return "tv", None
    if "speaker" in t or "sonos" in t:
        return "speaker", None
    if "printer" in t:
        return "printer", None
    if "iot" in t or "esp" in t or "tasmota" in t:
        return "iot", None
    if "network" in t or "router" in t:
        return "network", None
    if "pc" in t or "laptop" in t or "desktop" in t:
        return "laptop", None
    if "gaming" in t or "nintendo" in t or "steam" in t:
        return "console", None
    if "raspberry" in t:
        return "iot", "Linux"
    if "camera" in t or "ring" in t or "doorbell" in t:
        return "camera", None
    if "watch" in t:
        return "watch", None
    if "phone" in t or "tablet" in t:
        return "phone", None
    if re.search(r"\bmac\b", t) or "macbook" in t or "homepod" in t or "apple" in t:
        return "unknown", "macOS"
    return None, None


# ---------------------------------------------------------------------------
# TLS cert text / HTTP banner free-text classification
# ---------------------------------------------------------------------------

def _classify_media_text(text):
    if not text:
        return None
    t = text.lower()
    if "onn" in t:
        return ("tv", "Android")
    if "chromecast" in t or "google cast" in t or "googlecast" in t:
        if any(k in t for k in ("mini", "audio", "speaker", "nest audio")):
            return ("speaker", "embedded")
        return ("tv", "embedded")
    if "apple tv" in t or "appletv" in t:
        return ("tv", "tvOS")
    if "homepod" in t:
        return ("speaker", "embedded")
    if "roku" in t:
        return ("tv", "embedded")
    if "firetv" in t or "fire tv" in t or "fire-tv" in t or "amazon fire" in t:
        return ("tv", "Android")
    if "webos" in t:
        return ("tv", "embedded")
    if "tizen" in t:
        return ("tv", "embedded")
    if "bravia" in t:
        return ("tv", "embedded")
    if "vizio" in t or "smartcast" in t:
        return ("tv", "embedded")
    if "widevine" in t:
        return ("tv", "embedded")
    return None


def _classify_http_text(text):
    m = _classify_media_text(text)
    if m:
        return m
    t = text.lower()
    if "tasmota" in t or "iot" in t:
        return ("iot", "embedded")
    if "printer" in t or "octoprint" in t:
        return ("printer", "embedded")
    if any(k in t for k in ("router", "netgear", "tp-link", "openwrt", "dd-wrt", "unifi")):
        return ("network", "embedded")
    if "synology" in t or "qnap" in t or "nas" in t:
        return ("network", "embedded")
    if "home assistant" in t:
        return ("iot", "embedded")
    if "pi-hole" in t or "raspberry" in t:
        return ("iot", "Linux")
    return None


# ---------------------------------------------------------------------------
# mDNS service list classification
# ---------------------------------------------------------------------------

# Fixed priority order for tie-breaking / display-name preference among
# mDNS service types. Anything not in this list sorts after it, alphabetically.
_MDNS_PRIORITY_ORDER = [
    "_companion-link._tcp",
    "_airplay._tcp",
    "_googlecast._tcp",
    "_android-tv-remote._tcp",
    "_raop._tcp",
    "_sonos._tcp",
    "_spotify-connect._tcp",
    "_hap._tcp",
    "_homekit._tcp",
    "_matter._tcp",
    "_ipp._tcp",
    "_printer._tcp",
    "_airprint._tcp",
    "_pdl-datastream._tcp",
    "_workstation._tcp",
    "_smb._tcp",
    "_afpovertcp._tcp",
    "_adisk._tcp",
    "_device-info._tcp",
]


def _mdns_priority_index(stype):
    try:
        return _MDNS_PRIORITY_ORDER.index(stype)
    except ValueError:
        return len(_MDNS_PRIORITY_ORDER) + 1


def _all_service_text(services):
    parts = []
    for s in services:
        parts.append((s.get("name") or "").lower())
        parts.append((s.get("hostname") or "").lower())
    return " ".join(parts)


def _mdns_candidates(services, mac):
    """Returns list of (service_type, dtype_or_None, os_or_None, conf, mfr_or_None)."""
    if not services:
        return []
    private = is_private_mac(mac) if mac else False
    text = _all_service_text(services)
    stypes = {s.get("type", "") for s in services}
    is_ipad = "ipad" in text
    out = []

    if "_companion-link._tcp" in stypes:
        dtype = "tablet" if is_ipad else "phone"
        out.append(("_companion-link._tcp", dtype, "iOS", 0.9, "Apple"))
    if "_airplay._tcp" in stypes:
        if private:
            dtype = "tablet" if is_ipad else "phone"
            out.append(("_airplay._tcp", dtype, "iOS", 0.9, "Apple"))
        else:
            out.append(("_airplay._tcp", None, None, 0.9, "Apple"))
    if "_googlecast._tcp" in stypes:
        if any(k in text for k in ("speaker", "audio", "mini", "nest audio")):
            out.append(("_googlecast._tcp", "speaker", "embedded", 0.9, None))
        else:
            out.append(("_googlecast._tcp", "tv", "embedded", 0.9, None))
    if "_android-tv-remote._tcp" in stypes:
        out.append(("_android-tv-remote._tcp", "tv", "Android", 0.9, None))
    if "_raop._tcp" in stypes:
        out.append(("_raop._tcp", "speaker", "embedded", 0.9, None))
    if "_sonos._tcp" in stypes:
        out.append(("_sonos._tcp", "speaker", "embedded", 0.9, "Sonos"))
    if "_spotify-connect._tcp" in stypes:
        out.append(("_spotify-connect._tcp", "speaker", "embedded", 0.9, None))
    for t in ("_ipp._tcp", "_printer._tcp", "_airprint._tcp", "_pdl-datastream._tcp"):
        if t in stypes:
            out.append((t, "printer", "embedded", 0.9, None))
    for t in ("_hap._tcp", "_matter._tcp", "_homekit._tcp"):
        if t in stypes:
            out.append((t, "iot", "embedded", 0.9, None))
    if "_workstation._tcp" in stypes:
        out.append(("_workstation._tcp", "desktop", "Linux", 0.9, None))
    for t in ("_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_device-info._tcp"):
        if t in stypes:
            out.append((t, "laptop", None, 0.5, None))
    return out


def _mdns_display_name(services):
    if not services:
        return ""
    present = {}
    for s in services:
        t = s.get("type", "")
        name = s.get("name") or ""
        if t and name and t not in present:
            present[t] = name
    if not present:
        return ""
    preferred = ["_companion-link._tcp", "_airplay._tcp", "_googlecast._tcp"]
    order = [t for t in preferred if t in present]
    order += sorted(t for t in present if t not in preferred)
    for t in order:
        if present.get(t):
            return present[t]
    return ""


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------

def _pick_best(candidates, default_value, default_conf, default_source):
    """candidates: list of (source, value, conf). Highest confidence wins;
    ties broken by fixed source priority, then by value string for full
    determinism.
    """
    if not candidates:
        return {"value": default_value, "confidence": default_conf, "source": default_source}

    def key(c):
        source, value, conf = c
        try:
            src_idx = _SOURCE_PRIORITY.index(source)
        except ValueError:
            src_idx = len(_SOURCE_PRIORITY)
        return (-conf, src_idx, str(value))

    best = sorted(candidates, key=key)[0]
    return {"value": best[1], "confidence": best[2], "source": best[0]}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def resolve(evidence: dict) -> dict:
    """Resolve a device's identity from all available evidence.

    Deterministic and idempotent: same evidence -> byte-identical output.
    """
    mac = evidence.get("mac") or ""
    private = is_private_mac(mac)

    vendor = evidence.get("vendor") or ""
    hostname = evidence.get("hostname") or ""
    mdns_hostname = evidence.get("mdns_hostname") or ""
    mdns_services = evidence.get("mdns_services") or []
    netbios_name = evidence.get("netbios_name") or ""
    tls_cert_text = evidence.get("tls_cert_text") or ""
    http_type = evidence.get("http_type") or ""
    legacy_device_type = evidence.get("legacy_device_type") or ""
    custom_name = evidence.get("custom_name") or ""
    custom_type = evidence.get("custom_type") or ""

    mdns_cands = _mdns_candidates(mdns_services, mac)

    # ---- device_type candidates ----
    type_cands = []
    if custom_type and custom_type in CANONICAL_TYPES:
        type_cands.append(("user", custom_type, 1.0))
    for stype, dtype, osv, conf, mfr in mdns_cands:
        if dtype is not None:
            type_cands.append(("mdns_services", dtype, conf))
    if tls_cert_text:
        m = _classify_media_text(tls_cert_text)
        if m:
            type_cands.append(("tls_cert", m[0], 0.9))
    if http_type:
        m = _classify_http_text(http_type)
        if m:
            type_cands.append(("http", m[0], 0.9))
    if mdns_hostname:
        d, o = _match_hostname_patterns(mdns_hostname)
        if d:
            type_cands.append(("mdns_hostname", d, 0.7))
    if netbios_name:
        d, o = _match_hostname_patterns(netbios_name)
        if d:
            type_cands.append(("netbios", d, 0.7))
    if hostname:
        d, o = _match_hostname_patterns(hostname)
        if d:
            type_cands.append(("hostname", d, 0.7))
    if vendor:
        m = _match_vendor(vendor)
        if m:
            type_cands.append(("vendor", m[0], m[2]))
    if legacy_device_type:
        d, o = _parse_legacy(legacy_device_type)
        if d:
            type_cands.append(("legacy", d, 0.3))
    if private:
        type_cands.append(("private_mac", "phone", 0.3))

    device_type = _pick_best(type_cands, "unknown", 0.1, "fallback")

    # ---- os_guess candidates ----
    os_cands = []
    for stype, dtype, osv, conf, mfr in mdns_cands:
        if osv is not None:
            os_cands.append(("mdns_services", osv, conf))
    if tls_cert_text:
        m = _classify_media_text(tls_cert_text)
        if m and m[1]:
            os_cands.append(("tls_cert", m[1], 0.9))
    if http_type:
        m = _classify_http_text(http_type)
        if m and m[1]:
            os_cands.append(("http", m[1], 0.9))
    if mdns_hostname:
        d, o = _match_hostname_patterns(mdns_hostname)
        if o:
            os_cands.append(("mdns_hostname", o, 0.7))
    if netbios_name:
        d, o = _match_hostname_patterns(netbios_name)
        if o:
            os_cands.append(("netbios", o, 0.7))
    if hostname:
        d, o = _match_hostname_patterns(hostname)
        if o:
            os_cands.append(("hostname", o, 0.7))
    if vendor:
        m = _match_vendor(vendor)
        if m and m[1]:
            os_cands.append(("vendor", m[1], m[2]))
    if legacy_device_type:
        d, o = _parse_legacy(legacy_device_type)
        if o:
            os_cands.append(("legacy", o, 0.3))

    os_guess = _pick_best(os_cands, "", 0.0, "none")

    # ---- manufacturer candidates ----
    mfr_cands = []
    for stype, dtype, osv, conf, mfr in mdns_cands:
        if mfr is not None:
            mfr_cands.append(("mdns_services", mfr, conf))
    if private:
        mfr_cands.append(("private_mac", "Private (randomized MAC)", 0.9))
    elif vendor:
        mfr_cands.append(("vendor", vendor, 0.9))

    manufacturer = _pick_best(mfr_cands, "", 0.0, "none")

    # ---- display_name: strict waterfall, not confidence-based ----
    if custom_name:
        display_name = {"value": custom_name, "confidence": 1.0, "source": "user"}
    else:
        display_name = None
        mdns_name = _mdns_display_name(mdns_services)
        if mdns_name:
            display_name = {"value": mdns_name, "confidence": 0.9, "source": "mdns_services"}
        elif mdns_hostname and _clean_hostname(mdns_hostname):
            display_name = {"value": _clean_hostname(mdns_hostname), "confidence": 0.7, "source": "mdns_hostname"}
        elif netbios_name:
            display_name = {"value": netbios_name, "confidence": 0.7, "source": "netbios"}
        elif hostname and _clean_hostname(hostname):
            display_name = {"value": _clean_hostname(hostname), "confidence": 0.7, "source": "hostname"}
        elif vendor and _vendor_type_composite(vendor, device_type["value"]):
            display_name = {
                "value": _vendor_type_composite(vendor, device_type["value"]),
                "confidence": 0.4,
                "source": "vendor",
            }
        elif private:
            display_name = {
                "value": f"Private device {_last_two_octets(mac)}",
                "confidence": 0.3,
                "source": "private_mac",
            }
        else:
            display_name = {
                "value": f"Device {_last_two_octets(mac)}",
                "confidence": 0.1,
                "source": "fallback",
            }

    return {
        "display_name": display_name,
        "device_type": device_type,
        "os_guess": os_guess,
        "manufacturer": manufacturer,
        "is_private_mac": private,
        "engine_version": ENGINE_VERSION,
    }


# ---------------------------------------------------------------------------
# DB row -> evidence dict
# ---------------------------------------------------------------------------

def build_evidence(row: dict) -> dict:
    """Convert a devices-table DB row into an evidence dict for resolve().

    row keys: mac, hostname, custom_name, custom_type (may be absent),
    manufacturer, device_type, fingerprint_data (JSON string, possibly ''
    or invalid).
    """
    mac = row.get("mac") or ""
    hostname = row.get("hostname") or ""
    custom_name = row.get("custom_name") or ""
    custom_type = row.get("custom_type") or ""
    manufacturer = row.get("manufacturer") or ""
    device_type = row.get("device_type") or ""
    fingerprint_data = row.get("fingerprint_data") or ""

    vendor = "" if manufacturer in ("Unknown", "Randomized MAC", "Private (randomized MAC)") else manufacturer

    legacy_device_type = "" if device_type in CANONICAL_TYPES or device_type in ("Unknown", "") else device_type

    mdns_services = []
    mdns_hostname = ""
    netbios_name = ""
    tls_cert_text = ""
    http_type = ""

    if fingerprint_data:
        try:
            fp = json.loads(fingerprint_data)
        except (ValueError, TypeError):
            fp = {}
        if isinstance(fp, dict):
            ms = fp.get("mdns_services")
            if isinstance(ms, list):
                mdns_services = ms

            mdns_info = fp.get("mdns")
            if isinstance(mdns_info, dict):
                mdns_hostname = mdns_info.get("hostname") or ""

            nb_info = fp.get("netbios")
            if isinstance(nb_info, dict):
                netbios_name = nb_info.get("name") or ""

            tls_info = fp.get("tls_cert")
            if isinstance(tls_info, dict):
                tls_cert_text = tls_info.get("cert_text") or ""

            http_info = fp.get("http_banner")
            if isinstance(http_info, dict):
                http_type = http_info.get("identified_as") or ""

    return {
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "mdns_hostname": mdns_hostname,
        "mdns_services": mdns_services,
        "netbios_name": netbios_name,
        "tls_cert_text": tls_cert_text,
        "http_type": http_type,
        "legacy_device_type": legacy_device_type,
        "custom_name": custom_name,
        "custom_type": custom_type,
    }

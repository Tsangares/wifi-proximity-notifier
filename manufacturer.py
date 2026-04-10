import logging
from mac_vendor_lookup import MacLookup

log = logging.getLogger(__name__)

_mac_lookup = None


def _get_lookup():
    global _mac_lookup
    if _mac_lookup is None:
        _mac_lookup = MacLookup()
        try:
            _mac_lookup.update_vendors()
            log.info("Vendor DB updated successfully")
        except Exception as e:
            log.warning("Could not update vendor DB (using cached): %s", e)
    return _mac_lookup


def init():
    """Pre-initialize the vendor database. Call at startup."""
    _get_lookup()


# Map manufacturer substrings to friendly device types
_TYPE_MAP = [
    # Apple — real (non-randomized) MACs are Macs, Apple TVs, HomePods
    # iPhones/iPads use randomized MACs and get identified via hostname
    (["apple"], "Apple (Mac/TV/HomePod)"),
    # Android manufacturers
    (["samsung"], "Android (Samsung)"),
    (["google"], "Android (Google)"),
    (["oneplus", "oppo", "bbk"], "Android (OnePlus/Oppo)"),
    (["xiaomi", "redmi"], "Android (Xiaomi)"),
    (["huawei", "honor"], "Android (Huawei)"),
    (["motorola", "lenovo"], "Android (Motorola/Lenovo)"),
    (["lg electron"], "Android (LG)"),
    (["sony mobile", "sony "], "Android (Sony)"),
    (["htc"], "Android (HTC)"),
    (["zte"], "Android (ZTE)"),
    (["vivo"], "Android (Vivo)"),
    (["realme"], "Android (Realme)"),
    (["nothing"], "Android (Nothing)"),
    # Networking
    (["tp-link", "tplink"], "Network Device (TP-Link)"),
    (["netgear"], "Network Device (Netgear)"),
    (["asus", "asustek"], "PC/Network (ASUS)"),
    (["linksys", "belkin"], "Network Device (Linksys/Belkin)"),
    (["ubiquiti"], "Network Device (Ubiquiti)"),
    (["cisco"], "Network Device (Cisco)"),
    (["arris", "motorola mob"], "Network Device (Router/Modem)"),
    # PC / Laptop
    (["intel"], "PC/Laptop (Intel)"),
    (["realtek"], "PC/Network (Realtek)"),
    (["dell"], "PC/Laptop (Dell)"),
    (["hewlett", "hp "], "PC/Laptop (HP)"),
    (["lenovo"], "PC/Laptop (Lenovo)"),
    (["microsoft"], "Microsoft Device"),
    # Smart home
    (["amazon", "amzn"], "Smart Device (Amazon)"),
    (["ring"], "Smart Device (Ring)"),
    (["nest", "google llc"], "Smart Device (Google/Nest)"),
    (["sonos"], "Smart Speaker (Sonos)"),
    (["roku"], "Streaming (Roku)"),
    (["espressif"], "IoT Device (ESP)"),
    # Gaming
    (["nintendo"], "Gaming (Nintendo)"),
    (["valve"], "Gaming (Steam)"),
    # Other
    (["raspberry"], "Raspberry Pi"),
]


def _is_randomized_mac(mac):
    """Check if MAC is locally administered (randomized by phone/OS)."""
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)  # bit 1 = locally administered
    except (ValueError, IndexError):
        return False


def lookup(mac):
    """Return (manufacturer, device_type) for a MAC address."""
    if _is_randomized_mac(mac):
        return "Randomized MAC", "Phone/Tablet (MAC Randomized)"

    try:
        vendor = _get_lookup().lookup(mac)
    except Exception:
        return "Unknown", "Unknown"

    vendor_lower = vendor.lower()
    for keywords, dtype in _TYPE_MAP:
        for kw in keywords:
            if kw in vendor_lower:
                return vendor, dtype

    return vendor, "Other"


def identify_by_hostname(hostname):
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

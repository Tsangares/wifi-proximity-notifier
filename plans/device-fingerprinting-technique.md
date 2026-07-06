# Deep Device Identification via TLS Certificate & Service Probing

## What We Did

We identified an unknown device at `10.0.0.169` on the local network. The ARP table only gave us a MAC address (`a8:71:16:7f:70:d8`), which resolved to a generic vendor ("Earda Technologies"). That's not very useful.

### Step-by-step technique

1. **ARP table lookup** — `ip neigh | grep <ip>` gives MAC address + interface
2. **MAC vendor prefix** — first 3 octets (`a8:71:16`) map to a manufacturer via OUI database. This gave us "Earda Technologies" (an ODM), not the consumer brand.
3. **Port scan** — `nmap -sS -p <common-ports> <ip>` found only port **8443** open. Most ports were closed.
4. **TLS certificate inspection** — `curl -vsk https://<ip>:8443/` and reading the certificate subject/issuer:
   ```
   subject: CN=6998426556868190514
   issuer:  CN=Askey_Onn TV YOC Amlogic AMLS905Y4 Cast ICA
            O=Google Inc; OU=Widevine
   ```
   This single certificate revealed: **Onn TV, YOC series, Amlogic S905Y4 SoC, Google Cast/Widevine DRM**

### Why TLS certs are so rich

IoT devices, smart TVs, and Chromecast-based devices ship with Widevine DRM certificates baked in at the factory. These certs contain the **exact product line, chipset, and manufacturer** in the issuer CN. Unlike MAC OUI lookups (which often point to generic ODMs), TLS certs identify the actual consumer product.

---

## How to Generalize This for wifi-proximity-notifier

The current identification pipeline in `manufacturer.py` does:
```
MAC address → OUI vendor lookup → regex-based device type classification
```

This misses a lot. The proposed enhancement adds a **deep probe** layer:

```
MAC + IP → OUI vendor → deep probe (TLS certs, service banners, mDNS, UPnP) → rich identification
```

### Probe Techniques (ordered by usefulness)

#### 1. TLS Certificate Harvesting (best signal)
For every open TLS port (443, 8443, 8008, 4443, etc.):
```bash
echo | openssl s_client -connect <ip>:<port> 2>/dev/null | openssl x509 -noout -subject -issuer
```
or:
```bash
curl -vsk https://<ip>:<port>/ 2>&1 | grep -E '(subject|issuer):'
```
**Parses out**: product name, manufacturer, chipset, platform (Cast, Roku, etc.)

**Common patterns**:
| Issuer CN pattern | Device |
|---|---|
| `Onn TV` | Walmart Onn smart TV |
| `Chromecast` | Google Chromecast |
| `Roku` | Roku streaming device |
| `Amazon` + `Fire` | Fire TV Stick |
| `LG` + `webOS` | LG smart TV |
| `Samsung` + `Tizen` | Samsung smart TV |

#### 2. mDNS / DNS-SD Discovery
```bash
avahi-browse -art 2>/dev/null | grep -A5 <ip>
```
Devices advertise services like:
- `_googlecast._tcp` — Chromecast/Google TV devices (includes friendly name!)
- `_airplay._tcp` — Apple TVs, AirPlay speakers
- `_raop._tcp` — AirPlay audio
- `_spotify-connect._tcp` — Spotify Connect devices
- `_ipp._tcp` — Printers
- `_hap._tcp` — HomeKit accessories

#### 3. UPnP/SSDP Discovery
```bash
# Send M-SEARCH and parse responses
echo -e 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:"ssdp:discover"\r\nMX:3\r\nST:ssdp:all\r\n\r\n' | \
  socat - UDP4-DATAGRAM:239.255.255.250:1900,so-broadcast
```
Returns XML descriptions with `<friendlyName>`, `<modelName>`, `<manufacturer>` fields.

#### 4. HTTP Service Banner Grabbing
Many IoT devices run HTTP servers on common ports:
```bash
curl -s --connect-timeout 2 http://<ip>:8008/setup/eureka_info  # Chromecast
curl -s --connect-timeout 2 http://<ip>:8060/                    # Roku ECP
curl -s --connect-timeout 2 http://<ip>:80/description.xml       # UPnP
```

**Chromecast `/setup/eureka_info`** returns JSON with:
```json
{"name": "Living Room TV", "model_name": "Chromecast", ...}
```

**Roku port 8060** returns XML with model name, serial, software version.

#### 5. NBNS / NetBIOS (Windows/Samba devices)
```bash
nmblookup -A <ip>
```
Returns Windows hostname and workgroup — useful for PCs, NAS devices, printers.

---

## Proposed Implementation

### One-time enrichment script

```python
#!/usr/bin/env python3
"""
deep_identify.py — Probe all network devices for rich identification.
Run as: sudo python3 deep_identify.py
"""
import subprocess, json, re, ssl, socket, sqlite3
from pathlib import Path

DB_PATH = Path.home() / ".local/share/wifi-notifier/devices.db"

def get_open_tls_ports(ip, ports=(443, 8443, 8008, 4443, 7443)):
    """Quick SYN scan for common TLS ports."""
    result = subprocess.run(
        ["nmap", "-sS", "-p", ",".join(str(p) for p in ports),
         "--host-timeout", "5s", ip],
        capture_output=True, text=True, timeout=10
    )
    open_ports = []
    for line in result.stdout.splitlines():
        m = re.match(r"(\d+)/tcp\s+open", line)
        if m:
            open_ports.append(int(m.group(1)))
    return open_ports

def grab_tls_cert(ip, port):
    """Connect and extract TLS certificate subject/issuer."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                # Parse with openssl CLI for readable output
                proc = subprocess.run(
                    ["openssl", "x509", "-inform", "DER", "-noout",
                     "-subject", "-issuer"],
                    input=cert, capture_output=True, timeout=5
                )
                return proc.stdout.decode()
    except Exception:
        return None

def grab_chromecast_info(ip):
    """Try Chromecast eureka_info endpoint."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "2",
             f"http://{ip}:8008/setup/eureka_info"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip().startswith("{"):
            return json.loads(result.stdout)
    except Exception:
        return None

def grab_roku_info(ip):
    """Try Roku ECP endpoint."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "2", f"http://{ip}:8060/"],
            capture_output=True, text=True, timeout=5
        )
        if "<root" in result.stdout:
            return result.stdout
    except Exception:
        return None

def grab_mdns_services(ip):
    """Check avahi for advertised services."""
    try:
        result = subprocess.run(
            ["avahi-browse", "-art"],
            capture_output=True, text=True, timeout=8
        )
        lines = result.stdout.splitlines()
        services = []
        for i, line in enumerate(lines):
            if ip in line:
                # grab surrounding context
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                services.append("\n".join(lines[start:end]))
        return services
    except Exception:
        return []

def grab_netbios(ip):
    """Try NetBIOS name lookup."""
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=5
        )
        if "No reply" not in result.stdout:
            return result.stdout
    except Exception:
        return None

def identify_from_cert(cert_text):
    """Parse TLS cert text into a friendly device description."""
    if not cert_text:
        return None
    # Common patterns in issuer/subject CN
    patterns = [
        (r"Onn.TV", "Onn TV (Google TV)"),
        (r"Chromecast", "Google Chromecast"),
        (r"Roku", "Roku Streaming Device"),
        (r"Fire.?TV|Amazon.*Fire", "Amazon Fire TV"),
        (r"webOS.*LG|LG.*webOS", "LG Smart TV (webOS)"),
        (r"Tizen.*Samsung|Samsung.*Tizen", "Samsung Smart TV (Tizen)"),
        (r"Sony.*Bravia|Bravia", "Sony Bravia TV"),
        (r"Vizio", "Vizio Smart TV"),
        (r"Widevine", "DRM-capable streaming device"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, cert_text, re.IGNORECASE):
            return label
    return f"TLS device: {cert_text[:120]}"

def deep_probe(ip, mac):
    """Run all probes against a single device. Returns dict of findings."""
    findings = {"ip": ip, "mac": mac, "probes": {}}

    # TLS cert probe
    open_ports = get_open_tls_ports(ip)
    for port in open_ports:
        cert = grab_tls_cert(ip, port)
        if cert:
            findings["probes"][f"tls:{port}"] = cert
            ident = identify_from_cert(cert)
            if ident:
                findings["identified_as"] = ident

    # Chromecast probe
    cc = grab_chromecast_info(ip)
    if cc:
        findings["probes"]["chromecast"] = cc
        name = cc.get("name", "")
        model = cc.get("model_name", "")
        findings["identified_as"] = f"{name} ({model})" if model else name

    # Roku probe
    roku = grab_roku_info(ip)
    if roku:
        findings["probes"]["roku"] = roku[:500]
        m = re.search(r"<friendlyDeviceName>(.*?)</friendlyDeviceName>", roku)
        if m:
            findings["identified_as"] = f"Roku: {m.group(1)}"

    # mDNS
    mdns = grab_mdns_services(ip)
    if mdns:
        findings["probes"]["mdns"] = mdns

    # NetBIOS
    nb = grab_netbios(ip)
    if nb:
        findings["probes"]["netbios"] = nb

    return findings

def main():
    # Get all devices from ARP table
    result = subprocess.run(["ip", "neigh"], capture_output=True, text=True)
    devices = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and "lladdr" in parts:
            ip = parts[0]
            mac = parts[parts.index("lladdr") + 1]
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                devices.append((ip, mac))

    print(f"Found {len(devices)} devices on local network\n")

    results = []
    for ip, mac in devices:
        print(f"Probing {ip} ({mac})...")
        info = deep_probe(ip, mac)
        results.append(info)
        ident = info.get("identified_as", "Unknown")
        print(f"  → {ident}\n")

    # Write results
    out = Path("/tmp/device-scan-results.json")
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nFull results written to {out}")

if __name__ == "__main__":
    main()
```

### Integration into wifi-proximity-notifier

To integrate this into the existing codebase:

1. **Add a `deep_probe.py` module** with the probe functions above
2. **Call it from `scanner.py`** after initial device discovery — run deep probe on any device where `device_type` is generic (e.g., just a vendor name, or "Unknown")
3. **Store results** in a new `fingerprint` column on the `devices` table, or update `device_type` / `manufacturer` with the richer info
4. **Cache results by MAC** — only re-probe if a device hasn't been fingerprinted yet, or if its IP changed
5. **Run as background thread** since probing is slow (~5-10s per device) — don't block the fast ARP scan loop

### Performance considerations

- Full probe takes ~5-10 seconds per device (nmap + TLS + HTTP + mDNS)
- Should only run on **first discovery** of a device, not every scan cycle
- mDNS browse (`avahi-browse -art`) is a single broadcast that returns all devices — run once, parse for all IPs
- Consider a `last_probed` timestamp to re-probe periodically (e.g., weekly)

### Required system dependencies

- `nmap` — port scanning
- `openssl` — TLS cert parsing
- `avahi-utils` — mDNS discovery (`avahi-browse`, `avahi-resolve`)
- `samba` — NetBIOS lookup (`nmblookup`)
- `curl` — HTTP probing

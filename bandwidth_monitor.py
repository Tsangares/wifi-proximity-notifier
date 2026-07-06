#!/usr/bin/env python3
"""
Bandwidth monitor — runs on the Pi (nes).
ARP spoofs the gateway so all LAN traffic routes through us,
counts bytes per device, and exposes stats via HTTP on port 5556.

Usage: sudo python3 bandwidth_monitor.py

NOTE: This is a standalone tool, separate from the wifi-proximity-notifier
daemon (app.py/scanner.py) in this repo. It targets the Raspberry Pi "nes",
not the machine running the notifier — it's kept here for convenience but
is not started by app.py, not installed by install.sh, and shares no code
with the notifier. Don't run this on a laptop/desktop; the ARP spoofing is
meant for the Pi sitting on the LAN as a dedicated monitor.
"""

import subprocess
import threading
import signal
import sys
import json
import time
import struct
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict

GATEWAY = "10.0.0.1"
IFACE = "wlan0"
PORT = 5556
INTERVAL = 5  # seconds between stats snapshots

# Per-device byte counters: {ip: {"in": bytes, "out": bytes, "last_seen": time}}
stats = defaultdict(lambda: {"in": 0, "out": 0, "rate_in": 0, "rate_out": 0, "last_seen": 0})
stats_lock = threading.Lock()
prev_stats = {}
running = True


def get_local_devices():
    """Ping sweep then get devices from ARP table."""
    # Ping sweep to populate ARP table
    print("[*] Ping sweeping 10.0.0.0/24...")
    procs = []
    for i in range(1, 255):
        ip = f"10.0.0.{i}"
        p = subprocess.Popen(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        procs.append(p)
        if len(procs) >= 50:
            for pp in procs:
                pp.wait()
            procs = []
    for p in procs:
        p.wait()

    result = subprocess.run(["ip", "neigh", "show", "dev", IFACE],
                            capture_output=True, text=True)
    devices = []
    for line in result.stdout.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 3 and parts[-1] not in ("FAILED",):
            ip = parts[0]
            if ip != GATEWAY and not ip.startswith("fe80"):
                devices.append(ip)
    return devices


def arpspoof_target(target_ip):
    """Run arpspoof for a single target (tell target we're the gateway)."""
    proc = subprocess.Popen(
        ["arpspoof", "-i", IFACE, "-t", target_ip, GATEWAY],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return proc


def arpspoof_gateway(targets):
    """Tell the gateway we're all the targets."""
    # Spoof gateway for each target
    procs = []
    for target_ip in targets:
        proc = subprocess.Popen(
            ["arpspoof", "-i", IFACE, "-t", GATEWAY, target_ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        procs.append(proc)
    return procs


def enable_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                   capture_output=True)


def disable_forwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                   capture_output=True)


def packet_counter():
    """Capture packets on the interface and count bytes per IP."""
    import ctypes
    import fcntl

    # Raw socket to capture all IP packets
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    sock.bind((IFACE, 0))
    sock.settimeout(1.0)

    my_ip = subprocess.run(
        ["ip", "-4", "addr", "show", IFACE],
        capture_output=True, text=True
    ).stdout
    # Parse our IP
    local_ip = None
    for line in my_ip.split("\n"):
        line = line.strip()
        if line.startswith("inet "):
            local_ip = line.split()[1].split("/")[0]
            break

    while running:
        try:
            packet, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except Exception:
            continue

        if len(packet) < 34:
            continue

        # Ethernet header is 14 bytes, IP header starts at byte 14
        ip_header = packet[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
        total_length = iph[2]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        # Skip our own traffic
        if src_ip == local_ip or dst_ip == local_ip:
            continue

        now = time.time()
        with stats_lock:
            if src_ip != GATEWAY and not src_ip.startswith("10.0.0."):
                # Incoming from internet to a device
                stats[dst_ip]["in"] += total_length
                stats[dst_ip]["last_seen"] = now
            elif dst_ip != GATEWAY:
                # Outgoing from device to internet
                stats[src_ip]["out"] += total_length
                stats[src_ip]["last_seen"] = now
            else:
                # Local traffic: device -> gateway (outbound)
                stats[src_ip]["out"] += total_length
                stats[src_ip]["last_seen"] = now
                stats[dst_ip]["in"] += total_length
                stats[dst_ip]["last_seen"] = now

    sock.close()


def rate_calculator():
    """Calculate rates every INTERVAL seconds."""
    global prev_stats
    while running:
        time.sleep(INTERVAL)
        with stats_lock:
            now = time.time()
            for ip, s in stats.items():
                prev = prev_stats.get(ip, {"in": 0, "out": 0})
                elapsed = INTERVAL
                s["rate_in"] = (s["in"] - prev["in"]) / elapsed
                s["rate_out"] = (s["out"] - prev["out"]) / elapsed
            prev_stats = {ip: {"in": s["in"], "out": s["out"]} for ip, s in stats.items()}


def format_bytes(b):
    for unit in ["B/s", "KB/s", "MB/s"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} GB/s"


class StatsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/bandwidth":
            with stats_lock:
                data = {}
                for ip, s in stats.items():
                    data[ip] = {
                        "bytes_in": s["in"],
                        "bytes_out": s["out"],
                        "rate_in": round(s["rate_in"], 1),
                        "rate_out": round(s["rate_out"], 1),
                        "rate_in_human": format_bytes(s["rate_in"]),
                        "rate_out_human": format_bytes(s["rate_out"]),
                        "active": s["rate_in"] + s["rate_out"] > 100,
                        "last_seen": s["last_seen"],
                    }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
        elif self.path == "/":
            # Simple text summary
            with stats_lock:
                lines = ["Device Bandwidth Monitor", "=" * 50]
                for ip in sorted(stats.keys()):
                    s = stats[ip]
                    active = "ACTIVE" if s["rate_in"] + s["rate_out"] > 100 else "idle"
                    lines.append(
                        f"{ip:>15}  ↓{format_bytes(s['rate_in']):>12}  "
                        f"↑{format_bytes(s['rate_out']):>12}  {active}"
                    )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write("\n".join(lines).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress request logging


spoof_procs = []


def cleanup(sig=None, frame=None):
    global running
    running = False
    print("\nStopping ARP spoofing...")
    for p in spoof_procs:
        p.terminate()
    for p in spoof_procs:
        p.wait()
    disable_forwarding()
    print("Cleaned up. ARP tables will recover in ~30s.")
    sys.exit(0)


def main():
    global spoof_procs

    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        print("Must run as root")
        sys.exit(1)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)  # Don't die on child exit

    enable_forwarding()
    print(f"[+] IP forwarding enabled")

    # Discover devices
    devices = get_local_devices()
    print(f"[+] Found {len(devices)} devices: {', '.join(devices)}")

    # Start ARP spoofing — limit to avoid overwhelming the Pi
    MAX_TARGETS = 8
    if len(devices) > MAX_TARGETS:
        print(f"[!] Too many devices ({len(devices)}), spoofing first {MAX_TARGETS}")
        devices = devices[:MAX_TARGETS]

    print(f"[+] Starting ARP spoof (gateway={GATEWAY})...")
    for dev_ip in devices:
        # Tell device we're the gateway
        p = arpspoof_target(dev_ip)
        spoof_procs.append(p)
        # Tell gateway we're the device
        p2 = subprocess.Popen(
            ["arpspoof", "-i", IFACE, "-t", GATEWAY, dev_ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        spoof_procs.append(p2)
        time.sleep(0.2)  # Stagger launches

    print(f"[+] Spoofing {len(devices)} devices ({len(spoof_procs)} arpspoof processes)")

    # Start packet counter
    counter_thread = threading.Thread(target=packet_counter, daemon=True)
    counter_thread.start()
    print(f"[+] Packet counter running")

    # Start rate calculator
    rate_thread = threading.Thread(target=rate_calculator, daemon=True)
    rate_thread.start()

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", PORT), StatsHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(f"[+] HTTP server on http://0.0.0.0:{PORT}")
    print(f"    API: http://nes:{PORT}/api/bandwidth")
    print(f"    Summary: http://nes:{PORT}/")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()

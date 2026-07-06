Run an emergency scan with increasing levels of precision to determine which phones are on the network.

## Level 1 — Database check (instant)
Query the SQLite DB for currently-active phones:
```bash
sqlite3 ~/.local/share/wifi-notifier/devices.db "SELECT mac, custom_name, device_type, hostname, manufacturer, ip FROM devices WHERE is_active = 1 AND (device_type LIKE '%phone%' OR device_type LIKE '%Phone%' OR hostname LIKE '%iphone%' OR hostname LIKE '%android%' OR hostname LIKE '%pixel%' OR hostname LIKE '%galaxy%' OR custom_name LIKE '%phone%');"
```
Report the results immediately.

## Level 2 — Passive ARP table (fast, no probing)
Check the kernel ARP table for those phone IPs:
```bash
ip neigh
```
Cross-reference phone IPs from Level 1 against ARP state. Report which are REACHABLE vs STALE vs missing.

## Level 3 — Active arping probes (confirms presence)
For each phone IP found in Levels 1-2, run an arping probe to confirm the device is truly present (works even on sleeping iPhones/Androids):
```bash
arping -c 3 -W 0.3 <ip>
```
This requires root. If not root, note that and skip.

## Reporting
After each level, print results immediately so the user sees progressive updates:
- Level 1: "DB says these phones are active: ..."
- Level 2: "ARP table confirms: ... REACHABLE / ... STALE / ... MISSING"
- Level 3: "Arping confirms: ... ALIVE / ... GONE"

Final summary: which phones are **confirmed present** on the network.
If no phones found at any level, say "No phones detected."

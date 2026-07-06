# Scan & Disconnect Optimizations

## What we changed (2026-04-08)

### Faster disconnect detection
- **Parallel arping**: missing devices are probed concurrently (up to 8 threads) instead of one-by-one. This was the biggest bottleneck — with 15 devices, sequential probing could take 45s+.
- **Reduced probe count**: 3 → 2 arping probes. arping is reliable at Layer 2; 2 probes is sufficient.
- **Shorter probe sleep**: 1s → 0.5s between failed probes.
- **Removed dead code**: `MISSING_PROBE_AFTER` was defined but never checked.

**Result**: worst-case disconnect detection ~15s (ARP stale 10s + scan interval 3s + parallel arping 1.5s). Target was ≤30s.

### Targeted nmap scanning
- **Problem**: nmap was scanning all 254 IPs in the /24 every 30s, frequently timing out (45s limit).
- **Fix**: nmap now scans only known device IPs for hostname refresh. Full /24 sweep runs every 5 minutes for new device discovery.
- **Also added**: `-T4 --max-retries 1` for faster nmap, increased subprocess timeout to 90s, and detail loop now prevents overlapping runs.

### nmap "Too many open files" fix
- Detail loop was starting a new nmap before the previous one finished (30s interval, 45s+ scan time). Now subtracts elapsed scan time from sleep interval.

## Timing breakdown (current)

| Phase | Duration | Notes |
|---|---|---|
| Kernel ARP stale | 5–10s | `gc_stale_time=5`, `base_reachable_time_ms=10000` |
| Fast scan interval | 3s | `ip neigh` + `arp-scan --localnet` |
| Arping confirmation | ~1.5s | 2 probes × 0.5s, parallel across all missing devices |
| **Total (single device)** | **~10–15s** | |
| **Total (batch, e.g. restart)** | **~10–15s** | Same, thanks to parallelism |

## Future optimization ideas

### DHCP range awareness
- Router DHCP range is 10.0.0.2–254 (full subnet), so no narrowing possible there.
- However, observed devices cluster in 10.0.0.1–30 with a few outliers (99, 111, 169).
- `arp-scan --localnet` is already a broadcast (not sequential), so DHCP range doesn't help for connect detection.
- For nmap, we already target only known IPs.

### Passive connect detection — IMPLEMENTED (2026-07-06)
- `net.NeighMonitor` wraps a persistent `ip monitor neigh` subprocess (`net.py`). `scanner._passive_monitor_loop` consumes its line stream and feeds REACHABLE events straight into `_process_scan_results` — the same connect/reconnect path the poller uses — so new and returning devices are notified in near real time instead of waiting for the next poll.
- Only REACHABLE lines count as "alive" (matches the poller's `reachable_macs` semantics). Deletions from the monitor stream are ignored on purpose: disconnect still goes through the existing arping-confirmation path (`_queue_disconnect_checks` / `_probe_disconnect`), since sleeping devices produce spurious absence that would cause false disconnects if trusted directly from the monitor.
- The poll loop was **not** replaced, per the "keep it as fallback/reconcile" call — `ip monitor neigh` has no initial dump (it's a pure event stream), so the poller still covers the startup snapshot and reconciles anything the monitor misses (dropped netlink message, restart gap). `FAST_SCAN_INTERVAL` was relaxed from 3s to 10s since it's no longer the primary connect-detection path.
- Startup notifications are gated by a `threading.Event` (`_startup_done`) so the passive listener doesn't fire during the silent first-scan pass.
- Handles `ip monitor neigh` dying: `NeighMonitor.lines()` catches process exit/errors and respawns after `restart_delay` (default 2s); exits cleanly (no busy loop) if the `ip` binary is missing.
- Verified live: in a real (non-mock) run, a new device joining the LAN was detected and notified ~2s after the passive thread started, well before the next scheduled 10s poll — see `tests/test_neigh_monitor.py` (parser + restart behavior, offline) and `tests/test_passive_connect_integration.py` (end-to-end through `_process_scan_results` with a temp DB).

### Reduce ARP stale time further
- Current: `gc_stale_time=5`, `base_reachable_time_ms=10000`
- Could try `gc_stale_time=3`, `base_reachable_time_ms=5000` — but may increase ARP traffic and false disconnects for slow IoT devices.

### Deep device fingerprinting
- See `device-fingerprinting-technique.md` for TLS cert probing, mDNS, UPnP, etc.
- Would run as one-time enrichment on first discovery, not every scan.

### 0.0.0.x IP bug
- Several devices show IPs like `0.0.0.x` — these are likely stale ARP entries or parsing issues. Should investigate and filter/fix.

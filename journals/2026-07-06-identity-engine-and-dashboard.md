# 2026-07-06 — Device identity engine + router-style dashboard

Big milestone day for the WiFi proximity notifier: the scattered device
identification logic became a single deterministic identity engine, and the
dashboard grew into a proper router-style device manager. Same-day follow-up
to this morning's passive `ip monitor neigh` connect detection work.

## What was built

### Identity engine (`identity.py`, ~700 lines, pure stdlib)

Identification used to be smeared across three files: `manufacturer.py`
(OUI vendor → free-text type guesses), `fingerprint.py` (mDNS/TLS/HTTP/NetBIOS
probes overwriting the same `device_type` column), and whatever wrote last,
won. Labels flip-flopped between rescans and there was no notion of OS,
confidence, or *why* a device got a label.

Now a single pure function fuses every evidence source into four canonical
fields — display name, device type (13-value enum: phone, tablet, laptop,
desktop, tv, console, iot, network, printer, speaker, watch, camera, unknown),
OS guess (iOS/Android/Windows/macOS/Linux/tvOS/embedded), and manufacturer —
each carrying a confidence score and the source that asserted it:

```
user (1.0) > mDNS services / TLS certs / HTTP banners (0.9)
           > mDNS hostname / NetBIOS / hostname patterns (0.7)
           > OUI vendor inference (0.4-0.5)
           > legacy free-text parse (0.3) > fallback (0.1)
```

Key properties:

- Deterministic and idempotent — same evidence, same labels, always.
  Ties broken by a fixed source-priority list, sorted iteration everywhere.
- User-set names/types/owners are sacred: stored in dedicated columns that
  automatic code never writes.
- Randomized (locally-administered) MACs get a PRIVATE MAC badge and a
  stable "Private device xx:xx" label unless mDNS/NetBIOS/hostname evidence
  pins them down (e.g. `_companion-link._tcp` → iPhone).
- `ENGINE_VERSION` gates a startup backfill: bump it after a rules change and
  every stored device is re-resolved from its accumulated evidence.

`resolver.py` is the thin glue (DB row → evidence → resolution → persist);
`device_db.py` gained an additive migration (8 new columns, nothing dropped).

### Dashboard rework

`/api/devices` now serves the enriched identity view; new `/api/meta` and
`/api/devices/<mac>/update` endpoints (name/type/owner with canonical-type
validation, 400 on garbage). The single-page UI kept the glassmorphism dark
theme and colorblind-safe design (text badges, shapes, brightness — never
color alone) and added: stats tiles, filter chips with live counts
(All/Online/New/Needs labeling/Private MAC), free-text search, sortable
columns with a deterministic secondary sort, inline rename + type dropdown
("Auto" = engine-resolved) + owner editing, an identity-provenance panel
(click the type icon to see which source produced each label and at what
confidence), a day-grouped activity timeline with JOINED/LEFT text markers,
and a stacked-card mobile layout for phone use over Tailscale
(`http://taxi:5555` via MagicDNS).

### Safety fix worth remembering

`--mock` mode used to seed its fake devices into the *real* `devices.db` —
it had actually wiped the user-level database at some point. Mock mode now
uses a separate `mock.db`, and `WIFI_NOTIFIER_DB` overrides the path for
tests.

## Software involved

- Python 3 + Flask, `mac-vendor-lookup` (existing venv)
- SQLite (WAL mode), additive `ALTER TABLE` migration
- Playwright (already in venv) for dashboard screenshots
- `arp-scan`, `nmap`, `arping`, `iproute2`, `avahi` (system tools)

## Commands used

```bash
# full test suite (offline, no root needed)
./venv/bin/python3 -m unittest discover -s tests

# mock demo + screenshot
python3 app.py --mock --port 5558
python3 ~/.claude/skills/screenshot/capture.py --url http://localhost:5558 \
    --output docs/dashboard.png --width 1280 --height 1200 \
    --wait-selector .device-row --wait-seconds 3 --full-page
```

## Issues hit and resolutions

- **Mock data had clobbered the real user DB** (see above) — isolated mock.db,
  moved the polluted file aside.
- **Legacy string parsing gotcha**: `"Phone/Tablet (MAC Randomized)"` contains
  the substring "mac", which matched the Apple/macOS rule and gave private
  phones `os: macOS`. Fixed with explicit "randomized"/"phone" rules and a
  word-boundary match for "mac". Lesson: substring rulesets need the specific
  cases ordered before the generic ones, and tests only protect the cases you
  actually wrote.
- **avahi-daemon turned out to be inactive on the laptop** — meaning mDNS
  browsing (the strongest phone-identification signal) had silently never
  worked. `avahi-browse` failing was invisible because the code degrades
  gracefully. Enabled as part of the service setup.
- **Live verification without root**: reading the ARP table, `ip monitor
  neigh`, and NetBIOS all work unprivileged, so the engine could be verified
  against the real LAN before the systemd unit was installed: a Brother print
  server was identified via NetBIOS name pattern (printer, 0.7), the NETGEAR
  router via OUI (network), three ESP32 sensors and a Raspberry Pi as iot,
  and three randomized-MAC phones got stable private-device labels.

## Test status

65 tests green (18 pre-existing + 47 new identity-engine tests), all offline.

## Open items

- Enable `avahi-daemon` and install/enable the systemd unit (root step).
- Weak-label improvements: "SHENZHEN BILIAN" (WiFi module OUI) and "Earda"
  (lighting IoT vendor) currently land as unknown/fallback — good candidates
  for the next ruleset rev (ENGINE_VERSION 2).
- Auth token for the dashboard if it ever binds beyond LAN + tailnet
  (hook stub already in place).

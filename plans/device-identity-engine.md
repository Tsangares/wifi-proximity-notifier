# Device Identity Engine

## Problem

Device identification was scattered across three places that never converged:

- `manufacturer.py` — OUI vendor lookup → free-text type guesses ("Android (Samsung)"),
  randomized-MAC detection, hostname inference ("iPhone", "Windows Desktop")
- `fingerprint.py` — deep probes (mDNS services, TLS certs, HTTP banners, NetBIOS)
  that overwrote `device_type` with yet more free-text strings
- the DB `device_type` column — whichever source wrote last, won

Result: inconsistent labels, no notion of OS, no confidence, no record of *why*
a device was labeled a certain way, and labels that could flip between rescans.

## Design

One identity-resolution layer, split into a pure core and a thin glue module:

```
evidence (DB row) ──> identity.build_evidence() ──> identity.resolve() ──> resolver ──> DB
                        (pure, deterministic)         (pure, deterministic)   (persists)
```

### identity.py — pure logic, no I/O

- `resolve(evidence) -> resolution` fuses all evidence sources into four canonical
  fields, each with a confidence (0..1) and provenance (which source asserted it):
  - `display_name` — best human name
  - `device_type` — canonical enum: phone, tablet, laptop, desktop, tv, console,
    iot, network, printer, speaker, watch, camera, unknown
  - `os_guess` — iOS, Android, Windows, macOS, Linux, tvOS, embedded, or ""
  - `manufacturer`
- Evidence sources, ranked (ties broken by this fixed order):
  user (1.0) > mdns_services / tls_cert / http (0.9) > mdns_hostname / netbios /
  hostname patterns (0.7) > vendor OUI inference (0.4–0.5) > legacy free-text
  type parse (0.3) > fallback (0.1)
- Deterministic and idempotent: same evidence → identical output. No randomness,
  no clock dependence, sorted iteration everywhere. Labels cannot flip-flop
  across rescans because resolution is a pure function of stored (sticky) evidence.
- Curated rulesets: OUI-vendor keyword → (type, OS), hostname pattern → (type, OS)
  (e.g. `iPhone`→phone/iOS, `DESKTOP-*`→desktop/Windows, `esp32|tasmota|sonoff|tuya`→
  iot/embedded, `raspberrypi`→iot/Linux, `BRW*`→printer), mDNS service → type
  (`_companion-link`→phone/iOS, `_raop`→speaker, `_ipp`→printer, ...), TLS-cert and
  HTTP-banner patterns.
- Randomized (locally-administered) MACs: flagged `is_private_mac`; labeled
  "Private device xx:xx" with type phone at low confidence unless mDNS/NetBIOS/
  hostname provides a stable identity (then that wins).
- `ENGINE_VERSION` — bumped whenever rules change; drives backfill.

### User overrides are sacred

`custom_name`, `custom_type`, `owner` are user-set columns. Automatic code never
writes them (`device_db.set_identity()` doesn't touch them). At render time
`custom_name`/`custom_type` win over resolved values; in `resolve()` they surface
as source "user", confidence 1.0.

### resolver.py — glue

- `resolve_row/resolve_mac` — build evidence from a DB row, resolve, persist via
  `device_db.set_identity()`.
- `backfill()` — re-resolve every device whose `identity_version` differs from
  `ENGINE_VERSION`. Runs at every startup, so rule improvements retroactively
  relabel accumulated history without losing any evidence or overrides.

### Schema (additive migration, no data loss)

New `devices` columns: `display_name`, `resolved_type`, `os_guess`,
`identity_meta` (JSON with per-field value/confidence/source), `identity_version`,
`is_private_mac`, `custom_type`, `owner`. The legacy `device_type` column is kept
as raw free-text *evidence* (fingerprint probes still write it); the dashboard
displays only canonical `resolved_type`/`custom_type`.

### Resolution triggers

1. Startup backfill (engine version mismatch)
2. New device discovered
3. Hostname newly learned or changed
4. Fingerprint probe completed (incl. mDNS improvement pass)

### Mock-mode safety

`--mock` previously seeded fake devices into the real `devices.db`, destroying
history. Mock mode now uses a separate `mock.db` (`device_db.use_mock_db()`),
and `WIFI_NOTIFIER_DB` overrides the DB path for tests.

## Testing

`tests/test_identity.py` — offline, pure-logic: fusion priorities, override
protection, determinism/idempotence, private-MAC handling, canonical-enum
validity, `build_evidence` parsing of real fingerprint JSON.

"""Glue between the pure identity engine (identity.py) and the database.

identity.py is pure logic (evidence in, labels out). This module feeds it
DB rows and persists the results. All automatic identity writes go through
here so the rules are applied consistently:

- resolve_row / resolve_mac: re-resolve one device from its stored evidence.
- backfill: re-resolve every device whose identity predates the current
  ENGINE_VERSION (runs at startup, so rule improvements retroactively fix
  old devices without losing any stored evidence).

User-set fields (custom_name, custom_type, owner) are read as overrides but
NEVER written by this module.
"""

import json
import logging

import identity
import device_db

log = logging.getLogger(__name__)


def resolve_row(row):
    """Resolve identity for one devices-table row dict and persist it.
    Returns the resolution dict from identity.resolve()."""
    evidence = identity.build_evidence(row)
    res = identity.resolve(evidence)
    meta = json.dumps(res, sort_keys=True)
    device_db.set_identity(
        row["mac"],
        display_name=res["display_name"]["value"],
        resolved_type=res["device_type"]["value"],
        os_guess=res["os_guess"]["value"],
        manufacturer=res["manufacturer"]["value"],
        identity_meta=meta,
        is_private_mac=res["is_private_mac"],
        engine_version=res["engine_version"],
    )
    return res


def resolve_mac(mac):
    """Fetch a device by MAC and re-resolve its identity. No-op if unknown."""
    row = device_db.get_device(mac)
    if row is None:
        return None
    try:
        return resolve_row(row)
    except Exception as e:
        log.error("Identity resolution failed for %s: %s", mac, e, exc_info=True)
        return None


def backfill():
    """Re-resolve all devices with stale/missing identity. Idempotent —
    devices already resolved by the current engine version are skipped."""
    rows = device_db.devices_needing_identity(identity.ENGINE_VERSION)
    if not rows:
        return 0
    ok = 0
    for row in rows:
        try:
            resolve_row(row)
            ok += 1
        except Exception as e:
            log.error("Backfill: identity resolution failed for %s: %s", row["mac"], e)
    log.info("Identity backfill: resolved %d/%d devices (engine v%d)",
             ok, len(rows), identity.ENGINE_VERSION)
    return ok

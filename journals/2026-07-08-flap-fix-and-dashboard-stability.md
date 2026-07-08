# 2026-07-08 — Chasing a notification storm: flap suppression, silent DBUS failures, and a jittery dashboard

Today was mostly debugging and hardening rather than new features. It started
from two vague complaints — "why does the laptop keep connecting and
disconnecting?" and "the dashboard is hard to read, it keeps moving things
around" — and turned into a tour of several latent bugs. Writing it up with the
failures front and center, because that's where the interesting parts were.

## The investigation

I started from the logs rather than the code:

```bash
# every connect/disconnect-ish line for the last few days
journalctl -u wifi-notifier --since "3 days ago" -o short-iso | \
  grep -iE "join|left|connect|disconnect|gone|reachable|stale"

# which MACs disconnect the most
journalctl -u wifi-notifier --since "3 days ago" -o cat | \
  grep -oE "DISCONNECT: ([0-9a-f:]+)" | awk '{print $2}' | sort | uniq -c | sort -rn

# which devices actually fired desktop notifications, joined vs left
journalctl -u wifi-notifier --since "2 days ago" -o cat | \
  grep "NOTIFY:" | grep -oE "NOTIFY: Device (Joined|Left): [^—(]+" | sort | uniq -c | sort -rn
```

The DB lives under root (`/root/.local/share/wifi-notifier/devices.db`) and
isn't readable as my user, so I mapped MACs to names through the running
dashboard instead — a nice reminder that the API is the least-privilege way in:

```bash
curl -s http://localhost:5555/api/devices | python3 -m json.tool
```

The picture that fell out: the single worst offender was a device the user had
nicknamed like a laptop, but which advertises itself over mDNS as an **iPad**
(hostname `iPad.local`) with a **randomized MAC**. It generated **33 "Device
Left" desktop notifications in two days**. The next several offenders were all
the same species — Apple phones/tablets with private MACs.

## Failure #1 — we declared sleeping Apple devices "gone" too eagerly

The disconnect path confirms a device is gone with `arping` (layer 2, so it
works on phones that ignore ICMP). Good idea, but the confirmation window was
far too tight for modern power-save: **5 probes at `-W 0.3` spread over ~1.5 s**.
An associated-but-napping iPhone/iPad can easily miss all five broadcast ARP
probes, so the scanner marks it inactive; on its next transmit the kernel flips
it back to `REACHABLE` and we "reconnect" it. One sleep/wake cycle = one flap.

The kernel ARP timers we tune at startup (`base_reachable_time_ms=10000`,
`gc_stale_time=5`) make this worse: an idle-but-present device drops out of
`REACHABLE` within ~10 s and can be garbage-collected from the table entirely,
pushing it onto the "absent" disconnect path within a couple of minutes.

## Failure #2 — the flap dampener reset itself on every nap

There *was* already flap suppression, and on paper it looked reasonable:
suppress the notification once a device records ≥2 disconnects within 10 minutes.
But it had a subtle self-defeating bug:

```python
# scanner.py — on reconnect
if disc_time and (now - disc_time).total_seconds() >= FLAP_SUPPRESS_TIME:  # 300 s
    _flap_history.pop(mac, None)   # "genuine return" → wipe flap history
```

A device that sleeps for **more than 5 minutes**, wakes briefly, and sleeps
again gets its flap history wiped on every return — so it never accumulates the
2-in-10-minutes needed to be classified as flapping. The exact devices we most
wanted to suppress (deep sleepers) were the ones that always slipped through.
That's why the iPad kept notifying 33 times despite "having" flap suppression.

## Failure #3 — 15 notifications silently thrown on the floor

While grepping I noticed a burst of warnings after one restart:

```
[WARNING] notifier: gdbus failed (rc=1): Error connecting:
          Could not connect: No such file or directory
```

The daemon runs as root and shells out to `gdbus` **as user `wil`** to reach the
desktop session bus. After a restart while the graphical session wasn't fully
up, that socket didn't exist yet — so ~15 notifications failed and were lost,
each logged once at WARNING and then forgotten. No retry, no recovery log, and
WARNING-per-event means a real outage would drown the journal.

## Failure #4 — the dashboard reshuffled itself every 5 seconds

The client polls `/api/devices` every 5 s and re-sorts the whole list by
`last_seen` descending. Every scan bumps an online device's `last_seen`, so
those rows constantly re-sort to the top and the render pass physically
`appendChild`-moves the DOM nodes — the list visibly jumps while you're trying
to read it. On top of that the filter chips and sort buttons were rebuilt with
`innerHTML` on every refresh, rows replayed their fade-in animation whenever any
field changed (so an online↔offline flip flashed), and the activity feed reset
its scroll position on each new event. Individually minor; together, jittery.

## Failure #5 — good hostnames were rendered nearly invisible

Related but separate: a device with a real hostname like `diort` *is* resolved
correctly by the identity engine (the name is there, at 0.7 confidence, sourced
from the hostname). But the dashboard only put a **custom nickname** into the
name field's value; an auto-resolved name showed only as a placeholder in a
colour almost identical to the background (`#333345`). Worse, any device without
a manual nickname counted toward "Needs labeling" — so devices that already
told us their name were nagging to be named.

## Also spotted (smaller)

- **Randomized-MAC rotation → NEW DEVICE spam.** A phone that rotates its MAC
  looks like a brand-new device each time, and the new-device path has no
  private-MAC guard, so it notifies on every rotation.
- **Unbounded in-memory state.** `_last_seen`, `_flap_history`, `_disconnect_ts`
  and `_disconnect_pending` accumulate an entry per MAC ever seen; with MAC
  randomization that grows without bound.
- **Stale-IP arping.** The disconnect probe uses the *stored* IP, which can be
  wrong after a DHCP change → a false "gone".

## The fixes

Work was split into parallel streams (scanner/notifications, dashboard, and
release infra) and implemented largely by delegated coding agents, with each
diff reviewed before acceptance. What landed:

**Disconnect detection (the flap storm).** Two changes, because there were two
root causes:

- *Type-aware grace.* The trigger for the false disconnects was the STALE path
  firing after only 60 s. Phones, tablets, and watches now get a 150 s stale /
  300 s absent grace (laptops 90/180; everything else keeps 60/120) before we
  even start probing — a sleeping device gets minutes to answer, not seconds.
- *Wider arping window.* The confirmation probe deadline went from 300 ms to
  1 s, and the five probes are now spread over ~15 s instead of ~1.5 s, so a
  power-napping device is caught on its next wake interval.

**Chronic-flap suppression, done right.** The reset bug is gone: flap history is
now a rolling one-hour window that is *pruned*, never wiped. A device that
disconnects three times within the hour is classified chronic and muted on both
"left" and "rejoined" until it settles — so a genuinely-bouncing device goes
quiet after a couple of events instead of notifying on every cycle forever.

**Notification hardening.**

- The `gdbus` "no session" failure is now logged once on the way down and once
  on recovery, instead of a WARNING per lost notification — no more silent
  floods, and the log tells you the session was simply absent.
- A brand-new randomized MAC with no hostname/mDNS name yet is tracked silently
  instead of firing a notification on every MAC rotation.
- Per-device **mute**: a 🔕 toggle on any dashboard row (new sacred `muted`
  column) suppresses that device's notifications outright.

**Housekeeping bugs.** The in-memory tracking dicts are now pruned hourly (drop
MACs unseen for 6 h and not active), so MAC randomization can't leak memory
forever. And the disconnect probe re-reads the device's current IP from the live
ARP table before arping, so a post-DHCP address change no longer causes a false
"gone".

**Dashboard: stop the reshuffle.** The list now defaults to a stable
online-first-then-name sort (so a `last_seen` tick never reorders anything), the
reorder pass only moves rows that are actually out of place — and never a row
you're editing or one with its detail panel open — the fade-in is scoped to
genuinely-new rows (no more online/offline flash), the filter chips and sort
buttons are built once and updated in place, and the activity feed keeps its
scroll position. Net effect: the page updates every 5 s without anything
jumping.

**Dashboard: names you can actually read.** A device with a real hostname/mDNS
name (confidence ≥ 0.7) now shows that name bold in the name field — marked with
a hollow "auto-detected" dot to distinguish it from a name you set — instead of
a near-invisible placeholder. "Needs labeling" now keys off resolved-name
confidence, so only genuinely anonymous devices (a random MAC with no name) get
flagged. Also added a 24-hour presence-history strip in each device's detail
panel, drawn client-side from the existing activity log.

**Release readiness.** Added an MIT `LICENSE` (the README badge had been
claiming MIT with no file), a GitHub Actions workflow running the test suite on
Python 3.11–3.13, and truthed-up the README (the "no flicker" claim is now
actually true, the tuning constants match reality, the new endpoints are
documented, and a personal tailnet IP/hostname were redacted).

**Tests.** The suite grew from 69 to 100 — new coverage for the type-aware
timeout helpers, the chronic-flapper classifier (including a regression test for
the old reset bug), the `gdbus` dedup logging, and the private-MAC
new-device suppression. All green. The mute + presence endpoints were verified
in-process via Flask's test client (11/11 checks), which also neatly sidesteps a
sandbox that blocks binding a real port.

## How it was built (process note)

Worth recording because it worked well: the work was decomposed into three
**file-disjoint** streams — scanner/notifications, dashboard, and release infra
— and handed to parallel coding agents running concurrently, with every diff
reviewed before acceptance. Disjoint file sets meant no git contention despite
running at the same time. The dashboard itself was split into two sequential
waves (flicker/name-visibility first, then the mute + presence features) because
both touch the one big template file. A couple of review catches mattered: a
test was incidentally using a locally-administered (`aa:`) MAC for a
"generic new device" case, which the new private-MAC suppression would have
broken — fixed by moving it to a non-private prefix and adding explicit
suppression tests instead of weakening the assertion.

One environment wrinkle: this sandbox blocks binding a real TCP port, so the
usual `app.py --mock` smoke test wouldn't start. Flask's in-process
`test_client()` dispatches requests without a socket, which sidestepped it
entirely and verified the mute + presence endpoints (11/11 checks).

## Shipping

Landed on branch `flap-fix-and-dashboard-stability`, PR #1. **CI is green across
Python 3.11 / 3.12 / 3.13** — and notably it ran clean in a bare CI container
(no root, no `arp-scan`/`nmap`/`ip` present), which is the real proof the suite
is genuinely offline. GitGuardian's secret scan passed too, an independent check
that the tailnet-IP redaction was complete. Test count went 69 → 100.

## Versions / tools

Arch Linux, kernel 7.0.x; Python 3.14 (local venv) with the CI matrix targeting
3.11–3.13; `arp-scan`, `nmap`, `iputils`/`arping`; Flask 3.1; systemd +
journalctl; GitHub Actions (CI) via the `gh` CLI; `node --check` for JS syntax.

## Open items

- **Live-verify on the running service.** All of the above is verified by the
  test suite and in-process checks, but the production daemon hasn't been
  restarted onto the new code yet. The real proof is a restart followed by
  watching `journalctl -u wifi-notifier -f` across a sleep/wake cycle of the
  worst-offending Apple device and confirming the repeated "Device Left"
  notifications are gone while a genuine departure still fires.
- **Screenshots are stale.** `docs/dashboard.png` still shows the pre-change UI;
  regenerating it needs a mock server bound to a port, which the current
  sandbox blocks. Regenerate from `python3 app.py --mock` in a normal shell.
- **Deferred features** (designed, not built): a "watched-only" notification
  mode, a who's-home / by-owner overview, and prominent unknown-device
  (never-seen MAC) alerts.
- Identity `ENGINE_VERSION` was deliberately *not* bumped — no identity
  resolution rules changed, only the dashboard's presentation of them.

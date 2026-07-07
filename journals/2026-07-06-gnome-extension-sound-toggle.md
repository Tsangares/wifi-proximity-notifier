# 2026-07-06 — GNOME Shell extension: sound toggle + dashboard shortcut

Second milestone today. After getting the daemon running as a systemd service
with the new identity engine, the missing piece of day-to-day ergonomics was a
way to mute the connect/disconnect chirps without SSH-ing into config files —
and a one-click way to reach the dashboard. So the notifier now has a top-bar
GNOME extension.

## What was built

**Backend (the part the extension talks to):**

- A `settings` key/value table in the SQLite DB, with `get_setting()` /
  `set_setting()` in `device_db.py`. Additive migration like everything else —
  a `CREATE TABLE IF NOT EXISTS` in `_init_tables`.
- `GET/POST /api/settings` in `dashboard.py`. Currently one key:
  `sound_enabled` (boolean, persisted, default on).
- `notifier._play_sound()` checks the setting before calling `paplay`, so the
  toggle takes effect immediately for the root daemon — no restart. Desktop
  notifications keep appearing; only the sound is gated.

**The extension** (`gnome-extension/wifi-notifier@tsangares/`):

- ESM-style extension for GNOME Shell 45–50 (tested on 50.1, Wayland, Arch).
- Top-bar wifi icon with a live online-device count next to it.
- Menu: an "N of M devices online" status line, a **Notification sounds**
  switch, and **Open Dashboard** (launches the default browser via
  `Gio.AppInfo.launch_default_for_uri`).
- Talks HTTP to `127.0.0.1:5555` with libsoup 3 (`Soup.Session`,
  `send_and_read_async`). Refreshes when the menu opens plus every 30 s in the
  background. If the daemon is down: offline icon, count hidden, switch
  greyed out; a failed toggle reverts the switch and raises a shell
  notification instead of silently lying.

## Commands used

```bash
# install
ln -sfn "$(pwd)/gnome-extension/wifi-notifier@tsangares" ~/.local/share/gnome-shell/extensions/wifi-notifier@tsangares
gnome-extensions enable wifi-notifier@tsangares
```

```bash
# verify the API end-to-end
curl -s -X POST -H 'Content-Type: application/json' -d '{"sound_enabled": false}' http://127.0.0.1:5555/api/settings
```

## Issues hit

- **Wayland discovery**: `gnome-extensions enable` right after symlinking
  fails with "does not exist" — GNOME Shell only scans the extensions
  directory at login on Wayland. Worked around by appending the UUID to
  `org.gnome.shell enabled-extensions` via gsettings so it activates on the
  next login; on X11 an `Alt+F2` → `r` shell restart would do.
- **Syntax-checking shell extensions**: gjs can't run them standalone, but
  `node --check` on a `.mjs` copy catches parse errors cheaply.

## Versions

GNOME Shell 50.1, libsoup 3, Python 3 + Flask (venv), node (syntax check only).

## Open items

- Extension is installed and pre-enabled; needs one logout/login to appear.
- Possible future: expose more settings (notification on/off separate from
  sound), and a matching toggle in the web dashboard UI.

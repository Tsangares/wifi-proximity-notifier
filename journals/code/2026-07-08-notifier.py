import subprocess
import logging
import os
import threading
import time
import pwd

log = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONNECT_SOUND = os.path.join(SCRIPT_DIR, "static", "connect.wav")
DISCONNECT_SOUND = os.path.join(SCRIPT_DIR, "static", "disconnect.wav")
FALLBACK_SOUND = "/usr/share/sounds/gnome/default/alerts/swing.ogg"
DISMISS_AFTER = 5  # seconds — notification slides to tray after this

# Find the real (non-root) user for sending notifications
_NOTIFY_UID = int(os.environ.get("SUDO_UID", 0)) or 1000
_NOTIFY_USER = None
try:
    _NOTIFY_USER = pwd.getpwuid(_NOTIFY_UID).pw_name
except KeyError:
    pass

_DBUS_ADDR = os.environ.get("DBUS_SESSION_BUS_ADDRESS",
                             f"unix:path=/run/user/{_NOTIFY_UID}/bus")

# gdbus fails with this specific message when the target user has no active
# desktop session (e.g. logged out, or the session bus socket isn't up yet
# at boot). That's an expected, recurring condition — not worth a WARNING
# on every single notification — so we track whether we're already in that
# state and only log the transition (down / recovered), not every failure.
_DBUS_UNAVAILABLE_SIGNATURE = "Could not connect: No such file or directory"
_dbus_session_down = False


def _get_sound(connect=True):
    path = CONNECT_SOUND if connect else DISCONNECT_SOUND
    if os.path.exists(path):
        return path
    if os.path.exists(FALLBACK_SOUND):
        return FALLBACK_SOUND
    return None


def _notify_env():
    """Build environment for notification commands to reach the user's session."""
    env = os.environ.copy()
    env["DBUS_SESSION_BUS_ADDRESS"] = _DBUS_ADDR
    env["DISPLAY"] = os.environ.get("DISPLAY", ":0")
    env["XDG_RUNTIME_DIR"] = f"/run/user/{_NOTIFY_UID}"
    return env


def _run_as_user(cmd, **kwargs):
    """Run a command as the desktop user (not root) so notifications appear."""
    if os.getuid() == 0 and _NOTIFY_USER:
        cmd = ["sudo", "-u", _NOTIFY_USER, "--preserve-env=DBUS_SESSION_BUS_ADDRESS,DISPLAY,XDG_RUNTIME_DIR"] + cmd
    return subprocess.run(cmd, env=_notify_env(), **kwargs)


def _popen_as_user(cmd, **kwargs):
    """Popen as the desktop user."""
    if os.getuid() == 0 and _NOTIFY_USER:
        cmd = ["sudo", "-u", _NOTIFY_USER, "--preserve-env=DBUS_SESSION_BUS_ADDRESS,DISPLAY,XDG_RUNTIME_DIR"] + cmd
    return subprocess.Popen(cmd, env=_notify_env(), **kwargs)


def _send_notification(title, body, icon="network-wireless", timeout=DISMISS_AFTER):
    """Send notification via gdbus and auto-close after timeout."""
    global _dbus_session_down
    try:
        result = _run_as_user(
            [
                "gdbus", "call", "--session",
                "--dest", "org.freedesktop.Notifications",
                "--object-path", "/org/freedesktop/Notifications",
                "--method", "org.freedesktop.Notifications.Notify",
                "wifi-notifier",
                "0",
                icon,
                title,
                body,
                "[]",
                "{}",
                str(timeout * 1000),
            ],
            capture_output=True, text=True, timeout=5,
        )
        out = result.stdout.strip()
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if _DBUS_UNAVAILABLE_SIGNATURE in stderr:
                # No desktop session to notify into — expected/recurring
                # (e.g. logged out). Log the state transition once, not on
                # every notification attempt.
                if not _dbus_session_down:
                    log.info("No desktop session DBUS available for notifications "
                             "(user has no active session) — will keep trying "
                             "silently until it recovers")
                    _dbus_session_down = True
            else:
                log.warning("gdbus failed (rc=%d): %s", result.returncode, stderr)
        else:
            if _dbus_session_down:
                log.info("Desktop session DBUS available again — notifications recovered")
                _dbus_session_down = False
        # Don't force-close — let GNOME move it to the tray naturally
    except Exception as e:
        log.warning("gdbus notification failed: %s", e)
        # Fallback to notify-send
        try:
            _popen_as_user(
                ["notify-send", "-i", icon, "-t", str(timeout * 1000), title, body],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            log.warning("notify-send fallback also failed")


def _close_notification(nid, delay):
    """Close a notification after delay seconds."""
    time.sleep(delay)
    try:
        _run_as_user(
            [
                "gdbus", "call", "--session",
                "--dest", "org.freedesktop.Notifications",
                "--object-path", "/org/freedesktop/Notifications",
                "--method", "org.freedesktop.Notifications.CloseNotification",
                str(nid),
            ],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


def _clean_type(device_type):
    """Remove 'MAC Randomized' from display type."""
    if device_type and "MAC Randomized" in device_type:
        return "Phone/Tablet"
    return device_type


def sound_enabled():
    """Sound on/off, persisted in the DB (toggled via /api/settings or the GNOME extension)."""
    try:
        import device_db
        return device_db.get_setting("sound_enabled", "1") == "1"
    except Exception:
        return True


def _play_sound(connect=True):
    if not sound_enabled():
        return
    sound = _get_sound(connect)
    if sound:
        try:
            _popen_as_user(
                ["paplay", sound],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            log.warning("paplay failed")


def notify_new_device(mac, ip, manufacturer, device_type, is_returning=False, custom_name=""):
    dtype = _clean_type(device_type)
    display_name = custom_name or dtype
    if is_returning:
        title = f"Device Connected: {display_name}"
    else:
        title = f"NEW DEVICE: {display_name}"
    body = f"{manufacturer}\nMAC: {mac}\nIP: {ip}"

    log.info("NOTIFY: %s — %s %s (%s) at %s", title, dtype, manufacturer, mac, ip)

    _send_notification(title, body, icon="network-wireless")
    _play_sound(connect=True)


def notify_device_left(mac, ip, manufacturer, device_type, custom_name=""):
    name = custom_name or _clean_type(device_type)
    title = f"Device Left: {name}"
    body = f"{manufacturer}\nMAC: {mac}\nIP: {ip}"

    log.info("NOTIFY: %s — %s (%s)", title, name, mac)

    _send_notification(title, body, icon="network-wireless-offline")
    _play_sound(connect=False)

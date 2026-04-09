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
DISMISS_AFTER = 10  # seconds

# Find the real (non-root) user for sending notifications
_NOTIFY_UID = int(os.environ.get("SUDO_UID", 0)) or 1000
_NOTIFY_USER = None
try:
    _NOTIFY_USER = pwd.getpwuid(_NOTIFY_UID).pw_name
except KeyError:
    pass

_DBUS_ADDR = os.environ.get("DBUS_SESSION_BUS_ADDRESS",
                             f"unix:path=/run/user/{_NOTIFY_UID}/bus")


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
            log.warning("gdbus failed (rc=%d): %s", result.returncode, result.stderr.strip())
        if "uint32" in out:
            nid = out.split("uint32")[1].strip().rstrip(",)")
            threading.Thread(
                target=_close_notification, args=(int(nid), timeout), daemon=True
            ).start()
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


def _play_sound(connect=True):
    sound = _get_sound(connect)
    if sound:
        try:
            _popen_as_user(
                ["paplay", sound],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            log.warning("paplay failed")


def notify_new_device(mac, ip, manufacturer, device_type, is_returning=False):
    dtype = _clean_type(device_type)
    if is_returning:
        title = f"Device Connected: {dtype}"
    else:
        title = f"NEW DEVICE: {dtype}"
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

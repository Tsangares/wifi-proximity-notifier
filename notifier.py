import subprocess
import logging
import os
import threading
import time

log = logging.getLogger(__name__)

CHIRP_SOUND = "/usr/share/sounds/gnome/default/alerts/swing.ogg"
CHIRP_FALLBACKS = [
    "/usr/share/sounds/gnome/default/alerts/click.ogg",
    "/usr/share/sounds/freedesktop/stereo/message-new-instant.oga",
    "/usr/share/sounds/speech-dispatcher/test.wav",
]
DISMISS_AFTER = 10  # seconds


def _find_sound():
    if os.path.exists(CHIRP_SOUND):
        return CHIRP_SOUND
    for f in CHIRP_FALLBACKS:
        if os.path.exists(f):
            return f
    return None


def _send_notification(title, body, icon="network-wireless", timeout=DISMISS_AFTER):
    """Send notification via gdbus and auto-close after timeout."""
    try:
        result = subprocess.run(
            [
                "gdbus", "call", "--session",
                "--dest", "org.freedesktop.Notifications",
                "--object-path", "/org/freedesktop/Notifications",
                "--method", "org.freedesktop.Notifications.Notify",
                "wifi-notifier",  # app name
                "0",              # replaces_id
                icon,
                title,
                body,
                "[]",             # actions
                "{}",             # hints
                str(timeout * 1000),
            ],
            capture_output=True, text=True, timeout=5,
        )
        # Parse notification ID from output like "(uint32 42,)"
        out = result.stdout.strip()
        if "uint32" in out:
            nid = out.split("uint32")[1].strip().rstrip(",)")
            # Schedule close after timeout
            threading.Thread(
                target=_close_notification, args=(int(nid), timeout), daemon=True
            ).start()
    except Exception as e:
        log.warning("gdbus notification failed, falling back to notify-send: %s", e)
        try:
            subprocess.Popen(
                ["notify-send", "-i", icon, "-t", str(timeout * 1000), title, body],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            log.warning("notify-send not found")


def _close_notification(nid, delay):
    """Close a notification after delay seconds."""
    time.sleep(delay)
    try:
        subprocess.run(
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


def notify_new_device(mac, ip, manufacturer, device_type, is_returning=False):
    title = "Returning Device" if is_returning else "New Device Detected!"
    body = f"{device_type}\n{manufacturer}\nMAC: {mac}\nIP: {ip}"

    log.info("NOTIFY: %s — %s %s (%s) at %s", title, device_type, manufacturer, mac, ip)

    _send_notification(title, body, icon="network-wireless")

    # Chirp sound
    sound = _find_sound()
    if sound:
        try:
            subprocess.Popen(
                ["paplay", sound],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            log.warning("paplay not found")


def notify_device_left(mac, ip, manufacturer, device_type, custom_name=""):
    name = custom_name or device_type
    title = "Device Disconnected"
    body = f"{name}\n{manufacturer}\nMAC: {mac}\nIP: {ip}"

    log.info("NOTIFY: %s — %s (%s)", title, name, mac)

    _send_notification(title, body, icon="network-wireless-offline")

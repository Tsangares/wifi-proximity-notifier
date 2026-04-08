import subprocess
import logging
import os

log = logging.getLogger(__name__)

CHIRP_SOUND = "/usr/share/sounds/gnome/default/alerts/swing.ogg"
# Fallback options
CHIRP_FALLBACKS = [
    "/usr/share/sounds/gnome/default/alerts/click.ogg",
    "/usr/share/sounds/freedesktop/stereo/message-new-instant.oga",
    "/usr/share/sounds/speech-dispatcher/test.wav",
]


def _find_sound():
    if os.path.exists(CHIRP_SOUND):
        return CHIRP_SOUND
    for f in CHIRP_FALLBACKS:
        if os.path.exists(f):
            return f
    return None


def notify_new_device(mac, ip, manufacturer, device_type, is_returning=False):
    title = "Returning Device" if is_returning else "New Device Detected!"
    body = f"{device_type}\n{manufacturer}\nMAC: {mac}\nIP: {ip}"

    log.info("NOTIFY: %s — %s %s (%s) at %s", title, device_type, manufacturer, mac, ip)

    # Desktop notification
    try:
        urgency = "normal"
        icon = "network-wireless"
        subprocess.Popen(
            ["notify-send", "-u", urgency, "-i", icon, "-t", "10000", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        log.warning("notify-send not found")

    # Chirp sound
    sound = _find_sound()
    if sound:
        try:
            subprocess.Popen(
                ["paplay", sound],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            log.warning("paplay not found")


def notify_device_left(mac, ip, manufacturer, device_type, custom_name=""):
    name = custom_name or device_type
    title = "Device Disconnected"
    body = f"{name}\n{manufacturer}\nMAC: {mac}\nIP: {ip}"

    log.info("NOTIFY: %s — %s (%s)", title, name, mac)

    try:
        subprocess.Popen(
            ["notify-send", "-u", "low", "-i", "network-wireless-offline", "-t", "3000", title, body],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pass

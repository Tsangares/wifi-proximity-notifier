from flask import Flask, render_template, jsonify, request
import json
import device_db
import fingerprint

app = Flask(__name__)

CANONICAL_TYPES_FALLBACK = [
    "phone", "tablet", "laptop", "desktop", "tv", "console",
    "iot", "network", "printer", "speaker", "watch", "camera", "unknown",
]
OS_VALUES = ["iOS", "Android", "Windows", "macOS", "Linux", "tvOS", "embedded", ""]


@app.before_request
def _check_auth():
    # Future: bearer-token check goes here.
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    return jsonify({"devices": device_db.get_devices_view()})


@app.route("/api/meta")
def api_meta():
    try:
        from identity import CANONICAL_TYPES
        types = list(CANONICAL_TYPES)
    except ImportError:
        types = CANONICAL_TYPES_FALLBACK
    return jsonify({"types": types, "os_values": OS_VALUES})


@app.route("/api/devices/<mac>/rename", methods=["POST"])
def api_rename(mac):
    data = request.get_json(force=True)
    name = data.get("name", "").strip()
    device_db.rename_device(mac, name)
    return jsonify({"ok": True})


@app.route("/api/devices/<mac>/update", methods=["POST"])
def api_update(mac):
    data = request.get_json(force=True) or {}
    try:
        from identity import CANONICAL_TYPES
        canonical_types = set(CANONICAL_TYPES)
    except ImportError:
        canonical_types = set(CANONICAL_TYPES_FALLBACK)

    name = data.get("name")
    dtype = data.get("type")
    owner = data.get("owner")

    if dtype is not None and dtype != "" and dtype not in canonical_types:
        return jsonify({"ok": False, "error": "invalid type"}), 400

    if name is not None:
        name = name.strip()
    if owner is not None:
        owner = owner.strip()

    device_db.update_device_user_fields(mac, name=name, dtype=dtype, owner=owner)
    return jsonify({"ok": True})


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        if "sound_enabled" in data:
            device_db.set_setting("sound_enabled", "1" if data["sound_enabled"] else "0")
    return jsonify({"sound_enabled": device_db.get_setting("sound_enabled", "1") == "1"})


@app.route("/api/activity")
def api_activity():
    limit = request.args.get("limit", 100, type=int)
    logs = device_db.get_activity_log(limit)
    return jsonify(logs)


@app.route("/api/devices/<mac>/fingerprint")
def api_fingerprint(mac):
    device = device_db.get_device(mac)
    if not device:
        return jsonify({"status": "not_found"}), 404
    fp_data = device.get("fingerprint_data", "")
    if fp_data:
        try:
            return jsonify({"status": "ok", "data": json.loads(fp_data),
                            "manufacturer": device.get("manufacturer", "Unknown"),
                            "device_type": device.get("device_type", "Unknown")})
        except json.JSONDecodeError:
            pass
    return jsonify({"status": "not_probed",
                    "manufacturer": device.get("manufacturer", "Unknown"),
                    "device_type": device.get("device_type", "Unknown")})


@app.route("/api/devices/<mac>/reprobe", methods=["POST"])
def api_reprobe(mac):
    device = device_db.get_device(mac)
    if not device:
        return jsonify({"ok": False, "error": "not found"}), 404
    device_db.clear_last_probed(mac)
    fingerprint.queue_probe(mac, device.get("ip", ""))
    return jsonify({"ok": True})

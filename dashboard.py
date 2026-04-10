from flask import Flask, render_template, jsonify, request
import json
import device_db
import fingerprint

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    active = device_db.get_active_devices()
    inactive = device_db.get_inactive_devices()
    return jsonify({"active": active, "inactive": inactive})


@app.route("/api/devices/<mac>/rename", methods=["POST"])
def api_rename(mac):
    data = request.get_json(force=True)
    name = data.get("name", "").strip()
    device_db.rename_device(mac, name)
    return jsonify({"ok": True})


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

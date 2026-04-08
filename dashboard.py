from flask import Flask, render_template, jsonify, request
import device_db

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

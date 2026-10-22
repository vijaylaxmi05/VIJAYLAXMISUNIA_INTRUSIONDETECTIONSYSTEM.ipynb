"""
Flask web dashboard for the NIDS.
"""

from flask import Flask, render_template, jsonify
from nids import alert_store
import nids as _nids_pkg

app = Flask(__name__, template_folder="templates")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    return jsonify(alert_store.get_all())


@app.route("/api/alerts/clear", methods=["POST"])
def api_clear():
    alert_store.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/status")
def api_status():
    return jsonify({"running": _nids_pkg.sniffer_running})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    _nids_pkg.sniffer_running = False
    return jsonify({"status": "stopped"})


@app.route("/api/resume", methods=["POST"])
def api_resume():
    _nids_pkg.sniffer_running = True
    return jsonify({"status": "running"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

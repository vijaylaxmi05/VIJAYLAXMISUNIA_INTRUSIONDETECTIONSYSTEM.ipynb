"""
In-memory alert store — thread-safe list of alert dictionaries.
"""

import threading
from datetime import datetime


class AlertStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._alerts = []

    def add(self, alert_type: str, src_ip: str, dst_ip: str, detail: str = ""):
        alert = {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "type": alert_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "detail": detail,
        }
        with self._lock:
            self._alerts.append(alert)
        print(f"[ALERT] {alert['timestamp']} | {alert_type} | {src_ip} -> {dst_ip} | {detail}")
        return alert

    def get_all(self):
        with self._lock:
            return list(self._alerts)

    def clear(self):
        with self._lock:
            self._alerts.clear()

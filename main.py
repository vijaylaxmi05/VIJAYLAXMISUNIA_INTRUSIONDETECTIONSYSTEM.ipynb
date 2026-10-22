"""
Main entry point — starts the sniffer in a background thread
and launches the Flask dashboard.
"""

import threading
import argparse
import sys
import os

# Ensure project root is on sys.path so 'nids' and 'dashboard' are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nids import sniffer
from dashboard.app import app


def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System")
    parser.add_argument(
        "-i", "--interface",
        default="Wi-Fi",
        help="Network interface to sniff (default: Wi-Fi). Ignored in simulate mode.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Dashboard port (default: 5000)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        default=False,
        help="Run in simulation mode — generates realistic fake traffic "
             "(no Npcap / root required).",
    )
    args = parser.parse_args()

    # Start packet sniffer / simulator in a daemon thread
    sniff_thread = threading.Thread(
        target=sniffer.start,
        kwargs={"interface": args.interface, "simulate": args.simulate},
        daemon=True,
        name="sniffer",
    )
    sniff_thread.start()

    mode = "SIMULATION" if args.simulate else f"LIVE ({args.interface})"
    print(f"[*] Mode     : {mode}")
    print(f"[*] Dashboard: http://127.0.0.1:{args.port}")

    # Run Flask (blocking)
    app.run(host="0.0.0.0", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

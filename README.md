# 🛡 Network Intrusion Detection System (NIDS)

A Python-based **Network Intrusion Detection System** built for a cybersecurity bootcamp.  
Uses **Scapy** for live packet sniffing and **Flask** for a real-time web dashboard.  
Includes a built-in **simulation mode** — no special drivers required to see live data.

---

## Features

| Detection Rule | Trigger |
|---|---|
| **SYN Flood** | > 100 SYN packets from one IP within 5 s |
| **Port Scan** | > 15 distinct destination ports from one IP within 5 s |
| **ICMP Flood** | > 50 ICMP packets from one IP within 5 s |
| **Null Scan** | TCP packet with all flags = 0 |
| **Xmas Scan** | TCP packet with FIN + PSH + URG flags set |

### Dashboard
- Live alert table (newest first) with colour-coded attack badges
- Summary stat cards — total alerts, per-attack-type counts
- **⏹ Stop / ▶ Resume** button — pause/resume the sniffer without restarting
- **🗑 Clear** button — wipe the alert list
- Auto-refresh every 5 s (pauses automatically when sniffer is stopped)

---

## Project Structure

```
nids_project/
├── main.py                  # Entry point — sniffer thread + Flask
├── requirements.txt
├── README.md
├── nids/
│   ├── __init__.py          # Shared AlertStore instance + sniffer_running flag
│   ├── alert_store.py       # Thread-safe in-memory alert list
│   ├── detector.py          # Detection rules engine (5 rules)
│   └── sniffer.py           # Live capture (Scapy) + simulation mode
└── dashboard/
    ├── __init__.py
    ├── app.py               # Flask REST API + routes
    └── templates/
        └── index.html       # Dark-theme live dashboard
```

---

## Quick Start

### Option A — Simulation mode (no drivers needed) ✅ Recommended for demos

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run
python main.py --simulate
```

Open **http://localhost:5000** — alerts start appearing within seconds.

---

### Option B — Live capture (real network traffic)

**Windows (run terminal as Administrator)**

1. Install [Npcap](https://npcap.com/#download)
2. Run:
```bash
pip install -r requirements.txt
python main.py -i "Wi-Fi"
```

**Linux / macOS**

```bash
pip install -r requirements.txt
sudo python main.py -i eth0
```

---

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `-i / --interface` | `Wi-Fi` | Network interface for live capture |
| `--port` | `5000` | Flask dashboard port |
| `--simulate` | off | Generate synthetic attack traffic (no Npcap needed) |

---

## REST API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/alerts` | Returns all alerts as JSON |
| `POST` | `/api/alerts/clear` | Clears all alerts |
| `GET` | `/api/status` | Returns `{"running": true/false}` |
| `POST` | `/api/stop` | Pauses the sniffer |
| `POST` | `/api/resume` | Resumes the sniffer |

---

## How It Works

```
                        ┌─────────────────────────────────┐
                        │  Sniffer thread (daemon)         │
  Network packets  ───► │  sniffer.py  ──►  detector.py   │
  (or simulation)       │                       │          │
                        └───────────────────────┼─────────┘
                                                ▼
                                        AlertStore (shared)
                                                │
                              Flask /api/alerts ◄─── Dashboard
                              polls every 5 s         (browser)
```

The sniffer and Flask run in **separate threads** sharing a single `AlertStore` instance protected by a `threading.Lock`. The `sniffer_running` flag (also on the `nids` package) lets the dashboard Stop/Resume the sniffer without restarting the process.

---

## Requirements

- Python **3.9+**
- `flask >= 3.0`
- `scapy >= 2.5`
- **Windows live capture**: [Npcap](https://npcap.com/) + run as Administrator
- **Linux/macOS live capture**: `sudo` / raw socket permissions


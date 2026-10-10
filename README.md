# Network Intrusion Detection and Threat Monitoring System

A beginner-friendly Computer Networks mini-project. The application monitors
network traffic, detects predefined suspicious patterns, stores the resulting
security events in SQLite, and displays them on a minimal web dashboard.

> Detections produced by this tool are *possible* suspicious activity, not
> proof of an attack. Only monitor networks you own or are explicitly
> authorized to monitor. Never generate attack traffic or scan external
> networks.

## Status

Stages 0-9 are complete: project scaffolding, configuration loading and
validation, shared data models, Scapy-to-`PacketRecord` parsing, synthetic
record helpers, the SQLite storage layer, the five detection rules, alert
deduplication, the detection engine, a Scapy capture wrapper, a read-only Flask
JSON API (`nids/api.py`), a plain HTML/CSS/JavaScript dashboard
(`nids/web/`), and the `run.py` entry point.

Live packet capture is disabled by default and never starts automatically —
neither on import, app creation, nor when running `run.py`.

## Architecture

```
run.py                 entry point (dashboard + API)
config.json            all thresholds and the known-device inventory
nids/config.py         load/validate config, apply defaults
nids/models.py         PacketRecord / Alert / Device dataclasses
nids/parser.py         Scapy packet -> PacketRecord
nids/synthetic.py      fake PacketRecords for tests/demo
nids/detectors/        one file per detection rule
nids/dedup.py          suppress duplicate ongoing alerts
nids/engine.py         run detectors over records, collect alerts
nids/db.py             SQLite schema + read/write helpers
nids/capture.py        Scapy sniff() wrapper (only place using live capture)
nids/api.py            read-only Flask JSON API (create_app)
nids/web/              dashboard blueprint, templates, static
tests/                 pytest tests
```

Data flows one way: capture or synthetic records -> parser -> engine (detectors
+ dedup) -> SQLite -> API -> dashboard. The API and dashboard are read-only;
they never trigger detection or capture.

## Detection modules

1. Possible port scanning — many unique destination ports from one source in a time window.
2. Traffic anomaly — packet rate above a configured threshold.
3. ARP anomaly — an observed IPv4-to-MAC mapping changes unexpectedly.
4. Unknown device — a device not present in the configured inventory.
5. Repeated connection attempts — repeated TCP attempts to the same service above a threshold.

Detections are *possible* suspicious activity, never proof of an attack.

## Tech stack

- Python 3.12
- Scapy — packet capture and parsing
- Flask — backend and dashboard
- SQLite (standard-library `sqlite3`) — persistence
- Plain HTML, minimal CSS, vanilla JavaScript — frontend

## Setup (macOS)

Python 3.12 is required. If `python3.12` is not installed, install it with
Homebrew:

```bash
brew install python@3.12
```

Then, from the project root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Running the dashboard

From the project root, start the local server (bound to `127.0.0.1` only):

```bash
.venv/bin/python run.py
```

Then open <http://127.0.0.1:5000/> in your browser. Press `Ctrl+C` to stop.
The first run creates `nids.db` in the project root. `run.py` does not start
packet capture, so the dashboard shows whatever is already stored (initially
nothing).

## API endpoints

All endpoints are read-only and return JSON.

| Endpoint | Response |
| --- | --- |
| `GET /api/health` | `{"status": "ok"}` |
| `GET /api/alerts` | `{"count": N, "alerts": [<alert>, ...]}` (newest first) |
| `GET /api/devices` | `{"count": N, "devices": [<device>, ...]}` |
| `GET /api/stats` | `{"total_alerts": N, "alerts_by_severity": {...}, "tracked_devices": N}` |

`GET /api/alerts` accepts an optional `limit` query parameter (whole number,
1–500; default 50). Invalid limits return `400` with `{"error": "..."}`.
Unknown routes return a JSON `404`, and unexpected failures return a generic
JSON `500` without stack traces.

An alert object contains: `alert_type`, `severity`, `message`, `timestamp`
(Unix epoch seconds), `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`.
A device object contains: `ip`, `mac`, `hostname`, `label`, `known`,
`first_seen`, `last_seen`.

## Configuration

All thresholds live in `config.json`; never edit thresholds anywhere else.

- `capture` — `enabled`, `interface`, `packet_limit`, `timeout_seconds`
  (capture is `false` by default).
- `port_scan` — `enabled`, `window_seconds`, `unique_ports_threshold`.
- `traffic_anomaly` — `enabled`, `window_seconds`, `packet_rate_threshold`.
- `arp_anomaly` — `enabled`.
- `unknown_device` — `enabled`, plus the `known_devices` inventory.
- `repeated_connections` — `enabled`, `window_seconds`, `attempts_threshold`.
- `dedup` — `window_seconds` (how long an ongoing event stays quiet).
- `known_devices` — a list of `{"ip": "...", "mac": "...", "label": "..."}`
  entries (`mac` and `label` optional) describing trusted devices.

Missing sections fall back to the defaults in `nids/config.py`; invalid files
or values raise a clear `ConfigError`.

## Testing

Run the full test suite (uses temporary SQLite files; never touches the real
`nids.db` and never captures packets):

```bash
.venv/bin/python -m pytest -q
```

The tests build the pipeline from synthetic packet records
(`nids/synthetic.py`), so they are deterministic and need no privileges. To
experiment or preview the dashboard with data, write alerts into a temporary
database and point the app at it, for example:

```bash
.venv/bin/python -c "from nids import db; from nids.models import Alert; db.init_db('demo.db'); db.insert_alert(Alert(alert_type='port_scan', severity='high', message='demo alert', timestamp=1.0, src_ip='10.0.0.1', dst_ip='10.0.0.2', src_port=40000, dst_port=80, protocol='TCP'), 'demo.db')"
.venv/bin/python -c "from run import build_app; build_app(db_path='demo.db').run(host='127.0.0.1', port=5000)"
```

## Live packet capture

Live capture is optional and off by default. `nids/capture.py` is the only
place that uses Scapy's `sniff`, and it only runs when explicitly started. On
macOS, live capture usually needs access to `/dev/bpf*` (often root, e.g.
`sudo`), and normal setups cannot use monitor mode, so you will typically only
observe traffic to and from your own machine. Never run capture with elevated
privileges automatically. Prefer the synthetic workflow for development and
demonstrations. See `nids/capture.py` for the documented notes; a future stage
may add optional capture controls.

## Notes and limitations

- Detections are *possible* suspicious activity, never proof of an attack.
- The dashboard binds to `127.0.0.1` only and must never be exposed publicly.
- No authentication is implemented; run it locally only.
- The API is read-only: there are no endpoints to start/stop capture or write
  data, and `run.py` does not start capture.
- The dashboard shows the most recent alerts (default limit) and auto-refreshes
  every 10 seconds; there is no pagination or filtering yet.

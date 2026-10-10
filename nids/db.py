"""Thin SQLite layer for storing alerts and devices.

All SQL lives here so the rest of the project never talks to the database
directly. Every public function accepts an optional ``db_path`` (defaulting to
``nids.db`` next to the project root) so tests can point at a temporary file.
Timestamps are stored as floating-point Unix epoch seconds, matching
:mod:`nids.models`.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .models import Alert, Device

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "nids.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'medium',
    message TEXT NOT NULL DEFAULT '',
    timestamp REAL NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    hostname TEXT,
    label TEXT,
    known INTEGER NOT NULL DEFAULT 0,
    first_seen REAL,
    last_seen REAL
);
"""

_UPSERT_DEVICE = """
INSERT INTO devices (ip, mac, hostname, label, known, first_seen, last_seen)
VALUES (:ip, :mac, :hostname, :label, :known, :first_seen, :last_seen)
ON CONFLICT (ip) DO UPDATE SET
    mac = COALESCE(excluded.mac, devices.mac),
    hostname = COALESCE(excluded.hostname, devices.hostname),
    label = COALESCE(excluded.label, devices.label),
    known = excluded.known,
    first_seen = COALESCE(devices.first_seen, excluded.first_seen),
    last_seen = COALESCE(excluded.last_seen, devices.last_seen)
"""

_ALERT_COLUMNS = (
    "alert_type, severity, message, timestamp, "
    "src_ip, dst_ip, src_port, dst_port, protocol"
)


def init_db(db_path=DEFAULT_DB_PATH):
    """Create the database file and required tables if they do not exist."""
    with _connection(db_path) as connection:
        connection.executescript(SCHEMA)


def insert_alert(alert, db_path=DEFAULT_DB_PATH):
    """Insert an :class:`~nids.models.Alert` and return its new row id."""
    with _connection(db_path) as connection:
        cursor = connection.execute(
            f"INSERT INTO alerts ({_ALERT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.alert_type,
                alert.severity,
                alert.message,
                alert.timestamp,
                alert.src_ip,
                alert.dst_ip,
                alert.src_port,
                alert.dst_port,
                alert.protocol,
            ),
        )
        return cursor.lastrowid


def insert_device(device, db_path=DEFAULT_DB_PATH):
    """Insert a device, or update it if the IP already exists.

    The original ``first_seen`` is preserved; missing optional values on the
    new record do not overwrite values already stored.
    """
    with _connection(db_path) as connection:
        connection.execute(
            _UPSERT_DEVICE,
            {
                "ip": device.ip,
                "mac": device.mac,
                "hostname": device.hostname,
                "label": device.label,
                "known": int(bool(device.known)),
                "first_seen": device.first_seen,
                "last_seen": device.last_seen,
            },
        )


def get_alerts(limit=100, db_path=DEFAULT_DB_PATH):
    """Return the newest alerts first, up to ``limit``, as ``Alert`` objects."""
    with _connection(db_path) as connection:
        rows = connection.execute(
            f"SELECT {_ALERT_COLUMNS} FROM alerts ORDER BY timestamp DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_alert(row) for row in rows]


def get_devices(db_path=DEFAULT_DB_PATH):
    """Return all tracked devices, ordered by IP address, as ``Device`` objects."""
    with _connection(db_path) as connection:
        rows = connection.execute(
            "SELECT ip, mac, hostname, label, known, first_seen, last_seen "
            "FROM devices ORDER BY ip"
        ).fetchall()
    return [_row_to_device(row) for row in rows]


def get_stats(db_path=DEFAULT_DB_PATH):
    """Return simple dashboard statistics.

    Keys: ``total_alerts``, ``alerts_by_severity`` (a dict) and
    ``tracked_devices``.
    """
    with _connection(db_path) as connection:
        total_alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        severity_rows = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
        ).fetchall()
        tracked_devices = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    by_severity = {row["severity"]: row["count"] for row in severity_rows}
    return {
        "total_alerts": total_alerts,
        "alerts_by_severity": by_severity,
        "tracked_devices": tracked_devices,
    }


@contextmanager
def _connection(db_path):
    path = Path(db_path)
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _row_to_alert(row):
    return Alert(
        alert_type=row["alert_type"],
        severity=row["severity"],
        message=row["message"],
        timestamp=row["timestamp"],
        src_ip=row["src_ip"],
        dst_ip=row["dst_ip"],
        src_port=row["src_port"],
        dst_port=row["dst_port"],
        protocol=row["protocol"],
    )


def _row_to_device(row):
    return Device(
        ip=row["ip"],
        mac=row["mac"],
        hostname=row["hostname"],
        label=row["label"],
        known=bool(row["known"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
    )

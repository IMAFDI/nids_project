"""
NIDS — SQLite Database Module
Persists all intrusion events, anomaly detections, and system events.
"""

import os
import sqlite3
import logging
import threading
from datetime import datetime

logger = logging.getLogger('NIDS.Database')

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'nids.db')

# Thread-local storage for connections (SQLite is not thread-safe with shared connections)
_local = threading.local()


def get_connection(db_path=None):
    """Get a thread-local SQLite connection."""
    path = db_path or DB_PATH
    if not hasattr(_local, 'conn') or _local.conn is None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _local.conn = sqlite3.connect(path, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")  # Better concurrency
    return _local.conn


def init_db(db_path=None):
    """Initialise the database schema (creates tables if they don't exist)."""
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS intrusion_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            event_type      TEXT    NOT NULL,   -- 'signature' | 'anomaly'
            severity        TEXT    NOT NULL,   -- LOW | MEDIUM | HIGH | CRITICAL
            src_ip          TEXT,
            dst_ip          TEXT,
            protocol        TEXT,
            src_port        INTEGER,
            dst_port        INTEGER,
            description     TEXT,
            rule_id         INTEGER,
            packet_length   INTEGER,
            tcp_flags       INTEGER,
            ttl             INTEGER,
            count           INTEGER,
            threshold       INTEGER,
            raw_message     TEXT
        );

        CREATE TABLE IF NOT EXISTS system_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            level       TEXT NOT NULL,
            message     TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_intrusion_timestamp
            ON intrusion_events (timestamp);
        CREATE INDEX IF NOT EXISTS idx_intrusion_severity
            ON intrusion_events (severity);
        CREATE INDEX IF NOT EXISTS idx_intrusion_src_ip
            ON intrusion_events (src_ip);
    """)
    conn.commit()
    logger.info(f"Database initialised at '{db_path or DB_PATH}'.")


def log_intrusion_event(event_type, severity, message, details=None, db_path=None):
    """
    Persist an intrusion event to the database.

    Args:
        event_type (str): 'signature' or 'anomaly'
        severity   (str): LOW | MEDIUM | HIGH | CRITICAL
        message    (str): Human-readable description
        details   (dict): Optional dict with src_ip, dst_ip, protocol, etc.
        db_path    (str): Override DB path (optional)
    """
    conn = get_connection(db_path)
    details = details or {}
    try:
        conn.execute("""
            INSERT INTO intrusion_events
                (timestamp, event_type, severity, src_ip, dst_ip, protocol,
                 src_port, dst_port, description, rule_id, packet_length,
                 tcp_flags, ttl, count, threshold, raw_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            event_type,
            severity,
            details.get('src_ip'),
            details.get('dst_ip'),
            str(details.get('protocol', '')),
            details.get('src_port'),
            details.get('dst_port'),
            details.get('description', message),
            details.get('rule_id'),
            details.get('packet_length'),
            details.get('tcp_flags'),
            details.get('ttl'),
            details.get('count'),
            details.get('threshold'),
            message,
        ))
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to write intrusion event to DB: {e}")


def log_system_event(level, message, db_path=None):
    """Persist a system-level log event."""
    conn = get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO system_events (timestamp, level, message) VALUES (?, ?, ?)",
            (datetime.utcnow().isoformat(), level, message)
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to write system event to DB: {e}")


def get_recent_events(limit=100, severity=None, db_path=None):
    """Fetch recent intrusion events, optionally filtered by severity."""
    conn = get_connection(db_path)
    if severity:
        rows = conn.execute(
            "SELECT * FROM intrusion_events WHERE severity=? ORDER BY timestamp DESC LIMIT ?",
            (severity, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM intrusion_events ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats(db_path=None):
    """Return summary statistics for the dashboard."""
    conn = get_connection(db_path)
    stats = {}

    stats['total'] = conn.execute(
        "SELECT COUNT(*) FROM intrusion_events"
    ).fetchone()[0]

    for sev in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        stats[sev.lower()] = conn.execute(
            "SELECT COUNT(*) FROM intrusion_events WHERE severity=?", (sev,)
        ).fetchone()[0]

    stats['by_type'] = {
        row[0]: row[1]
        for row in conn.execute(
            "SELECT event_type, COUNT(*) FROM intrusion_events GROUP BY event_type"
        ).fetchall()
    }

    stats['top_sources'] = [
        {'src_ip': row[0], 'count': row[1]}
        for row in conn.execute(
            """SELECT src_ip, COUNT(*) as cnt FROM intrusion_events
               WHERE src_ip IS NOT NULL
               GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"""
        ).fetchall()
    ]

    stats['recent_24h'] = conn.execute(
        """SELECT COUNT(*) FROM intrusion_events
           WHERE timestamp >= datetime('now', '-24 hours')"""
    ).fetchone()[0]

    stats['timeline'] = [
        {'hour': row[0], 'count': row[1]}
        for row in conn.execute(
            """SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                      COUNT(*) as cnt
               FROM intrusion_events
               WHERE timestamp >= datetime('now', '-24 hours')
               GROUP BY hour ORDER BY hour"""
        ).fetchall()
    ]

    return stats

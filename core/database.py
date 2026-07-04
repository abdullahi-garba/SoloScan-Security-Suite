"""
core/database.py

Lightweight SQLite persistence for SoloScan -- the equivalent of Metasploit's
native database integration, adapted for a tool that has to run standalone on
Windows, Linux, AND Android (so a real Postgres server isn't practical).

Stores: discovered hosts, open ports, vulnerabilities, harvested credentials,
and OSINT findings, all timestamped, so a competition round's findings persist
across scans instead of living only in ephemeral PDF/CSV exports.

Every public function opens its own short-lived connection and is guarded by a
module-level lock, since multiple GUI background threads (scan, OSINT, etc.)
may write concurrently. This trades a little performance for correctness,
which is the right call for this app's scan-volume.
"""

import sqlite3
import json
import os
import threading
from datetime import datetime

DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "soloscan.db")
_lock = threading.Lock()


def _get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates all tables if they don't already exist. Safe to call every app start."""
    with _lock:
        conn = _get_connection()
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            mac TEXT,
            hostname TEXT,
            os_guess TEXT,
            first_seen TEXT,
            last_seen TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            status TEXT,
            service TEXT,
            banner TEXT,
            discovered_at TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            source TEXT,
            severity TEXT,
            description TEXT,
            discovered_at TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            service TEXT,
            username TEXT,
            password TEXT,
            discovered_at TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS osint_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            category TEXT,
            details TEXT,
            discovered_at TEXT
        )""")
        conn.commit()
        conn.close()


def _now():
    return datetime.now().isoformat(timespec="seconds")


# ----------------------------------------------------------------------
# WRITES
# ----------------------------------------------------------------------

def upsert_host(ip, mac=None, hostname=None, os_guess=None):
    """Inserts a new host, or updates last_seen (and any newly-known fields) on an existing one."""
    now = _now()
    with _lock:
        conn = _get_connection()
        cur = conn.cursor()
        row = cur.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
        if row:
            updates, params = ["last_seen = ?"], [now]
            if mac: updates.append("mac = ?"); params.append(mac)
            if hostname: updates.append("hostname = ?"); params.append(hostname)
            if os_guess: updates.append("os_guess = ?"); params.append(os_guess)
            params.append(ip)
            cur.execute(f"UPDATE hosts SET {', '.join(updates)} WHERE ip = ?", params)
        else:
            cur.execute(
                "INSERT INTO hosts (ip, mac, hostname, os_guess, first_seen, last_seen) VALUES (?,?,?,?,?,?)",
                (ip, mac, hostname, os_guess, now, now)
            )
        conn.commit()
        conn.close()


def add_port(host_ip, port, status, service, banner):
    with _lock:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO ports (host_ip, port, status, service, banner, discovered_at) VALUES (?,?,?,?,?,?)",
            (host_ip, port, status, service, banner, _now())
        )
        conn.commit()
        conn.close()


def add_vulnerability(target, source, severity, description):
    with _lock:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO vulnerabilities (target, source, severity, description, discovered_at) VALUES (?,?,?,?,?)",
            (target, source, severity, description, _now())
        )
        conn.commit()
        conn.close()


def add_credential(target, service, username, password):
    with _lock:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO credentials (target, service, username, password, discovered_at) VALUES (?,?,?,?,?)",
            (target, service, username, password, _now())
        )
        conn.commit()
        conn.close()


def add_osint_finding(target, category, details):
    if not isinstance(details, str):
        details = json.dumps(details, default=str)
    with _lock:
        conn = _get_connection()
        conn.execute(
            "INSERT INTO osint_findings (target, category, details, discovered_at) VALUES (?,?,?,?)",
            (target, category, details, _now())
        )
        conn.commit()
        conn.close()


# ----------------------------------------------------------------------
# READS
# ----------------------------------------------------------------------

def get_hosts():
    with _lock:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM hosts ORDER BY last_seen DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_ports(host_ip=None, limit=300):
    with _lock:
        conn = _get_connection()
        if host_ip:
            rows = conn.execute(
                "SELECT * FROM ports WHERE host_ip = ? ORDER BY discovered_at DESC LIMIT ?", (host_ip, limit)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM ports ORDER BY discovered_at DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_vulnerabilities(limit=300):
    with _lock:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM vulnerabilities ORDER BY discovered_at DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_credentials(limit=300):
    with _lock:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM credentials ORDER BY discovered_at DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def get_osint_findings(target=None, limit=300):
    with _lock:
        conn = _get_connection()
        if target:
            rows = conn.execute(
                "SELECT * FROM osint_findings WHERE target = ? ORDER BY discovered_at DESC LIMIT ?", (target, limit)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM osint_findings ORDER BY discovered_at DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def search_all(term):
    """Simple cross-table substring search, used by the GUI search box and the 'db search' command."""
    like = f"%{term}%"
    with _lock:
        conn = _get_connection()
        results = {
            "hosts": [dict(r) for r in conn.execute(
                "SELECT * FROM hosts WHERE ip LIKE ? OR hostname LIKE ? OR mac LIKE ? OR os_guess LIKE ?",
                (like, like, like, like)).fetchall()],
            "ports": [dict(r) for r in conn.execute(
                "SELECT * FROM ports WHERE host_ip LIKE ? OR service LIKE ? OR banner LIKE ?",
                (like, like, like)).fetchall()],
            "vulnerabilities": [dict(r) for r in conn.execute(
                "SELECT * FROM vulnerabilities WHERE target LIKE ? OR description LIKE ? OR source LIKE ?",
                (like, like, like)).fetchall()],
            "credentials": [dict(r) for r in conn.execute(
                "SELECT * FROM credentials WHERE target LIKE ? OR service LIKE ?", (like, like)).fetchall()],
        }
        conn.close()
        return results


def get_stats():
    """Quick counts for each table, used for an at-a-glance summary in the GUI."""
    with _lock:
        conn = _get_connection()
        stats = {}
        for table in ("hosts", "ports", "vulnerabilities", "credentials", "osint_findings"):
            stats[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        conn.close()
        return stats


def clear_all():
    """Wipes every table -- e.g. to start a fresh competition round with a clean slate."""
    with _lock:
        conn = _get_connection()
        for table in ("hosts", "ports", "vulnerabilities", "credentials", "osint_findings"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()
"""SQLite persistence: sites, checks, incidents, alert state, VPS stats and WHOIS cache.

All timestamps are UTC epoch seconds (REAL). A fresh connection is opened per
operation so the scheduler thread and dashboard threads can share one Storage.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    url         TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS checks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id      INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    ts           REAL NOT NULL,
    status       TEXT NOT NULL,            -- up | warning | down
    http_status  INTEGER,
    response_ms  INTEGER,
    cause_code   TEXT,
    summary      TEXT,
    details      TEXT                      -- JSON
);
CREATE INDEX IF NOT EXISTS idx_checks_site_ts ON checks(site_id, ts);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);

CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id      INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    started_at   REAL NOT NULL,
    ended_at     REAL,
    cause_code   TEXT,
    cause        TEXT,
    details      TEXT                      -- JSON
);
CREATE INDEX IF NOT EXISTS idx_incidents_site ON incidents(site_id, started_at);

CREATE TABLE IF NOT EXISTS site_state (
    site_id              INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    first_failure_at     REAL,
    incident_id          INTEGER,
    last_alert_at        REAL,
    last_alert_cause     TEXT
);

CREATE TABLE IF NOT EXISTS warning_alerts (
    key           TEXT NOT NULL,           -- site name or "VPS"
    code          TEXT NOT NULL,
    first_seen_at REAL NOT NULL,
    seen_count    INTEGER NOT NULL DEFAULT 1,
    last_sent_at  REAL,
    PRIMARY KEY (key, code)
);

CREATE TABLE IF NOT EXISTS vps_stats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    reachable   INTEGER NOT NULL,
    ports       TEXT,                      -- JSON {port: bool}
    ram_percent REAL,
    cpu_load    REAL,
    cpu_cores   INTEGER,
    disk_percent REAL,
    oom_kills   INTEGER,
    services    TEXT,                      -- JSON
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_vps_ts ON vps_stats(ts);

CREATE TABLE IF NOT EXISTS kv (
    key         TEXT PRIMARY KEY,          -- small latest-value records, e.g. "server_status"
    value       TEXT NOT NULL,             -- JSON
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS whois_cache (
    domain      TEXT PRIMARY KEY,
    expires_at  REAL,
    checked_at  REAL NOT NULL,
    error       TEXT
);
"""


@dataclass
class SiteState:
    """Per-site alerting state that must survive restarts."""

    site_id: int
    consecutive_failures: int = 0
    first_failure_at: float | None = None
    incident_id: int | None = None
    last_alert_at: float | None = None
    last_alert_cause: str | None = None
    escalated_at: float | None = None  # when the current incident was escalated (once per incident)
    # Closed incident whose RECOVERED message has not been delivered yet (retried every cycle):
    recovery_pending: int | None = None             # ... to the normal alert recipients
    recovery_pending_escalation: int | None = None  # ... to the escalation contacts


# Columns added after the first release: (table, column, SQL type). Applied on startup.
MIGRATIONS = [
    ("site_state", "escalated_at", "REAL"),
    ("site_state", "recovery_pending", "INTEGER"),
    ("site_state", "recovery_pending_escalation", "INTEGER"),
    ("incidents", "acknowledged_at", "REAL"),
    ("incidents", "acknowledged_by", "TEXT"),
]


class Storage:
    """Thin data-access layer over a single SQLite file."""

    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._memory_conn: sqlite3.Connection | None = None
        if path == ":memory:":  # tests: keep one shared connection alive
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row
        with self._conn() as conn:
            if path != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            for table, column, sql_type in MIGRATIONS:  # upgrade databases created by older versions
                existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        if self._memory_conn is not None:
            with self._write_lock:
                yield self._memory_conn
                self._memory_conn.commit()
            return
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")  # WAL mode: crash-safe, far fewer disk syncs
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ sites
    def sync_sites(self, sites: list[tuple[str, str]]) -> dict[str, int]:
        """Insert/update sites from config. Returns {name: id}. History of removed sites is kept."""
        now = time.time()
        with self._conn() as conn:
            for name, url in sites:
                conn.execute(
                    "INSERT INTO sites(name, url, created_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET url=excluded.url", (name, url, now))
            rows = conn.execute("SELECT id, name FROM sites").fetchall()
        return {r["name"]: r["id"] for r in rows}

    # ------------------------------------------------------------------ checks
    def record_check(self, site_id: int, ts: float, status: str, http_status: int | None,
                     response_ms: int | None, cause_code: str | None, summary: str,
                     details: dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO checks(site_id, ts, status, http_status, response_ms, cause_code, summary, details)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (site_id, ts, status, http_status, response_ms, cause_code, summary,
                 json.dumps(details, default=str)))

    def record_checks(self, rows: list[tuple[int, float, str, int | None, int | None, str | None, str,
                                            dict[str, Any]]]) -> None:
        """Insert many checks in ONE transaction (a cycle's results; much faster than one commit each)."""
        if not rows:
            return
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO checks(site_id, ts, status, http_status, response_ms, cause_code, summary, details)"
                " VALUES (?,?,?,?,?,?,?,?)",
                [(*r[:7], json.dumps(r[7], default=str)) for r in rows])

    def latest_checks(self) -> list[dict[str, Any]]:
        """Most recent check per site (sites without checks are included with NULLs)."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT s.id AS site_id, s.name, s.url, c.ts, c.status, c.http_status, c.response_ms,
                       c.cause_code, c.summary, c.details
                FROM sites s
                LEFT JOIN checks c ON c.id = (SELECT id FROM checks WHERE site_id = s.id ORDER BY ts DESC LIMIT 1)
                ORDER BY s.name""").fetchall()
        return [_row(r, json_fields=("details",)) for r in rows]

    def response_history(self, since: float) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT s.name, c.ts, c.status, c.response_ms FROM checks c JOIN sites s ON s.id = c.site_id
                WHERE c.ts >= ? ORDER BY c.ts""", (since,)).fetchall()
        return [dict(r) for r in rows]

    def site_summary(self, since: float, until: float | None = None) -> dict[int, dict[str, Any]]:
        """Uptime % (up+warning / total) and average response time per site in [since, until)."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT site_id, COUNT(*) AS total,
                       SUM(CASE WHEN status != 'down' THEN 1 ELSE 0 END) AS ok,
                       AVG(CASE WHEN status != 'down' THEN response_ms END) AS avg_ms,
                       MAX(response_ms) AS max_ms
                FROM checks WHERE ts >= ? AND ts < ? GROUP BY site_id""",
                (since, until if until is not None else float("inf"))).fetchall()
        out: dict[int, dict[str, Any]] = {}
        for r in rows:
            out[r["site_id"]] = {
                "total": r["total"],
                "uptime_pct": round(100.0 * r["ok"] / r["total"], 2) if r["total"] else None,
                "avg_ms": int(r["avg_ms"]) if r["avg_ms"] is not None else None,
                "max_ms": r["max_ms"],
            }
        return out

    def daily_uptime(self, since: float, utc_offset_seconds: float = 0) -> dict[int, dict[int, float]]:
        """{site_id: {day_number: uptime %}}; day_number = local days since the epoch."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT site_id, CAST((ts + ?) / 86400 AS INTEGER) AS day, COUNT(*) AS total,
                       SUM(CASE WHEN status != 'down' THEN 1 ELSE 0 END) AS ok
                FROM checks WHERE ts >= ? GROUP BY site_id, day""", (utc_offset_seconds, since)).fetchall()
        out: dict[int, dict[int, float]] = {}
        for r in rows:
            out.setdefault(r["site_id"], {})[r["day"]] = round(100.0 * r["ok"] / r["total"], 2)
        return out

    # ------------------------------------------------------------------ incidents
    def incidents_between(self, start: float, end: float) -> list[dict[str, Any]]:
        """Incidents that overlap [start, end), including ones still open."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT i.*, s.name AS site_name FROM incidents i JOIN sites s ON s.id = i.site_id
                WHERE i.started_at < ? AND (i.ended_at IS NULL OR i.ended_at >= ?)
                ORDER BY i.started_at""", (end, start)).fetchall()
        return [_row(r, json_fields=("details",)) for r in rows]

    def open_incident(self, site_id: int, started_at: float, cause_code: str, cause: str,
                      details: dict[str, Any]) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO incidents(site_id, started_at, cause_code, cause, details) VALUES (?,?,?,?,?)",
                (site_id, started_at, cause_code, cause, json.dumps(details, default=str)))
            return int(cur.lastrowid)

    def update_incident_cause(self, incident_id: int, cause_code: str, cause: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE incidents SET cause_code=?, cause=? WHERE id=?", (cause_code, cause, incident_id))

    def acknowledge_incident(self, incident_id: int, by: str, ts: float) -> bool:
        """Mark an incident as being handled. Returns False if it does not exist or was already acked."""
        with self._conn() as conn:
            return conn.execute("UPDATE incidents SET acknowledged_at=?, acknowledged_by=? "
                                "WHERE id=? AND acknowledged_at IS NULL", (ts, by[:80], incident_id)).rowcount == 1

    def open_incident_for(self, site_name: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            r = conn.execute("SELECT i.* FROM incidents i JOIN sites s ON s.id = i.site_id "
                             "WHERE s.name=? AND i.ended_at IS NULL ORDER BY i.started_at DESC LIMIT 1",
                             (site_name,)).fetchone()
        return _row(r, json_fields=("details",)) if r else None

    def close_incident(self, incident_id: int, ended_at: float) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE incidents SET ended_at=? WHERE id=? AND ended_at IS NULL", (ended_at, incident_id))

    def get_incident(self, incident_id: int) -> dict[str, Any] | None:
        with self._conn() as conn:
            r = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return _row(r, json_fields=("details",)) if r else None

    def incidents(self, limit: int = 100, since: float | None = None) -> list[dict[str, Any]]:
        sql = ("SELECT i.*, s.name AS site_name, s.url FROM incidents i JOIN sites s ON s.id = i.site_id")
        params: list[Any] = []
        if since is not None:
            sql += " WHERE i.started_at >= ? OR i.ended_at IS NULL OR i.ended_at >= ?"
            params += [since, since]
        sql += " ORDER BY i.started_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_row(r, json_fields=("details",)) for r in rows]

    # ------------------------------------------------------------------ alert state
    def get_state(self, site_id: int) -> SiteState:
        with self._conn() as conn:
            r = conn.execute("SELECT * FROM site_state WHERE site_id=?", (site_id,)).fetchone()
        return SiteState(**dict(r)) if r else SiteState(site_id=site_id)

    def save_state(self, state: SiteState) -> None:
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO site_state(site_id, consecutive_failures, first_failure_at, incident_id,
                                       last_alert_at, last_alert_cause, escalated_at,
                                       recovery_pending, recovery_pending_escalation)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(site_id) DO UPDATE SET
                    escalated_at=excluded.escalated_at,
                    consecutive_failures=excluded.consecutive_failures,
                    first_failure_at=excluded.first_failure_at,
                    incident_id=excluded.incident_id,
                    last_alert_at=excluded.last_alert_at,
                    last_alert_cause=excluded.last_alert_cause,
                    recovery_pending=excluded.recovery_pending,
                    recovery_pending_escalation=excluded.recovery_pending_escalation""",
                (state.site_id, state.consecutive_failures, state.first_failure_at, state.incident_id,
                 state.last_alert_at, state.last_alert_cause, state.escalated_at,
                 state.recovery_pending, state.recovery_pending_escalation))

    def touch_warning(self, key: str, code: str, ts: float) -> tuple[int, float | None]:
        """Record that a warning is active this cycle. Returns (consecutive sightings, last_sent_at)."""
        with self._conn() as conn:
            conn.execute("INSERT INTO warning_alerts(key, code, first_seen_at, seen_count) VALUES (?,?,?,1) "
                         "ON CONFLICT(key, code) DO UPDATE SET seen_count = seen_count + 1", (key, code, ts))
            r = conn.execute("SELECT seen_count, last_sent_at FROM warning_alerts WHERE key=? AND code=?",
                             (key, code)).fetchone()
        return int(r["seen_count"]), r["last_sent_at"]

    def mark_warning_sent(self, key: str, code: str, ts: float) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE warning_alerts SET last_sent_at=? WHERE key=? AND code=?", (ts, key, code))

    def clear_warnings(self, key: str, keep_codes: set[str]) -> None:
        """Forget warnings that are no longer active so they alert again if they come back."""
        with self._conn() as conn:
            rows = conn.execute("SELECT code FROM warning_alerts WHERE key=?", (key,)).fetchall()
            for r in rows:
                if r["code"] not in keep_codes:
                    conn.execute("DELETE FROM warning_alerts WHERE key=? AND code=?", (key, r["code"]))

    # ------------------------------------------------------------------ VPS stats
    def record_vps(self, ts: float, reachable: bool, ports: dict[int, bool], stats: dict[str, Any] | None,
                   error: str | None) -> None:
        stats = stats or {}
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO vps_stats(ts, reachable, ports, ram_percent, cpu_load, cpu_cores, disk_percent,
                                      oom_kills, services, error) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (ts, int(reachable), json.dumps({str(k): v for k, v in ports.items()}),
                 stats.get("ram_percent"), stats.get("cpu_load"), stats.get("cpu_cores"),
                 stats.get("disk_percent"), stats.get("oom_kills"),
                 json.dumps(stats.get("services") or {}), error))

    def latest_vps(self) -> dict[str, Any] | None:
        with self._conn() as conn:
            r = conn.execute("SELECT * FROM vps_stats ORDER BY ts DESC LIMIT 1").fetchone()
        return _row(r, json_fields=("ports", "services")) if r else None

    def vps_history(self, since: float) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT ts, reachable, ram_percent, cpu_load, cpu_cores, disk_percent "
                                "FROM vps_stats WHERE ts >= ? ORDER BY ts", (since,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ key-value
    def set_kv(self, key: str, value: Any) -> None:
        with self._conn() as conn:
            conn.execute("INSERT INTO kv(key, value, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE "
                         "SET value=excluded.value, updated_at=excluded.updated_at",
                         (key, json.dumps(value, default=str), time.time()))

    def get_kv(self, key: str) -> Any:
        with self._conn() as conn:
            r = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(r["value"]) if r else None

    def delete_kv(self, key: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM kv WHERE key=?", (key,))

    def delete_kv_prefix(self, prefix: str) -> int:
        with self._conn() as conn:
            return conn.execute("DELETE FROM kv WHERE key LIKE ? ESCAPE '\\'",
                                (prefix.replace("%", "\\%").replace("_", "\\_") + "%",)).rowcount

    # ------------------------------------------------------------------ WHOIS cache
    def get_whois(self, domain: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            r = conn.execute("SELECT * FROM whois_cache WHERE domain=?", (domain,)).fetchone()
        return dict(r) if r else None

    def set_whois(self, domain: str, expires_at: float | None, error: str | None) -> None:
        with self._conn() as conn:
            conn.execute("INSERT INTO whois_cache(domain, expires_at, checked_at, error) VALUES (?,?,?,?) "
                         "ON CONFLICT(domain) DO UPDATE SET expires_at=excluded.expires_at, "
                         "checked_at=excluded.checked_at, error=excluded.error",
                         (domain, expires_at, time.time(), error))

    # ------------------------------------------------------------------ retention
    def purge(self, retention_days: int) -> dict[str, int]:
        """Delete check and VPS-stat rows older than ``retention_days``. Incidents are kept."""
        cutoff = time.time() - retention_days * 86400
        with self._conn() as conn:
            checks = conn.execute("DELETE FROM checks WHERE ts < ?", (cutoff,)).rowcount
            vps = conn.execute("DELETE FROM vps_stats WHERE ts < ?", (cutoff,)).rowcount
        return {"checks": checks, "vps_stats": vps}


def _row(r: sqlite3.Row, json_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    d = dict(r)
    for f in json_fields:
        if d.get(f):
            try:
                d[f] = json.loads(d[f])
            except (TypeError, ValueError):
                pass
    return d

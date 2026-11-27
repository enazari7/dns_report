"""Persistent diagnostic history, in SQLite.

WHAT THIS IS NOT
================
**This is not an accounting or billing source and must never be used as one.**

Rows here are keyed by client IP address, and client IPs change: a user gets a
new address from their ISP, another user inherits the old one, and the two are
indistinguishable from here. Traffic totals in this database therefore describe
*an address over a window of time*, not *a person*. Accounting is recorded in a
separate system that knows about accounts; this file knows about addresses.

The retention default is deliberately short for the same reason. Keeping months
of per-address totals would invite exactly the misuse this warning is trying to
prevent, and would not become more accurate with age.

WHAT THIS IS FOR
================
Four things that were previously lost on every restart:

* **events** - service went down, config went stale, the origin-NONE rate
  spiked, the two servers diverged. So you can answer "when did this start?"
* **audit** - who attempted which change, what the guards said, what happened.
* **domain registry** - when each name was first and last seen, and whether it
  went upstream. The dnsdist ring only holds the recent past, so a name's
  apparent first-seen time otherwise walks forward as entries age out.
* **traffic rollups** - per-client and per-SNI byte totals in fixed buckets,
  for the charts. Aggregated on write; individual connections are never stored.

Design notes: one file, WAL mode, no ORM. Writes go through a single lock
because SQLite allows one writer and the pollers are threaded. Every method
tolerates the database being unavailable - a broken history file must never
take the dashboard down with it.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from typing import Any

SCHEMA_VERSION = 1

# Bucket width for traffic rollups. Five minutes keeps a day of history for a
# busy client in a few hundred rows.
BUCKET_SECONDS = 300

DISCLAIMER = (
    "Diagnostic history only. Keyed by IP address, and addresses change hands - "
    "this is not an accounting or billing source."
)

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Detected conditions. `fingerprint` collapses a continuing condition into one
-- open row so a service that is down for an hour is one event, not 240.
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    detail_en   TEXT NOT NULL DEFAULT '',
    detail_fa   TEXT NOT NULL DEFAULT '',
    started_at  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    resolved_at REAL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    notified_at REAL,
    acked_at    REAL
);
CREATE INDEX IF NOT EXISTS events_open
    ON events(resolved_at, fingerprint);
CREATE INDEX IF NOT EXISTS events_time ON events(started_at DESC);

-- Every attempt to change something, successful or not.
CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    actor      TEXT NOT NULL,
    actor_ip   TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    outcome    TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    diff       TEXT NOT NULL DEFAULT '',
    backup     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_time ON audit(ts DESC);

-- One row per hostname ever observed. Survives restarts, unlike the ring.
CREATE TABLE IF NOT EXISTS domain_registry (
    name         TEXT PRIMARY KEY,
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    times_seen   INTEGER NOT NULL DEFAULT 1,
    went_upstream INTEGER NOT NULL DEFAULT 0,
    was_proxied  INTEGER NOT NULL DEFAULT 0,
    last_client  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS domain_last ON domain_registry(last_seen DESC);

-- Aggregated traffic. NOT per-connection: buckets only.
CREATE TABLE IF NOT EXISTS traffic (
    bucket      INTEGER NOT NULL,
    client_ip   TEXT NOT NULL,
    conns       INTEGER NOT NULL DEFAULT 0,
    problems    INTEGER NOT NULL DEFAULT 0,
    from_origin INTEGER NOT NULL DEFAULT 0,
    to_origin   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, client_ip)
);
CREATE INDEX IF NOT EXISTS traffic_bucket ON traffic(bucket DESC);

CREATE TABLE IF NOT EXISTS sni_traffic (
    bucket      INTEGER NOT NULL,
    sni         TEXT NOT NULL,
    conns       INTEGER NOT NULL DEFAULT 0,
    problems    INTEGER NOT NULL DEFAULT 0,
    from_origin INTEGER NOT NULL DEFAULT 0,
    to_origin   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, sni)
);
CREATE INDEX IF NOT EXISTS sni_bucket ON sni_traffic(bucket DESC);
"""


class Store:
    """SQLite-backed history. Every method is failure-tolerant by design."""

    def __init__(self, path: str, retention_days: int = 14,
                 enabled: bool = True):
        self.path = path
        self.retention_days = max(1, int(retention_days))
        self.enabled = bool(enabled) and bool(path)
        self.error: str | None = None
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None
        self._last_prune = 0.0
        if self.enabled:
            self._open()

    # -- lifecycle -----------------------------------------------------
    def _open(self) -> None:
        try:
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, mode=0o700, exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False,
                                   timeout=5.0)
            conn.row_factory = sqlite3.Row
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)))
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("disclaimer", DISCLAIMER))
            conn.commit()
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
            self._conn = conn
            self.error = None
        except (sqlite3.Error, OSError) as exc:
            self.enabled = False
            self.error = f"{self.path}: {exc}"

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    def _exec(self, sql: str, params: tuple = (), commit: bool = True):
        """Run a statement. Returns the cursor, or None if unavailable."""
        if not self.enabled or self._conn is None:
            return None
        try:
            with self._lock:
                cur = self._conn.execute(sql, params)
                if commit:
                    self._conn.commit()
                return cur
        except sqlite3.Error as exc:
            self.error = str(exc)
            return None

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        if not self.enabled or self._conn is None:
            return []
        try:
            with self._lock:
                rows = self._conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error as exc:
            self.error = str(exc)
            return []

    # -- events --------------------------------------------------------
    def open_event(self, fingerprint: str, kind: str, severity: str,
                   subject: str = "", detail: dict | None = None,
                   now: float | None = None) -> None:
        """Record that a condition is currently true.

        Called repeatedly while the condition persists; the open row is updated
        rather than duplicated, so "sniproxy is down" is one event with a
        duration, not one row per poll.
        """
        now = now or time.time()
        d = detail or {}
        cur = self._exec(
            "UPDATE events SET last_seen = ?, occurrences = occurrences + 1, "
            "detail_en = ?, detail_fa = ? "
            "WHERE fingerprint = ? AND resolved_at IS NULL",
            (now, d.get("en", ""), d.get("fa", ""), fingerprint))
        if cur is not None and cur.rowcount:
            return
        self._exec(
            "INSERT INTO events(fingerprint, kind, severity, subject, "
            "detail_en, detail_fa, started_at, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (fingerprint, kind, severity, subject, d.get("en", ""),
             d.get("fa", ""), now, now))

    def close_event(self, fingerprint: str, now: float | None = None) -> bool:
        """Mark a condition as no longer true. Returns True if one was open."""
        cur = self._exec(
            "UPDATE events SET resolved_at = ? "
            "WHERE fingerprint = ? AND resolved_at IS NULL",
            (now or time.time(), fingerprint))
        return bool(cur is not None and cur.rowcount)

    def open_events(self) -> list[dict]:
        return self._query(
            "SELECT * FROM events WHERE resolved_at IS NULL "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' "
            "THEN 1 ELSE 2 END, started_at DESC")

    def recent_events(self, limit: int = 200,
                      since: float | None = None) -> list[dict]:
        if since:
            return self._query(
                "SELECT * FROM events WHERE started_at >= ? "
                "ORDER BY started_at DESC LIMIT ?", (since, int(limit)))
        return self._query(
            "SELECT * FROM events ORDER BY started_at DESC LIMIT ?",
            (int(limit),))

    def ack_event(self, event_id: int, now: float | None = None) -> bool:
        cur = self._exec("UPDATE events SET acked_at = ? WHERE id = ?",
                         (now or time.time(), int(event_id)))
        return bool(cur is not None and cur.rowcount)

    def events_pending_notification(self) -> list[dict]:
        """Open events that no notifier has claimed yet."""
        return self._query(
            "SELECT * FROM events WHERE resolved_at IS NULL "
            "AND notified_at IS NULL ORDER BY started_at")

    def mark_notified(self, event_id: int, now: float | None = None) -> None:
        self._exec("UPDATE events SET notified_at = ? WHERE id = ?",
                   (now or time.time(), int(event_id)))

    # -- audit ---------------------------------------------------------
    def audit(self, actor: str, action: str, outcome: str, target: str = "",
              actor_ip: str = "", detail: str = "", diff: str = "",
              backup: str = "", now: float | None = None) -> None:
        """Record an attempt to change something.

        Called for refusals and failures too - "who tried to add a bare root
        and was stopped" is exactly as interesting as what succeeded.
        """
        self._exec(
            "INSERT INTO audit(ts, actor, actor_ip, action, target, outcome, "
            "detail, diff, backup) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now or time.time(), actor, actor_ip, action, target, outcome,
             detail[:4000], diff[:20000], backup))

    def audit_log(self, limit: int = 200, action: str = "",
                  actor: str = "") -> list[dict]:
        sql = "SELECT * FROM audit WHERE 1=1"
        params: list[Any] = []
        if action:
            sql += " AND action = ?"
            params.append(action)
        if actor:
            sql += " AND actor = ?"
            params.append(actor)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(int(limit))
        return self._query(sql, tuple(params))

    # -- domain registry -----------------------------------------------
    def note_domains(self, names: list[dict], now: float | None = None) -> None:
        """Upsert observations. Each entry: {name, upstream: bool, client: str}.

        `first_seen` only ever moves backwards, which is the whole point: the
        dnsdist ring forgets, this does not.
        """
        if not self.enabled or self._conn is None or not names:
            return
        now = now or time.time()
        rows = []
        for e in names:
            name = (e.get("name") or "").strip().lower()
            if not name:
                continue
            up = 1 if e.get("upstream") else 0
            rows.append((name, now, now, up, 0 if up else 1,
                         e.get("client") or ""))
        if not rows:
            return
        try:
            with self._lock:
                self._conn.executemany(
                    "INSERT INTO domain_registry(name, first_seen, last_seen, "
                    "went_upstream, was_proxied, last_client) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET "
                    "  last_seen = excluded.last_seen, "
                    "  first_seen = MIN(first_seen, excluded.first_seen), "
                    "  times_seen = times_seen + 1, "
                    "  went_upstream = went_upstream + excluded.went_upstream, "
                    "  was_proxied = was_proxied + excluded.was_proxied, "
                    "  last_client = excluded.last_client",
                    rows)
                self._conn.commit()
        except sqlite3.Error as exc:
            self.error = str(exc)

    def domain_first_seen(self, name: str) -> float | None:
        rows = self._query(
            "SELECT first_seen FROM domain_registry WHERE name = ?",
            (name.strip().lower(),))
        return rows[0]["first_seen"] if rows else None

    def domains_seen(self, limit: int = 500, contains: str = "",
                     upstream_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM domain_registry WHERE 1=1"
        params: list[Any] = []
        if contains:
            sql += " AND name LIKE ?"
            params.append(f"%{contains.strip().lower()}%")
        if upstream_only:
            sql += " AND went_upstream > 0"
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(int(limit))
        return self._query(sql, tuple(params))

    # -- traffic rollups -----------------------------------------------
    def add_traffic(self, records: list[dict],
                    now: float | None = None) -> None:
        """Fold access-log records into time buckets.

        Individual connections are never stored - only per-bucket totals. That
        keeps the file small and makes it structurally unable to serve as a
        per-connection log of who went where.
        """
        if not self.enabled or self._conn is None or not records:
            return
        by_client: dict[tuple[int, str], list[int]] = {}
        by_sni: dict[tuple[int, str], list[int]] = {}
        for r in records:
            bucket = int((r.get("ts") or now or time.time())
                         // BUCKET_SECONDS * BUCKET_SECONDS)
            problem = 1 if r.get("problem") else 0
            fo = int(r.get("from_origin") or 0)
            to = int(r.get("to_origin") or 0)

            k = (bucket, r.get("client_ip") or "?")
            acc = by_client.setdefault(k, [0, 0, 0, 0])
            acc[0] += 1
            acc[1] += problem
            acc[2] += fo
            acc[3] += to

            sni = r.get("sni") or "(none)"
            k2 = (bucket, sni)
            acc2 = by_sni.setdefault(k2, [0, 0, 0, 0])
            acc2[0] += 1
            acc2[1] += problem
            acc2[2] += fo
            acc2[3] += to

        try:
            with self._lock:
                self._conn.executemany(
                    "INSERT INTO traffic(bucket, client_ip, conns, problems, "
                    "from_origin, to_origin) VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(bucket, client_ip) DO UPDATE SET "
                    "  conns = conns + excluded.conns, "
                    "  problems = problems + excluded.problems, "
                    "  from_origin = from_origin + excluded.from_origin, "
                    "  to_origin = to_origin + excluded.to_origin",
                    [(b, c, *v) for (b, c), v in by_client.items()])
                self._conn.executemany(
                    "INSERT INTO sni_traffic(bucket, sni, conns, problems, "
                    "from_origin, to_origin) VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(bucket, sni) DO UPDATE SET "
                    "  conns = conns + excluded.conns, "
                    "  problems = problems + excluded.problems, "
                    "  from_origin = from_origin + excluded.from_origin, "
                    "  to_origin = to_origin + excluded.to_origin",
                    [(b, s, *v) for (b, s), v in by_sni.items()])
                self._conn.commit()
        except sqlite3.Error as exc:
            self.error = str(exc)

    def traffic_series(self, hours: float = 6, client_ip: str = "",
                       buckets: int = 0) -> list[dict]:
        """Totals per bucket over a window, optionally for one client."""
        since = int((time.time() - hours * 3600) // BUCKET_SECONDS
                    * BUCKET_SECONDS)
        if client_ip:
            rows = self._query(
                "SELECT bucket, conns, problems, from_origin, to_origin "
                "FROM traffic WHERE bucket >= ? AND client_ip = ? "
                "ORDER BY bucket", (since, client_ip))
        else:
            rows = self._query(
                "SELECT bucket, SUM(conns) AS conns, SUM(problems) AS problems,"
                " SUM(from_origin) AS from_origin, SUM(to_origin) AS to_origin "
                "FROM traffic WHERE bucket >= ? GROUP BY bucket "
                "ORDER BY bucket", (since,))
        return rows

    def top_talkers(self, hours: float = 6, limit: int = 15) -> list[dict]:
        since = int((time.time() - hours * 3600) // BUCKET_SECONDS
                    * BUCKET_SECONDS)
        return self._query(
            "SELECT client_ip, SUM(conns) AS conns, SUM(problems) AS problems, "
            "SUM(from_origin) AS from_origin, SUM(to_origin) AS to_origin, "
            "MAX(bucket) AS last_bucket "
            "FROM traffic WHERE bucket >= ? GROUP BY client_ip "
            "ORDER BY (SUM(from_origin) + SUM(to_origin)) DESC LIMIT ?",
            (since, int(limit)))

    def top_snis(self, hours: float = 6, limit: int = 15) -> list[dict]:
        since = int((time.time() - hours * 3600) // BUCKET_SECONDS
                    * BUCKET_SECONDS)
        return self._query(
            "SELECT sni, SUM(conns) AS conns, SUM(problems) AS problems, "
            "SUM(from_origin) AS from_origin, SUM(to_origin) AS to_origin "
            "FROM sni_traffic WHERE bucket >= ? GROUP BY sni "
            "ORDER BY (SUM(from_origin) + SUM(to_origin)) DESC LIMIT ?",
            (since, int(limit)))

    def problem_rate(self, minutes: float = 15) -> dict:
        """Share of connections flagged as a problem in the recent window.
        Used by the alert rules."""
        since = int((time.time() - minutes * 60) // BUCKET_SECONDS
                    * BUCKET_SECONDS)
        rows = self._query(
            "SELECT SUM(conns) AS conns, SUM(problems) AS problems "
            "FROM traffic WHERE bucket >= ?", (since,))
        if not rows or not rows[0].get("conns"):
            return {"conns": 0, "problems": 0, "rate": 0.0}
        conns = rows[0]["conns"] or 0
        problems = rows[0]["problems"] or 0
        return {"conns": conns, "problems": problems,
                "rate": (problems / conns) if conns else 0.0}

    # -- housekeeping --------------------------------------------------
    def prune(self, force: bool = False) -> dict:
        """Drop data past the retention window.

        Retention is short on purpose: per-address totals do not get more
        meaningful with age, and a long history invites treating this as an
        accounting record, which it is not.
        """
        now = time.time()
        if not force and now - self._last_prune < 3600:
            return {"skipped": True}
        self._last_prune = now
        cutoff = now - self.retention_days * 86400
        bucket_cutoff = int(cutoff)
        out = {}
        for table, col, val in (
            ("traffic", "bucket", bucket_cutoff),
            ("sni_traffic", "bucket", bucket_cutoff),
            ("audit", "ts", cutoff),
        ):
            cur = self._exec(f"DELETE FROM {table} WHERE {col} < ?", (val,))
            out[table] = cur.rowcount if cur is not None else 0
        # Resolved events are kept longer - they are the thing you look back at.
        cur = self._exec(
            "DELETE FROM events WHERE resolved_at IS NOT NULL AND started_at < ?",
            (now - max(self.retention_days, 60) * 86400,))
        out["events"] = cur.rowcount if cur is not None else 0
        # The registry is tiny and its whole value is being long-lived, but drop
        # names not seen in a very long time so it cannot grow without bound.
        cur = self._exec("DELETE FROM domain_registry WHERE last_seen < ?",
                         (now - 365 * 86400,))
        out["domain_registry"] = cur.rowcount if cur is not None else 0
        return out

    def stats(self) -> dict:
        if not self.enabled:
            return {"enabled": False, "error": self.error, "path": self.path}
        counts = {}
        for t in ("events", "audit", "domain_registry", "traffic",
                  "sni_traffic"):
            rows = self._query(f"SELECT COUNT(*) AS n FROM {t}")
            counts[t] = rows[0]["n"] if rows else 0
        size = 0
        try:
            size = os.path.getsize(self.path)
        except OSError:
            pass
        return {
            "enabled": True,
            "path": self.path,
            "size": size,
            "counts": counts,
            "retention_days": self.retention_days,
            "bucket_seconds": BUCKET_SECONDS,
            "open_events": len(self.open_events()),
            "error": self.error,
            "disclaimer": DISCLAIMER,
        }


class NullStore(Store):
    """Used when history is disabled. Every call is a no-op.

    A separate class rather than `if store:` scattered through the callers -
    the calling code should not have to care.
    """

    def __init__(self):  # noqa: D107 - deliberately does not call super
        self.path = ""
        self.retention_days = 0
        self.enabled = False
        self.error = None
        self._lock = threading.Lock()
        self._conn = None
        self._last_prune = 0.0

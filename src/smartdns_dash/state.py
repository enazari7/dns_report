"""Shared runtime state: the live feed ring and the background pollers.

The servers are modest VMs that also carry live traffic, so the design is:
one background task reads each source at a configurable interval, everything
else serves from memory. No endpoint ever re-reads a whole log file, and N
open browser tabs cost the same as one.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from typing import Any

from . import alerts as alertmod
from .config import Config
from .config import warnings as cfgwarnings
from .sources import dnsdist as dd
from .sources import domains as dom
from .sources import portwatch as pw
from .sources import sniproxy_log as slog
from .sources import sysinfo
from .store import NullStore, Store


class Broadcaster:
    """Fan-out to connected SSE clients. Slow clients get dropped rather than
    backing up the producer."""

    def __init__(self, queue_size: int = 200):
        self.queue_size = queue_size
        self._subs: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self.queue_size)
        async with self._lock:
            self._subs.append(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue) -> None:
        async with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    async def publish(self, event: str, data: Any) -> None:
        async with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait((event, data))
            except asyncio.QueueFull:
                # Drop the oldest so a stalled tab cannot wedge the feed.
                try:
                    q.get_nowait()
                    q.put_nowait((event, data))
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    @property
    def count(self) -> int:
        return len(self._subs)


class AppState:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.started = time.time()

        # Live proxy feed
        self.feed: deque[dict] = deque(maxlen=cfg.feed_ring)
        self.feed_seq = 0
        self.tailer = slog.MultiTailer(cfg.log_files, from_end=True)
        self.broadcaster = Broadcaster()

        # dnsdist
        self.console = dd.DnsdistConsole(cfg.console, cfg.dnsdist_key)
        self.first_seen = dd.FirstSeenTracker()
        self.watch_client: str | None = None
        self.grepq_cache: dict[str, Any] = {
            "client_ip": None, "ts": 0, "unproxied": [], "proxied": [],
            "rows": 0, "error": None,
        }

        # Status
        self.status_cache: dict[str, Any] = {"ts": 0}

        # Guarded writes
        self.plans = dom.PlanStore(ttl_s=300)
        self.write_lock = threading.Lock()
        self.last_change: dict | None = None
        self.change_log: deque[dict] = deque(maxlen=200)

        # Persistent diagnostic history. Never an accounting source: see the
        # module docstring in store.py.
        self.store = (Store(cfg.history_path, cfg.history_retention_days)
                      if cfg.history_enabled else NullStore())
        self.notifiers = (alertmod.build_notifiers(cfg)
                          if cfg.alerts_enabled else [])
        self.last_peer_diff: dict | None = None
        self.alert_summary: dict = {"open": 0, "closed": 0}

        # Port watcher
        self.portwatcher = pw.PortWatcher(
            interface=cfg.pw_interface, ignore_ports=cfg.pw_ignore_ports,
            timeout_s=cfg.pw_timeout_s, max_runtime_s=cfg.pw_max_runtime_s)

        self._tasks: list[asyncio.Task] = []

    # -- feed ----------------------------------------------------------
    def backfill(self, n: int = 200) -> None:
        """Seed the in-memory ring from the tail of the logs on startup.

        These rows are fed to the domain registry but deliberately NOT to the
        traffic rollups: the registry's first_seen only moves backwards so
        replaying is harmless, whereas folding the same connections into a
        bucket again on every restart would inflate the totals.
        """
        rows = self.tailer.backfill(n)
        for rec in rows:
            self.feed_seq += 1
            rec["seq"] = self.feed_seq
            self.feed.append(rec)
        seen = [{"name": r["sni"], "upstream": False, "client": r["client_ip"]}
                for r in rows if r["sni"]]
        if seen:
            self.store.note_domains(seen)

    def recent(self, limit: int = 200, client_ip: str = "",
               sni: str = "", problems_only: bool = False,
               since_seq: int = 0) -> list[dict]:
        out = []
        for rec in reversed(self.feed):
            if since_seq and rec["seq"] <= since_seq:
                break
            if client_ip and rec["client_ip"] != client_ip:
                continue
            if sni and sni not in rec["sni"]:
                continue
            if problems_only and not rec["problem"]:
                continue
            out.append(rec)
            if len(out) >= limit:
                break
        out.reverse()
        return out

    def feed_clients(self) -> list[dict]:
        """Distinct client IPs in the ring, most recent first - so you can
        pick one without knowing it in advance."""
        seen: dict[str, dict] = {}
        for rec in self.feed:
            e = seen.setdefault(rec["client_ip"], {
                "client_ip": rec["client_ip"], "count": 0,
                "last_ts": rec["ts"], "problems": 0, "bytes": 0,
            })
            e["count"] += 1
            e["last_ts"] = max(e["last_ts"], rec["ts"])
            e["bytes"] += rec["bytes_tx"] + rec["bytes_rx"]
            if rec["problem"]:
                e["problems"] += 1
        return sorted(seen.values(), key=lambda x: -x["last_ts"])

    # -- pollers -------------------------------------------------------
    async def start(self) -> None:
        self.backfill(200)
        self._tasks = [
            asyncio.create_task(self._poll_logs()),
            asyncio.create_task(self._poll_grepq()),
            asyncio.create_task(self._poll_status()),
        ]

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._tasks = []
        self.portwatcher.stop()
        self.store.close()

    async def _poll_logs(self) -> None:
        interval = max(0.2, self.cfg.log_ms / 1000.0)
        while True:
            try:
                recs = await asyncio.to_thread(self.tailer.read_new)
                if recs:
                    batch = []
                    for r in recs:
                        self.feed_seq += 1
                        r["seq"] = self.feed_seq
                        self.feed.append(r)
                        batch.append(r)
                    await self.broadcaster.publish("feed", batch)
                    # Fold into time buckets for the charts, and note the SNIs
                    # so the domain registry outlives the dnsdist ring.
                    await asyncio.to_thread(self.store.add_traffic, batch)
                    seen = [{"name": r["sni"], "upstream": False,
                             "client": r["client_ip"]}
                            for r in batch if r["sni"]]
                    if seen:
                        await asyncio.to_thread(self.store.note_domains, seen)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a poller must not die
                await self.broadcaster.publish(
                    "error", {"where": "logs", "message": str(exc)})
            await asyncio.sleep(interval)

    async def _poll_grepq(self) -> None:
        interval = max(1.0, self.cfg.grepq_ms / 1000.0)
        while True:
            client = self.watch_client
            if client:
                try:
                    data = await asyncio.to_thread(self._grepq_once, client)
                    self.grepq_cache = data
                    await self.broadcaster.publish("unproxied", data)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    self.grepq_cache = {
                        "client_ip": client, "ts": time.time(),
                        "unproxied": [], "proxied": [], "rows": 0,
                        "error": str(exc)}
                    await self.broadcaster.publish("unproxied",
                                                   self.grepq_cache)
            await asyncio.sleep(interval)

    def _grepq_once(self, client_ip: str) -> dict:
        rows = self.console.grepq(client_ip, self.cfg.grepq_limit)
        cl = dd.classify(rows)
        unproxied = self.first_seen.apply(client_ip, cl["unproxied"])
        proxied = self.first_seen.apply(client_ip, cl["proxied"])
        pf = dom.parse(self.cfg.domains)
        for e in unproxied + proxied:
            e["matched_suffix"] = dom.match_suffix(e["name"], pf)

        # Persist observations, then prefer the stored first-seen: the ring only
        # holds the recent past, so its idea of "first seen" walks forward as
        # entries age out.
        self.store.note_domains(
            [{"name": e["name"], "upstream": True, "client": client_ip}
             for e in unproxied]
            + [{"name": e["name"], "upstream": False, "client": client_ip}
               for e in proxied])
        for e in unproxied + proxied:
            stored = self.store.domain_first_seen(e["name"])
            if stored is not None:
                e["first_seen"] = min(e.get("first_seen", stored), stored)
        return {
            "client_ip": client_ip,
            "ts": time.time(),
            "unproxied": unproxied,
            "proxied": proxied,
            "rows": cl["total_rows"],
            "error": None,
        }

    async def _poll_status(self) -> None:
        interval = max(3.0, self.cfg.status_ms / 1000.0)
        while True:
            try:
                data = await asyncio.to_thread(self._status_once)
                self.status_cache = data
                await self.broadcaster.publish("status", data)
                if self.cfg.alerts_enabled:
                    await asyncio.to_thread(self._alerts_once, data)
                    await self.broadcaster.publish(
                        "events", {"open": self.store.open_events(),
                                   "summary": self.alert_summary})
                await asyncio.to_thread(self.store.prune)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self.status_cache = {"ts": time.time(), "error": str(exc)}
            await asyncio.sleep(interval)

    def _status_once(self) -> dict:
        cfg = self.cfg
        watch = [cfg.domains]
        if cfg.generated_proxy:
            watch.append(cfg.generated_proxy)
        stale = sysinfo.staleness(cfg.staleness_unit, watch)
        services = [sysinfo.service_status(u) for u in cfg.restart]
        if cfg.staleness_unit not in cfg.restart:
            services.append(sysinfo.service_status(cfg.staleness_unit))

        pf = dom.parse(cfg.domains)
        stats = dd.fetch_stats(cfg.api_url, cfg.dnsdist_api_key())
        console_problem = self.console.available()

        return {
            "ts": time.time(),
            "server": {
                "name": cfg.display_name,
                "spoof_ip": cfg.spoof_ip,
                "spoof_source": cfg.spoof_source,
                "local_ip": cfg.resolved_local_ip,
                "behind_proxy": cfg.behind_proxy,
                "bind": cfg.bind,
                "port": cfg.port,
                "single_server": not cfg.peer_enabled,
                "allow_ips": len(cfg.allow_ips),
                "peer_name": cfg.peer_name if cfg.peer_enabled else "",
            },
            "config_warnings": cfgwarnings(cfg),
            "history": self.store.stats(),
            "alerts": {
                "enabled": cfg.alerts_enabled,
                "summary": self.alert_summary,
                "open": len(self.store.open_events()),
                "notifiers": [n.name for n in self.notifiers if n.enabled()],
            },
            "staleness": stale,
            "services": services,
            "domains": {
                "path": cfg.domains,
                "count": len(pf.entries),
                "duplicates": len(pf.duplicates),
                "invalid": len(pf.invalid),
                "redundant": len(pf.redundant()),
                "mtime": pf.mtime,
                "error": pf.error,
            },
            "dnsdist": {
                "console": cfg.console,
                "problem": console_problem,
                "stats": stats,
            },
            "logs": self.tailer.stats(),
            "feed_len": len(self.feed),
            "subscribers": self.broadcaster.count,
            "watch_client": self.watch_client,
            "uptime_s": time.time() - self.started,
        }

    def _alerts_once(self, status: dict) -> None:
        """Evaluate the rules, then reconcile and dispatch.

        Closing resolved conditions matters as much as opening new ones: an
        event that never clears teaches people to ignore the badge.
        """
        try:
            rate = self.store.problem_rate(minutes=15)
            findings = alertmod.evaluate(
                status, rate, self.last_peer_diff,
                problem_threshold=self.cfg.alerts_problem_threshold)
            self.alert_summary = alertmod.reconcile(self.store, findings)
            if self.notifiers:
                self.alert_summary.update(alertmod.dispatch(
                    self.store, self.notifiers,
                    lang=self.cfg.language,
                    min_severity=self.cfg.alerts_min_severity))
        except Exception as exc:  # noqa: BLE001 - alerting must never kill the poller
            self.alert_summary = {"error": str(exc)}

    # -- change log ----------------------------------------------------
    def record_change(self, entry: dict) -> None:
        entry["ts"] = time.time()
        self.change_log.appendleft(entry)
        self.last_change = entry

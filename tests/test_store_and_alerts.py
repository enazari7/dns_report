"""Persistent history and the alert rules.

The history is deliberately NOT an accounting source - client IPs change hands -
and a couple of tests below pin that intent so it cannot quietly drift into one.
"""

from __future__ import annotations

import time

import pytest

from smartdns_dash import alerts, i18n
from smartdns_dash.store import BUCKET_SECONDS, NullStore, Store


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "history.db"), retention_days=14)
    yield s
    s.close()


# --------------------------------------------------------------------------
# what this database is and is not
# --------------------------------------------------------------------------

def test_disclaimer_is_recorded_in_the_file_itself(store):
    """Anyone who opens the database with sqlite3 should find the warning."""
    rows = store._query("SELECT value FROM meta WHERE key = 'disclaimer'")
    assert rows
    assert "accounting" in rows[0]["value"]


def test_only_aggregates_are_stored_never_connections(store):
    """No per-connection log: the schema must make that structurally true."""
    store.add_traffic([
        {"ts": time.time(), "client_ip": "1.1.1.1", "sni": "a.com",
         "from_origin": 10, "to_origin": 5, "problem": False},
        {"ts": time.time(), "client_ip": "1.1.1.1", "sni": "a.com",
         "from_origin": 20, "to_origin": 5, "problem": False},
    ])
    rows = store._query("SELECT * FROM traffic")
    assert len(rows) == 1, "two connections must fold into one bucket row"
    assert rows[0]["conns"] == 2
    assert rows[0]["from_origin"] == 30
    tables = {r["name"] for r in store._query(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "connections" not in tables


def test_retention_is_short_by_default(store):
    assert store.retention_days <= 30


def test_prune_drops_old_traffic(store):
    old = int(time.time() - 60 * 86400)
    store._exec("INSERT INTO traffic(bucket, client_ip, conns) VALUES (?,?,?)",
                (old, "1.1.1.1", 5))
    store.add_traffic([{"ts": time.time(), "client_ip": "2.2.2.2",
                        "sni": "a.com", "from_origin": 1, "to_origin": 1}])
    store.prune(force=True)
    remaining = {r["client_ip"] for r in store._query(
        "SELECT client_ip FROM traffic")}
    assert remaining == {"2.2.2.2"}


# --------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------

def test_a_continuing_condition_is_one_event_not_one_per_poll(store):
    for _ in range(10):
        store.open_event("service:sniproxy:down", "service", "critical",
                         "sniproxy", i18n.M("down", "خاموش"))
    open_ = store.open_events()
    assert len(open_) == 1
    assert open_[0]["occurrences"] == 10


def test_event_records_a_duration(store):
    store.open_event("x", "k", "warning", "s", now=1000.0)
    store.open_event("x", "k", "warning", "s", now=1600.0)
    ev = store.open_events()[0]
    assert ev["started_at"] == 1000.0
    assert ev["last_seen"] == 1600.0


def test_closing_and_reopening_makes_a_second_event(store):
    store.open_event("x", "k", "warning", "s", now=1000.0)
    assert store.close_event("x", now=1100.0) is True
    assert store.open_events() == []
    store.open_event("x", "k", "warning", "s", now=2000.0)
    assert len(store.open_events()) == 1
    assert len(store.recent_events()) == 2


def test_closing_something_not_open_is_harmless(store):
    assert store.close_event("never-opened") is False


def test_events_are_bilingual(store):
    store.open_event("x", "k", "warning", "s",
                     i18n.M("english detail", "جزئیات فارسی"))
    ev = store.open_events()[0]
    assert ev["detail_en"] == "english detail"
    assert ev["detail_fa"] == "جزئیات فارسی"


def test_ack_marks_but_does_not_close(store):
    store.open_event("x", "k", "warning", "s")
    ev = store.open_events()[0]
    assert store.ack_event(ev["id"]) is True
    still = store.open_events()[0]
    assert still["acked_at"] is not None
    assert still["resolved_at"] is None


# --------------------------------------------------------------------------
# domain registry
# --------------------------------------------------------------------------

def test_first_seen_only_moves_backwards(store):
    """The dnsdist ring forgets; this must not. Otherwise a name's apparent
    first-seen time walks forward as ring entries age out."""
    store.note_domains([{"name": "a.com", "upstream": True}], now=2000.0)
    store.note_domains([{"name": "a.com", "upstream": True}], now=1000.0)
    store.note_domains([{"name": "a.com", "upstream": True}], now=3000.0)
    assert store.domain_first_seen("a.com") == 1000.0
    row = store.domains_seen()[0]
    assert row["last_seen"] == 3000.0
    assert row["times_seen"] == 3


def test_registry_tracks_upstream_versus_proxied(store):
    store.note_domains([{"name": "a.com", "upstream": True}])
    store.note_domains([{"name": "a.com", "upstream": False}])
    row = store.domains_seen()[0]
    assert row["went_upstream"] == 1
    assert row["was_proxied"] == 1


def test_registry_filters(store):
    store.note_domains([{"name": "a.example.com", "upstream": True},
                        {"name": "b.other.net", "upstream": False}])
    assert len(store.domains_seen(contains="example")) == 1
    assert [r["name"] for r in store.domains_seen(upstream_only=True)] == \
        ["a.example.com"]


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------

def test_refusals_are_audited_not_just_successes(store):
    store.audit("admin", "add", "refused", "newgame.net", actor_ip="1.2.3.4",
                detail="bare root")
    store.audit("admin", "add", "applied", "dl.newgame.net")
    outcomes = {a["outcome"] for a in store.audit_log()}
    assert outcomes == {"refused", "applied"}


def test_audit_filters(store):
    store.audit("admin", "add", "applied", "a.com")
    store.audit("viewer", "login", "ok", "")
    assert len(store.audit_log(action="add")) == 1
    assert len(store.audit_log(actor="viewer")) == 1


# --------------------------------------------------------------------------
# a broken database must never take the dashboard down
# --------------------------------------------------------------------------

def test_unwritable_path_degrades_quietly(tmp_path):
    s = Store(str(tmp_path / "nope" / "sub" / "x.db"))
    bad = Store("/proc/definitely/not/writable.db")
    assert bad.enabled is False
    assert bad.error
    # And every call is still safe.
    bad.open_event("x", "k", "warning", "s")
    bad.audit("a", "b", "c")
    bad.add_traffic([{"ts": 1, "client_ip": "1.1.1.1", "sni": "a"}])
    assert bad.open_events() == []
    assert bad.traffic_series() == []
    assert bad.stats()["enabled"] is False
    s.close()


def test_null_store_is_silent():
    n = NullStore()
    n.open_event("x", "k", "warning", "s")
    n.audit("a", "b", "c")
    n.note_domains([{"name": "a.com"}])
    n.add_traffic([{"ts": 1, "client_ip": "1.1.1.1", "sni": "a"}])
    assert n.open_events() == []
    assert n.top_talkers() == []
    assert n.stats()["enabled"] is False


# --------------------------------------------------------------------------
# rollups and series
# --------------------------------------------------------------------------

def test_traffic_series_and_top_lists(store):
    now = time.time()
    store.add_traffic([
        {"ts": now, "client_ip": "1.1.1.1", "sni": "a.com",
         "from_origin": 1000, "to_origin": 100, "problem": False},
        {"ts": now, "client_ip": "1.1.1.1", "sni": "", "from_origin": 0,
         "to_origin": 0, "problem": True},
        {"ts": now, "client_ip": "2.2.2.2", "sni": "b.com",
         "from_origin": 50, "to_origin": 5, "problem": False},
    ])
    series = store.traffic_series(hours=1)
    assert len(series) == 1
    assert series[0]["conns"] == 3
    assert series[0]["problems"] == 1

    top = store.top_talkers(hours=1)
    assert top[0]["client_ip"] == "1.1.1.1"          # ordered by bytes
    snis = {r["sni"] for r in store.top_snis(hours=1)}
    assert "(none)" in snis, "an empty SNI must still be visible"

    rate = store.problem_rate(minutes=60)
    assert rate["conns"] == 3 and rate["problems"] == 1
    assert rate["rate"] == pytest.approx(1 / 3)


def test_traffic_series_can_be_filtered_to_one_client(store):
    now = time.time()
    store.add_traffic([
        {"ts": now, "client_ip": "1.1.1.1", "sni": "a", "from_origin": 10,
         "to_origin": 1},
        {"ts": now, "client_ip": "2.2.2.2", "sni": "a", "from_origin": 99,
         "to_origin": 9},
    ])
    only = store.traffic_series(hours=1, client_ip="2.2.2.2")
    assert len(only) == 1 and only[0]["from_origin"] == 99


def test_buckets_are_aligned(store):
    store.add_traffic([{"ts": 1_700_000_123, "client_ip": "1.1.1.1",
                        "sni": "a", "from_origin": 1, "to_origin": 1}])
    bucket = store._query("SELECT bucket FROM traffic")[0]["bucket"]
    assert bucket % BUCKET_SECONDS == 0


# --------------------------------------------------------------------------
# alert rules
# --------------------------------------------------------------------------

def test_service_down_is_critical():
    f = alerts.rule_services_down({"services": [
        {"unit": "sniproxy", "healthy": False, "active_state": "inactive",
         "sub_state": "dead"},
        {"unit": "dnsdist", "healthy": True},
    ]})
    assert len(f) == 1
    assert f[0].severity == "critical"
    assert f[0].fingerprint == "service:sniproxy:down"
    assert "fa" in f[0].detail


def test_stale_config_is_flagged():
    f = alerts.rule_config_stale({"staleness": {
        "stale": True, "unit": "sniproxy", "lag_s": 900}})
    assert len(f) == 1 and f[0].severity == "warning"
    assert "15" in f[0].detail["en"]


def test_not_stale_produces_nothing():
    assert alerts.rule_config_stale({"staleness": {"stale": False}}) == []


def test_problem_rate_needs_a_minimum_sample():
    """Two failures out of three at 4am is noise, not an incident."""
    assert alerts.rule_problem_rate({"conns": 3, "rate": 0.66}) == []
    hit = alerts.rule_problem_rate({"conns": 100, "rate": 0.4})
    assert len(hit) == 1
    assert "40%" in hit[0].detail["en"]


def test_problem_rate_respects_the_threshold():
    assert alerts.rule_problem_rate({"conns": 100, "rate": 0.1},
                                    threshold=0.25) == []
    assert alerts.rule_problem_rate({"conns": 100, "rate": 0.1},
                                    threshold=0.05)


def test_peer_divergence_is_flagged():
    f = alerts.rule_peer_diverged({"in_sync": False, "only_mine": ["a"],
                                   "only_theirs": ["b", "c"],
                                   "their_name": "DNS-02"})
    assert len(f) == 1 and f[0].subject == "DNS-02"
    assert alerts.rule_peer_diverged({"in_sync": True}) == []
    assert alerts.rule_peer_diverged(None) == []


def test_reconcile_opens_then_closes(store):
    status = {"services": [{"unit": "sniproxy", "healthy": False,
                            "active_state": "inactive", "sub_state": "dead"}]}
    r = alerts.reconcile(store, alerts.evaluate(status, {}))
    assert r["open"] == 1
    assert len(store.open_events()) == 1

    # Service recovers: the event must close itself, or the badge becomes noise
    # that people learn to ignore.
    healthy = {"services": [{"unit": "sniproxy", "healthy": True}]}
    r = alerts.reconcile(store, alerts.evaluate(healthy, {}))
    assert r["closed"] == 1
    assert store.open_events() == []


# --------------------------------------------------------------------------
# notifiers
# --------------------------------------------------------------------------

def test_log_notifier_is_the_default_and_enabled():
    n = alerts.LogNotifier()
    assert n.enabled() is True
    assert n.send({"severity": "warning", "subject": "x",
                   "detail_en": "y", "detail_fa": "ی"}) is True


def test_webhook_and_telegram_are_off_until_configured():
    assert alerts.WebhookNotifier().enabled() is False
    assert alerts.TelegramNotifier().enabled() is False
    assert alerts.TelegramNotifier("token", "chat").enabled() is True


def test_webhook_payload_shape():
    n = alerts.WebhookNotifier("http://example.invalid/hook")
    import json
    body = json.loads(n.payload({"severity": "critical", "kind": "service",
                                 "subject": "sniproxy", "detail_en": "down",
                                 "detail_fa": "خاموش",
                                 "started_at": 1.0}, "fa"))
    assert body["severity"] == "critical"
    assert body["detail"] == "خاموش"          # language honoured
    assert "sniproxy" in body["text"]


def test_dispatch_marks_notified_only_on_success(store):
    store.open_event("x", "service", "critical", "sniproxy",
                     i18n.M("down", "خاموش"))

    class Failing(alerts.Notifier):
        name = "failing"

        def enabled(self):
            return True

        def send(self, event, lang="en"):
            return False

    r = alerts.dispatch(store, [Failing()])
    assert r["sent"] == 0
    assert len(store.events_pending_notification()) == 1, "must retry later"

    r = alerts.dispatch(store, [alerts.LogNotifier()])
    assert r["sent"] == 1
    assert store.events_pending_notification() == []


def test_dispatch_respects_min_severity(store):
    store.open_event("i", "config", "info", "x", i18n.M("a", "ا"))
    r = alerts.dispatch(store, [alerts.LogNotifier()], min_severity="warning")
    assert r["sent"] == 0 and r["skipped"] == 1


def test_a_raising_notifier_does_not_break_dispatch(store):
    store.open_event("x", "service", "critical", "s", i18n.M("d", "د"))

    class Exploding(alerts.Notifier):
        name = "boom"

        def enabled(self):
            return True

        def send(self, event, lang="en"):
            raise RuntimeError("kaboom")

    r = alerts.dispatch(store, [Exploding(), alerts.LogNotifier()])
    assert r["sent"] == 1, "the working notifier still delivered"

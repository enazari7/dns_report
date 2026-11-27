"""The v1.2 features over HTTP: roles, groups, charts, probe, metrics, triage."""

from __future__ import annotations

import pytest
from tests.conftest import access_log_line, wait_for

# --------------------------------------------------------------------------
# read-only role
# --------------------------------------------------------------------------

def test_operator_and_viewer_roles_land_in_the_page(client, viewer_client):
    assert 'data-role="operator"' in client.get("/").text
    assert 'data-role="viewer"' in viewer_client.get("/").text


@pytest.mark.parametrize("path,body", [
    ("/api/domains/preview", {"action": "add", "domain": "a.example.com"}),
    ("/api/domains/apply", {"token": "x", "confirm": "y"}),
    ("/api/domains/apply-both", {"token": "x", "confirm": "y"}),
    ("/api/backups/restore", {"name": "x", "confirm": "RESTORE"}),
    ("/api/portwatch", {"action": "start"}),
    ("/api/events/ack", {"id": 1}),
])
def test_viewer_cannot_change_anything(viewer_client, path, body):
    """Enforced on the server, not by hiding buttons."""
    r = viewer_client.post(path, json=body, headers=viewer_client.h)
    assert r.status_code == 403


@pytest.mark.parametrize("path", [
    "/api/status", "/api/feed", "/api/traffic", "/api/events", "/api/audit",
    "/api/registry", "/api/groups", "/api/history", "/api/domains",
])
def test_viewer_can_read_everything(viewer_client, path):
    assert viewer_client.get(path).status_code == 200


def test_viewer_may_run_the_probe(viewer_client):
    """Read-only and side-effect free, and it makes whoever is looking better
    informed - so the viewer gets it."""
    r = viewer_client.post("/api/probe", json={"domain": "nothing.invalid"},
                           headers=viewer_client.h)
    assert r.status_code == 200


def test_role_is_inside_the_signed_token_not_a_cookie_field(cfg):
    from smartdns_dash import auth
    tok = auth.make_token(cfg.secret_key, "viewer", 12, role="viewer")
    assert auth.read_token(cfg.secret_key, tok)["r"] == "viewer"
    # Tampering invalidates the signature rather than changing the role.
    body, _, sig = tok.partition(".")
    assert auth.read_token(cfg.secret_key, body + "." + sig[:-2] + "xx") is None


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------

def test_login_is_audited(client):
    actions = {a["action"] for a in client.get("/api/audit").json()["entries"]}
    assert "login" in actions


def test_a_refused_change_is_audited(client):
    client.post("/api/domains/preview",
                json={"action": "add", "domain": "sub.example.com"},
                headers=client.h)
    rows = client.get("/api/audit").json()["entries"]
    refused = [a for a in rows if a["outcome"] == "refused"]
    assert refused and refused[0]["target"] == "sub.example.com"


def test_an_applied_change_is_audited_with_its_diff(client):
    p = client.post("/api/domains/preview",
                    json={"action": "add", "domain": "dl.newgame.net"},
                    headers=client.h).json()
    client.post("/api/domains/apply",
                json={"token": p["token"], "confirm": "dl.newgame.net"},
                headers=client.h)
    rows = client.get("/api/audit").json()["entries"]
    applied = [a for a in rows if a["outcome"] == "applied"]
    assert applied
    assert "dl.newgame.net" in applied[0]["diff"]
    assert applied[0]["actor"] == "admin"


def test_audit_can_be_filtered(client):
    rows = client.get("/api/audit", params={"action": "login"}).json()["entries"]
    assert rows and all(a["action"] == "login" for a in rows)


# --------------------------------------------------------------------------
# groups
# --------------------------------------------------------------------------

def test_groups_are_read_from_the_allow_list(client):
    d = client.get("/api/groups").json()
    names = [g["name"] for g in d["groups"]]
    assert names == ["clash"]
    assert d["groups"][0]["active_count"] == 2
    assert d["ungrouped"] == 4
    assert "fa" in d["howto"]


def test_disabling_a_group_switches_off_every_member(client, deployment):
    p = client.post("/api/domains/preview",
                    json={"action": "group-disable", "domain": "clash",
                          "comment": "whole game got worse"},
                    headers=client.h).json()
    assert p["ok"] is True
    r = client.post("/api/domains/apply",
                    json={"token": p["token"], "confirm": "clash"},
                    headers=client.h).json()
    assert r["ok"] is True

    d = client.get("/api/groups").json()
    assert d["groups"][0]["state"] == "off"
    text = deployment.domains.read_text()
    assert "whole game got worse" in text
    assert "gs.clashofclans.com" in text, "commented out, not deleted"

    # And it goes back.
    p = client.post("/api/domains/preview",
                    json={"action": "group-enable", "domain": "clash"},
                    headers=client.h).json()
    r = client.post("/api/domains/apply",
                    json={"token": p["token"], "confirm": "clash"},
                    headers=client.h).json()
    assert r["ok"] is True
    assert client.get("/api/groups").json()["groups"][0]["state"] == "on"


def test_group_round_trip_preserves_inline_comments(client, deployment):
    for action in ("group-disable", "group-enable"):
        p = client.post("/api/domains/preview",
                        json={"action": action, "domain": "clash"},
                        headers=client.h).json()
        client.post("/api/domains/apply",
                    json={"token": p["token"], "confirm": "clash"},
                    headers=client.h)
    assert "# api" in deployment.domains.read_text()


def test_tagging_moves_an_entry_into_a_group(client):
    p = client.post("/api/domains/preview",
                    json={"action": "tag", "domain": "sg.msdkfaas.com",
                          "group": "codm"},
                    headers=client.h).json()
    assert p["ok"] is True
    client.post("/api/domains/apply",
                json={"token": p["token"], "confirm": "sg.msdkfaas.com"},
                headers=client.h)
    names = [g["name"] for g in client.get("/api/groups").json()["groups"]]
    assert "codm" in names


def test_unknown_group_is_refused_and_lists_what_exists(client):
    p = client.post("/api/domains/preview",
                    json={"action": "group-disable", "domain": "nope"},
                    headers=client.h).json()
    assert p["ok"] is False
    assert "clash" in p["blockers"][0]["en"]


def test_unknown_action_is_rejected(client):
    r = client.post("/api/domains/preview",
                    json={"action": "delete", "domain": "a.com"},
                    headers=client.h)
    assert r.status_code == 400


# --------------------------------------------------------------------------
# traffic rollups over HTTP
# --------------------------------------------------------------------------

def test_traffic_rollups_from_live_log_lines(client, deployment):
    with open(deployment.https_log, "a", encoding="utf-8") as fh:
        fh.write(access_log_line(30, "sg.msdkfaas.com", 4363, 1628))
        fh.write(access_log_line(20, "live.test.com", 500, 200))
        fh.write(access_log_line(10, "", 0, 0))
        fh.write(access_log_line(5, "live.test.com", 900, 300, "10.0.0.9"))

    def all_four_bucketed():
        d = client.get("/api/traffic", params={"hours": 1}).json()
        # Sum across buckets: four lines spanning 30 seconds can straddle a
        # bucket boundary, so the last bucket alone may hold fewer.
        return d if sum(s["conns"] for s in d["series"]) >= 4 else None

    d = wait_for(all_four_bucketed)
    assert d, "the four appended lines were never bucketed"
    assert d["problem_rate"]["problems"] >= 1
    clients = {c["client_ip"] for c in d["top_clients"]}
    assert {"84.241.45.220", "10.0.0.9"} <= clients
    snis = {s["sni"] for s in d["top_snis"]}
    assert "live.test.com" in snis
    assert "(none)" in snis, "an empty SNI must still be visible"
    assert "fa" in d["disclaimer"]


def test_traffic_can_be_filtered_to_one_client(client, deployment):
    with open(deployment.https_log, "a", encoding="utf-8") as fh:
        fh.write(access_log_line(5, "x.test", 900, 300, "10.0.0.9"))

    d = wait_for(lambda: (lambda r: r if r["series"] else None)(
        client.get("/api/traffic",
                   params={"hours": 1, "client_ip": "10.0.0.9"}).json()))
    assert d, "nothing recorded for that client"
    assert sum(s["from_origin"] for s in d["series"]) == 900


def test_traffic_rejects_a_bad_client_ip(client):
    assert client.get("/api/traffic",
                      params={"client_ip": "nope"}).status_code == 400


def test_backfill_does_not_double_count_traffic(client):
    """Startup seeds the in-memory ring from the log tail. Folding those rows
    into the buckets again on every restart would inflate the totals, so only
    the registry gets them."""
    d = client.get("/api/traffic", params={"hours": 24}).json()
    seeded = sum(s["conns"] for s in d["series"])
    reg = {r["name"] for r in client.get("/api/registry").json()["domains"]}
    assert "sg.msdkfaas.com" in reg, "the registry does get the backfill"
    assert seeded == 0, "but the rollups do not"


# --------------------------------------------------------------------------
# events over HTTP
# --------------------------------------------------------------------------

def test_events_open_for_a_down_service(client):
    d = client.get("/api/events").json()
    assert d["enabled"] is True
    fps = {e["fingerprint"] for e in d["open"]}
    # Nothing is actually running in a test environment, which is exactly the
    # condition the rules are meant to notice.
    assert any(f.startswith("service:") for f in fps), fps
    assert all("detail_fa" in e for e in d["open"])


def test_acknowledging_keeps_the_event_open(client):
    ev = client.get("/api/events").json()["open"][0]
    assert client.post("/api/events/ack", json={"id": ev["id"]},
                       headers=client.h).json()["ok"] is True
    after = [e for e in client.get("/api/events").json()["open"]
             if e["id"] == ev["id"]]
    assert after and after[0]["acked_at"] is not None


def test_notifiers_are_in_app_only_by_default(client):
    d = client.get("/api/events").json()
    assert "telegram" not in d["notifiers"]
    assert "webhook" not in d["notifiers"]


# --------------------------------------------------------------------------
# probe
# --------------------------------------------------------------------------

def test_probe_rejects_junk(client):
    for bad in ["nodot", "", "https://x.com/p"]:
        r = client.post("/api/probe", json={"domain": bad}, headers=client.h)
        assert r.status_code == 400, bad


def test_probe_rejects_a_non_ip_resolver(client):
    r = client.post("/api/probe",
                    json={"domain": "a.example.com", "resolver": "not-an-ip"},
                    headers=client.h)
    assert r.status_code == 400


def test_probe_reports_when_the_name_is_already_covered(client):
    d = client.post("/api/probe", json={"domain": "sub.example.com"},
                    headers=client.h).json()
    assert d["already_listed"] is True
    assert d["matched_suffix"] == "example.com"


def test_probe_result_is_bilingual_and_audited(client):
    d = client.post("/api/probe", json={"domain": "nothing.invalid"},
                    headers=client.h).json()
    assert "fa" in d["verdict"]
    actions = {a["action"] for a in client.get("/api/audit").json()["entries"]}
    assert "probe" in actions


def test_probe_needs_csrf(client):
    assert client.post("/api/probe",
                       json={"domain": "a.example.com"}).status_code == 403


# --------------------------------------------------------------------------
# metrics
# --------------------------------------------------------------------------

def test_metrics_needs_the_token(anon_client):
    assert anon_client.get("/metrics").status_code == 403


def test_metrics_accepts_query_or_bearer(anon_client):
    assert anon_client.get(
        "/metrics", params={"token": "test-metrics-token"}).status_code == 200
    assert anon_client.get(
        "/metrics",
        headers={"Authorization": "Bearer test-metrics-token"}).status_code == 200


def test_metrics_shape(anon_client):
    body = anon_client.get("/metrics",
                           params={"token": "test-metrics-token"}).text
    assert "# HELP smartdns_dashboard_up" in body
    assert "# TYPE smartdns_dashboard_up gauge" in body
    assert "smartdns_allowlist_entries" in body
    for line in body.splitlines():
        if line and not line.startswith("#"):
            assert " " in line, f"malformed sample: {line!r}"


def test_metrics_exposes_no_per_client_data(anon_client):
    """Per-address byte counters here would be an accounting record by the back
    door, and Prometheus keeps them far longer than the retention window."""
    body = anon_client.get("/metrics",
                           params={"token": "test-metrics-token"}).text
    assert "client_ip" not in body
    assert "84.241.45.220" not in body


def _disable_section(config_path: str, section: str) -> None:
    """Flip `enabled = true` to false in one section only."""
    with open(config_path, encoding="utf-8") as fh:
        text = fh.read()
    text = text.replace(f"[{section}]\nenabled = true",
                        f"[{section}]\nenabled = false")
    with open(config_path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _client_for(config_path: str):
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app
    from smartdns_dash.config import load
    return TestClient(create_app(load(config_path)))


def test_metrics_disabled_is_a_404(deployment):
    _disable_section(deployment.config, "metrics")
    with _client_for(deployment.config) as c:
        assert c.get("/metrics").status_code == 404


# --------------------------------------------------------------------------
# triage
# --------------------------------------------------------------------------

def test_triage_page_renders(anon_client):
    r = anon_client.get("/triage")
    assert r.status_code == 200
    assert "Permited" in r.text


def test_triage_is_honest_about_what_it_cannot_know(anon_client):
    """The router's Permited list is not readable from the server, so the page
    must present a likelihood with its evidence, never a fact."""
    d = anon_client.get("/api/triage").json()
    assert "Permited" in d["limitation"]["en"]
    assert "does not prove it" in d["limitation"]["en"]
    assert "fa" in d["limitation"]


def test_triage_only_reports_the_callers_own_address_when_anonymous(anon_client):
    d = anon_client.get("/api/triage",
                        params={"client_ip": "84.241.45.220"}).json()
    assert d["client_ip"] != "84.241.45.220"


def test_triage_lets_an_operator_ask_about_any_address(client):
    d = client.get("/api/triage", params={"client_ip": "84.241.45.220"}).json()
    assert d["client_ip"] == "84.241.45.220"
    assert d["proxied_count"] >= 1


def test_triage_rejects_a_bad_address(client):
    assert client.get("/api/triage",
                      params={"client_ip": "nope"}).status_code == 400


def test_triage_disabled_is_a_404(deployment):
    _disable_section(deployment.config, "triage")
    with _client_for(deployment.config) as c:
        assert c.get("/triage").status_code == 404
        assert c.get("/api/triage").status_code == 404


# --------------------------------------------------------------------------
# PWA
# --------------------------------------------------------------------------

def test_manifest_and_worker_are_served_and_allowed_by_the_csp(client):
    page = client.get("/")
    csp = page.headers["content-security-policy"]
    assert "manifest-src 'self'" in csp
    assert "worker-src 'self'" in csp
    assert "manifest.webmanifest" in page.text
    assert client.get("/static/manifest.webmanifest").status_code == 200
    assert client.get("/static/sw.js").status_code == 200
    assert client.get("/static/icon.svg").status_code == 200


def test_still_no_external_origins(client):
    """The box may have no outbound HTTP at all."""
    for path in ("/", "/static/app.js", "/static/style.css", "/static/sw.js"):
        body = client.get(path).text
        assert "https://" not in body.replace(
            "https://api.telegram.org", "")   # a configured notifier target
        assert "cdn" not in body.lower()


# --------------------------------------------------------------------------
# apply to both servers
# --------------------------------------------------------------------------

def test_apply_both_is_refused_without_a_peer(client):
    p = client.post("/api/domains/preview",
                    json={"action": "add", "domain": "dl.newgame.net"},
                    headers=client.h).json()
    r = client.post("/api/domains/apply-both",
                    json={"token": p["token"], "confirm": "dl.newgame.net"},
                    headers=client.h)
    assert r.status_code == 400


def test_remote_apply_script_has_its_own_rollback():
    """The peer must undo its own change if the generator fails there, because
    the local side cannot reach in and fix it."""
    from smartdns_dash.sources import peer
    assert "ROLLED_BACK" in peer.REMOTE_APPLY
    assert "cp -p \"$BAK\" \"$DOMAINS\"" in peer.REMOTE_APPLY
    # And a restart failure must be a non-zero exit, not a silent success.
    assert "exit 4" in peer.REMOTE_APPLY

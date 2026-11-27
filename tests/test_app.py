"""HTTP surface: auth, CSRF, the allow-list gate, and every read-only route."""

from __future__ import annotations

import pytest

# --------------------------------------------------------------------------
# authentication
# --------------------------------------------------------------------------

def test_index_requires_a_session(anon_client):
    r = anon_client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].endswith("/login")


def test_api_requires_a_session(anon_client):
    assert anon_client.get("/api/status").status_code == 401


def test_bad_credentials_rejected(anon_client):
    r = anon_client.post("/login", data={"username": "admin",
                                         "password": "wrong"},
                         follow_redirects=False)
    assert "Invalid" in r.headers["location"]


def test_wrong_username_rejected(anon_client, deployment):
    r = anon_client.post("/login", data={"username": "root",
                                         "password": deployment.password},
                         follow_redirects=False)
    assert "Invalid" in r.headers["location"]


def test_login_then_logout(anon_client, deployment):
    r = anon_client.post("/login", data={"username": "admin",
                                         "password": deployment.password},
                         follow_redirects=False)
    assert r.status_code == 302
    assert anon_client.get("/").status_code == 200
    anon_client.post("/logout", follow_redirects=False)
    assert anon_client.get("/", follow_redirects=False).status_code == 302


def test_login_is_rate_limited_per_source(anon_client):
    for _ in range(4):
        anon_client.post("/login", data={"username": "admin",
                                         "password": "wrong"},
                         follow_redirects=False)
    r = anon_client.post("/login", data={"username": "admin",
                                         "password": "wrong"},
                         follow_redirects=False)
    assert "Too+many" in r.headers["location"]


@pytest.mark.parametrize("forged", [
    "forged.signature",
    "eyJ1IjoiYWRtaW4ifQ.bm90YXNpZ25hdHVyZQ",
    "nodot",
    "",
])
def test_forged_cookie_is_rejected(anon_client, forged):
    """The session cookie is HMAC-signed; anything unsigned must not pass."""
    r = anon_client.get("/api/status",
                        headers={"Cookie": f"smartdns_dash={forged}"})
    assert r.status_code == 401


def test_a_cookie_signed_with_another_key_is_rejected(anon_client, cfg):
    from smartdns_dash import auth
    other = auth.make_token(auth.new_secret_key(), "admin", 12)
    r = anon_client.get("/api/status",
                        headers={"Cookie": f"smartdns_dash={other}"})
    assert r.status_code == 401


def test_an_expired_cookie_is_rejected(anon_client, cfg):
    from smartdns_dash import auth
    expired = auth.make_token(cfg.secret_key, "admin", -1)
    r = anon_client.get("/api/status",
                        headers={"Cookie": f"smartdns_dash={expired}"})
    assert r.status_code == 401


# --------------------------------------------------------------------------
# hardening
# --------------------------------------------------------------------------

def test_security_headers_present(client):
    h = client.get("/").headers
    assert h["x-frame-options"] == "DENY"
    assert h["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in h["content-security-policy"]


def test_csp_allows_no_external_scripts(client):
    """The box may have no outbound HTTP at all, and a dashboard that needs a
    CDN to render is useless there."""
    csp = client.get("/").headers["content-security-policy"]
    assert "script-src 'self'" in csp
    page = client.get("/").text
    assert "http://" not in page.replace("http://127.0.0.1", "")
    assert "cdn" not in page.lower()


@pytest.mark.parametrize("path,body", [
    ("/api/domains/preview", {"action": "add", "domain": "a.example.com"}),
    ("/api/watch", {"client_ip": "1.2.3.4"}),
    ("/api/peer/paste", {"text": "a.com"}),
    ("/api/portwatch", {"action": "start"}),
    ("/api/backups/restore", {"name": "x", "confirm": "RESTORE"}),
])
def test_state_changing_routes_need_csrf(client, path, body):
    assert client.post(path, json=body).status_code == 403


def test_backup_path_traversal_blocked(client):
    for name in ["../../etc/passwd", "/etc/passwd", ".hidden"]:
        r = client.get("/api/backups/diff", params={"name": name})
        assert r.status_code in (400, 404), name


def test_unknown_log_is_404(client):
    assert client.get("/api/logs/etc-passwd").status_code == 404


def test_watch_rejects_non_addresses(client):
    r = client.post("/api/watch", json={"client_ip": "not-an-ip"},
                    headers=client.h)
    assert r.status_code == 400


# --------------------------------------------------------------------------
# read-only routes
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/api/status", "/api/feed", "/api/clients", "/api/domains",
    "/api/backups", "/api/changes", "/api/portwatch", "/api/peer/probe",
    "/api/watch", "/api/dnsdist/top", "/api/dnsdist/servers", "/api/doctor",
])
def test_read_routes_are_200(client, path):
    assert client.get(path).status_code == 200


def test_healthz_needs_no_auth(anon_client):
    assert anon_client.get("/healthz").text == "ok"


def test_feed_parsed_the_seed_log(client):
    rows = client.get("/api/feed").json()["rows"]
    snis = {r["sni"] for r in rows}
    assert "sg.msdkfaas.com" in snis
    assert any(r["problem"] for r in rows)      # the NONE/empty-SNI line


def test_feed_filters(client):
    assert client.get("/api/feed",
                      params={"client_ip": "9.9.9.9"}).json()["rows"] == []
    only = client.get("/api/feed", params={"problems_only": True}).json()["rows"]
    assert only and all(r["problem"] for r in only)


def test_clients_list_is_derived_from_the_feed(client):
    ips = [c["client_ip"] for c in client.get("/api/clients").json()["clients"]]
    assert "84.241.45.220" in ips


def test_domains_route_reports_issues(client):
    d = client.get("/api/domains").json()
    assert [e["suffix"] for e in d["entries"]][:2] == \
        ["sg.msdkfaas.com", "west-tdm.codmwest.com"]
    assert d["redundant"] == [["west-tdm.codmwest.com", "codmwest.com"]]


def test_client_view_combines_both_sides(client):
    d = client.get("/api/client/84.241.45.220").json()
    assert len(d["proxy_rows"]) == 2
    assert "grepq" in d
    # bilingual hint about the MikroTik Permited list
    assert "en" in d["permitted_hint"] and "fa" in d["permitted_hint"]


# --------------------------------------------------------------------------
# identity resolution
# --------------------------------------------------------------------------

def test_spoof_target_read_from_the_dnsdist_config(client):
    """Nothing is hard-coded: the address listed domains resolve to is read
    back out of the generated config, so a clone needs no edit."""
    srv = client.get("/api/status").json()["server"]
    assert srv["spoof_ip"] == "203.0.113.7"
    assert "dnsdist.conf" in srv["spoof_source"]


def test_changing_the_generated_config_changes_the_spoof_target(deployment):
    from smartdns_dash.config import load
    deployment.dnsdist_conf.write_text(
        deployment.dnsdist_conf.read_text().replace("203.0.113.7",
                                                    "198.51.100.9"))
    assert load(deployment.config).spoof_ip == "198.51.100.9"


def test_name_falls_back_to_hostname(cfg):
    import socket
    assert cfg.display_name == socket.gethostname()


# --------------------------------------------------------------------------
# lookup
# --------------------------------------------------------------------------

def test_lookup_explains_a_matching_suffix(client):
    d = client.get("/api/lookup",
                   params={"name": "west-tdm.codmwest.com"}).json()
    assert d["is_proxied"] is True
    assert d["matched_suffix"] == "west-tdm.codmwest.com"
    assert "en" in d["verdict"] and "fa" in d["verdict"]
    assert d["spoof_ip"] == "203.0.113.7"


def test_lookup_on_an_unlisted_name(client):
    d = client.get("/api/lookup",
                   params={"name": "totally.unlisted.example.org"}).json()
    assert d["is_proxied"] is False
    assert d["matched_suffix"] is None


def test_lookup_reports_covering_suffixes(client):
    d = client.get("/api/lookup", params={"name": "x.codmwest.com"}).json()
    assert d["matched_suffix"] == "codmwest.com"
    assert "codmwest.com" in d["covering_candidates"]


def test_lookup_rejects_a_non_ip_resolver(client):
    r = client.get("/api/lookup", params={"name": "a.com",
                                          "resolver": "not-an-ip"})
    assert r.status_code == 400


# --------------------------------------------------------------------------
# guarded write path over HTTP
# --------------------------------------------------------------------------

def test_preview_refuses_a_covered_domain(client):
    d = client.post("/api/domains/preview",
                    json={"action": "add", "domain": "sub.codmwest.com"},
                    headers=client.h).json()
    assert d["ok"] is False
    assert d["blockers"][0]["fa"]


def test_preview_warns_on_a_bare_root(client):
    d = client.post("/api/domains/preview",
                    json={"action": "add", "domain": "newgame.net"},
                    headers=client.h).json()
    assert d["ok"] is True
    assert len(d["warnings"]) >= 2


def test_apply_requires_the_typed_domain(client):
    p = client.post("/api/domains/preview",
                    json={"action": "add", "domain": "dl.newgame.net"},
                    headers=client.h).json()
    bad = client.post("/api/domains/apply",
                      json={"token": p["token"], "confirm": "wrong"},
                      headers=client.h)
    assert bad.status_code == 400
    # a typo must not burn the plan
    good = client.post("/api/domains/apply",
                       json={"token": p["token"],
                             "confirm": "dl.newgame.net"},
                       headers=client.h)
    assert good.status_code == 200


def test_apply_with_an_unknown_token_is_refused(client):
    r = client.post("/api/domains/apply",
                    json={"token": "nope", "confirm": "a.com"},
                    headers=client.h)
    assert r.status_code == 400


def test_applied_change_appears_in_the_history(client, deployment):
    p = client.post("/api/domains/preview",
                    json={"action": "add", "domain": "dl.newgame.net",
                          "comment": "from a test"},
                    headers=client.h).json()
    client.post("/api/domains/apply",
                json={"token": p["token"], "confirm": "dl.newgame.net"},
                headers=client.h)
    changes = client.get("/api/changes").json()["changes"]
    assert changes[0]["target"] == "dl.newgame.net"
    assert "from a test" in deployment.domains.read_text()


def test_preview_rejects_an_unknown_action(client):
    r = client.post("/api/domains/preview",
                    json={"action": "delete", "domain": "a.com"},
                    headers=client.h)
    assert r.status_code == 400


# --------------------------------------------------------------------------
# peer diff
# --------------------------------------------------------------------------

def test_peer_probe_when_disabled(client):
    d = client.get("/api/peer/probe").json()
    assert d["enabled"] is False
    assert "fa" in d["message"]


def test_paste_mode_diff(client):
    d = client.post("/api/peer/paste",
                    json={"text": "codmwest.com\nzz.example.com # note\n"},
                    headers=client.h).json()
    assert d["in_sync"] is False
    assert d["only_theirs"] == ["zz.example.com"]
    assert "sg.msdkfaas.com" in d["only_mine"]
    assert "fa" in d["message"]


def test_paste_mode_in_sync(client, deployment):
    same = deployment.domains.read_text()
    d = client.post("/api/peer/paste", json={"text": same},
                    headers=client.h).json()
    assert d["in_sync"] is True


def test_paste_rejects_an_implausible_payload(client):
    r = client.post("/api/peer/paste", json={"text": "x" * 2_000_001},
                    headers=client.h)
    assert r.status_code == 400


def test_ssh_diff_unavailable_when_peer_disabled(client):
    assert client.get("/api/peer/diff").status_code == 400


# --------------------------------------------------------------------------
# port watcher is opt-in
# --------------------------------------------------------------------------

def test_portwatch_cannot_be_started_when_disabled(client):
    r = client.post("/api/portwatch", json={"action": "start"},
                    headers=client.h)
    assert r.status_code == 403


def test_portwatch_status_readable_when_disabled(client):
    d = client.get("/api/portwatch").json()
    assert d["running"] is False
    assert d["config_enabled"] is False


# --------------------------------------------------------------------------
# i18n
# --------------------------------------------------------------------------

def test_page_carries_both_language_options(client):
    page = client.get("/").text
    assert 'data-lang="en"' in page
    assert 'data-lang="fa"' in page


def test_login_page_renders_in_persian(cfg, anon_client):
    cfg.language = "fa"
    page = anon_client.get("/login").text
    assert "رمز عبور" in page
    assert 'dir="rtl"' in page


def test_generated_messages_are_bilingual(client):
    st = client.get("/api/status").json()
    assert set(st["staleness"]["message"]) >= {"en", "fa"}

"""Config loading, port safety, proxy handling, and the IP allow-list.

The port tests are the important ones here. This dashboard is a guest on a box
whose job is DNS; taking a port the resolver needs would break the very thing
it exists to observe.
"""

from __future__ import annotations

import re

import pytest

from smartdns_dash import config as cfgmod
from smartdns_dash import preflight
from smartdns_dash.config import ConfigError, load


def _rewrite(path, **kv):
    """Rewrite `key = value` lines in a test config."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for k, v in kv.items():
        text = re.sub(rf"^{k} *=.*$", f"{k} = {v}", text, flags=re.M)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# --------------------------------------------------------------------------
# port safety
# --------------------------------------------------------------------------

@pytest.mark.parametrize("port", sorted(preflight.RESERVED))
def test_dns_stack_ports_are_refused_outright(deployment, port):
    _rewrite(deployment.config, port=port)
    with pytest.raises(ConfigError) as e:
        load(deployment.config)
    assert str(port) in str(e.value)


@pytest.mark.parametrize("port", [53, 80, 443, 5199, 8083, 9100, 22])
def test_the_specific_ports_that_would_break_the_service(port):
    v = preflight.check_port(port)
    assert v["fatal"], f"port {port} must be refused"


def test_a_high_port_is_accepted(deployment):
    _rewrite(deployment.config, port=19443)
    assert load(deployment.config).port == 19443


def test_game_range_is_discouraged_but_not_fatal():
    v = preflight.check_port(8085)
    assert v["fatal"] is None or "in use" in v["fatal"]
    assert any("8000-8100" in w for w in v["warnings"])


def test_privileged_range_is_flagged():
    v = preflight.check_port(1024 - 1)
    assert v["fatal"] or v["warnings"]


def test_occupied_port_is_detected():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        v = preflight.check_port(port, "127.0.0.1")
        assert v["fatal"] and "in use" in v["fatal"]
    finally:
        s.close()


def test_pick_free_port_avoids_reserved():
    p = preflight.pick_free_port("127.0.0.1")
    assert p is not None
    assert p not in preflight.RESERVED


def test_preferred_ports_are_all_clear_of_reserved():
    assert not set(preflight.PREFERRED) & set(preflight.RESERVED)


def test_doctor_runs_and_reports_structure(cfg):
    d = preflight.run(cfg)
    assert set(d) >= {"port", "dns_stack", "listeners", "paths", "tools",
                      "console_key", "spoof_ip"}
    labels = {p["label"] for p in d["paths"]}
    assert "domains.txt" in labels and "dnsdist.conf" in labels
    assert d["console_key"] is True


def test_doctor_flags_an_unreadable_required_path(cfg, deployment):
    deployment.domains.unlink()
    rows = {p["label"]: p for p in preflight.path_checks(cfg)}
    assert rows["domains.txt"]["ok"] is False
    assert rows["domains.txt"]["fatal"] is True


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------

def test_public_bind_needs_an_acknowledgement(deployment):
    _rewrite(deployment.config, bind="0.0.0.0")
    with pytest.raises(ConfigError) as e:
        load(deployment.config)
    assert "behind_proxy" in str(e.value)


def test_public_bind_with_behind_proxy_is_fine(deployment):
    _rewrite(deployment.config, bind="0.0.0.0", behind_proxy="true")
    assert load(deployment.config).behind_proxy is True


def test_public_bind_with_exposed_is_fine(deployment):
    _rewrite(deployment.config, bind="0.0.0.0", exposed="true")
    assert load(deployment.config).exposed is True


def test_short_secret_is_refused(deployment):
    _rewrite(deployment.config, secret_key="tooshort")
    with pytest.raises(ConfigError):
        load(deployment.config)


def test_missing_password_hash_is_refused(deployment):
    _rewrite(deployment.config, password_hash="")
    with pytest.raises(ConfigError):
        load(deployment.config)


def test_half_configured_tls_is_refused(deployment):
    _rewrite(deployment.config, tls_cert="/tmp/cert.pem")
    with pytest.raises(ConfigError) as e:
        load(deployment.config)
    assert "tls_key" in str(e.value)


def test_warning_for_plain_http_on_a_public_bind(deployment):
    _rewrite(deployment.config, bind="0.0.0.0", exposed="true")
    c = load(deployment.config)
    warns = " ".join(cfgmod.warnings(c))
    assert "clear" in warns
    assert "allow_ips" in warns


def test_warning_for_wildcard_forwarded_allow_ips(deployment):
    _rewrite(deployment.config, bind="0.0.0.0", behind_proxy="true",
             forwarded_allow_ips="*")
    warns = " ".join(cfgmod.warnings(load(deployment.config)))
    assert "spoof" in warns


# --------------------------------------------------------------------------
# env file parsing
# --------------------------------------------------------------------------

def test_env_parsing_handles_quotes_export_and_comments(tmp_path):
    f = tmp_path / "smartdns.env"
    f.write_text(
        "# comment\n"
        'export SMARTDNS_DNSDIST_KEY="abc+def/ghi="\n'
        "PLAIN=value with spaces # trailing comment\n"
        "SINGLE='quoted value'\n"
        "not_a_line\n")
    env = cfgmod.read_env_file(str(f))
    assert env["SMARTDNS_DNSDIST_KEY"] == "abc+def/ghi="
    assert env["PLAIN"] == "value with spaces"
    assert env["SINGLE"] == "quoted value"


def test_missing_env_file_is_not_fatal(tmp_path):
    assert cfgmod.read_env_file(str(tmp_path / "nope")) == {}


# --------------------------------------------------------------------------
# identity resolution
# --------------------------------------------------------------------------

def test_spoof_detection_prefers_the_spoof_directive(tmp_path):
    f = tmp_path / "dnsdist.conf"
    f.write_text('newServer({address="8.8.8.8:53"})\n'
                 'addAction(x, SpoofAction("203.0.113.7"))\n')
    ip, src = cfgmod.detect_spoof_ip(str(f), "")
    assert ip == "203.0.113.7"
    assert "spoof" in src


def test_spoof_detection_ignores_upstream_resolvers(tmp_path):
    f = tmp_path / "dnsdist.conf"
    f.write_text('newServer({address="1.1.1.1:53"})\n'
                 'newServer({address="8.8.4.4:53"})\n')
    ip, _ = cfgmod.detect_spoof_ip(str(f), "")
    assert ip == ""


def test_spoof_detection_ignores_private_addresses(tmp_path):
    f = tmp_path / "dnsdist.conf"
    f.write_text('setLocal("0.0.0.0:53")\nlocal x = "172.20.46.2"\n')
    ip, _ = cfgmod.detect_spoof_ip(str(f), "")
    assert ip == ""


def test_explicit_public_ip_wins_over_detection(deployment):
    _rewrite(deployment.config, public_ip="1.2.3.4")
    c = load(deployment.config)
    assert c.spoof_ip == "1.2.3.4"
    assert c.spoof_source == "config"


def test_self_ips_includes_the_spoof_target(cfg):
    assert "203.0.113.7" in cfg.self_ips()


# --------------------------------------------------------------------------
# IP allow-list
# --------------------------------------------------------------------------

@pytest.mark.parametrize("allow,addr,expected", [
    ("", "9.9.9.9", True),                       # empty = unrestricted
    ("203.0.113.45", "203.0.113.45", True),
    ("203.0.113.45", "203.0.113.46", False),
    ("10.8.0.0/24", "10.8.0.7", True),
    ("10.8.0.0/24", "10.9.0.7", False),
    ("203.0.113.45, 10.8.0.0/24", "10.8.0.1", True),
    ("203.0.113.45", "not-an-ip", False),
    ("garbage", "203.0.113.45", False),
])
def test_allowed_client(deployment, allow, addr, expected):
    _rewrite(deployment.config, allow_ips=allow)
    c = load(deployment.config)
    assert cfgmod.allowed_client(c, addr) is expected


def test_allowlist_middleware_blocks_before_auth(deployment):
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app
    _rewrite(deployment.config, allow_ips="203.0.113.45")
    with TestClient(create_app(load(deployment.config))) as c:
        # TestClient's peer is "testclient", which is not in the list.
        assert c.get("/login").status_code == 403
        assert c.get("/healthz").status_code == 403


def test_allowlist_permits_a_listed_source(deployment):
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app
    _rewrite(deployment.config, allow_ips="testclient, 203.0.113.45")
    c = load(deployment.config)
    # "testclient" is not an IP so allowed_client rejects it; assert the real
    # behaviour rather than pretending otherwise.
    assert cfgmod.allowed_client(c, "203.0.113.45") is True
    with TestClient(create_app(c)) as tc:
        assert tc.get("/healthz").status_code == 403


# --------------------------------------------------------------------------
# reverse proxy
# --------------------------------------------------------------------------

def test_forwarded_for_is_trusted_only_from_an_allowed_proxy(deployment):
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app
    _rewrite(deployment.config, bind="0.0.0.0", behind_proxy="true",
             forwarded_allow_ips="testclient", max_login_attempts="2")
    with TestClient(create_app(load(deployment.config))) as c:
        for _ in range(3):
            c.post("/login", data={"username": "admin", "password": "x"},
                   headers={"X-Forwarded-For": "203.0.113.9"},
                   follow_redirects=False)
        locked = c.post("/login", data={"username": "admin", "password": "x"},
                        headers={"X-Forwarded-For": "203.0.113.9"},
                        follow_redirects=False)
        other = c.post("/login", data={"username": "admin", "password": "x"},
                       headers={"X-Forwarded-For": "198.51.100.4"},
                       follow_redirects=False)
    assert "Too+many" in locked.headers["location"]
    assert "Invalid" in other.headers["location"], \
        "one client's lockout must not affect another"


def test_forged_forwarded_for_is_ignored_from_an_untrusted_peer(deployment):
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app
    _rewrite(deployment.config, bind="0.0.0.0", behind_proxy="true",
             forwarded_allow_ips="10.0.0.1", max_login_attempts="2")
    with TestClient(create_app(load(deployment.config))) as c:
        for i in range(3):
            c.post("/login", data={"username": "admin", "password": "x"},
                   headers={"X-Forwarded-For": f"8.8.8.{i}"},
                   follow_redirects=False)
        r = c.post("/login", data={"username": "admin", "password": "x"},
                   headers={"X-Forwarded-For": "9.9.9.9"},
                   follow_redirects=False)
    assert "Too+many" in r.headers["location"], \
        "a client must not mint a fresh rate-limit bucket per guess"


def test_secure_cookie_behind_a_tls_proxy(deployment):
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app
    _rewrite(deployment.config, bind="0.0.0.0", behind_proxy="true")
    with TestClient(create_app(load(deployment.config))) as c:
        r = c.post("/login",
                   data={"username": "admin", "password": deployment.password},
                   follow_redirects=False)
    assert "Secure" in r.headers.get("set-cookie", "")


def test_root_path_prefixes_assets_and_redirects(deployment):
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app
    _rewrite(deployment.config, root_path="/dns")
    with TestClient(create_app(load(deployment.config))) as c:
        login = c.get("/login")
        assert "/dns/static/style.css" in login.text
        assert 'action="/dns/login"' in login.text
        r = c.post("/login",
                   data={"username": "admin", "password": deployment.password},
                   follow_redirects=False)
        assert r.headers["location"] == "/dns/"
        assert "Path=/dns/" in r.headers["set-cookie"]
        token = re.search(r"smartdns_dash=([^;]+)", r.headers["set-cookie"]).group(1)
        page = c.get("/", headers={"Cookie": "smartdns_dash=" + token})
        assert 'data-base="/dns"' in page.text
        assert "/dns/static/app.js" in page.text


def test_no_root_path_leaves_urls_clean(client):
    page = client.get("/").text
    assert 'src="/static/app.js"' in page
    assert 'data-base=""' in page

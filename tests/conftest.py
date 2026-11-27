"""Shared fixtures: a throwaway deployment on disk, and a logged-in client.

Every test that needs the app gets its own temporary tree - config, allow-list,
logs, a stub dnsdist.conf, a fake update script - so nothing here ever touches
a real /etc or restarts a real service.
"""

from __future__ import annotations

import re
import textwrap

import pytest

from smartdns_dash import auth

PASSWORD = "correct horse battery staple"
VIEWER_PASSWORD = "read only account password"

REFERENCE_LINE = (
    "2026-08-02 15:17:14 84.241.45.220:39460 -> 172.20.46.2:443 -> "
    "129.226.1.156:443 [sg.msdkfaas.com] 4363/4363 bytes tx 1628/1628 "
    "bytes rx 0.751 seconds"
)
NO_SNI_LINE = (
    "2026-08-02 15:17:20 84.241.45.220:39461 -> 172.20.46.2:443 -> NONE "
    "[] 0/0 bytes tx 0/0 bytes rx 0.002 seconds"
)

DOMAINS = textwrap.dedent("""\
    # allow-list
    sg.msdkfaas.com
    west-tdm.codmwest.com   # tdm matchmaking
    codmwest.com
    example.com

    # @group clash
    gs.clashofclans.com
    api.clashofclans.com   # api
    # @endgroup
    """)

# A stub of what update-smartdns.sh generates. The spoof address in here is the
# authoritative source for `public_ip = auto`.
DNSDIST_CONF = textwrap.dedent("""\
    -- generated, do not edit
    setLocal("0.0.0.0:53")
    newServer({address="1.1.1.1:53", pool="upstream"})
    newServer({address="8.8.8.8:53", pool="upstream"})
    proxyNames = newSuffixMatchNode()
    proxyNames:add(newDNSName("sg.msdkfaas.com"))
    addAction(SuffixMatchNodeRule(proxyNames), SpoofAction("203.0.113.7"))
    webserver("127.0.0.1:8083")
    controlSocket("127.0.0.1:5199")
    """)


@pytest.fixture
def deployment(tmp_path):
    """A complete fake deployment. Returns an object with paths + config path."""
    etc = tmp_path / "etc"
    logs = tmp_path / "log"
    bk = tmp_path / "backups"
    for d in (etc, logs, bk):
        d.mkdir(parents=True, exist_ok=True)

    (etc / "domains.txt").write_text(DOMAINS)
    (etc / "dnsdist.conf").write_text(DNSDIST_CONF)
    (etc / "smartdns.env").write_text(
        'export SMARTDNS_DNSDIST_KEY="abc123+key/with=chars"\n')
    (logs / "https_access.log").write_text(
        REFERENCE_LINE + "\n" + NO_SNI_LINE + "\n")
    (logs / "http_access.log").write_text("")

    upd = tmp_path / "update.sh"
    upd.write_text("#!/bin/sh\necho regenerated\nexit 0\n")
    upd.chmod(0o755)

    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text(textwrap.dedent(f"""\
        [server]
        name = auto
        public_ip = auto
        local_ip = auto
        bind = 127.0.0.1
        port = 19443
        exposed = false
        behind_proxy = false
        forwarded_allow_ips = 127.0.0.1
        allow_ips =
        tls_cert =
        tls_key =
        root_path =
        language = en

        [auth]
        username = admin
        password_hash = {auth.hash_password(PASSWORD)}
        viewer_username = viewer
        viewer_password_hash = {auth.hash_password(VIEWER_PASSWORD)}
        secret_key = {auth.new_secret_key()}
        session_hours = 12
        max_login_attempts = 3

        [paths]
        domains = {etc / 'domains.txt'}
        generated_proxy = {etc / 'domains.proxy'}
        dnsdist_conf = {etc / 'dnsdist.conf'}
        sniproxy_conf = {etc / 'sniproxy.conf'}
        env_file = {etc / 'smartdns.env'}
        update_script = {upd}
        backup_dir = {bk}
        https_log = {logs / 'https_access.log'}
        http_log = {logs / 'http_access.log'}
        error_log = {logs / 'error.log'}
        update_log = {logs / 'update.log'}

        [dnsdist]
        console = 127.0.0.1:5199
        key_var = SMARTDNS_DNSDIST_KEY
        grepq_limit = 100
        api_url =

        [services]
        restart = none
        staleness_unit = sniproxy

        [peer]
        enabled = false
        name = PEER-01
        host =

        [poll]
        log_ms = 200
        grepq_ms = 60000
        status_ms = 60000
        feed_ring = 500

        [portwatch]
        enabled = false

        [history]
        enabled = true
        path = {tmp_path / 'history.db'}
        retention_days = 14

        [alerts]
        enabled = true
        log = false

        [probe]
        enabled = true

        [metrics]
        enabled = true
        token = test-metrics-token

        [triage]
        enabled = true
        """))

    class D:
        pass

    d = D()
    d.root = tmp_path
    d.config = str(cfg_path)
    d.domains = etc / "domains.txt"
    d.dnsdist_conf = etc / "dnsdist.conf"
    d.https_log = logs / "https_access.log"
    d.backups = bk
    d.update_script = upd
    d.password = PASSWORD
    d.viewer_password = VIEWER_PASSWORD
    d.history = tmp_path / "history.db"
    d.logs = logs
    return d


@pytest.fixture
def cfg(deployment):
    from smartdns_dash.config import load
    return load(deployment.config)


@pytest.fixture
def client(cfg):
    """A TestClient wrapping the real app, already logged in.

    `csrf` is attached so state-changing tests do not each have to scrape it
    out of the page.
    """
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app

    with TestClient(create_app(cfg)) as c:
        c.post("/login", data={"username": "admin", "password": PASSWORD})
        page = c.get("/")
        m = re.search(r'data-csrf="([^"]+)"', page.text)
        c.csrf = m.group(1) if m else ""
        c.h = {"X-CSRF-Token": c.csrf}
        yield c


@pytest.fixture
def anon_client(cfg):
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app

    with TestClient(create_app(cfg)) as c:
        yield c


@pytest.fixture
def viewer_client(cfg):
    """Logged in as the read-only account."""
    from fastapi.testclient import TestClient

    from smartdns_dash.app import create_app

    with TestClient(create_app(cfg)) as c:
        c.post("/login", data={"username": "viewer",
                               "password": VIEWER_PASSWORD})
        page = c.get("/")
        m = re.search(r'data-csrf="([^"]+)"', page.text)
        c.csrf = m.group(1) if m else ""
        c.h = {"X-CSRF-Token": c.csrf}
        yield c


def wait_for(predicate, timeout: float = 8.0, interval: float = 0.1):
    """Poll until `predicate()` returns something truthy, then return it.

    The background pollers are asynchronous, so a fixed sleep is a race that
    passes alone and fails under load. Returns None on timeout so the caller's
    own assertion produces the useful message.
    """
    import time as _time
    deadline = _time.monotonic() + timeout
    while _time.monotonic() < deadline:
        got = predicate()
        if got:
            return got
        _time.sleep(interval)
    return None


def access_log_line(seconds_ago: float, sni: str, from_origin: int,
                    to_origin: int, client: str = "84.241.45.220") -> str:
    """A log line stamped relative to now.

    Fixed timestamps would fall outside the rollup query windows, which is a
    trap worth not falling into twice.
    """
    import datetime
    ts = (datetime.datetime.now()
          - datetime.timedelta(seconds=seconds_ago)).strftime(
              "%Y-%m-%d %H:%M:%S")
    origin = "NONE" if not sni else "129.226.1.156:443"
    return (f"{ts} {client}:39460 -> 172.20.46.2:443 -> {origin} "
            f"[{sni}] {from_origin}/{from_origin} bytes tx "
            f"{to_origin}/{to_origin} bytes rx 0.751 seconds\n")

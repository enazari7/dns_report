"""Configuration loading for the Smart DNS dashboard.

Stdlib only. The config file is a plain INI read once at startup; the dnsdist
console key is read from /etc/smartdns/smartdns.env on every use so that a key
rotation does not require restarting the dashboard.
"""

from __future__ import annotations

import configparser
import ipaddress
import os
import re
import shlex
import socket
import subprocess
from dataclasses import dataclass, field

DEFAULT_CONFIG_PATH = "/etc/smartdns-dashboard/config.ini"

LOOPBACK = ("127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1")


class ConfigError(Exception):
    pass


@dataclass
class Config:
    path: str

    # [server]
    name: str = ""
    public_ip: str = "auto"
    local_ip: str = "auto"
    bind: list[str] = field(default_factory=lambda: ["127.0.0.1"])
    port: int = 9443
    exposed: bool = False
    tls_cert: str = ""
    tls_key: str = ""
    behind_proxy: bool = False
    forwarded_allow_ips: str = "127.0.0.1"
    allow_ips: list[str] = field(default_factory=list)
    root_path: str = ""
    language: str = "en"

    # [auth]
    username: str = "admin"
    password_hash: str = ""
    secret_key: str = ""
    session_hours: int = 12
    max_login_attempts: int = 5
    # A second credential that can see everything and change nothing. Useful
    # when someone else needs to look without being able to break anything.
    viewer_username: str = ""
    viewer_password_hash: str = ""

    # [history]
    history_enabled: bool = True
    history_path: str = "/var/lib/smartdns-dashboard/history.db"
    history_retention_days: int = 14

    # [alerts]
    alerts_enabled: bool = True
    alerts_log: bool = True
    alerts_problem_threshold: float = 0.25
    alerts_min_severity: str = "warning"
    alerts_webhook_url: str = ""
    alerts_webhook_template: str = ""
    alerts_telegram_token: str = ""
    alerts_telegram_chat: str = ""

    # [probe]
    probe_enabled: bool = True
    probe_resolver: str = "1.1.1.1"
    probe_timeout: float = 4.0

    # [metrics]
    metrics_enabled: bool = False
    metrics_token: str = ""

    # [triage]
    triage_enabled: bool = False

    # [paths]
    domains: str = "/etc/smartdns/domains.txt"
    generated_proxy: str = "/etc/smartdns/generated/domains.proxy"
    dnsdist_conf: str = "/etc/dnsdist/dnsdist.conf"
    sniproxy_conf: str = "/etc/sniproxy.conf"
    env_file: str = "/etc/smartdns/smartdns.env"
    update_script: str = "/usr/local/bin/update-smartdns.sh"
    backup_dir: str = "/root/smartdns-backups"
    https_log: str = "/var/log/sniproxy/https_access.log"
    http_log: str = "/var/log/sniproxy/http_access.log"
    error_log: str = "/var/log/sniproxy/error.log"
    update_log: str = "/var/log/smartdns/update.log"

    # [dnsdist]
    console: str = "127.0.0.1:5199"
    key_var: str = "SMARTDNS_DNSDIST_KEY"
    grepq_limit: int = 600
    api_url: str = ""
    api_key_var: str = "SMARTDNS_DNSDIST_API_KEY"

    # [services]
    restart: list[str] = field(default_factory=lambda: ["sniproxy", "dnsdist"])
    staleness_unit: str = "sniproxy"

    # [peer]
    peer_enabled: bool = False
    peer_name: str = "peer"
    peer_host: str = ""
    peer_ssh_user: str = "root"
    peer_ssh_port: int = 22
    peer_ssh_key: str = ""
    peer_ssh_timeout: int = 8

    # [poll]
    log_ms: int = 1000
    grepq_ms: int = 5000
    status_ms: int = 15000
    feed_ring: int = 2000

    # [portwatch]
    pw_enabled: bool = False
    pw_interface: str = "any"
    pw_ignore_ports: list[int] = field(default_factory=lambda: [53, 80, 443])
    pw_timeout_s: float = 3.0
    pw_max_runtime_s: int = 900

    # -- identity, resolved lazily -------------------------------------
    # Nothing about this deployment is hard-coded. Clone the VM, change the
    # addresses, and these resolve to the new values with no code change.
    _resolved_local: str | None = None
    _resolved_spoof: str | None = None
    _spoof_source: str = ""

    @property
    def resolved_local_ip(self) -> str:
        """The address of this box. `auto` picks the first global IPv4."""
        if self._resolved_local is None:
            v = (self.local_ip or "").strip()
            if v and v.lower() != "auto":
                self._resolved_local = v
            else:
                addrs = local_addresses()
                self._resolved_local = addrs[0] if addrs else "127.0.0.1"
        return self._resolved_local

    @property
    def spoof_ip(self) -> str:
        """The address listed hosts are spoofed to.

        On this topology the public address lives on the MikroTik, not on the
        server, so it cannot be read off an interface. It *is* written into
        the generated dnsdist config, which is the authoritative source - so
        `auto` reads it from there and a cloned server picks up its own value
        without anyone editing the dashboard config.
        """
        if self._resolved_spoof is None:
            v = (self.public_ip or "").strip()
            if v and v.lower() != "auto":
                self._resolved_spoof = v
                self._spoof_source = "config"
            else:
                found, src = detect_spoof_ip(self.dnsdist_conf,
                                             self.generated_proxy)
                if found:
                    self._resolved_spoof = found
                    self._spoof_source = src
                else:
                    self._resolved_spoof = ""
                    self._spoof_source = "unknown"
        return self._resolved_spoof

    @property
    def spoof_source(self) -> str:
        _ = self.spoof_ip          # force lazy resolution
        return self._spoof_source

    def self_ips(self) -> set[str]:
        """Every address that counts as "us" when judging a DNS answer."""
        out = set(local_addresses())
        if self.spoof_ip:
            out.add(self.spoof_ip)
        out.add(self.resolved_local_ip)
        return {a for a in out if a}

    @property
    def display_name(self) -> str:
        if self.name and self.name.lower() != "auto":
            return self.name
        return socket.gethostname() or "smartdns"

    @property
    def is_public_bind(self) -> bool:
        return any(b not in LOOPBACK for b in self.bind)

    @property
    def serving_https(self) -> bool:
        return bool(self.tls_cert and self.tls_key)

    # ------------------------------------------------------------------
    @property
    def log_files(self) -> dict[str, str]:
        """Access logs to tail, keyed by the label shown in the UI."""
        out = {}
        if self.https_log:
            out["https"] = self.https_log
        if self.http_log:
            out["http"] = self.http_log
        return out

    def env(self) -> dict[str, str]:
        """Parse smartdns.env fresh. Returns {} if unreadable."""
        return read_env_file(self.env_file)

    def dnsdist_key(self) -> str | None:
        return self.env().get(self.key_var) or None

    def dnsdist_api_key(self) -> str | None:
        env = self.env()
        return env.get(self.api_key_var) or env.get(self.key_var) or None


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def local_addresses() -> list[str]:
    """Global-scope IPv4 addresses on this host, most-likely-primary first."""
    out: list[str] = []
    try:
        proc = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True, text=True, timeout=5)
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3].split("/")[0]
                if addr and addr not in out:
                    out.append(addr)
    except (OSError, subprocess.SubprocessError):
        pass
    if not out:
        # Fallback that needs no external command and sends no packets.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
            out.append(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    return out


def detect_spoof_ip(dnsdist_conf: str, generated_proxy: str) -> tuple:
    """Read the spoof target out of the generated dnsdist config.

    Returns (ip, source). This is what makes the dashboard portable: the
    address listed domains resolve to is decided by the smartdns generator,
    not by us, so we read it back rather than asking the operator to keep two
    places in sync.
    """
    locals_ = set(local_addresses())
    for path in (dnsdist_conf,):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        # An explicit spoof directive is authoritative: whatever the generator
        # wrote there IS the answer, so only obviously-impossible addresses are
        # rejected. Being fussy here would break lab and documentation ranges.
        for m in re.finditer(r"[Ss]poof\w*\s*\(([^)]*)\)", text):
            for c in _IPV4.findall(m.group(1)):
                if _explicit_ok(c, locals_):
                    return c, f"{path} (spoof)"
        # Fall back to any address that is neither loopback, nor an upstream
        # resolver, nor one of our own interfaces.
        counts: dict[str, int] = {}
        for c in _IPV4.findall(text):
            if _usable_public(c, locals_):
                counts[c] = counts.get(c, 0) + 1
        if counts:
            best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            return best, f"{path} (inferred)"
    return "", "unknown"


_KNOWN_RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                    "9.9.9.9", "149.112.112.112", "208.67.222.222"}


def _explicit_ok(addr: str, locals_: set[str]) -> bool:
    """Accept an address named in a spoof directive unless it is meaningless
    there: loopback, unspecified, multicast, or one of our own interfaces
    (which would mean the client never leaves this host)."""
    if addr in locals_:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    # RFC1918 is legitimate on a purely internal deployment, so only addresses
    # that could never be a spoof target are rejected.
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)


def _usable_public(addr: str, locals_: set[str]) -> bool:
    if addr in _KNOWN_RESOLVERS or addr in locals_:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_private or ip.is_multicast
                or ip.is_unspecified or ip.is_reserved or ip.is_link_local)


_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def read_env_file(path: str) -> dict[str, str]:
    """Parse a shell-style KEY=VALUE env file.

    Handles `export FOO=bar`, single/double quotes, and inline comments on
    unquoted values. Deliberately does not execute anything.
    """
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                m = _ENV_LINE.match(line)
                if not m:
                    continue
                key, val = m.group(1), m.group(2).strip()
                if val[:1] in ("'", '"'):
                    try:
                        parts = shlex.split(val, comments=True)
                        val = parts[0] if parts else ""
                    except ValueError:
                        val = val.strip("\"'")
                else:
                    # Unquoted: an inline comment must be preceded by whitespace.
                    val = re.split(r"\s+#", val, maxsplit=1)[0].strip()
                out[key] = val
    except OSError:
        return {}
    return out


def _split_list(value: str, sep: str = ",") -> list[str]:
    if not value:
        return []
    if sep == ",":
        parts = value.split(",")
    else:
        parts = value.split()
    return [p.strip() for p in parts if p.strip()]


def load(path: str | None = None) -> Config:
    path = path or os.environ.get("SMARTDNS_DASH_CONFIG") or DEFAULT_CONFIG_PATH
    if not os.path.exists(path):
        raise ConfigError(f"config file not found: {path}")

    cp = configparser.ConfigParser(inline_comment_prefixes=None)
    # Preserve case of keys is not needed; values are what matter.
    with open(path, encoding="utf-8") as fh:
        cp.read_file(fh)

    def g(section: str, key: str, default):
        if not cp.has_option(section, key):
            return default
        val = cp.get(section, key).strip()
        if val == "":
            return default if isinstance(default, (list, bool, int, float)) else ""
        return val

    def gb(section: str, key: str, default: bool) -> bool:
        raw = g(section, key, None)
        if raw is None:
            return default
        return str(raw).strip().lower() in ("1", "true", "yes", "on")

    def gi(section: str, key: str, default: int) -> int:
        raw = g(section, key, None)
        if raw is None:
            return default
        try:
            return int(str(raw).strip())
        except ValueError:
            return default

    def gf(section: str, key: str, default: float) -> float:
        raw = g(section, key, None)
        if raw is None:
            return default
        try:
            return float(str(raw).strip())
        except ValueError:
            return default

    c = Config(path=path)

    c.name = g("server", "name", c.name)
    c.public_ip = g("server", "public_ip", c.public_ip)
    c.local_ip = g("server", "local_ip", c.local_ip)
    c.bind = _split_list(g("server", "bind", "127.0.0.1")) or ["127.0.0.1"]
    c.port = gi("server", "port", c.port)
    c.exposed = gb("server", "exposed", c.exposed)
    c.tls_cert = g("server", "tls_cert", "")
    c.tls_key = g("server", "tls_key", "")
    c.behind_proxy = gb("server", "behind_proxy", c.behind_proxy)
    c.allow_ips = _split_list(g("server", "allow_ips", ""))
    c.forwarded_allow_ips = g("server", "forwarded_allow_ips",
                              c.forwarded_allow_ips)
    c.root_path = (g("server", "root_path", "") or "").rstrip("/")
    if c.root_path and not c.root_path.startswith("/"):
        c.root_path = "/" + c.root_path
    c.language = g("server", "language", c.language)

    c.username = g("auth", "username", c.username)
    c.password_hash = g("auth", "password_hash", "")
    c.secret_key = g("auth", "secret_key", "")
    c.session_hours = gi("auth", "session_hours", c.session_hours)
    c.max_login_attempts = gi("auth", "max_login_attempts", c.max_login_attempts)
    c.viewer_username = g("auth", "viewer_username", "")
    c.viewer_password_hash = g("auth", "viewer_password_hash", "")

    c.history_enabled = gb("history", "enabled", c.history_enabled)
    c.history_path = g("history", "path", c.history_path)
    c.history_retention_days = gi("history", "retention_days",
                                  c.history_retention_days)

    c.alerts_enabled = gb("alerts", "enabled", c.alerts_enabled)
    c.alerts_log = gb("alerts", "log", c.alerts_log)
    c.alerts_problem_threshold = gf("alerts", "problem_threshold",
                                    c.alerts_problem_threshold)
    c.alerts_min_severity = g("alerts", "min_severity", c.alerts_min_severity)
    c.alerts_webhook_url = g("alerts", "webhook_url", "")
    c.alerts_webhook_template = g("alerts", "webhook_template", "")
    c.alerts_telegram_token = g("alerts", "telegram_token", "")
    c.alerts_telegram_chat = g("alerts", "telegram_chat_id", "")

    c.probe_enabled = gb("probe", "enabled", c.probe_enabled)
    c.probe_resolver = g("probe", "resolver", c.probe_resolver)
    c.probe_timeout = gf("probe", "timeout", c.probe_timeout)

    c.metrics_enabled = gb("metrics", "enabled", c.metrics_enabled)
    c.metrics_token = g("metrics", "token", "")

    c.triage_enabled = gb("triage", "enabled", c.triage_enabled)

    for key in ("domains", "generated_proxy", "dnsdist_conf", "sniproxy_conf",
                "env_file", "update_script", "backup_dir", "https_log",
                "http_log", "error_log", "update_log"):
        setattr(c, key, g("paths", key, getattr(c, key)))

    c.console = g("dnsdist", "console", c.console)
    c.key_var = g("dnsdist", "key_var", c.key_var)
    c.grepq_limit = gi("dnsdist", "grepq_limit", c.grepq_limit)
    c.api_url = g("dnsdist", "api_url", "")
    c.api_key_var = g("dnsdist", "api_key_var", c.api_key_var)

    # An explicitly empty (or `none`) value means "restart nothing" - for a
    # deployment that manages restarts elsewhere, and for tests. Absent means
    # use the default, because silently restarting nothing would reintroduce
    # the stale-config trap this tool exists to catch.
    if cp.has_option("services", "restart"):
        raw_restart = cp.get("services", "restart").strip()
        c.restart = ([] if raw_restart.lower() in ("", "none")
                     else _split_list(raw_restart, sep=" "))
    else:
        c.restart = ["sniproxy", "dnsdist"]
    c.staleness_unit = g("services", "staleness_unit", c.staleness_unit)

    c.peer_enabled = gb("peer", "enabled", False)
    c.peer_name = g("peer", "name", c.peer_name)
    c.peer_host = g("peer", "host", "")
    c.peer_ssh_user = g("peer", "ssh_user", c.peer_ssh_user)
    c.peer_ssh_port = gi("peer", "ssh_port", c.peer_ssh_port)
    c.peer_ssh_key = g("peer", "ssh_key", "")
    c.peer_ssh_timeout = gi("peer", "ssh_timeout", c.peer_ssh_timeout)

    c.log_ms = gi("poll", "log_ms", c.log_ms)
    c.grepq_ms = gi("poll", "grepq_ms", c.grepq_ms)
    c.status_ms = gi("poll", "status_ms", c.status_ms)
    c.feed_ring = gi("poll", "feed_ring", c.feed_ring)

    c.pw_enabled = gb("portwatch", "enabled", False)
    c.pw_interface = g("portwatch", "interface", c.pw_interface)
    ports = _split_list(g("portwatch", "ignore_ports", "53,80,443"))
    c.pw_ignore_ports = [int(p) for p in ports if p.isdigit()] or [53, 80, 443]
    c.pw_timeout_s = gf("portwatch", "timeout_s", c.pw_timeout_s)
    c.pw_max_runtime_s = gi("portwatch", "max_runtime_s", c.pw_max_runtime_s)

    _validate(c)
    return c


def _validate(c: Config) -> None:
    problems = []
    if not c.secret_key or len(c.secret_key) < 32:
        problems.append(
            "[auth] secret_key is missing or too short. Generate one with:\n"
            '    python3 -c "import secrets;print(secrets.token_hex(32))"')
    if not c.password_hash:
        problems.append(
            "[auth] password_hash is empty. Generate one with:\n"
            "    smartdns-dashboard hash-password")
    if c.is_public_bind and not (c.exposed or c.behind_proxy):
        problems.append(
            f"[server] bind={','.join(c.bind)} is not loopback, but neither "
            "exposed nor behind_proxy is set.\n"
            "    Set behind_proxy=true if nginx (or similar) terminates in "
            "front of it,\n"
            "    or exposed=true if you are deliberately publishing this port "
            "yourself.\n"
            "    Either way the login still applies - see README section 4.")
    # Never take a port the DNS/proxy machinery needs. This box exists to
    # answer DNS; the dashboard is a guest on it.
    from .preflight import PREFERRED, RESERVED
    if c.port in RESERVED:
        problems.append(
            f"[server] port = {c.port} belongs to {RESERVED[c.port]}.\n"
            "    The dashboard must not take a port the DNS/proxy stack "
            "needs.\n"
            f"    Use something in the {PREFERRED[0]}+ range, e.g. "
            f"port = {PREFERRED[0]}")
    if c.viewer_username and not c.viewer_password_hash:
        problems.append(
            "[auth] viewer_username is set but viewer_password_hash is empty.\n"
            "    Generate one with:  smartdns-dashboard hash-password --viewer")
    if c.viewer_username and c.viewer_username == c.username:
        problems.append(
            "[auth] viewer_username must differ from username, otherwise the "
            "read-only account would shadow the operator account.")
    if c.alerts_min_severity not in ("critical", "warning", "info"):
        problems.append(
            "[alerts] min_severity must be critical, warning or info.")
    if c.tls_cert and not c.tls_key:
        problems.append("[server] tls_cert is set but tls_key is not.")
    if c.tls_key and not c.tls_cert:
        problems.append("[server] tls_key is set but tls_cert is not.")
    if problems:
        raise ConfigError("\n\n".join(problems))


def allowed_client(c: Config, addr: str) -> bool:
    """Is this source address permitted at all?

    An empty allow_ips means no restriction. Entries may be single addresses
    or CIDR networks. This is a second lock, not the only one - the password
    still applies.
    """
    if not c.allow_ips:
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for entry in c.allow_ips:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def warnings(c: Config) -> list[str]:
    """Non-fatal advice, surfaced by `check` and in the UI header."""
    out = []
    if not c.spoof_ip:
        out.append(
            "Could not determine the address that listed domains are spoofed "
            f"to. Tried [server] public_ip and {c.dnsdist_conf}. The Lookup "
            "panel will still work but cannot confirm a spoofed answer. Set "
            "[server] public_ip explicitly to fix.")
    if c.is_public_bind and not c.serving_https and not c.behind_proxy:
        out.append(
            "Serving plain HTTP on a non-loopback address. Passwords cross "
            "the network in the clear. Put it behind a TLS-terminating proxy "
            "(behind_proxy=true) or set tls_cert/tls_key.")
    if (c.is_public_bind and not c.behind_proxy and not c.allow_ips):
        out.append(
            "Listening beyond loopback with no reverse proxy and no "
            "[server] allow_ips. Anything that can reach the port can attempt "
            "the login. Add allow_ips, or put a proxy in front.")
    if c.metrics_enabled and not c.metrics_token and c.is_public_bind:
        out.append(
            "[metrics] enabled with no token while listening beyond loopback. "
            "The metrics endpoint needs no login, so anyone who can reach the "
            "port can read your traffic counters. Set a token.")
    if c.triage_enabled:
        out.append(
            "[triage] the client triage page is unauthenticated by design. It "
            "reveals only whether the dashboard has seen the caller's own "
            "address, but it is still a public endpoint - keep it off unless "
            "you want players using it.")
    if c.behind_proxy and c.forwarded_allow_ips == "*":
        out.append(
            "forwarded_allow_ips is '*'. Any client could then spoof its own "
            "source address in X-Forwarded-For and defeat the login rate "
            "limit. Set it to the proxy's address.")
    return out

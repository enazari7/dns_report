"""CLI entry point.

    smartdns-dashboard run
    smartdns-dashboard hash-password
    smartdns-dashboard selftest [logs|dnsdist|domains|status|peer|portwatch|all]
    smartdns-dashboard check          # config sanity, no server started
    smartdns-dashboard doctor         # port safety + environment check
    smartdns-dashboard make-cert      # self-signed TLS, no proxy needed
    smartdns-dashboard reconfigure    # re-point a clone at new addresses
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import __version__, auth
from .config import (
    DEFAULT_CONFIG_PATH,
    ConfigError,
    detect_spoof_ip,
    load,
    local_addresses,
)
from .config import warnings as cfg_warnings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="smartdns-dashboard",
                                description="Smart DNS observability dashboard")
    p.add_argument("--config", "-c", default=None,
                   help=f"config file (default {DEFAULT_CONFIG_PATH})")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("run", help="start the web server")
    sub.add_parser("check", help="validate config and exit")
    sub.add_parser("doctor",
                   help="full environment check: port safety, what else is "
                        "listening, paths, tools, data sources")

    mc = sub.add_parser("make-cert",
                        help="generate a self-signed TLS cert so the password "
                             "is not sent in the clear without a proxy")
    mc.add_argument("--days", type=int, default=3650)
    mc.add_argument("--cn", default=None, help="certificate CN (default: hostname)")
    mc.add_argument("--dir", default="/etc/smartdns-dashboard")
    mc.add_argument("--write-config", action="store_true",
                    help="also point tls_cert/tls_key at the new files")

    rc = sub.add_parser(
        "reconfigure",
        help="change identity/network settings in place - use after cloning "
             "a VM or changing an address")
    rc.add_argument("--name")
    rc.add_argument("--public-ip", help="spoof target, or 'auto'")
    rc.add_argument("--local-ip", help="this box's address, or 'auto'")
    rc.add_argument("--bind")
    rc.add_argument("--port", type=int)
    rc.add_argument("--language", choices=["en", "fa"])
    rc.add_argument("--behind-proxy", choices=["true", "false"])
    rc.add_argument("--forwarded-allow-ips")
    rc.add_argument("--root-path")
    rc.add_argument("--exposed", choices=["true", "false"])
    rc.add_argument("--allow-ips",
                    help="comma-separated addresses/CIDRs allowed to reach the "
                         "dashboard at all; empty string clears it")
    rc.add_argument("--tls-cert")
    rc.add_argument("--tls-key")
    rc.add_argument("--peer-enabled", choices=["true", "false"])
    rc.add_argument("--peer-name")
    rc.add_argument("--peer-host")
    rc.add_argument("--reset-secret", action="store_true",
                    help="issue a new session secret, logging everyone out "
                         "(do this on a cloned VM)")
    rc.add_argument("--password", help="also set a new password")
    rc.add_argument("--show", action="store_true",
                    help="print what was detected and exit")

    hp = sub.add_parser("hash-password", help="produce a password_hash line")
    hp.add_argument("--password", default=None,
                    help="read from argv instead of prompting (shell history!)")

    sub.add_parser("secret", help="generate a secret_key value")

    st = sub.add_parser("selftest", help="exercise one data source")
    st.add_argument("what", nargs="?", default="all",
                    choices=["all", "logs", "dnsdist", "domains", "status",
                             "peer", "portwatch"])
    st.add_argument("--client-ip", default=None,
                    help="a client IP to test grepq / portwatch against")
    st.add_argument("--seconds", type=int, default=15,
                    help="portwatch capture duration")

    args = p.parse_args(argv)
    cmd = args.cmd or "run"

    if cmd == "hash-password":
        pw = args.password
        if not pw:
            pw = getpass.getpass("New dashboard password: ")
            again = getpass.getpass("Repeat: ")
            if pw != again:
                print("passwords do not match", file=sys.stderr)
                return 1
        if len(pw) < 12:
            print("warning: shorter than 12 characters. If this dashboard is "
                  "reachable from outside, use a long random password.",
                  file=sys.stderr)
        print("\nPut this in [auth] of your config.ini:\n")
        print("password_hash = " + auth.hash_password(pw))
        return 0

    if cmd == "secret":
        print("secret_key = " + auth.new_secret_key())
        return 0

    try:
        cfg = load(args.config)
    except ConfigError as exc:
        print(f"config error:\n\n{exc}\n", file=sys.stderr)
        return 2

    if cmd == "check":
        print(f"config ok: {cfg.path}")
        print(f"  server         {cfg.display_name}")
        print(f"  spoof target   {cfg.spoof_ip or '(undetermined)'}"
              f"   [{cfg.spoof_source}]")
        print(f"  local address  {cfg.resolved_local_ip}")
        print(f"  interfaces     {', '.join(local_addresses()) or '(none)'}")
        print(f"  bind           {','.join(cfg.bind)}:{cfg.port}"
              + ("  [TLS]" if cfg.serving_https else ""))
        print(f"  root_path      {cfg.root_path or '/'}")
        print(f"  behind_proxy   {cfg.behind_proxy}"
              + (f"  (trusting {cfg.forwarded_allow_ips})"
                 if cfg.behind_proxy else ""))
        print(f"  exposed        {cfg.exposed}")
        print(f"  language       {cfg.language}")
        print(f"  domains        {cfg.domains}")
        print(f"  logs           {', '.join(cfg.log_files.values())}")
        print(f"  dnsdist        {cfg.console}")
        print("  console key    "
              + ("readable" if cfg.dnsdist_key() else "NOT READABLE"))
        print(f"  restart units  {' '.join(cfg.restart)}")
        print("  peer           "
              + (f"{cfg.peer_name} @ {cfg.peer_host}" if cfg.peer_enabled
                 else "disabled (single server / paste mode)"))
        print("  portwatch      "
              + ("enabled" if cfg.pw_enabled else "disabled"))
        warns = cfg_warnings(cfg)
        if warns:
            print()
            for w in warns:
                print("  WARNING: " + w.replace("\n", "\n           "))
        return 0

    if cmd == "doctor":
        from . import preflight
        return preflight.report(cfg)

    if cmd == "make-cert":
        return _make_cert(cfg, args)

    if cmd == "reconfigure":
        return _reconfigure(cfg, args)

    if cmd == "selftest":
        return _selftest(cfg, args.what, args.client_ip, args.seconds)

    # run
    import uvicorn

    from . import preflight
    from .app import create_app

    host = cfg.bind[0]
    verdict = preflight.check_port(cfg.port, host)
    if verdict["fatal"]:
        print(f"refusing to start: {verdict['fatal']}", file=sys.stderr)
        alt = preflight.pick_free_port(host)
        if alt:
            print(f"\n  a safe free port is {alt}:\n"
                  f"    smartdns-dashboard reconfigure --port {alt}\n"
                  f"    systemctl restart smartdns-dashboard", file=sys.stderr)
        print("\n  full diagnosis:  smartdns-dashboard doctor",
              file=sys.stderr)
        return 3
    for w in verdict["warnings"]:
        print("warning: " + w, file=sys.stderr)

    app = create_app(cfg)
    if len(cfg.bind) > 1:
        print(f"note: multiple bind addresses configured "
              f"({','.join(cfg.bind)}); uvicorn binds one. Using {host}. "
              "Bind 0.0.0.0 if you need both, with the MikroTik restriction "
              "in place.", file=sys.stderr)
    kwargs = {
        "host": host,
        "port": cfg.port,
        "log_level": "info",
        "access_log": False,
        "timeout_keep_alive": 65,
        "proxy_headers": cfg.behind_proxy,
    }
    if cfg.behind_proxy:
        kwargs["forwarded_allow_ips"] = cfg.forwarded_allow_ips
    if cfg.serving_https:
        kwargs["ssl_certfile"] = cfg.tls_cert
        kwargs["ssl_keyfile"] = cfg.tls_key
    for w in cfg_warnings(cfg):
        print("warning: " + w, file=sys.stderr)
    uvicorn.run(app, **kwargs)
    return 0


def _make_cert(cfg, args) -> int:
    """Self-signed TLS, for when there is no reverse proxy on the box.

    A browser warning once is a much smaller problem than a password crossing
    the network in cleartext.
    """
    import shutil
    import socket
    import subprocess

    if shutil.which("openssl") is None:
        print("openssl not found (apt install openssl)", file=sys.stderr)
        return 1
    os.makedirs(args.dir, mode=0o700, exist_ok=True)
    cert = os.path.join(args.dir, "cert.pem")
    key = os.path.join(args.dir, "key.pem")
    cn = args.cn or socket.gethostname() or "smartdns-dashboard"

    # SANs so browsers do not additionally complain about the name.
    sans = ["DNS:" + cn, "IP:127.0.0.1"]
    for a in local_addresses():
        sans.append("IP:" + a)
    if cfg.spoof_ip:
        sans.append("IP:" + cfg.spoof_ip)

    cmd = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-days", str(args.days), "-keyout", key, "-out", cert,
           "-subj", f"/CN={cn}",
           "-addext", "subjectAltName=" + ",".join(dict.fromkeys(sans))]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print((proc.stdout or "") + (proc.stderr or ""), file=sys.stderr)
        return 1
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    print(f"wrote {cert}")
    print(f"wrote {key}  (mode 600)")
    print("SANs: " + ", ".join(dict.fromkeys(sans)))

    if args.write_config:
        with open(cfg.path, encoding="utf-8") as fh:
            text = fh.read()
        text = _set_ini(text, "server", "tls_cert", cert)
        text = _set_ini(text, "server", "tls_key", key)
        tmp = cfg.path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, cfg.path)
        print(f"\nupdated {cfg.path}")
        print("apply it:  systemctl restart smartdns-dashboard")
    else:
        print("\nAdd to [server] in your config, then restart:")
        print(f"  tls_cert = {cert}")
        print(f"  tls_key  = {key}")
    return 0


def _set_ini(text: str, section: str, key: str, value: str) -> str:
    """Replace `key = ...` inside [section] only, preserving comments."""
    out, cur, done = [], None, False
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            cur = stripped[1:-1]
        elif cur == section and not done:
            import re
            m = re.match(r"^(\s*)" + re.escape(key) + r"\s*=", line)
            if m:
                out.append(f"{m.group(1)}{key} = {value}")
                done = True
                continue
        out.append(line)
    if not done:
        print(f"  note: [{section}] {key} not present, appending",
              file=sys.stderr)
        # Insert right after the section header.
        out2, placed = [], False
        for line in out:
            out2.append(line)
            stripped = line.strip()
            if stripped == f"[{section}]" and not placed:
                out2.append(f"{key} = {value}")
                placed = True
        if not placed:
            out2 += [f"[{section}]", f"{key} = {value}"]
        return "\n".join(out2)
    return "\n".join(out)


def _reconfigure(cfg, args) -> int:
    """Edit identity/network settings in the existing config file.

    This is the path for a cloned VM or a changed address: nothing about the
    deployment is compiled in, so re-pointing an instance is a config edit and
    a restart, never a reinstall.
    """
    import shutil
    import time

    detected_ifaces = local_addresses()
    detected_spoof, spoof_src = detect_spoof_ip(cfg.dnsdist_conf,
                                               cfg.generated_proxy)

    print("Detected on this machine:")
    print(f"  hostname          {cfg.display_name}")
    print(f"  interfaces        {', '.join(detected_ifaces) or '(none)'}")
    print(f"  spoof target      {detected_spoof or '(not found)'}"
          f"   [{spoof_src}]")
    print()
    print("Currently configured:")
    print(f"  name              {cfg.name}")
    print(f"  public_ip         {cfg.public_ip}  -> {cfg.spoof_ip or '?'}")
    print(f"  local_ip          {cfg.local_ip}  -> {cfg.resolved_local_ip}")
    print(f"  bind              {','.join(cfg.bind)}:{cfg.port}")
    print(f"  behind_proxy      {cfg.behind_proxy}")
    print(f"  root_path         {cfg.root_path or '/'}")
    print(f"  language          {cfg.language}")
    print("  peer              "
          + (f"{cfg.peer_name} @ {cfg.peer_host}" if cfg.peer_enabled
             else "disabled"))

    if args.show:
        print("\n--show: nothing written.")
        return 0

    changes = [
        ("server", "name", args.name),
        ("server", "public_ip", args.public_ip),
        ("server", "local_ip", args.local_ip),
        ("server", "bind", args.bind),
        ("server", "port", str(args.port) if args.port else None),
        ("server", "language", args.language),
        ("server", "behind_proxy", args.behind_proxy),
        ("server", "forwarded_allow_ips", args.forwarded_allow_ips),
        ("server", "root_path", args.root_path),
        ("server", "exposed", args.exposed),
        ("server", "allow_ips", args.allow_ips),
        ("server", "tls_cert", args.tls_cert),
        ("server", "tls_key", args.tls_key),
        ("peer", "enabled", args.peer_enabled),
        ("peer", "name", args.peer_name),
        ("peer", "host", args.peer_host),
    ]
    todo = [(s, k, v) for s, k, v in changes if v is not None]

    if not todo and not args.reset_secret and not args.password:
        print("\nNothing to change. Pass options, e.g.:")
        print("  smartdns-dashboard reconfigure --public-ip auto "
              "--local-ip auto --name auto --reset-secret")
        print("  smartdns-dashboard reconfigure --bind 127.0.0.1 "
              "--behind-proxy true --forwarded-allow-ips 127.0.0.1")
        print("  smartdns-dashboard reconfigure --peer-enabled true "
              "--peer-host 10.0.0.2 --peer-name OTHER-01")
        return 0

    with open(cfg.path, encoding="utf-8") as fh:
        text = fh.read()

    backup = f"{cfg.path}.{time.strftime('%Y%m%d-%H%M%S')}.bak"
    shutil.copy2(cfg.path, backup)
    print(f"\nbackup: {backup}")

    for section, key, value in todo:
        text = _set_ini(text, section, key, value)
        print(f"  [{section}] {key} = {value}")

    if args.reset_secret:
        text = _set_ini(text, "auth", "secret_key", auth.new_secret_key())
        print("  [auth] secret_key = (new - all sessions invalidated)")

    if args.password:
        text = _set_ini(text, "auth", "password_hash",
                        auth.hash_password(args.password))
        print("  [auth] password_hash = (new)")

    tmp = cfg.path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, cfg.path)

    try:
        new = load(cfg.path)
    except ConfigError as exc:
        print(f"\nthe result does not validate, restoring the backup:\n\n{exc}",
              file=sys.stderr)
        shutil.copy2(backup, cfg.path)
        return 2

    print("\nNew effective values:")
    print(f"  name              {new.display_name}")
    print(f"  spoof target      {new.spoof_ip or '(undetermined)'}"
          f"   [{new.spoof_source}]")
    print(f"  local address     {new.resolved_local_ip}")
    print(f"  bind              {','.join(new.bind)}:{new.port}")
    for w in cfg_warnings(new):
        print("  WARNING: " + w)
    print("\nApply it:  systemctl restart smartdns-dashboard")
    return 0


def _selftest(cfg, what: str, client_ip: str | None, seconds: int) -> int:
    from .sources import dnsdist as dd
    from .sources import domains as dom
    from .sources import peer as peermod
    from .sources import portwatch as pw
    from .sources import sniproxy_log as slog
    from .sources import sysinfo

    rc = 0
    order = ["logs", "domains", "dnsdist", "status", "peer", "portwatch"]
    todo = order if what == "all" else [what]

    for name in todo:
        print("\n" + "=" * 68)
        print(f"  selftest: {name}")
        print("=" * 68)
        if name == "logs":
            rc |= slog.selftest(list(cfg.log_files.values()))
        elif name == "domains":
            rc |= dom.selftest(cfg.domains)
        elif name == "dnsdist":
            rc |= dd.selftest(cfg.console, cfg.dnsdist_key(), client_ip,
                              min(cfg.grepq_limit, 300))
        elif name == "status":
            watch = [cfg.domains]
            if cfg.generated_proxy:
                watch.append(cfg.generated_proxy)
            rc |= sysinfo.selftest(cfg.staleness_unit, watch)
        elif name == "peer":
            if not cfg.peer_enabled or not cfg.peer_host:
                print("  peer disabled in config - paste mode only")
            else:
                rc |= peermod.selftest(cfg.peer_host, cfg.peer_ssh_user,
                                       cfg.peer_ssh_port, cfg.peer_ssh_key,
                                       cfg.peer_ssh_timeout, cfg.domains,
                                       cfg.display_name, cfg.peer_name)
        elif name == "portwatch":
            if not cfg.pw_enabled and what == "all":
                print("  portwatch disabled in config - skipping "
                      "(run `selftest portwatch` explicitly to force)")
            else:
                rc |= pw.selftest(cfg.pw_interface, client_ip, seconds,
                                  cfg.pw_ignore_ports)

    print("\n" + "=" * 68)
    print("  RESULT:", "all checks passed" if rc == 0 else
          "something failed - see FAIL lines above")
    print("=" * 68)
    return rc


if __name__ == "__main__":
    sys.exit(main())

"""Port safety and environment checks.

This dashboard runs on a box whose whole job is DNS and SNI proxying. It must
never take a port that machinery needs, and it must never be the reason a
resolver failed to bind after a reboot. So the port is checked in three places:

* at config load - a hard refusal for ports belonging to the DNS/proxy stack;
* by ``doctor`` - the full picture, including what is actually listening now;
* by the installer - which picks a free port instead of writing a broken config.

The dashboard binds exactly one TCP port and nothing else. It never listens on
53, 80 or 443, never opens a raw socket, and only reads dnsdist's console and
config. The one exception is the opt-in port watcher, which runs ``tcpdump`` in
capture mode - that opens no listening port either.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess

# Ports the DNS/proxy stack owns. Taking one of these would break the service
# this dashboard exists to observe, so it is a refusal, not a warning.
RESERVED: dict[int, str] = {
    22: "SSH - you would lock yourself out",
    53: "DNS - dnsdist's listener, the whole point of the box",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP - sniproxy's listener",
    123: "NTP",
    443: "HTTPS - sniproxy's listener",
    853: "DNS-over-TLS",
    5199: "dnsdist control socket",
    5353: "mDNS",
    8083: "dnsdist web/API (localhost-only by design)",
    9100: "node_exporter (localhost-only by design)",
    9153: "CoreDNS metrics",
}

# Ranges better left alone. Not refused, but flagged.
DISCOURAGED: list[tuple[int, int, str]] = [
    (1, 1023, "privileged range - a service may claim it after a reboot"),
    (8000, 8100, "commonly used by game and CDN backends, incl. the CODM "
                 "downloader on 8080/8085/8013"),
    (3478, 3479, "STUN/TURN - voice chat"),
    (27000, 27100, "Steam / Source engine"),
    (30000, 30100, "common game data channels"),
]

# Where to look first when picking a port automatically. Deliberately far from
# anything in RESERVED or DISCOURAGED.
PREFERRED = [9443, 9444, 9450, 9460, 17443, 17444, 18443, 19443]


def listeners() -> list[dict]:
    """What is listening on TCP right now, from `ss` (preferred) or /proc."""
    out: list[dict] = []
    if shutil.which("ss"):
        try:
            proc = subprocess.run(["ss", "-tlnpH"], capture_output=True,
                                  text=True, timeout=8)
            for line in (proc.stdout or "").splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[3]
                host, _, port = local.rpartition(":")
                if not port.isdigit():
                    continue
                who = ""
                m = re.search(r'users:\(\("([^"]+)"', line)
                if m:
                    who = m.group(1)
                out.append({"addr": host.strip("[]"), "port": int(port),
                            "process": who})
            if out:
                return out
        except (OSError, subprocess.SubprocessError):
            pass
    # Fallback: /proc/net/tcp, no process names.
    for path, fam in (("/proc/net/tcp", 4), ("/proc/net/tcp6", 6)):
        try:
            with open(path, encoding="ascii", errors="replace") as fh:
                next(fh, None)
                for line in fh:
                    f = line.split()
                    if len(f) < 4 or f[3] != "0A":  # 0A = LISTEN
                        continue
                    hexaddr, _, hexport = f[1].rpartition(":")
                    out.append({"addr": f"(ipv{fam})", "port": int(hexport, 16),
                                "process": ""})
        except (OSError, ValueError, StopIteration):
            continue
    return out


def port_in_use(port: int, bind: str = "0.0.0.0") -> dict | None:
    """Return the listener occupying this port, or None."""
    for l in listeners():
        if l["port"] != port:
            continue
        # A wildcard listener conflicts with any bind; otherwise only an exact
        # address match does.
        if l["addr"] in ("0.0.0.0", "*", "::", "(ipv4)", "(ipv6)"):
            return l
        if bind in ("0.0.0.0", "::") or l["addr"] == bind:
            return l
    return None


def can_bind(port: int, bind: str = "127.0.0.1") -> tuple[bool, str]:
    """Actually try to bind, which is the only authoritative answer."""
    fam = socket.AF_INET6 if ":" in bind else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind, port))
        s.close()
        return True, "ok"
    except OSError as exc:
        return False, exc.strerror or str(exc)


def check_port(port: int, bind: str = "127.0.0.1") -> dict:
    """Full verdict for one port: reserved, discouraged, occupied, bindable."""
    result = {
        "port": port, "bind": bind, "fatal": None, "warnings": [],
        "occupied_by": None, "bindable": None, "bind_error": None,
    }
    if port < 1 or port > 65535:
        result["fatal"] = f"{port} is not a valid TCP port"
        return result

    if port in RESERVED:
        result["fatal"] = (
            f"port {port} belongs to {RESERVED[port]}. The dashboard must "
            "never take a port the DNS/proxy stack needs. Pick something in "
            f"the {PREFERRED[0]}+ range.")
        return result

    for lo, hi, why in DISCOURAGED:
        if lo <= port <= hi:
            result["warnings"].append(
                f"port {port} is inside {lo}-{hi}: {why}")

    occ = port_in_use(port, bind)
    if occ:
        result["occupied_by"] = occ
        result["fatal"] = (
            f"port {port} is already in use by "
            f"{occ['process'] or 'another process'} on {occ['addr']}")
        return result

    ok, err = can_bind(port, bind if bind != "0.0.0.0" else "0.0.0.0")
    result["bindable"] = ok
    if not ok:
        result["bind_error"] = err
        result["fatal"] = f"cannot bind {bind}:{port} - {err}"
    return result


def pick_free_port(bind: str = "127.0.0.1",
                   preferred: list[int] | None = None) -> int | None:
    """First port from the preferred list that is safe and free."""
    for p in (preferred or PREFERRED):
        v = check_port(p, bind)
        if not v["fatal"]:
            return p
    return None


def dns_stack_intact(expect_ports=(53,)) -> list[dict]:
    """Confirm the ports the DNS machinery needs are still held by it.

    Reported for reassurance, not enforcement: if 53 is listening, the
    dashboard demonstrably has not taken it.
    """
    live = listeners()
    out = []
    for p in expect_ports:
        holders = [l for l in live if l["port"] == p]
        out.append({
            "port": p,
            "listening": bool(holders),
            "processes": sorted({l["process"] for l in holders if l["process"]}),
        })
    return out


def path_checks(cfg) -> list[dict]:
    """Every file the dashboard reads or writes, and whether it can."""
    checks = [
        ("domains.txt", cfg.domains, "rw"),
        ("generated proxy list", cfg.generated_proxy, "r"),
        ("dnsdist.conf", cfg.dnsdist_conf, "r"),
        ("smartdns.env", cfg.env_file, "r"),
        ("update script", cfg.update_script, "x"),
        ("backup dir", cfg.backup_dir, "d"),
        ("https access log", cfg.https_log, "r"),
        ("http access log", cfg.http_log, "r"),
    ]
    out = []
    for label, path, need in checks:
        exists = os.path.exists(path)
        row = {"label": label, "path": path, "exists": exists, "ok": exists,
               "detail": ""}
        if not exists:
            row["detail"] = "missing"
            # A missing access log is normal before any traffic.
            row["fatal"] = need in ("rw", "x")
        else:
            if "r" in need or "rw" in need:
                row["ok"] = os.access(path, os.R_OK)
                if not row["ok"]:
                    row["detail"] = "not readable"
            if row["ok"] and need == "rw":
                row["ok"] = os.access(path, os.W_OK)
                if not row["ok"]:
                    row["detail"] = "not writable"
            if row["ok"] and need == "x":
                row["ok"] = os.access(path, os.X_OK)
                if not row["ok"]:
                    row["detail"] = "not executable"
            if need == "d":
                row["ok"] = os.path.isdir(path) and os.access(path, os.W_OK)
                if not row["ok"]:
                    row["detail"] = "not a writable directory"
            row["fatal"] = (not row["ok"]) and need in ("rw", "x", "d")
        out.append(row)
    return out


def tool_checks() -> list[dict]:
    tools = [
        ("dnsdist", True, "the console is the main data source"),
        ("systemctl", True, "needed to restart services after a change"),
        ("dig", False, "Lookup panel (apt install dnsutils)"),
        ("tcpdump", False, "Port watch panel"),
        ("ss", False, "port checks fall back to /proc without it"),
        ("ssh", False, "two-server diff"),
    ]
    return [{"tool": t, "required": req, "why": why,
             "found": shutil.which(t) is not None} for t, req, why in tools]


def run(cfg) -> dict:
    """Everything doctor reports, as data."""
    bind = cfg.bind[0]
    return {
        "port": check_port(cfg.port, bind),
        "dns_stack": dns_stack_intact(),
        "listeners": sorted(listeners(), key=lambda l: l["port"]),
        "paths": path_checks(cfg),
        "tools": tool_checks(),
        "console_key": bool(cfg.dnsdist_key()),
        "spoof_ip": cfg.spoof_ip,
        "spoof_source": cfg.spoof_source,
    }


def report(cfg) -> int:
    """Human-readable doctor output. Returns non-zero on a fatal problem."""
    d = run(cfg)
    fatal = 0
    warn = 0

    print("=== listen port ===")
    p = d["port"]
    print(f"  requested      {p['bind']}:{p['port']}")
    if p["fatal"]:
        print(f"  FATAL          {p['fatal']}")
        alt = pick_free_port(p["bind"])
        if alt:
            print(f"  suggestion     use port {alt}:")
            print(f"                   smartdns-dashboard reconfigure "
                  f"--port {alt}")
        fatal += 1
    else:
        print("  ok             free, bindable, and clear of the DNS stack")
    for w in p["warnings"]:
        print(f"  warning        {w}")
        warn += 1

    print("\n=== DNS machinery still owns its ports ===")
    for row in d["dns_stack"]:
        who = ", ".join(row["processes"]) or "unknown process"
        if row["listening"]:
            print(f"  ok             :{row['port']} held by {who}")
        else:
            print(f"  warning        nothing is listening on :{row['port']} - "
                  "is dnsdist running?")
            warn += 1
    print("  note           the dashboard binds one TCP port and nothing "
          "else; it never listens on 53/80/443")

    print("\n=== other listeners on this host ===")
    for l in d["listeners"]:
        mark = "  <-- dashboard" if l["port"] == cfg.port else ""
        note = ""
        if l["port"] in RESERVED:
            note = f"   [{RESERVED[l['port']]}]"
        print(f"  {l['addr']:>18}:{l['port']:<6} "
              f"{(l['process'] or ''):<18}{note}{mark}")

    print("\n=== paths ===")
    for row in d["paths"]:
        if row["ok"]:
            print(f"  ok             {row['label']:22} {row['path']}")
        elif row.get("fatal"):
            print(f"  FATAL          {row['label']:22} {row['path']} "
                  f"({row['detail']})")
            fatal += 1
        else:
            print(f"  warning        {row['label']:22} {row['path']} "
                  f"({row['detail']})")
            warn += 1

    print("\n=== tools ===")
    for row in d["tools"]:
        if row["found"]:
            print(f"  ok             {row['tool']}")
        elif row["required"]:
            print(f"  FATAL          {row['tool']} missing - {row['why']}")
            fatal += 1
        else:
            print(f"  warning        {row['tool']} missing - {row['why']}")
            warn += 1

    print("\n=== data sources ===")
    if d["console_key"]:
        print("  ok             dnsdist console key readable")
    else:
        print("  FATAL          dnsdist console key not readable - check "
              f"{cfg.env_file} and [dnsdist] key_var")
        fatal += 1
    if d["spoof_ip"]:
        print(f"  ok             spoof target {d['spoof_ip']} "
              f"[{d['spoof_source']}]")
    else:
        print("  warning        spoof target undetermined - the Lookup panel "
              "cannot confirm a spoofed answer. Set [server] public_ip.")
        warn += 1

    print(f"\n{'=' * 60}")
    print(f"  {fatal} fatal, {warn} warning(s)")
    if fatal:
        print("  Fix the fatal items before starting the service.")
    print("=" * 60)
    return 1 if fatal else 0

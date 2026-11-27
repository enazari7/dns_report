"""dnsdist console wrapper: grepq, topQueries, showServers, plus the
Prometheus/JSON stats endpoint.

The ring buffer is the single most useful data source in this system. The
question it answers is: *what did this client ask for that we are NOT
proxying?*

grepq emits two shapes of row:

    -407.8  84.241.45.220:60004                32951 west-tdm.codmwest.com. \
A   RD  Question
    -407.8  84.241.45.220:60004  8.8.4.4:53    32951 west-tdm.codmwest.com. \
A   41.7  RD  No Error. 4 answers

Column 3 is the upstream server. **If it is populated, the query went upstream
- meaning dnsdist did NOT spoof it, so the name is not proxied.** If it is
absent, dnsdist answered from its own rules or cache.

A single name normally produces both rows (the Question, then the response).
So "is it proxied" cannot be decided from one row: a name is *unproxied* if it
appears in at least one row with an upstream, and *proxied* only if it never
does.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request

IPPORT_RE = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:]+):\d{1,5}$")

# Query types we care to distinguish. AAAA/HTTPS/SVCB are the ones dnsdist is
# supposed to be suppressing for proxied names.
SUPPRESSED_TYPES = {"AAAA", "HTTPS", "SVCB"}


class DnsdistError(Exception):
    pass


class DnsdistConsole:
    def __init__(self, console: str, key_getter, timeout: int = 10,
                 binary: str = "dnsdist"):
        self.console = console
        self._key_getter = key_getter
        self.timeout = timeout
        self.binary = binary

    def available(self) -> str | None:
        """Return None if usable, else a human-readable reason."""
        if shutil.which(self.binary) is None:
            return f"{self.binary} not found in PATH"
        if not self._key_getter():
            return ("console key not readable - check that the env file "
                    "exists and contains the key variable")
        return None

    def run(self, lua: str) -> str:
        key = self._key_getter()
        if not key:
            raise DnsdistError("dnsdist console key unavailable")
        cmd = [self.binary, "-c", self.console, "-k", key, "-e", lua]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout)
        except FileNotFoundError:
            raise DnsdistError(f"{self.binary} not found")
        except subprocess.TimeoutExpired:
            raise DnsdistError(f"console timed out after {self.timeout}s")
        out = (proc.stdout or "")
        err = (proc.stderr or "").strip()
        if proc.returncode != 0:
            # Never echo the key back into an error message.
            raise DnsdistError(err or f"dnsdist exited {proc.returncode}")
        if err and not out.strip():
            raise DnsdistError(err)
        return out

    # -- grepq ---------------------------------------------------------
    def grepq(self, needle: str, limit: int) -> list[dict]:
        needle = needle.replace('"', '').replace("\\", "")
        limit = max(1, min(int(limit), 20000))
        raw = self.run(f'grepq("{needle}", {limit})')
        return parse_grepq(raw)

    def top_queries(self, n: int = 50) -> list[tuple[str, int]]:
        raw = self.run(f"topQueries({int(n)})")
        return parse_top(raw)

    def show_servers(self) -> list[dict]:
        return parse_show_servers(self.run("showServers()"))


def parse_grepq(raw: str) -> list[dict]:
    """Parse grepq() output into structured rows.

    Positional, with a guard: field 3 (index 2) is the upstream only when it
    looks like ip:port. Otherwise it is the query id and everything shifts
    left by one.
    """
    rows: list[dict] = []
    now = time.time()
    for line in raw.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        t = line.split()
        if len(t) < 4:
            continue
        try:
            offset = float(t[0])
        except ValueError:
            continue  # header or noise
        if not IPPORT_RE.match(t[1]):
            continue
        client = t[1]

        if IPPORT_RE.match(t[2]):
            upstream: str | None = t[2]
            rest = t[3:]
        else:
            upstream = None
            rest = t[2:]

        if len(rest) < 3:
            continue
        qid = rest[0]
        name = rest[1].lower().rstrip(".")
        qtype = rest[2].upper()

        tail = " ".join(rest[3:])
        is_question = tail.endswith("Question")
        latency = None
        if not is_question and len(rest) > 3:
            try:
                latency = float(rest[3])
            except ValueError:
                latency = None

        rows.append({
            "offset": offset,          # negative seconds relative to now
            "ts": now + offset,
            "client": client,
            "client_ip": client.rsplit(":", 1)[0].strip("[]"),
            "upstream": upstream,
            "qid": qid,
            "name": name,
            "qtype": qtype,
            "latency_ms": latency,
            "is_question": is_question,
            "result": tail,
            "raw": line,
        })
    return rows


def parse_top(raw: str) -> list[tuple[str, int]]:
    """topQueries() prints roughly:  1   example.com.   1234   12.3%"""
    out = []
    for line in raw.splitlines():
        t = line.split()
        if len(t) < 3:
            continue
        name = t[1].lower().rstrip(".")
        count = t[2].replace(",", "")
        if not count.isdigit():
            continue
        if not name or name in ("name",):
            continue
        out.append((name, int(count)))
    return out


def parse_show_servers(raw: str) -> list[dict]:
    """showServers() is a fixed-width table; parse loosely by header names."""
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return []
    header = lines[0].split()
    if "Name" not in header and "Address" not in header:
        header = []
    out = []
    for line in lines[1:]:
        t = line.split()
        if len(t) < 3:
            continue
        row = {"raw": line}
        if header and len(t) >= len(header):
            row.update(dict(zip(header, t, strict=False)))
        else:
            row["Address"] = t[1] if len(t) > 1 else ""
            row["State"] = t[-1]
        out.append(row)
    return out


# ----------------------------------------------------------------------
def classify(rows: list[dict]) -> dict:
    """Split ring rows into proxied / unproxied name sets.

    unproxied: appeared at least once with an upstream server populated.
    proxied:   only ever answered locally.
    """
    upstream_names: dict[str, dict] = {}
    local_names: dict[str, dict] = {}
    all_seen: dict[str, dict] = {}

    for r in rows:
        name = r["name"]
        if not name:
            continue
        bucket = upstream_names if r["upstream"] else local_names
        entry = bucket.setdefault(name, {
            "name": name,
            "count": 0,
            "first_ts": r["ts"],
            "last_ts": r["ts"],
            "qtypes": set(),
            "upstreams": set(),
            "clients": set(),
        })
        entry["count"] += 1
        entry["first_ts"] = min(entry["first_ts"], r["ts"])
        entry["last_ts"] = max(entry["last_ts"], r["ts"])
        entry["qtypes"].add(r["qtype"])
        entry["clients"].add(r["client_ip"])
        if r["upstream"]:
            entry["upstreams"].add(r["upstream"])
        all_seen[name] = entry

    # A name that went upstream is unproxied, full stop - even if some of its
    # rows were answered locally (cache hits on a non-spoofed name).
    proxied = {n: e for n, e in local_names.items() if n not in upstream_names}
    return {
        "unproxied": _finish(upstream_names),
        "proxied": _finish(proxied),
        "total_rows": len(rows),
    }


def _finish(d: dict[str, dict]) -> list[dict]:
    out = []
    for e in d.values():
        out.append({
            "name": e["name"],
            "count": e["count"],
            "first_ts": e["first_ts"],
            "last_ts": e["last_ts"],
            "qtypes": sorted(e["qtypes"]),
            "upstreams": sorted(e["upstreams"]),
            "clients": sorted(e["clients"]),
        })
    out.sort(key=lambda x: (-x["count"], x["name"]))
    return out


class FirstSeenTracker:
    """Keeps the earliest observation of each name across polls.

    The ring buffer only holds the recent past, so a name's apparent
    first-seen time walks forward as older entries age out. This remembers the
    real one for the life of the process.
    """

    def __init__(self, cap: int = 20000):
        self._seen: dict[tuple[str, str], float] = {}
        self.cap = cap

    def note(self, client_ip: str, entries: list[dict]) -> None:
        for e in entries:
            key = (client_ip, e["name"])
            prev = self._seen.get(key)
            if prev is None or e["first_ts"] < prev:
                self._seen[key] = e["first_ts"]
        if len(self._seen) > self.cap:
            # Drop the oldest half rather than growing without bound.
            ordered = sorted(self._seen.items(), key=lambda kv: kv[1])
            for k, _ in ordered[: len(ordered) // 2]:
                self._seen.pop(k, None)

    def first_seen(self, client_ip: str, name: str, fallback: float) -> float:
        return self._seen.get((client_ip, name), fallback)

    def apply(self, client_ip: str, entries: list[dict]) -> list[dict]:
        self.note(client_ip, entries)
        for e in entries:
            e["first_seen"] = self.first_seen(client_ip, e["name"], e["first_ts"])
        return entries


# ----------------------------------------------------------------------
def fetch_stats(api_url: str, api_key: str | None,
                timeout: float = 4.0) -> dict:
    """Pull dnsdist's JSON stats. Returns {} on any failure - the stats panel
    is a nice-to-have and must never break the page."""
    if not api_url:
        return {}
    url = api_url.rstrip("/") + "/jsonstat?command=stats"
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("X-API-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return {}


def dig(name: str, server: str, qtype: str = "A",
        timeout: float = 4.0) -> dict:
    """Run dig against a specific resolver. Falls back gracefully if dig is
    not installed (apt install dnsutils)."""
    if shutil.which("dig") is None:
        return {"error": "dig not installed (apt install dnsutils)",
                "answers": [], "qtype": qtype, "server": server}
    cmd = ["dig", "+time=2", "+tries=1", "+short", f"@{server}", name, qtype]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "dig timed out", "answers": [], "qtype": qtype,
                "server": server}
    answers = [l.strip() for l in (proc.stdout or "").splitlines() if l.strip()]
    return {
        "error": (proc.stderr or "").strip() or None,
        "answers": answers,
        "qtype": qtype,
        "server": server,
    }


def selftest(console: str, key: str | None, client_ip: str | None,
             limit: int = 200) -> int:
    sample = (
        "-407.8  84.241.45.220:60004                   32951 "
        "west-tdm.codmwest.com.  A   RD  Question\n"
        "-407.8  84.241.45.220:60004   8.8.4.4:53      32951 "
        "west-tdm.codmwest.com.  A   41.7  RD  No Error. 4 answers\n"
        "-12.1   84.241.45.220:51110                   1044 "
        "sg.msdkfaas.com.  A   RD  Question\n"
    )
    print("--- reference grepq rows ---")
    rows = parse_grepq(sample)
    if len(rows) != 3:
        print(f"FAIL: expected 3 rows, parsed {len(rows)}")
        return 1
    for r in rows:
        print(f"  ts={r['offset']:>8} client={r['client_ip']:>15} "
              f"upstream={str(r['upstream']):>12} name={r['name']} "
              f"type={r['qtype']} question={r['is_question']}")
    c = classify(rows)
    print("  unproxied:", [e["name"] for e in c["unproxied"]])
    print("  proxied  :", [e["name"] for e in c["proxied"]])
    if [e["name"] for e in c["unproxied"]] != ["west-tdm.codmwest.com"]:
        print("FAIL: classification did not match the documented behaviour")
        return 1
    if [e["name"] for e in c["proxied"]] != ["sg.msdkfaas.com"]:
        print("FAIL: proxied set did not match")
        return 1

    if not key:
        print("\n(no console key available - skipping live check)")
        return 0
    console_obj = DnsdistConsole(console, lambda: key)
    print(f"\n--- live console {console} ---")
    try:
        servers = console_obj.show_servers()
        print(f"  showServers(): {len(servers)} rows")
        for s in servers[:5]:
            print("   ", s["raw"])
    except DnsdistError as exc:
        print(f"  FAIL showServers(): {exc}")
        return 1
    if client_ip:
        try:
            live = console_obj.grepq(client_ip, limit)
        except DnsdistError as exc:
            print(f"  FAIL grepq(): {exc}")
            return 1
        print(f"\n--- grepq({client_ip!r}, {limit}) -> {len(live)} rows ---")
        cl = classify(live)
        print(f"  unproxied names ({len(cl['unproxied'])}):")
        for e in cl["unproxied"][:25]:
            print(f"    {e['count']:>5}  {e['name']}")
        print(f"  proxied names ({len(cl['proxied'])}):")
        for e in cl["proxied"][:25]:
            print(f"    {e['count']:>5}  {e['name']}")
    return 0

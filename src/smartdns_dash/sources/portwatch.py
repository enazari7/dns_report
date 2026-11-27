"""Port watcher: TCP SYNs that never get a SYN-ACK.

This is the panel that would have found the Call of Duty Mobile downloader
problem in minutes instead of hours. The downloader speaks a binary Tencent
GCloud protocol on TCP 8080/8085/8013 with neither an SNI nor a Host header,
so sniproxy cannot route it - the connections just hang. From the client's
side the game opens and never downloads; from the server's side nothing
appears in the access log at all, because sniproxy never got far enough to log
anything.

The signature is a SYN from the client to a port we do not handle, with no
SYN-ACK coming back. That is what this watches for.

Implementation notes:

* Runs ``tcpdump`` as a child process and parses its text output. There is no
  pure-Python way to do this without raw sockets and a lot more code.
* A capture is bounded by ``max_runtime_s`` so a forgotten watcher cannot run
  forever on a box that also carries live traffic.
* The BPF filter is built from a validated client IP only - never from free
  text - so there is no filter-injection surface.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import threading
import time
from collections import OrderedDict
from collections.abc import Sequence

from .. import i18n

# tcpdump -n -l -i any output, e.g.
#   15:17:14.123456 IP 84.241.45.220.39460 > 172.20.46.2.8080: Flags [S], ...
# Newer tcpdump with -i any prefixes an interface field:
#   15:17:14.123456 eth0  In  IP 1.2.3.4.5 > 6.7.8.9.80: Flags [S], ...
LINE_RE = re.compile(
    r"^(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?:\S+\s+(?:In|Out|P|B|M)\s+)?"
    r"IP6?\s+"
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s+"
    r"Flags\s+\[(?P<flags>[^\]]*)\]"
)


def available() -> str | None:
    if shutil.which("tcpdump") is None:
        return "tcpdump not installed (apt install tcpdump)"
    return None


def build_filter(client_ip: str | None, ignore_ports: Sequence[int]) -> str:
    parts = ["tcp[tcpflags] & tcp-syn != 0"]
    if client_ip:
        ip = ipaddress.ip_address(client_ip)  # raises on anything unsafe
        parts.append(f"host {ip}")
    for p in ignore_ports:
        parts.append(f"not port {int(p)}")
    return " and ".join(parts)


class PortWatcher:
    """Tracks SYN -> SYN-ACK pairs and reports the SYNs left unanswered."""

    def __init__(self, interface: str = "any", ignore_ports=(53, 80, 443),
                 timeout_s: float = 3.0, max_runtime_s: int = 900,
                 cap: int = 4000):
        self.interface = interface
        self.ignore_ports = list(ignore_ports)
        self.timeout_s = float(timeout_s)
        self.max_runtime_s = int(max_runtime_s)
        self.cap = cap

        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._pending: OrderedDict[tuple[str, int, str, int], dict] = OrderedDict()
        self._results: OrderedDict[tuple[str, str, int], dict] = OrderedDict()
        self._started: float | None = None
        self._client_ip: str | None = None
        self.error: str | None = None
        self.lines_seen = 0
        self.lines_unparsed = 0

    # -- lifecycle -----------------------------------------------------
    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, client_ip: str | None = None) -> None:
        problem = available()
        if problem:
            raise RuntimeError(problem)
        self.stop()
        with self._lock:
            self._pending.clear()
            self._results.clear()
            self.error = None
            self.lines_seen = 0
            self.lines_unparsed = 0
            self._client_ip = client_ip
        bpf = build_filter(client_ip, self.ignore_ports)
        cmd = ["tcpdump", "-l", "-n", "-q", "-i", self.interface, bpf]
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1)
        except (FileNotFoundError, PermissionError) as exc:
            self._proc = None
            raise RuntimeError(f"could not start tcpdump: {exc}")
        self._started = time.time()
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        proc, self._proc = self._proc, None
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass
        self._started = None

    # -- capture -------------------------------------------------------
    def _reader(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            if proc is not self._proc:
                return
            if self._started and (time.time() - self._started) > self.max_runtime_s:
                self.error = (f"capture stopped after {self.max_runtime_s}s "
                              "(max_runtime_s)")
                self.stop()
                return
            self._handle(line)
        rc = proc.poll()
        if rc not in (0, None) and proc is self._proc:
            err = ""
            try:
                err = (proc.stderr.read() or "").strip() if proc.stderr else ""
            except (OSError, ValueError):
                pass
            self.error = err or f"tcpdump exited {rc}"

    def _handle(self, line: str) -> None:
        self.lines_seen += 1
        m = LINE_RE.match(line.strip())
        if not m:
            self.lines_unparsed += 1
            return
        flags = m.group("flags")
        src, dst = m.group("src"), m.group("dst")
        sport, dport = int(m.group("sport")), int(m.group("dport"))
        # tcpdump renders an ACK as "." inside the flag list, so "S." is a
        # SYN-ACK and a bare "S" is the client's opening SYN.
        is_syn = "S" in flags
        syn_ack = is_syn and "." in flags

        with self._lock:
            if syn_ack:
                # Server answered: dst/dport of the SYN-ACK is the original
                # client side.
                key = (dst, dport, src, sport)
                self._pending.pop(key, None)
                rkey = (dst, src, sport)
                if rkey in self._results:
                    self._results[rkey]["answered"] += 1
                    self._results[rkey]["unanswered"] = max(
                        0, self._results[rkey]["unanswered"] - 1)
            elif is_syn:
                key = (src, sport, dst, dport)
                self._pending[key] = {"ts": time.time(), "src": src,
                                      "sport": sport, "dst": dst,
                                      "dport": dport}
                while len(self._pending) > self.cap:
                    self._pending.popitem(last=False)

    # -- reporting -----------------------------------------------------
    def sweep(self) -> None:
        """Move SYNs older than timeout_s into the unanswered results."""
        cutoff = time.time() - self.timeout_s
        with self._lock:
            expired = [k for k, v in self._pending.items() if v["ts"] < cutoff]
            for k in expired:
                v = self._pending.pop(k)
                rkey = (v["src"], v["dst"], v["dport"])
                entry = self._results.setdefault(rkey, {
                    "client_ip": v["src"], "dst_ip": v["dst"],
                    "dport": v["dport"], "unanswered": 0, "answered": 0,
                    "first_ts": v["ts"], "last_ts": v["ts"],
                })
                entry["unanswered"] += 1
                entry["last_ts"] = max(entry["last_ts"], v["ts"])
            while len(self._results) > self.cap:
                self._results.popitem(last=False)

    def snapshot(self) -> dict:
        self.sweep()
        with self._lock:
            rows = [dict(v) for v in self._results.values()]
            pending = len(self._pending)
        rows.sort(key=lambda r: (-r["unanswered"], -r["last_ts"]))
        for r in rows:
            r["verdict"] = _verdict(r)
        return {
            "running": self.running,
            "client_ip": self._client_ip,
            "started": self._started,
            "runtime_s": (time.time() - self._started) if self._started else 0,
            "pending": pending,
            "rows": rows,
            "error": self.error,
            "lines_seen": self.lines_seen,
            "lines_unparsed": self.lines_unparsed,
            "interface": self.interface,
            "ignore_ports": self.ignore_ports,
            "max_runtime_s": self.max_runtime_s,
        }


# Ports known to carry protocols sniproxy cannot route.
_KNOWN_BAD = {
    8080: "CODM downloader (Tencent GCloud, binary, no SNI/Host)",
    8085: "CODM downloader (Tencent GCloud, binary, no SNI/Host)",
    8013: "CODM downloader (Tencent GCloud, binary, no SNI/Host)",
}


def _verdict(row: dict) -> dict:
    port = row["dport"]
    if row["unanswered"] == 0:
        return i18n.portwatch_fine()
    known = _KNOWN_BAD.get(port)
    if known:
        return i18n.portwatch_known_bad(port, row["unanswered"], known)
    return i18n.portwatch_unknown(port, row["unanswered"])


def selftest(interface: str, client_ip: str | None, seconds: int,
             ignore_ports: Sequence[int]) -> int:
    problem = available()
    if problem:
        print(f"  {problem}")
        return 1
    print("--- line parsing ---")
    samples = [
        "15:17:14.123456 IP 84.241.45.220.39460 > 172.20.46.2.8080: "
        "Flags [S], seq 1, win 64240, length 0",
        "15:17:14.223456 IP 172.20.46.2.8080 > 84.241.45.220.39460: "
        "Flags [S.], seq 2, ack 2, win 65160, length 0",
        "15:17:14.323456 eth0  In  IP 84.241.45.220.39461 > 1.2.3.4.8085: "
        "Flags [S], seq 1, win 64240, length 0",
    ]
    bad = 0
    for s in samples:
        m = LINE_RE.match(s)
        if not m:
            print(f"  FAIL {s[:60]}")
            bad += 1
        else:
            print(f"  ok   {m.group('src')}.{m.group('sport')} -> "
                  f"{m.group('dst')}.{m.group('dport')} "
                  f"flags=[{m.group('flags')}]")
    if bad:
        return 1

    print(f"\n--- live capture on {interface} for {seconds}s ---")
    print(f"    filter: {build_filter(client_ip, ignore_ports)}")
    w = PortWatcher(interface=interface, ignore_ports=ignore_ports,
                    max_runtime_s=seconds + 5)
    try:
        w.start(client_ip)
    except RuntimeError as exc:
        print(f"  FAIL: {exc}")
        return 1
    time.sleep(seconds)
    snap = w.snapshot()
    w.stop()
    print(f"  packets parsed: {snap['lines_seen'] - snap['lines_unparsed']} "
          f"/ {snap['lines_seen']}")
    if snap["error"]:
        print(f"  error: {snap['error']}")
    if not snap["rows"]:
        print("  no unanswered SYNs seen (either all good, or no traffic "
              "matched the filter)")
    for r in snap["rows"][:20]:
        print(f"  {r['client_ip']} -> {r['dst_ip']}:{r['dport']}  "
              f"unanswered={r['unanswered']} answered={r['answered']}")
        print(f"      {i18n.pick(r['verdict'])}")
    return 0

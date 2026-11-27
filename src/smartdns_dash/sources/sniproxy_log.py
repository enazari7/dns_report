"""sniproxy access-log parsing and rotation-safe tailing.

Reference line (from the project brief):

    2026-08-02 15:17:14 84.241.45.220:39460 -> 172.20.46.2:443 -> \
129.226.1.156:443 [sg.msdkfaas.com] 4363/4363 bytes tx 1628/1628 bytes rx \
0.751 seconds

Two things about this format that bite:

* The origin can be the literal string ``NONE`` when sniproxy could not
  resolve or connect. That is a routing failure and the UI flags it.
* The SNI can be empty (``[]``) when the client sent none. sniproxy cannot
  route those, so they are flagged too.

Byte direction: per the brief, ``tx`` is origin -> client and ``rx`` is
client -> origin. This module keeps the raw field names and exposes them as
``bytes_tx`` / ``bytes_rx`` plus the explicit aliases ``from_origin`` /
``to_origin`` so the UI never has to guess. If ``ss -ti`` ever proves the
opposite, flip ``TX_IS_FROM_ORIGIN`` below and nothing else changes.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterable
from datetime import datetime

TX_IS_FROM_ORIGIN = True

# The byte fields appear as "4363/4363" (written/total). Accept a bare number
# too, in case a build emits only one value.
_NUM = r"(?:\d+(?:/\d+)?)"

LINE_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<client>\S+)\s+->\s+"
    r"(?P<listener>\S+)\s+->\s+"
    r"(?P<origin>\S+)\s+"
    r"\[(?P<sni>[^\]]*)\]\s+"
    r"(?P<tx>" + _NUM + r")\s+bytes\s+tx\s+"
    r"(?P<rx>" + _NUM + r")\s+bytes\s+rx\s+"
    r"(?P<dur>[\d.]+)\s+seconds\s*$"
)


def _split_hostport(s: str) -> tuple[str, int | None]:
    """Split ``ip:port``. Handles bracketed IPv6 and the literal NONE."""
    if not s or s.upper() == "NONE":
        return ("NONE", None)
    if s.startswith("["):
        host, _, rest = s.partition("]")
        host = host[1:]
        port = rest.lstrip(":")
        return (host, int(port) if port.isdigit() else None)
    host, _, port = s.rpartition(":")
    if not host:  # no colon at all
        return (s, None)
    return (host, int(port) if port.isdigit() else None)


def _first_num(field: str) -> int:
    """'4363/4363' -> 4363. Uses the first value; they are normally equal and
    a divergence means a truncated transfer, which we surface separately."""
    head = field.split("/", 1)[0]
    return int(head) if head.isdigit() else 0


def _both_nums(field: str) -> tuple[int, int]:
    parts = field.split("/", 1)
    a = int(parts[0]) if parts[0].isdigit() else 0
    b = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else a
    return a, b


def parse_line(line: str, source: str = "") -> dict | None:
    """Parse one access-log line. Returns None for anything unrecognised."""
    line = line.strip()
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        return None
    g = m.groupdict()

    client_ip, client_port = _split_hostport(g["client"])
    listener_ip, listener_port = _split_hostport(g["listener"])
    origin_ip, origin_port = _split_hostport(g["origin"])

    tx_a, tx_b = _both_nums(g["tx"])
    rx_a, rx_b = _both_nums(g["rx"])

    # sniproxy writes local time without a zone. Treat it as local time.
    try:
        naive = datetime.strptime(g["date"] + " " + g["time"], "%Y-%m-%d %H:%M:%S")
        ts = naive.timestamp()
    except ValueError:
        ts = time.time()

    sni = g["sni"].strip().lower().rstrip(".")
    origin_failed = origin_ip == "NONE"

    rec = {
        "source": source,
        "ts": ts,
        "time": g["time"],
        "date": g["date"],
        "client_ip": client_ip,
        "client_port": client_port,
        "listener_ip": listener_ip,
        "listener_port": listener_port,
        "origin_ip": origin_ip,
        "origin_port": origin_port,
        "sni": sni,
        "bytes_tx": tx_a,
        "bytes_tx_total": tx_b,
        "bytes_rx": rx_a,
        "bytes_rx_total": rx_b,
        "duration": float(g["dur"]),
        "origin_failed": origin_failed,
        "no_sni": sni == "",
        "truncated": (tx_a != tx_b) or (rx_a != rx_b),
        "raw": line,
    }
    # Explicit direction aliases so the UI is never ambiguous.
    if TX_IS_FROM_ORIGIN:
        rec["from_origin"] = tx_a
        rec["to_origin"] = rx_a
    else:
        rec["from_origin"] = rx_a
        rec["to_origin"] = tx_a
    rec["problem"] = origin_failed or rec["no_sni"]
    return rec


class Tailer:
    """Rotation-safe incremental reader for one file.

    logrotate can replace a log in three ways, and all three have to be
    survived without either re-reading everything or stalling silently:

    * **rename + create** - the inode changes, so (st_dev, st_ino) catches it.
    * **copytruncate, shrinking** - the file is truncated to 0 and regrows;
      the size drops below our read position, which catches it.
    * **copytruncate, same size** - size and inode both look unchanged. Size
      comparison alone misses this, so we also fingerprint the first bytes of
      the file: if the head changed, it is not the same log any more.

    Partial trailing lines are buffered until the newline arrives, so a record
    read mid-write is never parsed as a truncated line.

    Note the ``from_end`` semantics: with the default True, content already in
    the file when the tailer first opens it is deliberately skipped - this is a
    live feed, not a backfill. Use ``tail_last()`` for history.
    """

    HEAD_BYTES = 256

    def __init__(self, path: str, label: str = "", from_end: bool = True,
                 max_line: int = 8192):
        self.path = path
        self.label = label or os.path.basename(path)
        self.from_end = from_end
        self.max_line = max_line
        self._fh = None
        self._ino: tuple[int, int] | None = None
        self._pos = 0
        self._head = b""
        self._buf = ""
        self.error: str | None = None
        self.bytes_read = 0
        self.lines_seen = 0
        self.lines_unparsed = 0
        self.rotations = 0

    # -- internals -----------------------------------------------------
    def _read_head(self) -> bytes:
        try:
            with open(self.path, "rb") as fh:
                return fh.read(self.HEAD_BYTES)
        except OSError:
            return b""

    def _open(self, seek_end: bool) -> None:
        self._close()
        try:
            # Held open across calls so the read offset survives; closed by
            # _close() on rotation or shutdown. A context manager cannot
            # express that.
            fh = open(self.path, encoding="utf-8",  # noqa: SIM115
                      errors="replace")
        except OSError as exc:
            self.error = f"{self.path}: {exc.strerror or exc}"
            return
        st = os.fstat(fh.fileno())
        self._fh = fh
        self._ino = (st.st_dev, st.st_ino)
        self._buf = ""
        if seek_end:
            fh.seek(0, os.SEEK_END)
        self._pos = fh.tell()
        self._head = self._read_head()
        self.error = None

    def _close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
        self._fh = None
        self._ino = None

    def _rotated(self) -> bool:
        try:
            st = os.stat(self.path)
        except OSError:
            return False
        if self._ino != (st.st_dev, st.st_ino):
            return True
        if st.st_size < self._pos:
            return True                      # truncated and shrank
        # Same inode, same-or-larger size. Appending never rewrites bytes that
        # are already there, so compare only the prefix the two have in common:
        # if those bytes changed, the content was replaced, not extended.
        if self._head and self._pos > 0:
            head_now = self._read_head()
            n = min(len(self._head), len(head_now))
            if n and head_now[:n] != self._head[:n]:
                return True
        return False

    # -- public --------------------------------------------------------
    def read_new(self) -> list[dict]:
        """Return records appended since the last call."""
        if self._fh is None:
            self._open(seek_end=self.from_end)
            if self._fh is None:
                return []
        elif self._rotated():
            # Drain whatever is left in the old handle first, then follow the
            # new file from its beginning.
            self.rotations += 1
            leftovers = self._drain()
            self._open(seek_end=False)
            return leftovers + (self._drain() if self._fh else [])
        return self._drain()

    def _drain(self) -> list[dict]:
        if self._fh is None:
            return []
        out: list[dict] = []
        try:
            chunk = self._fh.read()
        except OSError as exc:
            self.error = str(exc)
            self._close()
            return out
        self._pos = self._fh.tell()
        if not chunk:
            return out
        if len(self._head) < self.HEAD_BYTES:
            # Grow the fingerprint as content arrives, so a later same-size
            # truncation is still detectable.
            self._head = self._read_head()
        self.bytes_read += len(chunk)
        data = self._buf + chunk
        lines = data.split("\n")
        self._buf = lines.pop()  # incomplete trailing line
        if len(self._buf) > self.max_line:
            # A line this long is corruption, not a record. Drop it.
            self._buf = ""
        for line in lines:
            if not line.strip():
                continue
            self.lines_seen += 1
            rec = parse_line(line, source=self.label)
            if rec is None:
                self.lines_unparsed += 1
                continue
            out.append(rec)
        return out

    def tail_last(self, n: int) -> list[dict]:
        """Read the last n parsable records without disturbing the follow
        position. Reads at most the final 2 MiB of the file."""
        out: list[dict] = []
        limit = 2 * 1024 * 1024
        try:
            size = os.path.getsize(self.path)
            window = min(size, limit)
            with open(self.path, "rb") as fh:
                fh.seek(size - window)
                blob = fh.read().decode("utf-8", errors="replace")
        except OSError:
            return out
        lines = blob.split("\n")
        if size > limit and lines:
            lines = lines[1:]  # first line is probably cut mid-record
        for line in reversed(lines):
            if len(out) >= n:
                break
            rec = parse_line(line, source=self.label)
            if rec:
                out.append(rec)
        out.reverse()
        return out

    def stats(self) -> dict:
        return {
            "path": self.path,
            "label": self.label,
            "error": self.error,
            "lines_seen": self.lines_seen,
            "lines_unparsed": self.lines_unparsed,
            "rotations": self.rotations,
            "open": self._fh is not None,
        }


class MultiTailer:
    """Tails several access logs and merges them in timestamp order."""

    def __init__(self, files: dict[str, str], from_end: bool = True):
        self.tailers = [Tailer(path, label=label, from_end=from_end)
                        for label, path in files.items()]

    def read_new(self) -> list[dict]:
        recs: list[dict] = []
        for t in self.tailers:
            recs.extend(t.read_new())
        recs.sort(key=lambda r: r["ts"])
        return recs

    def backfill(self, n: int) -> list[dict]:
        recs: list[dict] = []
        for t in self.tailers:
            recs.extend(t.tail_last(n))
        recs.sort(key=lambda r: r["ts"])
        return recs[-n:] if n else recs

    def stats(self) -> list[dict]:
        return [t.stats() for t in self.tailers]


def selftest(paths: Iterable[str]) -> int:
    """Parse the sample line, then a real tail of each given file."""
    sample = ("2026-08-02 15:17:14 84.241.45.220:39460 -> 172.20.46.2:443 -> "
              "129.226.1.156:443 [sg.msdkfaas.com] 4363/4363 bytes tx "
              "1628/1628 bytes rx 0.751 seconds")
    rec = parse_line(sample, source="sample")
    print("--- reference line ---")
    if not rec:
        print("FAIL: reference line did not parse")
        return 1
    for k in ("client_ip", "listener_ip", "origin_ip", "origin_port", "sni",
              "bytes_tx", "bytes_rx", "from_origin", "to_origin", "duration"):
        print(f"  {k:14} = {rec[k]!r}")

    print("\n--- edge cases ---")
    for label, line in [
        ("origin NONE", "2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443 -> "
                        "NONE [x.example.com] 0/0 bytes tx 517/517 bytes rx "
                        "0.004 seconds"),
        ("empty SNI", "2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443 -> "
                      "NONE [] 0/0 bytes tx 0/0 bytes rx 0.001 seconds"),
        ("http log", "2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:80 -> "
                     "5.6.7.8:80 [api.example.com] 120/120 bytes tx 90/90 "
                     "bytes rx 0.030 seconds"),
    ]:
        r = parse_line(line, source="edge")
        status = "ok" if r else "FAIL"
        extra = ""
        if r:
            extra = (f"origin={r['origin_ip']} sni={r['sni']!r} "
                     f"problem={r['problem']}")
        print(f"  {label:12} {status:5} {extra}")

    rc = 0
    for p in paths:
        print(f"\n--- {p} ---")
        t = Tailer(p, from_end=False)
        recs = t.tail_last(5)
        if t.error:
            print(f"  error: {t.error}")
            rc = 1
            continue
        if not recs:
            print("  no parsable records in the last 2 MiB "
                  "(empty log, or the format differs - send me 3 raw lines)")
            continue
        for r in recs:
            print(f"  {r['time']} {r['client_ip']:>15} -> {r['origin_ip']:>15} "
                  f"[{r['sni']}] tx={r['bytes_tx']} rx={r['bytes_rx']}")
    return rc

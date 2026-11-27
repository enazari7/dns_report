"""Service state and the config-staleness check.

The staleness check exists because sniproxy reads its config only at startup.
If domains.txt (or the generated sniproxy.conf) is newer than the running
sniproxy process, the file on disk looks correct while the process is still
serving the old routing table. That is invisible from the shell and cost an
entire debugging session, so the dashboard puts it in the header.

Process start time is read from /proc rather than parsed out of systemd's
human-readable ActiveEnterTimestamp, which is locale- and timezone-dependent.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Sequence

from .. import i18n

_CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


def boot_time() -> float | None:
    try:
        with open("/proc/stat", encoding="ascii") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def process_start_time(pid: int) -> float | None:
    """Absolute unix time the process started, from /proc/<pid>/stat."""
    bt = boot_time()
    if bt is None or pid <= 0:
        return None
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return None
    # comm may contain spaces and parentheses; everything after the last ')'
    # is the stable part. starttime is field 22 overall = index 19 after that.
    try:
        tail = data[data.rindex(")") + 2:].split()
        starttime_ticks = float(tail[19])
    except (ValueError, IndexError):
        return None
    return bt + (starttime_ticks / _CLK_TCK)


def _systemctl_show(unit: str, props: Sequence[str]) -> dict[str, str]:
    cmd = ["systemctl", "show", unit, "-p", ",".join(props)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    out = {}
    for line in (proc.stdout or "").splitlines():
        k, _, v = line.partition("=")
        if k:
            out[k.strip()] = v.strip()
    return out


def service_status(unit: str) -> dict:
    props = _systemctl_show(unit, [
        "ActiveState", "SubState", "MainPID", "ActiveEnterTimestamp",
        "NRestarts", "Result", "ExecMainStatus",
    ])
    pid = 0
    try:
        pid = int(props.get("MainPID", "0") or 0)
    except ValueError:
        pid = 0
    started = process_start_time(pid) if pid else None
    return {
        "unit": unit,
        "active_state": props.get("ActiveState", "unknown"),
        "sub_state": props.get("SubState", ""),
        "pid": pid,
        "started_at": started,
        "started_text": props.get("ActiveEnterTimestamp", ""),
        "uptime_s": (time.time() - started) if started else None,
        "restarts": props.get("NRestarts", ""),
        "result": props.get("Result", ""),
        "healthy": props.get("ActiveState") == "active"
                   and props.get("SubState") == "running",
    }


def staleness(unit: str, watch_paths: Sequence[str]) -> dict:
    """Compare a unit's start time against the mtime of the files that feed
    its config. Newer file than process = the running config is stale."""
    st = service_status(unit)
    started = st.get("started_at")
    files: list[dict] = []
    newest = None
    for p in watch_paths:
        try:
            m = os.path.getmtime(p)
        except OSError:
            files.append({"path": p, "mtime": None, "missing": True,
                          "stale": False})
            continue
        stale = bool(started and m > started)
        files.append({"path": p, "mtime": m, "missing": False, "stale": stale})
        if newest is None or m > newest:
            newest = m

    is_stale = bool(started and newest and newest > started)
    lag = (newest - started) if is_stale and started and newest else 0.0
    return {
        "unit": unit,
        "service": st,
        "files": files,
        "stale": is_stale,
        "lag_s": lag,
        "message": (
            i18n.stale_message(unit, _ago(started), _ago(newest)) if is_stale
            else (i18n.fresh_message(unit) if started
                  else i18n.unknown_start(unit))
        ),
    }


def _ago(ts: float | None) -> str:
    if not ts:
        return "unknown"
    d = max(0.0, time.time() - ts)
    if d < 90:
        return f"{int(d)}s ago"
    if d < 5400:
        return f"{int(d / 60)}m ago"
    if d < 172800:
        return f"{d / 3600:.1f}h ago"
    return f"{d / 86400:.1f}d ago"


def journal(unit: str, lines: int = 100) -> str:
    cmd = ["journalctl", "-u", unit, "-n", str(int(lines)), "--no-pager",
           "-o", "short-iso"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return f"journalctl unavailable: {exc}"
    return (proc.stdout or "") + (proc.stderr or "")


def tail_file(path: str, lines: int = 200) -> str:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            window = min(size, 512 * 1024)
            fh.seek(size - window)
            blob = fh.read().decode("utf-8", errors="replace")
    except OSError as exc:
        return f"{path}: {exc.strerror or exc}"
    return "\n".join(blob.splitlines()[-lines:])


def selftest(unit: str, watch_paths: Sequence[str]) -> int:
    print(f"--- service {unit} ---")
    st = service_status(unit)
    for k, v in st.items():
        print(f"  {k:16} = {v}")
    print(f"\n--- staleness vs {list(watch_paths)} ---")
    s = staleness(unit, watch_paths)
    for f in s["files"]:
        mt = time.strftime("%Y-%m-%d %H:%M:%S",
                           time.localtime(f["mtime"])) if f["mtime"] else "-"
        print(f"  {f['path']:45} {mt}  stale={f['stale']} "
              f"missing={f['missing']}")
    print(f"  stale = {s['stale']}")
    print(f"  {i18n.pick(s['message'])}")
    return 0

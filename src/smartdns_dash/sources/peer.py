"""Fetching the other server's allow-list for the two-server diff.

Both servers must carry an identical list. Clients alternate between the two
nameservers, so any divergence shows up as intermittent behaviour - a game
that works every other launch. That is miserable to diagnose by hand, which is
why the diff is a first-class panel.

Two modes:

* **ssh** - requires key auth to the peer. The brief notes SSH is currently
  root+password with no key between the servers, so the README has the
  three commands to set that up.
* **paste** - no connectivity needed. You run one command on the other box and
  paste the output. Slower, but always available.

The SSH call is deliberately read-only: it runs ``cat`` on one fixed path and
nothing else, with BatchMode so it can never hang on a password prompt.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence

from .. import i18n
from . import domains as dom


class PeerError(Exception):
    pass


def ssh_command(host: str, user: str, port: int, key: str, timeout: int,
                remote_cmd: str) -> list[str]:
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",                 # never prompt for a password
        "-o", f"ConnectTimeout={max(1, timeout)}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-p", str(port),
    ]
    if key:
        cmd += ["-i", key, "-o", "IdentitiesOnly=yes"]
    cmd += [f"{user}@{host}", remote_cmd]
    return cmd


def fetch_via_ssh(host: str, user: str = "root", port: int = 22,
                  key: str = "", timeout: int = 8,
                  path: str = "/etc/smartdns/domains.txt") -> str:
    if shutil.which("ssh") is None:
        raise PeerError("ssh client not installed")
    if not host:
        raise PeerError("no peer host configured")
    # Fixed remote command, no interpolation of user input beyond the
    # configured path.
    remote = f"cat -- {_shquote(path)}"
    cmd = ssh_command(host, user, port, key, timeout, remote)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        raise PeerError(f"ssh to {host} timed out")
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        hint = ""
        joined = " ".join(err).lower()
        if "permission denied" in joined or "publickey" in joined:
            hint = (" - key auth is not set up yet. See README section 5, or "
                    "use paste mode.")
        elif "connection refused" in joined or "timed out" in joined:
            hint = " - is the peer reachable from this box?"
        raise PeerError((err[-1] if err else f"ssh exited {proc.returncode}")
                        + hint)
    return proc.stdout


def _shquote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def check_ssh(host: str, user: str, port: int, key: str,
              timeout: int) -> tuple[bool, str]:
    """Cheap reachability probe so the UI can say why the diff is unavailable
    before the user clicks anything."""
    if not host:
        return False, "no peer host configured"
    if shutil.which("ssh") is None:
        return False, "ssh client not installed"
    if key and not os.path.exists(key):
        return False, f"key file not found: {key}"
    cmd = ssh_command(host, user, port, key, timeout, "true")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        return False, "timed out"
    if proc.returncode == 0:
        return True, "ok"
    msg = (proc.stderr or "").strip().splitlines()
    return False, (msg[-1] if msg else f"exit {proc.returncode}")


def compare(local_path: str, peer_text: str, my_name: str,
            their_name: str) -> dict:
    mine = dom.parse(local_path)
    if mine.error:
        raise PeerError(mine.error)
    theirs = dom.normalize_text(peer_text)
    result = dom.diff_lists(mine.normalized(), theirs, my_name, their_name)
    result["my_count"] = len(mine.normalized())
    result["their_count"] = len(theirs)
    # diff_lists already supplies a bilingual message.
    return result


PASTE_HINT = i18n.PASTE_HINT


def selftest(host: str, user: str, port: int, key: str, timeout: int,
             local_path: str, my_name: str, their_name: str) -> int:
    print(f"--- ssh probe {user}@{host}:{port} ---")
    ok, msg = check_ssh(host, user, port, key, timeout)
    print(f"  reachable = {ok}  ({msg})")
    if not ok:
        print("\n  Falling back to paste mode is fine. To set up key auth:")
        print("    ssh-keygen -t ed25519 -N '' -f " + (key or "/root/.ssh/id_ed25519_smartdns"))
        print(f"    ssh-copy-id -i {(key or '/root/.ssh/id_ed25519_smartdns')}.pub {user}@{host}")
        return 0
    try:
        text = fetch_via_ssh(host, user, port, key, timeout)
    except PeerError as exc:
        print(f"  FAIL fetch: {exc}")
        return 1
    res = compare(local_path, text, my_name, their_name)
    print(f"\n  {my_name}: {res['my_count']} entries")
    print(f"  {their_name}: {res['their_count']} entries")
    print(f"  in sync: {res['in_sync']}")
    for s in res["only_mine"][:20]:
        print(f"    only on {my_name}:  {s}")
    for s in res["only_theirs"][:20]:
        print(f"    only on {their_name}: {s}")
    return 0


# ---------------------------------------------------------------------------
# Mirrored writes
# ---------------------------------------------------------------------------
#
# Applying a change to one server and forgetting the other is the commonest way
# the pair drifts apart, and the resulting symptom - a game that works every
# other launch - is miserable to diagnose. So the dashboard can do both in one
# action.
#
# The ordering is deliberate: peer first, local second. If the peer fails you
# still have a matched pair (both old) rather than a mismatched one. Applying
# locally first and then failing on the peer would leave exactly the divergence
# this feature exists to prevent.

REMOTE_APPLY = r"""
set -eu
DOMAINS="$1"; BACKUP_DIR="$2"; UPDATE="$3"; RESTART="$4"
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR" 2>/dev/null || true
BAK="$BACKUP_DIR/$(basename "$DOMAINS").$STAMP.peer"
cp -p "$DOMAINS" "$BAK"
echo "BACKUP=$BAK"
cat > "$DOMAINS.dash.tmp"
chmod --reference="$DOMAINS" "$DOMAINS.dash.tmp" 2>/dev/null || true
mv "$DOMAINS.dash.tmp" "$DOMAINS"
echo "WROTE=ok"
if ! "$UPDATE"; then
  echo "UPDATE=failed"
  cp -p "$BAK" "$DOMAINS"; "$UPDATE" >/dev/null 2>&1 || true
  echo "ROLLED_BACK=1"; exit 3
fi
echo "UPDATE=ok"
for unit in $RESTART; do
  if systemctl restart "$unit"; then echo "RESTART_$unit=ok";
  else echo "RESTART_$unit=failed"; exit 4; fi
done
echo "DONE=1"
"""


def apply_remote(host: str, user: str, port: int, key: str, timeout: int,
                 domains_path: str, backup_dir: str, update_script: str,
                 restart_units: Sequence[str], content: str) -> dict:
    """Write `content` to the peer's allow-list, regenerate and restart there.

    The whole operation is one shell script piped over SSH with the new file on
    stdin: a single round trip, and the remote side does its own backup and its
    own rollback if the generator fails. Splitting it into several SSH calls
    would leave windows where the peer is half-changed.
    """
    result = {"ok": False, "host": host, "steps": [], "backup": None,
              "error": None, "raw": ""}
    if shutil.which("ssh") is None:
        result["error"] = "ssh client not installed"
        return result
    if not host:
        result["error"] = "no peer host configured"
        return result

    cmd = ssh_command(host, user, port, key, timeout,
                      "sh -s -- "
                      f"{_shquote(domains_path)} {_shquote(backup_dir)} "
                      f"{_shquote(update_script)} "
                      f"{_shquote(' '.join(restart_units))}")
    script = REMOTE_APPLY + "\n"
    try:
        proc = subprocess.run(cmd, input=script + content,
                              capture_output=True, text=True,
                              timeout=max(timeout, 20) + 120)
    except subprocess.TimeoutExpired:
        result["error"] = f"ssh to {host} timed out during apply"
        return result

    out = (proc.stdout or "")
    result["raw"] = (out + (proc.stderr or ""))[-4000:]
    for line in out.splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k == "BACKUP":
            result["backup"] = v
        else:
            result["steps"].append({"name": k.lower().replace("_", " "),
                                    "ok": v == "ok" or v == "1",
                                    "detail": v})
    if proc.returncode == 0 and "DONE=1" in out:
        result["ok"] = True
    else:
        err = (proc.stderr or "").strip().splitlines()
        hint = ""
        joined = " ".join(err).lower()
        if "permission denied" in joined or "publickey" in joined:
            hint = " - key auth to the peer is not set up (README section 5)"
        elif "ROLLED_BACK=1" in out:
            hint = " - the peer rolled its own change back, so it is unchanged"
        result["error"] = ((err[-1] if err else f"ssh exited {proc.returncode}")
                           + hint)
    return result


def read_remote_mtime(host: str, user: str, port: int, key: str, timeout: int,
                      path: str) -> float | None:
    """Peer's allow-list mtime, so a mirrored write can refuse when the two
    files are already out of step."""
    cmd = ssh_command(host, user, port, key, timeout,
                      f"stat -c %Y -- {_shquote(path)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    try:
        return float((proc.stdout or "").strip())
    except ValueError:
        return None

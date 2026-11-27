#!/usr/bin/env python3
"""Smart DNS Observability Dashboard - single-file installer.

Everything is embedded in this one file. Copy it to the server any way you
like (SFTP in text mode is fine - that is the point) and run:

    sudo python3 install.py

Nothing about a particular server is baked in. Identity values default to
`auto` and are discovered at runtime, so this same file installs on a cloned
VM with different addresses. To re-point an existing install instead, use
`smartdns-dashboard reconfigure`.

Options:
    --check-only     verify the payload and print what would happen
    --extract-only   unpack to /opt/smartdns-dashboard, do nothing else
    --password PW    non-interactive password (careful: shell history)
    --name NAME      server label shown in the UI (default: hostname)
    --language en|fa default interface language
    --peer-host IP   the other server, for the two-server diff
    --peer-name NAME its label
    --behind-proxy   configure for nginx/Caddy in front (bind stays loopback)
    --viewer-password PW  also create a read-only account named "viewer"
    --allow-ips A,B  only these addresses/CIDRs may reach the dashboard
    --bind ADDR      listen address (default 127.0.0.1)
    --port N         listen port (default 9443)
    --no-start       install but do not enable/start the service
    --force-config   overwrite an existing config.ini
    --yes            never prompt; accept every default

Re-running upgrades the code in place and leaves your config alone.
"""

import base64
import binascii
import getpass
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import socket
import zipfile

APP_DIR = "/opt/smartdns-dashboard"
CFG_DIR = "/etc/smartdns-dashboard"
CFG = os.path.join(CFG_DIR, "config.ini")
UNIT = "/etc/systemd/system/smartdns-dashboard.service"
BACKUP_DIR = "/root/smartdns-backups"
HISTORY_DIR = "/var/lib/smartdns-dashboard"

PAYLOAD_SHA256 = "@@PAYLOAD_SHA256@@"
PAYLOAD_SIZE = @@PAYLOAD_SIZE@@



# ---------------------------------------------------------------- output
def say(msg):
    print("\n\033[1;34m==>\033[0m " + msg, flush=True)


def ok(msg):
    print("    \033[1;32m+\033[0m " + msg, flush=True)


def warn(msg):
    print("    \033[1;33m!\033[0m " + msg, flush=True)


def die(msg, code=1):
    print("\n\033[1;31m  x " + msg + "\033[0m\n", file=sys.stderr)
    sys.exit(code)


def run(cmd, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run(cmd, **kw)


# ---------------------------------------------------------------- payload
def payload_bytes():
    # Strip every kind of whitespace first: a text-mode transfer may have
    # rewritten the line endings, and that must not matter.
    clean = re.sub(r"\s+", "", PAYLOAD)
    try:
        blob = base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError) as exc:
        die("the embedded payload could not be decoded (%s).\n"
            "      This file was damaged in transfer. Re-send install.py, and\n"
            "      make sure your SFTP client is not converting it - in WinSCP\n"
            "      that is Options > Preferences > Transfer > Binary." % exc)
    digest = hashlib.sha256(blob).hexdigest()
    if digest != PAYLOAD_SHA256 or len(blob) != PAYLOAD_SIZE:
        die("payload checksum mismatch - this file arrived damaged.\n"
            "      expected sha256 %s (%d bytes)\n"
            "      got      sha256 %s (%d bytes)\n\n"
            "      Re-send install.py. In WinSCP set the transfer mode to\n"
            "      Binary (Options > Preferences > Transfer)."
            % (PAYLOAD_SHA256, PAYLOAD_SIZE, digest, len(blob)))
    return blob


def extract(dest):
    blob = payload_bytes()
    z = zipfile.ZipFile(io.BytesIO(blob))
    root = os.path.realpath(dest)
    names = z.namelist()
    for n in names:
        target = os.path.realpath(os.path.join(dest, n))
        if not target.startswith(root + os.sep) and target != root:
            die("refusing to extract outside the destination: %r" % n)
    z.extractall(dest)
    return names


# ---------------------------------------------------------------- checks
def check_python():
    if sys.version_info < (3, 10):
        die("python 3.10+ required, found %d.%d" % sys.version_info[:2])
    ok("python %d.%d" % sys.version_info[:2])


def check_tools():
    for tool, why in [
        ("dnsdist", "required - the dnsdist console is the main data source"),
        ("systemctl", "required"),
        ("dig", "optional, for the Lookup panel (apt install dnsutils)"),
        ("tcpdump", "optional, for the Port watch panel"),
        ("ssh", "optional, for the two-server diff"),
    ]:
        if shutil.which(tool):
            ok(tool)
        elif why.startswith("required"):
            warn("%s NOT FOUND - %s" % (tool, why))
        else:
            warn("%s not found - %s" % (tool, why))


def venv_packages():
    """Candidate apt packages that provide a working `python3 -m venv`."""
    minor = "python3.%d-venv" % sys.version_info[1]
    return [minor, "python3-venv"]


def apt_install(packages):
    """Try each package in turn; return the first that installs."""
    run(["apt-get", "update", "-qq"])
    for pkg in packages:
        r = run(["apt-get", "install", "-y", "-qq", pkg])
        if r.returncode == 0:
            ok("installed %s" % pkg)
            return pkg
    return None


def ensure_venv_module():
    """On Debian/Ubuntu the `venv` module imports fine while `ensurepip` is
    missing, so `python3 -m venv` fails with an empty-looking error. Check
    both."""
    import importlib.util
    have_venv = importlib.util.find_spec("venv") is not None
    have_ensurepip = importlib.util.find_spec("ensurepip") is not None
    if have_venv and have_ensurepip:
        return True
    missing = []
    if not have_venv:
        missing.append("venv")
    if not have_ensurepip:
        missing.append("ensurepip")
    say("Python is missing %s - installing the venv package"
        % " and ".join(missing))
    if apt_install(venv_packages()) is None:
        die("could not install a venv package (%s).\n"
            "      Install it by hand and re-run:\n"
            "        apt-get update && apt-get install -y %s\n"
            "        python3 install.py"
            % (", ".join(venv_packages()), venv_packages()[0]))
    return True


def venv_has_pip(venv_py):
    if not os.path.exists(venv_py):
        return False
    return run([venv_py, "-m", "pip", "--version"]).returncode == 0


def create_venv(venv_dir):
    """Create the virtualenv, with a real diagnostic when it fails.

    The classic Ubuntu failure prints its complaint to stdout, not stderr, so
    surface both - an empty error message is worse than useless.
    """
    def attempt():
        return run([sys.executable, "-m", "venv", venv_dir])

    r = attempt()
    if r.returncode == 0 and venv_has_pip(os.path.join(venv_dir, "bin",
                                                       "python")):
        return
    if r.returncode == 0:
        # venv reported success but produced no pip - same root cause.
        r.stdout = ((r.stdout or "") +
                    "\nvenv was created but contains no pip - the "
                    "python3-venv package is probably missing")
        r.returncode = 1

    out = ((r.stdout or "") + (r.stderr or "")).strip()
    if "ensurepip" in out or "python3-venv" in out or "-venv" in out:
        warn("venv needs an extra apt package; installing it")
        shutil.rmtree(venv_dir, ignore_errors=True)
        if apt_install(venv_packages()) is not None:
            r = attempt()
            if r.returncode == 0:
                return
            out = ((r.stdout or "") + (r.stderr or "")).strip()

    die("virtualenv creation failed.\n\n"
        "      %s\n\n"
        "      Most often this means the venv apt package is missing and this\n"
        "      box cannot reach the apt mirrors. Fix it by hand, then re-run\n"
        "      `python3 install.py`:\n\n"
        "        apt-get update && apt-get install -y %s"
        % (out.replace("\n", "\n      ") or "(no output from python -m venv)",
           venv_packages()[0]))


def local_ips():
    """Global IPv4 addresses on this host."""
    out = []
    r = run(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            addr = parts[3].split("/")[0]
            if addr and addr not in out:
                out.append(addr)
    return out


def detect_spoof_ip(app_dir):
    """Ask the installed package to read the spoof target out of the generated
    dnsdist config. Purely informational here - the app resolves it at runtime,
    so the config can stay on `auto`."""
    sys.path.insert(0, app_dir)
    try:
        from smartdns_dash.config import detect_spoof_ip as d
        return d("/etc/dnsdist/dnsdist.conf",
                 "/etc/smartdns/generated/domains.proxy")
    except Exception:
        return "", "unknown"
    finally:
        sys.path.pop(0)


def ask(prompt, default, assume_yes):
    if assume_yes:
        return default
    shown = f" [{default}]" if default else ""
    try:
        got = input(f"    {prompt}{shown}: ").strip()
    except EOFError:
        return default
    return got or default


# ---------------------------------------------------------------- config
def set_ini(text, section, key, value):
    """Replace `key = ...` inside [section] only."""
    out, cur, done = [], None, False
    for line in text.split("\n"):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1]
        elif cur == section and not done:
            m = re.match(r"^(\s*)" + re.escape(key) + r"\s*=", line)
            if m:
                out.append("%s%s = %s" % (m.group(1), key, value))
                done = True
                continue
        out.append(line)
    if not done:
        warn("config: [%s] %s not found, left unchanged" % (section, key))
    return "\n".join(out)


def write_config(app_dir, opts):
    os.makedirs(CFG_DIR, mode=0o700, exist_ok=True)
    os.chmod(CFG_DIR, 0o700)

    if os.path.exists(CFG) and not opts["force_config"]:
        ok("%s already exists - leaving it alone" % CFG)
        print("       to change addresses or the peer, use:")
        print("         %s/venv/bin/python -m smartdns_dash reconfigure --help"
              % APP_DIR)
        return False

    with open(os.path.join(app_dir, "config.example.ini"), encoding="utf-8") as fh:
        text = fh.read()

    import secrets
    text = set_ini(text, "auth", "secret_key", secrets.token_hex(32))

    ips = local_ips()
    spoof, spoof_src = detect_spoof_ip(app_dir)
    hostname = socket.gethostname() or "smartdns"

    print("    Detected:")
    print("      hostname       %s" % hostname)
    print("      addresses      %s" % (", ".join(ips) or "(none found)"))
    print("      spoof target   %s   [%s]"
          % (spoof or "not found", spoof_src))
    if not spoof:
        warn("could not read the spoof address from the dnsdist config. The "
             "dashboard still works; set [server] public_ip by hand if the "
             "Lookup panel needs it.")
    print()

    name = opts["name"] or ask("Server label", hostname, opts["yes"])
    text = set_ini(text, "server", "name", name)
    # public_ip / local_ip stay on `auto`: resolved at runtime, so a clone
    # picks up its own values with no edit.
    text = set_ini(text, "server", "language", opts["language"] or "en")
    bind = opts["bind"] or "127.0.0.1"
    text = set_ini(text, "server", "bind", bind)

    # Never write a config that would make the service refuse to start, and
    # never take a port the DNS/proxy stack needs.
    port = int(opts["port"] or 0)
    sys.path.insert(0, app_dir)
    try:
        from smartdns_dash import preflight
    except Exception:
        preflight = None
    finally:
        sys.path.pop(0)

    if preflight is not None:
        if port:
            v = preflight.check_port(port, bind)
            if v["fatal"]:
                warn("port %d rejected: %s" % (port, v["fatal"]))
                port = 0
            for w in v["warnings"]:
                warn(w)
        if not port:
            port = preflight.pick_free_port(bind) or 9443
            ok("chose port %d (free, and clear of the DNS stack)" % port)
    else:
        port = port or 9443
    text = set_ini(text, "server", "port", str(port))
    if opts["behind_proxy"]:
        text = set_ini(text, "server", "behind_proxy", "true")
        text = set_ini(text, "server", "forwarded_allow_ips", "127.0.0.1")
    if opts["allow_ips"]:
        text = set_ini(text, "server", "allow_ips", opts["allow_ips"])

    peer_host = opts["peer_host"]
    if peer_host is None and not opts["yes"]:
        other = [a for a in ips]
        hint = ("e.g. the other DNS server's internal address; blank for a "
                "single-server setup")
        print("    Two-server diff (optional). %s" % hint)
        peer_host = ask("Peer address", "", opts["yes"])
    if peer_host:
        text = set_ini(text, "peer", "enabled", "true")
        text = set_ini(text, "peer", "host", peer_host)
        peer_name = opts["peer_name"] or ask("Peer label", "peer", opts["yes"])
        text = set_ini(text, "peer", "name", peer_name)

    password = opts["password"]
    if password is None:
        say("Set the dashboard password")
        print("    This protects a web app that runs as root. Use something "
              "long.\n")
        while True:
            p1 = getpass.getpass("    Password: ")
            if len(p1) < 8:
                print("    too short, try again")
                continue
            p2 = getpass.getpass("    Repeat:   ")
            if p1 != p2:
                print("    they do not match, try again")
                continue
            password = p1
            break
        if len(password) < 12:
            warn("shorter than 12 characters - fine behind an SSH tunnel, "
                 "weak if you expose the port")

    sys.path.insert(0, app_dir)
    try:
        from smartdns_dash import auth
    finally:
        sys.path.pop(0)
    text = set_ini(text, "auth", "password_hash", auth.hash_password(password))
    if opts.get("viewer_password"):
        text = set_ini(text, "auth", "viewer_username", "viewer")
        text = set_ini(text, "auth", "viewer_password_hash",
                       auth.hash_password(opts["viewer_password"]))
        ok("created a read-only account: viewer")

    with open(CFG, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.chmod(CFG, 0o600)
    ok("wrote %s (mode 600)" % CFG)
    return True


# ---------------------------------------------------------------- main
def main(argv):
    args = set(argv)
    check_only = "--check-only" in args
    extract_only = "--extract-only" in args
    no_start = "--no-start" in args
    force_config = "--force-config" in args
    def opt(flag, default=None):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                return argv[i + 1]
        return default

    opts = {
        "password": opt("--password"),
        "name": opt("--name"),
        "language": opt("--language"),
        "peer_host": opt("--peer-host"),
        "peer_name": opt("--peer-name"),
        "bind": opt("--bind"),
        "port": opt("--port"),
        "behind_proxy": "--behind-proxy" in args,
        "allow_ips": opt("--allow-ips"),
        "viewer_password": opt("--viewer-password"),
        "force_config": force_config,
        "yes": "--yes" in args,
    }

    print(__doc__.split("\n")[0])
    print("-" * 66)

    say("Verifying the embedded payload")
    blob = payload_bytes()
    names = zipfile.ZipFile(io.BytesIO(blob)).namelist()
    ok("%d files, %d bytes, sha256 ok" % (len(names), len(blob)))
    need = ["smartdns_dash/app.py", "smartdns_dash/sources/domains.py",
            "smartdns_dash/templates/index.html",
            "smartdns_dash/static/app.js", "requirements.txt",
            "config.example.ini", "smartdns-dashboard.service"]
    missing = [n for n in need if n not in names]
    if missing:
        die("payload is incomplete, missing: " + ", ".join(missing))
    ok("all expected components present")

    if check_only:
        print("\n--check-only: payload is intact. Re-run without it to "
              "install.\n")
        return 0

    if os.geteuid() != 0:
        die("run as root:  sudo python3 install.py")

    say("Checking prerequisites")
    check_python()
    check_tools()

    say("Installing application to %s" % APP_DIR)
    os.makedirs(APP_DIR, exist_ok=True)
    # Extract to a temp dir first, then swap the package directory in. This
    # is what makes re-running safe even if you launched the installer from
    # inside APP_DIR.
    tmp = tempfile.mkdtemp(prefix="smartdns-dash-")
    try:
        extract(tmp)
        pkg_dst = os.path.join(APP_DIR, "smartdns_dash")
        old = pkg_dst + ".old"
        if os.path.exists(old):
            shutil.rmtree(old, ignore_errors=True)
        if os.path.exists(pkg_dst):
            os.rename(pkg_dst, old)
        shutil.copytree(os.path.join(tmp, "smartdns_dash"), pkg_dst)
        shutil.rmtree(old, ignore_errors=True)
        for name in ("requirements.txt", "config.example.ini", "README.md",
                     "install.sh", "smartdns-dashboard.service"):
            src = os.path.join(tmp, name)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(APP_DIR, name))
        ok("unpacked %d files" % len(names))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    os.chmod(APP_DIR, 0o750)

    if extract_only:
        print("\n--extract-only: files are in %s. Nothing else done.\n" % APP_DIR)
        return 0

    say("Creating virtualenv and installing dependencies")
    ensure_venv_module()
    venv_dir = os.path.join(APP_DIR, "venv")
    venv_py = os.path.join(venv_dir, "bin", "python")

    # A previous run that died mid-way can leave a venv with an interpreter
    # but no pip. Existing-directory is not proof of a working venv.
    if os.path.exists(venv_dir) and not venv_has_pip(venv_py):
        warn("existing virtualenv is incomplete (no pip) - rebuilding it")
        shutil.rmtree(venv_dir, ignore_errors=True)
    if not os.path.exists(venv_py):
        create_venv(venv_dir)
    if not venv_has_pip(venv_py):
        warn("venv has no pip - running ensurepip")
        run([venv_py, "-m", "ensurepip", "--upgrade"])
    if not venv_has_pip(venv_py):
        die("the virtualenv at %s has no working pip even after ensurepip.\n"
            "      Remove it and re-run:\n"
            "        rm -rf %s\n"
            "        apt-get install -y %s\n"
            "        python3 install.py"
            % (venv_dir, venv_dir, venv_packages()[0]))
    ok("virtualenv at %s" % venv_dir)

    run([venv_py, "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    r = run([venv_py, "-m", "pip", "install", "--quiet", "-r",
             os.path.join(APP_DIR, "requirements.txt")])
    if r.returncode != 0:
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        die("pip install failed.\n\n      %s\n\n"
            "      Check that this box can reach pypi.org over HTTPS. If it\n"
            "      is behind the same restrictions as the clients, you may\n"
            "      need a proxy:  https_proxy=... python3 install.py"
            % out.replace("\n", "\n      ")[-2000:])
    ok("dependencies installed")

    say("Configuration")
    write_config(APP_DIR, opts)

    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    ok("backup directory %s" % BACKUP_DIR)

    # Diagnostic history lives here. Mode 700: it records which addresses talked
    # to what, which is nobody else's business even though it is not an
    # accounting record.
    os.makedirs(HISTORY_DIR, mode=0o700, exist_ok=True)
    os.chmod(HISTORY_DIR, 0o700)
    ok("history directory %s" % HISTORY_DIR)

    say("Installing systemd unit")
    shutil.copy2(os.path.join(APP_DIR, "smartdns-dashboard.service"), UNIT)
    run(["systemctl", "daemon-reload"])
    ok(UNIT)

    env = dict(os.environ, SMARTDNS_DASH_CONFIG=CFG)
    say("Validating configuration")
    r = run([venv_py, "-m", "smartdns_dash", "check"], cwd=APP_DIR, env=env)
    print((r.stdout or "").rstrip())
    if r.returncode != 0:
        print((r.stderr or "").rstrip())
        die("config check failed. Fix %s then run:\n"
            "      systemctl enable --now smartdns-dashboard" % CFG)

    say("Environment and port-safety check")
    r = run([venv_py, "-m", "smartdns_dash", "doctor"], cwd=APP_DIR, env=env)
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        if line.strip().startswith(("FATAL", "warning")) or "fatal," in line:
            print("    " + line.strip())
    if r.returncode != 0:
        warn("doctor reported fatal problems. Full output:")
        print("      cd %s && venv/bin/python -m smartdns_dash doctor" % APP_DIR)
    else:
        ok("no fatal problems")

    say("Running read-only selftests")
    for what in ("logs", "domains", "status"):
        r = run([venv_py, "-m", "smartdns_dash", "selftest", what],
                cwd=APP_DIR, env=env)
        out = (r.stdout or "") + (r.stderr or "")
        bad = [l for l in out.splitlines() if "FAIL" in l or "error:" in l]
        if r.returncode == 0 and not bad:
            ok("selftest %s passed" % what)
        else:
            warn("selftest %s reported problems:" % what)
            for l in bad[:6]:
                print("        " + l.strip())
            print("        (full output: cd %s && venv/bin/python -m "
                  "smartdns_dash selftest %s)" % (APP_DIR, what))

    port, bind = read_bind()
    if no_start:
        say("--no-start: skipping enable/start")
    else:
        say("Enabling and starting the service")
        run(["systemctl", "enable", "smartdns-dashboard"])
        r = run(["systemctl", "restart", "smartdns-dashboard"])
        if r.returncode != 0:
            warn("start failed:\n" + (r.stderr or ""))
        else:
            import time
            time.sleep(2)
            st = run(["systemctl", "is-active", "smartdns-dashboard"])
            state = (st.stdout or "").strip()
            if state == "active":
                ok("smartdns-dashboard is active")
            else:
                warn("service state: %s" % state)
                print(run(["journalctl", "-u", "smartdns-dashboard",
                           "-n", "25", "--no-pager"]).stdout or "")

    print("""
------------------------------------------------------------------
Installed.

  config   %s
  app      %s
  listen   %s:%s
  logs     journalctl -u smartdns-dashboard -f

Open it through an SSH tunnel from your laptop (PowerShell works):

  ssh -N -L %s:127.0.0.1:%s root@<this server's public IP>

then browse to  http://127.0.0.1:%s

To reach it from outside instead, read README section 4 FIRST
(%s/README.md). This app runs as root - a port
alone is not access control. You need the login AND the MikroTik
source-IP restriction.

Before trusting the data, run:

  cd %s
  venv/bin/python -m smartdns_dash selftest all --client-ip <a client IP>
------------------------------------------------------------------
""" % (CFG, APP_DIR, bind, port, port, port, port, APP_DIR, APP_DIR))
    return 0


def read_bind():
    port, bind = "9443", "127.0.0.1"
    try:
        with open(CFG, encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"\s*port\s*=\s*(\S+)", line)
                if m:
                    port = m.group(1)
                m = re.match(r"\s*bind\s*=\s*(\S+)", line)
                if m:
                    bind = m.group(1)
    except OSError:
        pass
    return port, bind


PAYLOAD = """
@@PAYLOAD@@
"""

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)

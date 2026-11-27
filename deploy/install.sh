#!/usr/bin/env bash
#
# Installer for the Smart DNS Observability Dashboard.
# Run as root on each of INE-DNS-01 and INE-DNS-02.
#
#   bash install.sh
#
# Idempotent: safe to re-run to upgrade. It never overwrites an existing
# /etc/smartdns-dashboard/config.ini.

set -euo pipefail

APP_DIR=/opt/smartdns-dashboard
CFG_DIR=/etc/smartdns-dashboard
CFG=$CFG_DIR/config.ini
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT=/etc/systemd/system/smartdns-dashboard.service

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m  x %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"

# Refuse to run from inside the install target: the copy step below removes
# $APP_DIR/smartdns_dash first, which would delete the source out from under
# us. Unpack somewhere else (e.g. /root) and run it from there.
if [[ "$SRC_DIR" == "$APP_DIR" ]]; then
  die "do not run install.sh from inside $APP_DIR - copy this directory to
      /root/smartdns-dashboard and run it from there"
fi

if [[ ! -d "$SRC_DIR/src/smartdns_dash" ]]; then
  die "$SRC_DIR/src/smartdns_dash is missing. The checkout is incomplete.
      Use install.py instead if your file transfer keeps mangling things."
fi

say "Checking prerequisites"
command -v python3 >/dev/null || die "python3 not found"
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
say "  python $PYV"
python3 -c 'import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)' \
  || die "python 3.10+ required"

MISSING=()
command -v dnsdist  >/dev/null || MISSING+=(dnsdist)
command -v dig      >/dev/null || MISSING+=("dig (apt install dnsutils)")
command -v tcpdump  >/dev/null || MISSING+=("tcpdump (only needed for port watch)")
command -v ssh      >/dev/null || MISSING+=("ssh (only needed for the two-server diff)")
if [[ ${#MISSING[@]} -gt 0 ]]; then
  for m in "${MISSING[@]}"; do warn "missing: $m"; done
fi

if ! python3 -c 'import venv' 2>/dev/null; then
  say "Installing python3-venv"
  apt-get update -qq && apt-get install -y -qq python3-venv
fi

say "Installing application to $APP_DIR"
mkdir -p "$APP_DIR"
rm -rf "$APP_DIR/smartdns_dash"
cp -r "$SRC_DIR/src/smartdns_dash" "$APP_DIR/"
cp "$SRC_DIR/requirements.txt" "$APP_DIR/"
[[ -f "$SRC_DIR/README.md" ]] && cp "$SRC_DIR/README.md" "$APP_DIR/"
chmod -R go-rwx "$APP_DIR"

say "Creating virtualenv and installing dependencies"
if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
  python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

say "Configuration"
mkdir -p "$CFG_DIR"
chmod 700 "$CFG_DIR"
if [[ -f "$CFG" ]]; then
  warn "$CFG already exists - leaving it alone"
else
  cp "$SRC_DIR/config.example.ini" "$CFG"
  chmod 600 "$CFG"

  SECRET=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
  sed -i "s|^secret_key =.*|secret_key = $SECRET|" "$CFG"

  # Best-effort autodetect so the two servers do not end up identical.
  LOCAL_IP=$(ip -4 -o addr show scope global 2>/dev/null \
    | awk '{print $4}' | cut -d/ -f1 | head -1 || true)
  if [[ -n "${LOCAL_IP:-}" ]]; then
    sed -i "s|^local_ip =.*|local_ip = $LOCAL_IP|" "$CFG"
    case "$LOCAL_IP" in
      172.20.46.2)
        sed -i "s|^name =.*|name = INE-DNS-01|;s|^public_ip =.*|public_ip = 31.24.200.3|" "$CFG"
        sed -i "/^\[peer\]/,/^\[/{s|^name =.*|name = INE-DNS-02|;s|^host =.*|host = 172.20.46.10|}" "$CFG"
        ;;
      172.20.46.10)
        sed -i "s|^name =.*|name = INE-DNS-02|;s|^public_ip =.*|public_ip = 31.24.200.4|" "$CFG"
        sed -i "/^\[peer\]/,/^\[/{s|^name =.*|name = INE-DNS-01|;s|^host =.*|host = 172.20.46.2|}" "$CFG"
        ;;
    esac
    say "  detected local_ip $LOCAL_IP"
  fi

  echo
  say "Set the dashboard password now"
  "$APP_DIR/venv/bin/python" -m smartdns_dash hash-password \
    | tail -1 > /tmp/.sdh.$$
  HASH=$(grep -o 'scrypt\$.*' /tmp/.sdh.$$ || true)
  shred -u /tmp/.sdh.$$ 2>/dev/null || rm -f /tmp/.sdh.$$
  [[ -n "$HASH" ]] || die "password hashing failed"
  sed -i "s|^password_hash =.*|password_hash = $HASH|" "$CFG"
fi

say "Backup directory"
mkdir -p /root/smartdns-backups
chmod 700 /root/smartdns-backups

say "Installing systemd unit"
cp "$SRC_DIR/deploy/smartdns-dashboard.service" "$UNIT"
systemctl daemon-reload

say "Validating config"
if ! SMARTDNS_DASH_CONFIG=$CFG "$APP_DIR/venv/bin/python" -m smartdns_dash check; then
  die "config check failed - fix $CFG then run: systemctl enable --now smartdns-dashboard"
fi

say "Environment and port-safety check"
SMARTDNS_DASH_CONFIG=$CFG "$APP_DIR/venv/bin/python" -m smartdns_dash doctor \
  || warn "doctor reported fatal problems - see above"

say "Running selftests (read-only)"
SMARTDNS_DASH_CONFIG=$CFG "$APP_DIR/venv/bin/python" -m smartdns_dash \
  selftest logs || warn "log selftest reported problems"
SMARTDNS_DASH_CONFIG=$CFG "$APP_DIR/venv/bin/python" -m smartdns_dash \
  selftest domains || warn "domains selftest reported problems"

say "Enabling service"
systemctl enable --now smartdns-dashboard
sleep 2
systemctl --no-pager --lines=15 status smartdns-dashboard || true

PORT=$(awk -F= '/^port *=/{gsub(/ /,"",$2);print $2}' "$CFG" | head -1)
BIND=$(awk -F= '/^bind *=/{gsub(/ /,"",$2);print $2}' "$CFG" | head -1)

cat <<EOF

------------------------------------------------------------------
Installed.

  config   $CFG
  app      $APP_DIR
  listen   ${BIND:-127.0.0.1}:${PORT:-9443}
  logs     journalctl -u smartdns-dashboard -f

Open it through an SSH tunnel from your laptop:

  ssh -N -L ${PORT:-9443}:127.0.0.1:${PORT:-9443} root@<this server public ip>
  then browse to http://127.0.0.1:${PORT:-9443}

To reach it from outside instead, read README section 4 FIRST. This app
runs as root; a port alone is not access control. You need both the login
and the MikroTik source-IP restriction.
------------------------------------------------------------------
EOF

# Deployment — step by step

From a bare server to a working dashboard, in order, with the check that proves
each step worked. The README covers the same ground more briefly; this is the
runbook.

**The dashboard runs as root.** It writes `domains.txt`, runs the update script
and calls `systemctl restart`. Anyone who reaches it and passes the login has
root on the box. Steps 5 and 6 are not optional decoration.

---

## Step 0 — Prerequisites

On the target server:

| Need | Why | Check |
|---|---|---|
| Ubuntu 22.04+ (or any systemd distro) | `systemctl`, `/proc` | `systemctl --version` |
| Python 3.10+ | the app | `python3 -V` |
| `python3.X-venv` | `ensurepip`; the installer adds it if missing | `python3 -m venv /tmp/t && rm -rf /tmp/t` |
| `dnsdist` with a control socket | the main data source | `dnsdist --version` |
| `sniproxy` writing access logs | the live feed | `ls /var/log/sniproxy/` |
| `dnsutils` (optional) | the Lookup panel | `dig -v` |
| `tcpdump` (optional) | the Port watch panel | `tcpdump --version` |
| Outbound HTTPS to pypi.org | installing dependencies | `curl -sI https://pypi.org \| head -1` |

The dashboard needs `/etc/smartdns/smartdns.env` to contain the dnsdist console
key, and that key to work:

```bash
. /etc/smartdns/smartdns.env
dnsdist -c 127.0.0.1:5199 -k "$SMARTDNS_DNSDIST_KEY" -e 'showServers()'
```

If that fails, fix it first — half the panels depend on it.

---

## Step 1 — Get the code onto the server

### Option A — git (preferred)

```bash
cd /root
git clone https://github.com/enazari7/dns_report
cd dns_report
```

### Option B — one file, when git or binary transfer is a problem

Build the single-file installer on a machine that has the repo:

```bash
python3 tools/build_installer.py     # writes ./install.py
```

Copy `install.py` to the server by any means — it is designed to survive an
SFTP client in text mode, which corrupts archives. Then verify it arrived
intact **before** running it:

```bash
python3 install.py --check-only
```

> `install.py` is a build artifact: the repo zipped, base64-encoded and
> substituted into a template. base64 is an encoding, not obfuscation —
> `python3 install.py --extract-only` unpacks the readable tree. It is in
> `.gitignore`; CI rebuilds it on every push.

---

## Step 2 — Install

```bash
sudo bash deploy/install.sh        # from a git checkout
# or
sudo python3 install.py            # from the single file
```

Either one:

1. checks prerequisites and reports what is missing;
2. creates a virtualenv at `/opt/smartdns-dashboard/venv`;
3. installs the dependencies from `requirements.txt`;
4. writes `/etc/smartdns-dashboard/config.ini`, mode 600, with a generated
   `secret_key`;
5. asks for the dashboard password (and a label, and the peer, if interactive);
6. **picks a port that is free and clear of the DNS stack**;
7. creates `/root/smartdns-backups` and `/var/lib/smartdns-dashboard`, both 700;
8. installs the systemd unit;
9. runs `doctor` and the read-only selftests;
10. enables and starts the service.

Re-running upgrades the code and leaves the config alone.

Non-interactive, for a provisioning script:

```bash
sudo python3 install.py --yes \
  --name DNS-01 --language fa \
  --peer-host 10.0.0.2 --peer-name DNS-02 \
  --password "$(cat /root/.dash-pw)" \
  --viewer-password "$(cat /root/.dash-viewer-pw)" \
  --allow-ips 10.8.0.0/24
```

**Check:**

```bash
systemctl is-active smartdns-dashboard      # active
journalctl -u smartdns-dashboard -n 20
```

---

## Step 3 — Verify the environment, then the data

`doctor` first. It exits non-zero on anything fatal.

```bash
cd /opt/smartdns-dashboard
venv/bin/python -m smartdns_dash doctor
```

It reports the listen port's safety, everything else listening on the host,
whether the DNS machinery still owns `:53`, which paths are readable or
writable, which optional tools are missing, and whether the console key and
spoof target resolved.

Then the parsers, against your real data:

```bash
venv/bin/python -m smartdns_dash selftest all --client-ip <an active client>
```

Each one prints the documented reference sample first. If the reference passes
and live data does not, the format on your build differs — see
[DATA-FORMATS.md](DATA-FORMATS.md), which names the single file to change.

**Do not skip this.** Every panel is a parser over someone else's text format.

---

## Step 4 — Open it over an SSH tunnel

The safest access path, and the one to confirm it works with before exposing
anything.

```bash
# from your laptop
ssh -N -L 9443:127.0.0.1:9443 root@<server>
```

Then `http://127.0.0.1:9443`. The terminal stays silent — that is normal.

Two servers, two tunnels, two tabs:

```bash
ssh -N -L 9443:127.0.0.1:9443 root@<server-1>
ssh -N -L 9444:127.0.0.1:9443 root@<server-2>
```

**Check:** the header shows green chips for your units, the correct spoof
address, and no stale-config banner.

---

## Step 5 — Decide how it is reached, and lock that down

Pick exactly one of these.

### 5a — SSH tunnel only (default, safest)

Nothing to do. `bind = 127.0.0.1`, no port exposed.

### 5b — A VPN address

```ini
[server]
bind = 10.8.0.1        ; the WireGuard address
```

Any device already on the tunnel reaches it, phone included, with no port open
to the internet.

### 5c — Behind a reverse proxy

nginx does **not** have to run on the DNS server; a separate host is often
better, because the DNS box keeps one loopback listener and gains no exposure.

```ini
[server]
bind = 127.0.0.1
behind_proxy = true
forwarded_allow_ips = 127.0.0.1    ; the address the proxy connects from
```

`behind_proxy` makes uvicorn honour `X-Forwarded-Proto` (so redirects and the
`Secure` cookie flag are right) and makes the login rate limiter see real client
addresses instead of lumping everyone under the proxy. `forwarded_allow_ips`
lists who may *set* those headers — keep it at the proxy's address, because `*`
would let any client mint a fresh rate-limit bucket per guess.

A full config is in [`../deploy/nginx.conf.example`](../deploy/nginx.conf.example),
including the sub-path variant (`root_path = /dns`). **One line there is
load-bearing:**

```nginx
proxy_buffering off;   # the live feed is SSE; without this it arrives late
```

### 5d — Published port, no proxy

Two settings, both needed.

```bash
# 1. encrypt it, or the password crosses the network in cleartext
cd /opt/smartdns-dashboard
venv/bin/python -m smartdns_dash make-cert --write-config
```

```ini
# 2. restrict who may reach it at all — enforced before authentication
[server]
bind = 0.0.0.0
exposed = true
allow_ips = 203.0.113.45, 10.8.0.0/24
```

On a router/DNAT topology, restrict the source there too:

```
/ip firewall address-list
add list=DashAdmins address=203.0.113.45 comment="my laptop"

/ip firewall nat
add chain=dstnat action=dst-nat protocol=tcp \
    dst-address=<public-ip> dst-port=9443 \
    src-address-list=DashAdmins \
    to-addresses=<server-internal-ip> to-ports=9443 \
    comment="smartdns dashboard"

/ip firewall filter
add chain=forward action=accept protocol=tcp dst-port=9443 \
    dst-address=<server-internal-ip> src-address-list=DashAdmins \
    comment="dashboard allow"
add chain=forward action=drop protocol=tcp dst-port=9443 \
    comment="dashboard deny everyone else"
```

Check the ordering — rules are appended, and a `drop` above its `accept` locks
you out:

```
/ip firewall filter print where comment~"dashboard"
```

If your address is dynamic this breaks whenever it changes; 5b is the better
answer in that case.

**Check, whichever you chose:**

```bash
ss -tlnp | grep -E '9443|8083|9100|:53'
```

`8083` (dnsdist API) and `9100` (node_exporter) must stay on `127.0.0.1`.

---

## Step 6 — Apply the config and confirm

```bash
systemctl restart smartdns-dashboard
venv/bin/python -m smartdns_dash check
```

`check` prints the effective configuration and any non-fatal warnings. Read the
warnings; they are the things that will bite later.

---

## Step 7 — The second server

Repeat steps 1–6. Identity is auto-detected, so the same installer works
unchanged — see [CLONING.md](CLONING.md) if you are copying a VM image rather
than installing fresh.

### Key auth between the pair

Needed for the two-server diff and for **Apply to both**. Until it exists, the
diff falls back to paste mode.

On server 1:

```bash
ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519_smartdns -C smartdns-dashboard
ssh-copy-id -i /root/.ssh/id_ed25519_smartdns.pub root@<server-2>

# must succeed with no prompt
ssh -i /root/.ssh/id_ed25519_smartdns -o BatchMode=yes \
    root@<server-2> 'head -3 /etc/smartdns/domains.txt'
```

Mirror it on server 2, then in both configs:

```ini
[peer]
enabled = true
host = <the other server>
ssh_key = /root/.ssh/id_ed25519_smartdns
```

**Check:** the Server diff panel says the two lists are identical.

---

## Step 8 — Optional features

All off or conservative by default. Turn on what you want, then restart.

```ini
[auth]
; a second account that can see everything and change nothing
viewer_username = viewer
viewer_password_hash =        ; smartdns-dashboard hash-password

[history]
; diagnostic history: events, audit, domain registry, traffic charts
; NOT an accounting source — see the config comments
enabled = true
retention_days = 14

[alerts]
enabled = true                ; in-app only unless a transport is set below
; webhook_url =
; telegram_token =
; telegram_chat_id =

[metrics]
enabled = false               ; Prometheus at /metrics, needs a token
token =

[triage]
enabled = false               ; unauthenticated /triage page for players

[portwatch]
enabled = false               ; runs a continuous tcpdump; turn on while debugging
```

---

## Step 9 — Know the daily workflow

A user reports a game does not work:

1. **Debug client** → type their IP → Watch.
2. One column is what sniproxy routed; the other is what went upstream, i.e.
   **not** proxied, with a first-seen time each.
3. Have them reproduce the failure. Watch which names appear.
4. **Decide which genuinely need proxying — this stays manual.** Click **Test
   first** to get the evidence: can sniproxy actually route it, is it already
   reachable directly, are 8080/8085/8013 open.
5. If one qualifies: *add…* → review the guards → type the domain → apply. With
   two servers, **Apply to both**.
6. Re-test on the device.

If something breaks after an addition, *disable* it, or switch off its whole
group, or restore a backup.

---

## Upgrading

```bash
cd /root/dns_report && git pull
sudo bash deploy/install.sh
# or: copy a fresh install.py and run it
```

The config is left alone. Read `CHANGELOG.md` for anything that needs an
action.

---

## Uninstalling

```bash
systemctl disable --now smartdns-dashboard
rm /etc/systemd/system/smartdns-dashboard.service
systemctl daemon-reload
rm -rf /opt/smartdns-dashboard
# keep these if you want the history and the backups:
rm -rf /etc/smartdns-dashboard /var/lib/smartdns-dashboard
# /root/smartdns-backups holds your allow-list backups — probably keep it
```

The dashboard never modified anything in the DNS deployment except
`domains.txt`, and every change it made there is in `/root/smartdns-backups`.

---

## Troubleshooting index

| Symptom | Look at |
|---|---|
| Service refuses to start, "port belongs to …" | `doctor`, then `reconfigure --port` |
| 403 on every request including the login page | `allow_ips` vs what the server sees |
| Login loops back to the login page | cookie dropped: `behind_proxy`, or visit `https://` |
| Live feed arrives in clumps | `proxy_buffering off;` missing in nginx |
| Everyone locked out of login at once | `behind_proxy` false behind a proxy |
| A panel is empty | the matching `selftest`, then DATA-FORMATS.md |
| "dnsdist console" chip red | `check` — console key readable? |
| "spoof target unknown" chip | `[server] public_ip`, or `dnsdist_conf` path |
| DNS works but no proxy connections for a client | the router's `Permited` address-list |
| Traffic panel empty | `[history] enabled`, and note the backfill rule |

Full explanations in the README's troubleshooting section.

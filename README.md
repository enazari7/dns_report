# Smart DNS Observability Dashboard

[![CI](https://github.com/enazari7/dns_report/actions/workflows/ci.yml/badge.svg)](https://github.com/enazari7/dns_report/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A small self-hosted dashboard for a Smart DNS / SNI-proxy deployment. It
collapses the manual debugging loop — two terminals, a `grepq | awk` pipeline,
and eyeballing the difference — into one screen, and turns "edit domains.txt,
regenerate, remember to restart, repeat on the other server" into a guarded
button.

FastAPI + plain HTML. No JS build step, no external fonts or CDNs. English and
Persian interface, dark and light themes.

**It binds exactly one TCP port and never touches the DNS machinery's.** Ports
belonging to the resolver/proxy stack are refused outright; see section 4.

**Nothing about a particular server is compiled in.** Identity values default
to `auto` and are resolved at runtime, so the same installer works on one
server, two, or a cloned VM at a new address. See section 6.

### Documentation

| Document | For |
|---|---|
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Installing it, step by step, with the check that proves each step worked |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the pieces fit, and **§4: the parts that look wrong but are not** |
| [docs/DATA-FORMATS.md](docs/DATA-FORMATS.md) | Every external text format parsed, with reference samples. The file that goes stale first |
| [docs/API.md](docs/API.md) | Every HTTP route, its role requirement and its response shape |
| [docs/CLONING.md](docs/CLONING.md) | Moving it, cloning a VM, changing addresses |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Known limitations, deliberate non-goals, candidate next work |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, and the one rule that matters |
| [SECURITY.md](SECURITY.md) | Threat model — it runs as root — and the hardening checklist |

**Picking this up cold?** README → ARCHITECTURE → DATA-FORMATS → CONTRIBUTING,
then `make dev && make test` and read `tests/test_guards.py`: it is the
shortest description of what this tool promises not to do.

---

## 1. What each panel is for

| Panel | What it answers |
|---|---|
| **Debug client** | Pick a client IP. One side: what sniproxy actually routed. Other side: what that client asked for that went upstream, i.e. **not** proxied. The candidate list when a game breaks. |
| **Live feed** | Merged tail of `https_access.log` and `http_access.log`, streamed over SSE. Rows flagged when the origin is `NONE` or the SNI is empty. |
| **Allow-list** | Every active suffix, plus duplicates, unparsable lines, and entries already covered by a broader suffix. Add and disable go through the guarded flow. |
| **Lookup** | Does this hostname match an active suffix, which one, and what does `dig` return from this server right now. |
| **Server diff** | Normalized active list from both boxes, showing what exists on only one. SSH or paste. |
| **Backups** | Everything in `/root/smartdns-backups/`, diffed against current, with one-click restore. |
| **Port watch** | TCP SYNs to ports other than 53/80/443 that never got a SYN-ACK. Opt-in; runs a live capture. |
| **Traffic** | Bandwidth and connection counts over time, top clients and top destinations. Inline SVG, no chart library. |
| **Events** | Conditions currently true, with durations, plus history. A service down for an hour is one event, not one row per poll. |
| **Audit** | Every attempt to change something, successful or refused, and every hostname the server has ever seen with its real first-seen time. |
| **Logs** | `sniproxy` error log, `update.log`, and journals for sniproxy / dnsdist / unbound. |

The header carries a **staleness banner**. sniproxy reads its config only at
startup, so a regenerate-without-restart leaves the stale routing table live in
memory while the file on disk looks correct. The banner compares `domains.txt`
mtime against the sniproxy process start time and shouts when the process is
older.

The **Allow-list** panel also carries groups and the probe. A group is a
`# @group name` comment inside `domains.txt`, so the file stays the single
source of truth; switching one off comments out every member in one guarded
change — the fast way back out when a whole game got worse. The probe answers
"can sniproxy actually route this?" from the server before you add anything.

The language switch (EN / فا) is in the header and remembered per browser. Text
the server generates — guard warnings, lookup verdicts, staleness messages —
ships in both languages, so switching is instant. The layout works on a phone
and installs to a home screen.

### One thing to be clear about

The history database is **not an accounting source**, and the UI, the config and
the API payloads all say so. Its rows are keyed by client IP address, and
addresses change hands: a figure there describes an address over a window of
time, not a person. Accounting belongs in a system that knows about accounts.
Retention is short for the same reason, and `/metrics` deliberately exposes no
per-client counters — Prometheus would keep them far longer than the retention
window.

---

## 2. Install

### From a git checkout

```bash
git clone https://github.com/enazari7/dns_report
cd dns_report
sudo bash deploy/install.sh
```

Or as a normal Python package, if you would rather manage the environment
yourself:

```bash
python3 -m venv /opt/smartdns-dashboard/venv
/opt/smartdns-dashboard/venv/bin/pip install .
/opt/smartdns-dashboard/venv/bin/smartdns-dashboard --help
```

### From a single file (no git on the server)

`install.py` is a **build artifact, not the source.** It is the repository
zipped, base64-encoded and pasted into a Python file, so that one text file can
be copied to a server whose only transfer method mangles binaries. base64 is an
encoding, not encryption or obfuscation - nothing is hidden, and you can prove
that:

```bash
python3 install.py --extract-only    # unpacks the readable tree, does nothing else
```

Because it is generated, it is in `.gitignore`. Edit the repository, then
regenerate it:

```bash
python3 tools/build_installer.py     # rebuilds ./install.py from src/
python3 install.py --check-only      # verify the payload
```

Copy `install.py` to the server — that one file contains everything, and it is
built to survive an SFTP client in text mode. Then:

```bash
python3 install.py --check-only     # verify it arrived intact
sudo python3 install.py
```

Build it yourself with `python3 tools/build_installer.py`, or download the
`install.py` artifact from a CI run.

Either installer creates a virtualenv at `/opt/smartdns-dashboard/venv`, writes
`/etc/smartdns-dashboard/config.ini` (mode 600), generates a `secret_key`, asks
for a label / peer / password, picks a port that is free and clear of the DNS
stack, installs the systemd unit, runs `doctor` and the read-only selftests,
and starts the service. Re-running upgrades the code and leaves the config
alone.

Non-interactive, e.g. for a provisioning script:

```bash
sudo python3 install.py --yes \
  --name DNS-01 --language fa \
  --peer-host 10.0.0.2 --peer-name DNS-02 \
  --password "$(cat /root/.dash-pw)" \
  --allow-ips 10.8.0.0/24
```

Single-server deployments just omit `--peer-host`; the diff panel falls back to
paste mode and a "single server" chip appears in the header.

### Verify before trusting anything

```bash
cd /opt/smartdns-dashboard
venv/bin/python -m smartdns_dash doctor
venv/bin/python -m smartdns_dash selftest all --client-ip <a client IP>
```

`doctor` is the one to run first. It reports the listen port's safety, what
else is listening on the host, whether the DNS machinery still owns its ports,
which paths are readable or writable, which optional tools are missing, and
whether the dnsdist console key and spoof target resolved. It exits non-zero on
anything fatal.

`selftest` runs each parser against the documented reference input first, then
against your real data, and prints what it got. If a parser is wrong, this is
where it shows up — and it names the one file to fix.

---

## 3. Opening it — SSH tunnel (safest)

Leave `bind = 127.0.0.1` and tunnel from your laptop:

```bash
ssh -N -L 9443:127.0.0.1:9443 root@<server-1>
ssh -N -L 9444:127.0.0.1:9443 root@<server-2>
```

Then open `http://127.0.0.1:9443` and `http://127.0.0.1:9444` — both servers in
two tabs, nothing exposed, no firewall change.

Over an existing WireGuard interface instead, set `bind` to the tunnel address.
Any device already on the tunnel, phone included, reaches it directly.

---

## 4. Reaching it from outside

**The dashboard runs as root.** It writes `domains.txt`, runs the update script
and calls `systemctl restart`. Anyone who reaches it and gets past the login has
root on the box. An unusual port is not access control — scanners sweep the
whole range in hours.

### Port safety comes first

This dashboard is a guest on a machine whose job is answering DNS. It binds
**one** TCP port, never listens on 53/80/443, and never opens a raw socket. The
only exception is the opt-in port watcher, which runs `tcpdump` in capture mode
and opens no listener either.

Ports belonging to the DNS/proxy stack are **refused**, not warned about — at
config load and again before the server starts:

| Port | Owner |
|---|---|
| 22 | SSH — you would lock yourself out |
| 53, 853, 5353 | DNS / DoT / mDNS |
| 80, 443 | sniproxy's listeners |
| 5199 | dnsdist control socket |
| 8083 | dnsdist web/API (localhost-only by design) |
| 9100, 9153 | node_exporter, CoreDNS metrics |
| 67, 68, 123 | DHCP, NTP |

Ranges that are merely risky get a warning instead: the privileged range below
1024, `8000–8100` (game and CDN backends, including the CODM downloader on
8080/8085/8013), and common game/voice ranges.

The default is **9443**, deliberately far from all of it. Check any host with:

```bash
smartdns-dashboard doctor
```

which lists everything currently listening, confirms dnsdist still owns :53,
and suggests a free safe port if yours is taken.

### Without a reverse proxy

There may be no nginx on the box, and installing one just for this is not
worth it. Two settings cover it.

**1. Restrict who can reach it at all.** `allow_ips` is enforced in middleware,
before authentication runs — the in-app equivalent of an nginx `allow`/`deny`
block:

```ini
[server]
bind = 0.0.0.0
port = 9443
exposed = true
allow_ips = 203.0.113.45, 10.8.0.0/24
```

Single addresses or CIDR networks. Empty means unrestricted. It is a second
lock in front of the password, never a replacement for it.

**2. Encrypt it.** Otherwise the password crosses the network in cleartext:

```bash
smartdns-dashboard make-cert --write-config
systemctl restart smartdns-dashboard
```

That writes a self-signed pair to `/etc/smartdns-dashboard/`, with the
hostname, `127.0.0.1`, every local address and the spoof target as SANs, and
points the config at it. The browser warns once about the self-signed
certificate — a far smaller problem than a plaintext password.

Then verify nothing else got opened. `8083` and `9100` must stay on loopback:

```bash
ss -tlnp | grep -E '9443|8083|9100|:53'
```

On a MikroTik/DNAT topology, restrict the source there too — belt and braces
with `allow_ips`:

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

Check the ordering — MikroTik appends, and a `drop` above its `accept` locks
you out:

```
/ip firewall filter print where comment~"dashboard"
```

If your home address is dynamic this breaks whenever it changes. WireGuard is
the better answer there: set `bind` to the tunnel address, add no NAT rule at
all, and connect when you want the dashboard.

### With a reverse proxy, if you have one

nginx does **not** have to run on the DNS server. Running it on a separate host
and proxying across is often better — the DNS box keeps a single loopback
listener and gains no new exposure.

```ini
[server]
bind = 127.0.0.1              ; or an address the proxy can reach
behind_proxy = true
forwarded_allow_ips = 127.0.0.1
```

`behind_proxy` does three things: uvicorn honours `X-Forwarded-Proto`, so
redirects and the `Secure` cookie flag come out right; the login rate limiter
reads the real client address from `X-Forwarded-For` instead of lumping
everyone under the proxy's IP; and the loopback-bind check stops complaining.

`forwarded_allow_ips` lists the addresses allowed to *set* those headers. Keep
it at the proxy's address. If it were `*`, any client could attach a fake
`X-Forwarded-For` and mint a fresh rate-limit bucket per guess.

A full config is in [`deploy/nginx.conf.example`](deploy/nginx.conf.example),
including the sub-path variant (`root_path = /dns`). One line there is
load-bearing:

```nginx
proxy_buffering off;   # the live feed is SSE; without this it arrives late
```

## 5. SSH key between two servers (for the diff)

The two-server diff falls back to paste mode until key auth exists between the
boxes. On the first server:

```bash
ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519_smartdns \
  -C "smartdns-dashboard"
ssh-copy-id -i /root/.ssh/id_ed25519_smartdns.pub root@<other-server>

# must succeed with no prompt
ssh -i /root/.ssh/id_ed25519_smartdns -o BatchMode=yes \
    root@<other-server> 'head -3 /etc/smartdns/domains.txt'
```

Mirror it on the second server, then in both configs:

```ini
[peer]
enabled = true
host = <other-server>
ssh_key = /root/.ssh/id_ed25519_smartdns
```

The dashboard only ever runs `cat /etc/smartdns/domains.txt` over that
connection, with `BatchMode=yes` so it can never hang on a password prompt.

Paste mode needs nothing: run `cat /etc/smartdns/domains.txt` on the other box
and paste the output into the panel.

---

## 6. Moving it, cloning it, changing addresses

Nothing is hard-coded. Three values could in principle tie an install to one
machine, and all three are discovered:

| Value | How it is resolved when set to `auto` |
|---|---|
| `name` | the system hostname |
| `local_ip` | the first global IPv4 on this host |
| `public_ip` — the address listed domains are spoofed to | read out of the generated dnsdist config (`dnsdist_conf`) |

That last one matters. On a MikroTik/DNAT topology the public address lives on
the router, not on the server, so no interface carries it and it cannot be
guessed. But the smartdns generator writes it into `dnsdist.conf` as the spoof
target, which is the authoritative source — so the dashboard reads it back
instead of asking you to keep two files in sync. `check` prints where it came
from:

```
spoof target   31.24.200.3   [/etc/dnsdist/dnsdist.conf (spoof)]
```

Clone a VM, change its address, re-run the smartdns generator, and the
dashboard follows. If it cannot find the spoof target it says so in the header
and in `check`; pin `public_ip` explicitly in that case.

### After cloning

```bash
cd /opt/smartdns-dashboard
venv/bin/python -m smartdns_dash reconfigure --show     # what it detects now
venv/bin/python -m smartdns_dash reconfigure \
    --name NEW-HOST-01 --public-ip auto --local-ip auto \
    --peer-host <new-peer> --peer-name NEW-HOST-02 \
    --reset-secret
systemctl restart smartdns-dashboard
```

`--reset-secret` issues a new session-signing key. Do it on any clone: the
image carries the original `secret_key`, so a session cookie minted on one
clone would otherwise be valid on all of them.

`reconfigure` backs up the config first, writes only the keys you name,
re-validates the result, and restores the backup automatically if the result
does not load. Other options: `--bind`, `--port`, `--behind-proxy`,
`--forwarded-allow-ips`, `--root-path`, `--exposed`, `--language`,
`--password`. Run `reconfigure --help` for the full list.

### Adapting to a different layout

Every path lives in `[paths]`. A deployment with different filenames — a
different sniproxy log location, a different generator script — needs no code
change, only that section. The dashboard also runs happily with `[peer]
enabled = false` as a single-server tool.

---

## 7. The workflow this replaces

A user reports a game does not work.

1. Open **Debug client**, type the client IP, press Watch.
2. One column is what sniproxy routed. The other is what went upstream — the
   unproxied names, with a first-seen time each.
3. Have them reproduce the failure. Watch which names appear at that moment.
4. **Decide which of those genuinely need proxying. This stays manual.** Most
   do not. Adding domains speculatively is what broke Clash of Clans, the CODM
   downloader, and CODM voice chat during development.
5. If one qualifies, click *add…* next to it. Review the guards, type the
   domain to confirm, apply. The dashboard backs up, writes, regenerates and
   **restarts** — never one without the other.
6. Repeat on the other server, or check the **Server diff** panel.
7. Re-test on the device.

### Step 4 is the whole job

Click **Test first** before **Preview change**. The probe answers, from this
server:

- does a TLS handshake complete with that name as the SNI on 443? That is
  exactly the mechanism sniproxy routes on, so a completed handshake is proof it
  can;
- does HTTP on 80 answer a Host header? The other thing it can route on;
- is the host reachable directly right now? If it is, adding it may be a
  regression rather than a fix;
- are 8080/8085/8013 open? That is the Tencent GCloud downloader signature —
  proxying the domain will make the game open and never download.

It never adds anything. It makes the answer to the questions below evidence
instead of memory.

Before adding anything, ask:

- **Is it TLS or HTTP?** sniproxy routes on the SNI or the Host header. A raw
  binary protocol has neither, so proxying it makes the connection hang. The
  CODM downloader is exactly this: Tencent GCloud on TCP 8080/8085/8013. The
  game opens and never downloads.
- **Is it UDP?** sniproxy is TCP-only. Proxying `*.west-gvoice.codmwest.com`
  killed voice chat entirely.
- **Does it already work directly?** Then adding it is a regression, not a fix.
- **Is it a root or an FQDN?** A root captures every subdomain, now and in
  future, including services you have not seen yet. There is no exclude
  syntax. Prefer the exact FQDN you saw failing.

The **Port watch** panel answers the first question directly: unanswered SYNs
to a non-80/443 port mean the traffic never reaches sniproxy at all, so no
allow-list entry can help.

If something breaks after an addition, use *disable* on the Allow-list panel
(comments the line out, regenerates, restarts) or restore a backup. Faster than
deleting the line and safer than editing by hand. If a whole game got worse,
put its hostnames in a group and switch the group off in one change.

With two servers, **Apply to both** does the change on the peer and here in one
action. The peer goes first on purpose: if it fails, this server is left
untouched and the pair stays matched rather than diverging — which is the state
this feature exists to prevent. It refuses outright if the two lists already
differ.

---

## 8. Guards on the write path

Nothing is written without all of these:

- **Already covered** → refused outright, naming the suffix that covers it.
  A suffix matches every subdomain, so the line would change nothing.
- **Bare root** → loud warning, listing the subdomains already observed under
  it (from both the proxy log and the dnsdist ring), or saying plainly that
  none have been observed and you cannot see what you are about to capture.
- **Subsumes existing entries** → lists which ones become redundant.
- **Backup first** → timestamped copy in `/root/smartdns-backups/` before any
  write. If the write or the update script fails, the backup is restored
  automatically.
- **Diff preview** → the exact unified diff of the change, and what gets
  written is byte-for-byte what you reviewed.
- **Typed confirmation** → you must type the domain itself, not click OK.
- **File changed since preview** → refused; re-run the preview.
- **Single-use, 5-minute plan token** → a stale browser tab cannot replay a
  write. One change at a time, enforced by a lock.
- **Restart is mandatory** → the update script and `systemctl restart` run as
  one unit. There is no path that regenerates without restarting.

Candidates are presented with evidence. Nothing is ever added automatically.

---

## 9. Configuration notes

`/etc/smartdns-dashboard/config.ini`, mode 600. After editing:
`systemctl restart smartdns-dashboard`.

Poll intervals default to conservative values because these are often modest
VMs carrying live traffic:

```ini
[poll]
log_ms    = 1000     # log tail - incremental, never re-reads the file
grepq_ms  = 5000     # only polls while a client is selected
status_ms = 15000
```

`grepq` only runs while you have a client selected on the Debug panel, and
`grepq_limit` bounds how much of the ring it scans. Log tailing is incremental
and rotation-aware (inode tracking, plus truncation-in-place), so logrotate
causes neither a re-read nor a silent stall.

The dnsdist console key is read from `smartdns.env` on every use, not cached,
so rotating it does not need a dashboard restart. It is never echoed into an
error message or a log line.

---

## 10. Troubleshooting

**Login succeeds then bounces back to the login page.** The cookie is being
dropped. Behind a TLS proxy, make sure `behind_proxy = true` and that nginx
sends `X-Forwarded-Proto`. Serving TLS directly, visit `https://`, not `http://`.

**Live feed updates in clumps, or not at all, behind nginx.** `proxy_buffering
off;` is missing. The feed is SSE and nginx buffers it by default.

**Everyone gets locked out of login at once behind a proxy.** `behind_proxy` is
false, so every request looks like it comes from the proxy and they share one
rate-limit bucket.

**"dnsdist console" chip is red.** Run `smartdns_dash check` — it reports
whether the key is readable. Usually `smartdns.env` is unreadable or `key_var`
does not match the variable name in the file.

**"spoof target unknown" chip.** The dashboard could not find the spoofed
address in `dnsdist_conf`. Everything works except confirming a spoofed answer
in Lookup. Set `[server] public_ip` explicitly, or point `dnsdist_conf` at the
right file.

**Unproxied panel is empty but the client is clearly active.** The ring buffer
window may be shorter than the gap since the last query. Reproduce the failure
while watching, or raise `grepq_limit`.

**Client has working DNS but nothing appears in the proxy feed.** On a MikroTik
setup, check that its IP is in the `Permited` address-list. Port 53 is open to
all, but the DNAT for 80/443 is gated on that list — so DNS resolves and spoofs
correctly while every proxy connection silently fails. The Debug panel raises
this hint automatically when it sees DNS activity with no proxied connections.

**A name matches a suffix but `dig` does not return the expected address.**
Either the running config is stale (check the banner), or you queried a
resolver that is not this server. The Lookup panel flags both cases.

**Byte direction looks wrong.** `tx` is origin→client and `rx` is
client→origin, and this was misread once during debugging. If `ss -ti` proves
otherwise, flip `TX_IS_FROM_ORIGIN` at the top of
`smartdns_dash/sources/sniproxy_log.py`. The UI labels derive from it.

**A parser returns nothing.** Run the matching selftest. It prints the
reference case first, so you can see immediately whether the format itself
differs on your build:

```bash
venv/bin/python -m smartdns_dash selftest logs
venv/bin/python -m smartdns_dash selftest dnsdist --client-ip <client>
venv/bin/python -m smartdns_dash selftest domains
venv/bin/python -m smartdns_dash selftest status
venv/bin/python -m smartdns_dash selftest peer
venv/bin/python -m smartdns_dash selftest portwatch --client-ip <client> --seconds 20
```

**Service refuses to start with "port ... belongs to ...".** That port is owned
by the DNS/proxy stack. Run `doctor` for a suggested free port, then
`reconfigure --port <n>` and restart.

**403 forbidden on every request, even the login page.** `allow_ips` is set and
your source address is not in it. Check what the server sees — behind a proxy
without `behind_proxy = true` it sees the proxy, not you.

**Traffic panel is empty.** Either `[history] enabled = false`, or nothing has
been logged since the dashboard started. The startup backfill deliberately does
not feed the traffic rollups — replaying the same connections on every restart
would inflate the totals — so the chart begins from when the service came up.

**Events badge never clears.** Events close themselves when the condition
clears, so a stuck one means the condition is still true. Check the Events panel
for what it actually says.

**Probe says NOT PROXYABLE for a host that clearly works.** The probe resolves
through `[probe] resolver`, which must not be this server: the local resolver
returns the spoof address for a listed name, and the probe would end up testing
the proxy against itself.

**`/metrics` returns 403.** It needs the token from `[metrics] token`, as
`?token=...` or an `Authorization: Bearer ...` header. A scraper cannot log in,
so the token is the access control.

**Service logs:** `journalctl -u smartdns-dashboard -f`

---

## 11. Repository layout

```
smartdns-dashboard/
├── pyproject.toml              packaging; `smartdns-dashboard` console script
├── README.md  CHANGELOG.md  CONTRIBUTING.md  LICENSE
├── Makefile                    dev / test / lint / installer shortcuts
├── config.example.ini          every option, commented
├── requirements.txt            pinned set for the deployed venv
├── .github/
│   ├── workflows/ci.yml        tests on 3.10-3.12, lint, installer checks
│   └── scripts/check-i18n.mjs  fails the build on a missing translation
├── deploy/
│   ├── smartdns-dashboard.service
│   ├── install.sh              install from a git checkout
│   └── nginx.conf.example      only if you have a proxy to put in front
├── tools/
│   ├── build_installer.py      builds the single-file install.py
│   └── installer_template.py
├── tests/                      pytest suite (~290 cases)
│   ├── conftest.py             a throwaway deployment per test
│   ├── test_parsers.py         reference inputs for every text format
│   ├── test_guards.py          the write path, one test per guard
│   ├── test_app.py             HTTP surface, auth, CSRF, i18n
│   ├── test_config_and_ports.py  port safety, proxy handling, allow-list
│   ├── test_store_and_alerts.py  history, retention, rules, notifiers
│   └── test_features.py        roles, groups, charts, probe, metrics, triage
└── src/smartdns_dash/
    ├── __main__.py             run / doctor / check / reconfigure /
    │                           make-cert / selftest / hash-password
    ├── config.py               INI + env parsing, identity auto-detection
    ├── preflight.py            port safety and environment checks
    ├── i18n.py                 bilingual server messages
    ├── auth.py                 scrypt, signed cookie + role, CSRF, throttle
    ├── store.py                SQLite history - NOT an accounting source
    ├── alerts.py               rules, reconciliation, notifier interface
    ├── probe.py                active "can this be proxied?" test
    ├── state.py                feed ring, background pollers, SSE fan-out
    ├── app.py                  routes
    ├── sources/
    │   ├── sniproxy_log.py     access-log parser + rotation-safe tailer
    │   ├── dnsdist.py          console wrapper, grepq classifier, dig
    │   ├── domains.py          suffix matching + the guarded write path
    │   ├── sysinfo.py          service state, staleness check
    │   ├── peer.py             two-server diff
    │   └── portwatch.py        tcpdump SYN watcher
    ├── templates/              index.html, login.html, triage.html
    └── static/                 app.js, style.css, sw.js, manifest, icon
```

Each module under `sources/` has a `selftest()` that runs against the
documented reference input and then against live data. When something parses
wrong, that is the one file to change.

### Development

```bash
make dev        # venv + editable install with dev extras
make test       # pytest
make lint       # ruff + JS syntax + translation catalog completeness
make installer  # build and verify install.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: guards on the write
path may be added but never removed, and the dashboard must never be able to
take a port the resolver needs.

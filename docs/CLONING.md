# Cloning, moving, changing addresses

Nothing about a particular server is compiled in. Three values could tie an
install to one machine, and all three are discovered at runtime:

| Value | When set to `auto` |
|---|---|
| `name` | the system hostname |
| `local_ip` | the first global IPv4 on this host |
| `public_ip` — the address listed domains are spoofed to | read out of the generated dnsdist config |

That last one matters most. On a DNAT topology the public address lives on the
router, not on any interface here, so it cannot be read off the network stack
or guessed. But the smartdns generator writes it into `dnsdist.conf` as the
spoof target, which makes that file the authoritative source — so the dashboard
reads it back instead of asking anyone to keep two files in sync.

`check` and `doctor` both print where the value came from:

```
spoof target   31.24.200.3   [/etc/dnsdist/dnsdist.conf (spoof)]
```

Clone a VM, change its address, re-run the smartdns generator, and the
dashboard follows. If it cannot find the spoof target it says so in the header
and in `check`; pin `[server] public_ip` explicitly in that case.

---

## After cloning a VM image

```bash
cd /opt/smartdns-dashboard
venv/bin/python -m smartdns_dash reconfigure --show       # what it detects now
```

Then re-point it:

```bash
venv/bin/python -m smartdns_dash reconfigure \
    --name NEW-HOST-01 --public-ip auto --local-ip auto \
    --peer-host <the other server> --peer-name NEW-HOST-02 \
    --reset-secret
systemctl restart smartdns-dashboard
```

**`--reset-secret` matters on every clone.** The image carries the original
`secret_key`, so without it a session cookie minted on one clone would be valid
on all of them.

Consider also:

- a **new password** (`--password`), since the image carries the old hash;
- clearing the **history database** if the clone should not inherit the
  original's observations: `rm /var/lib/smartdns-dashboard/history.db` and
  restart;
- the **SSH key** for the peer diff, if the image carries one that no longer
  matches the new pair.

`reconfigure` backs the config up first, writes only the keys you name,
re-validates the result, and restores the backup automatically if the result
does not load.

Other options: `--bind`, `--port`, `--behind-proxy`, `--forwarded-allow-ips`,
`--allow-ips`, `--root-path`, `--exposed`, `--language`, `--tls-cert`,
`--tls-key`. Run `reconfigure --help` for the full list.

---

## Changing a port

```bash
venv/bin/python -m smartdns_dash doctor               # suggests a free safe port
venv/bin/python -m smartdns_dash reconfigure --port 9450
systemctl restart smartdns-dashboard
```

Ports belonging to the DNS/proxy stack are refused outright — at config load
and again before the server starts. See `preflight.RESERVED`.

---

## A different deployment layout

Every path lives in `[paths]`. A deployment with different filenames — another
sniproxy log location, another generator script — needs no code change, only
that section:

```ini
[paths]
domains = /etc/smartdns/domains.txt
generated_proxy = /etc/smartdns/generated/domains.proxy
dnsdist_conf = /etc/dnsdist/dnsdist.conf
sniproxy_conf = /etc/sniproxy.conf
env_file = /etc/smartdns/smartdns.env
update_script = /usr/local/bin/update-smartdns.sh
backup_dir = /root/smartdns-backups
https_log = /var/log/sniproxy/https_access.log
http_log = /var/log/sniproxy/http_access.log
error_log = /var/log/sniproxy/error.log
update_log = /var/log/smartdns/update.log
```

Which units get restarted after a change is `[services] restart`. Set it to
`none` only if something else handles restarts — a regenerate without a restart
leaves sniproxy serving the old table while the file on disk looks correct,
which is the exact trap the staleness banner exists to catch.

---

## Single-server use

`[peer] enabled = false` is fully supported. The Server diff panel falls back
to paste mode, **Apply to both** is refused with a clear message, and a
"single server" chip appears in the header.

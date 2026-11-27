# Data formats

Every external text format this project parses, with a real reference sample
and the traps in each. **This is the file that goes stale first**, because the
formats belong to other programs and drift between versions.

If a panel is empty on a real server, start here, then run the matching
`selftest` — each one prints the reference case before touching live data, so a
format change is obvious immediately:

```bash
cd /opt/smartdns-dashboard
venv/bin/python -m smartdns_dash selftest logs
venv/bin/python -m smartdns_dash selftest dnsdist --client-ip <a client>
venv/bin/python -m smartdns_dash selftest domains
venv/bin/python -m smartdns_dash selftest status
venv/bin/python -m smartdns_dash selftest peer
venv/bin/python -m smartdns_dash selftest portwatch --client-ip <a client>
```

---

## 1. sniproxy access log

**Files:** `/var/log/sniproxy/https_access.log`, `.../http_access.log`
**Parser:** `sources/sniproxy_log.py` → `LINE_RE`, `parse_line()`
**Tests:** `tests/test_parsers.py::test_reference_line_fields` and neighbours

### Reference line

```
2026-08-02 15:17:14 84.241.45.220:39460 -> 172.20.46.2:443 -> 129.226.1.156:443 [sg.msdkfaas.com] 4363/4363 bytes tx 1628/1628 bytes rx 0.751 seconds
```

### Fields

| Position | Meaning | Notes |
|---|---|---|
| 1–2 | date, time | local time, **no zone** — parsed as local |
| 3 | client `ip:port` | |
| 4 | `->` | literal |
| 5 | listener `ip:port` | tells you 80 vs 443 |
| 6 | `->` | literal |
| 7 | origin `ip:port` | **can be the literal `NONE`** |
| 8 | `[SNI]` | **can be empty: `[]`** |
| 9–11 | `written/total bytes tx` | two numbers; a divergence means a truncated transfer |
| 12–14 | `written/total bytes rx` | |
| 15–16 | duration `seconds` | |

### Traps

- **`NONE` origin** means sniproxy could not resolve or connect. A routing
  failure; the UI flags the row.
- **Empty SNI** means the client sent none, so sniproxy had nothing to route
  on. Also flagged.
- **Byte direction.** `tx` is origin → client; `rx` is client → origin. This was
  misread once during debugging. The parser exposes `from_origin` / `to_origin`
  aliases derived from a single constant, `TX_IS_FROM_ORIGIN`. If `ss -ti` ever
  proves the opposite, flip that one constant and both aliases follow.
- **Log rotation.** Three variants, all handled; see `ARCHITECTURE.md` §4.
- **Partial lines.** A record read mid-write is buffered until the newline
  arrives, never parsed truncated and never counted as a bad line.

### Edge samples kept as tests

```
2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443 -> NONE [x.example.com] 0/0 bytes tx 517/517 bytes rx 0.004 seconds
2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443 -> NONE [] 0/0 bytes tx 0/0 bytes rx 0.001 seconds
2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:80 -> 5.6.7.8:80 [api.example.com] 120/120 bytes tx 90/90 bytes rx 0.030 seconds
```

---

## 2. dnsdist console — `grepq()`

**Invocation:**

```bash
. /etc/smartdns/smartdns.env
dnsdist -c 127.0.0.1:5199 -k "$SMARTDNS_DNSDIST_KEY" -e 'grepq("CLIENT_IP", 500)'
```

**Parser:** `sources/dnsdist.py` → `parse_grepq()`, `classify()`
**Tests:** `tests/test_parsers.py::test_grepq_column_shift` and neighbours

This is the single most useful data source in the system: it answers *what did
this client ask for that we are not proxying?*

### Reference output

Two shapes, and the same query usually produces both:

```
-407.8  84.241.45.220:60004                   32951 west-tdm.codmwest.com.  A   RD  Question
-407.8  84.241.45.220:60004   8.8.4.4:53      32951 west-tdm.codmwest.com.  A   41.7  RD  No Error. 4 answers
```

### Traps

- **Column shift.** Field 3 is the upstream server **only when it looks like
  `ip:port`**. In a Question row it is the query id and everything after shifts
  left by one. The parser checks the shape rather than counting fields.
- **An upstream means NOT proxied.** If the upstream column is populated the
  query went upstream, so dnsdist did not spoof it.
- **One row is not enough to decide.** A name is unproxied if it appears in *at
  least one* row with an upstream; it is proxied only if it never does. Judging
  from the Question row alone would classify everything as proxied.
- **Timestamps are negative seconds relative to now**, so absolute time is
  `now + offset`.
- **Query names carry a trailing dot**, stripped on parse.
- **The ring forgets.** A name's apparent first-seen time walks forward as
  entries age out, which is why `store.py` keeps a registry whose `first_seen`
  only ever moves backwards.

### The derived view, as a shell one-liner

Useful for checking the parser against the shell:

```bash
dnsdist -c 127.0.0.1:5199 -k "$KEY" -e 'grepq("84.241.45.220", 600)' \
  | awk '$3 ~ /:53$/ {print tolower($5)}' | sed 's/\.$//' | sort -u
```

### Other console commands used

| Command | Parser | Used for |
|---|---|---|
| `topQueries(50)` | `parse_top()` | top-queries list |
| `showServers()` | `parse_show_servers()` | upstream health; parsed loosely by header name |

---

## 3. The allow-list

**File:** `/etc/smartdns/domains.txt`
**Parser:** `sources/domains.py` → `parse()`
**Tests:** `tests/test_parsers.py`, `tests/test_guards.py`

### Format

One domain suffix per line. `#` starts a comment; a line whose code part is
empty is inactive. Inline comments are preserved for display and survive a
disable/enable round trip.

```
# allow-list
sg.msdkfaas.com
west-tdm.codmwest.com   # tdm matchmaking

# @group codm
west-chat.codmwest.com
# @endgroup

api.other.example   # @group misc
```

### Conventions this project adds

Both are comments, so `domains.txt` remains the single source of truth and
nothing else has to be kept in sync.

**Groups.** A `# @group <name>` line opens a group that runs until `# @endgroup`
or the next `@group`; `# @group <name>` in a line's own comment tags just that
line. Names: `[A-Za-z0-9._-]`, up to 40 characters.

**Disabled entries.**

```
# DISABLED via dashboard 2026-08-03 22:49:22 - reason | west-tdm.codmwest.com   # matchmaking
```

The delimiter is ` | `, **not** `:`, because the timestamp and the reason both
contain colons and a colon delimiter cannot be unambiguously undone. `|` is
stripped from reasons on the way in, so it only ever appears as the delimiter.
`DISABLED_LEGACY_RE` still parses the colon form written before 1.2.0.

### Matching rules

- A suffix matches its own root **and every subdomain**: `example.com` matches
  `a.b.example.com`.
- The **most specific** (longest) matching suffix wins when several match.
- **CNAME targets are never matched** — matching is on the query name only.
- **No exclude syntax.** List the exact FQDN; never the root.
- `registrable_depth()` decides "is this a bare root" using a small
  multi-label-TLD set (`co.uk`, `co.ir`, …). Not a full Public Suffix List; a
  miss costs an extra warning, never a wrong write.

---

## 4. `smartdns.env`

**File:** `/etc/smartdns/smartdns.env`
**Parser:** `config.py` → `read_env_file()`

Shell-style `KEY=VALUE`. Handles `export `, single and double quotes, and
inline comments on unquoted values. **Nothing is executed.** Read fresh on every
use so a key rotation needs no restart. The key is never logged or echoed into
an error message.

```bash
# comment
export SMARTDNS_DNSDIST_KEY="abc+def/ghi="
PLAIN=value with spaces # trailing comment
SINGLE='quoted value'
```

---

## 5. Generated dnsdist config

**File:** `/etc/dnsdist/dnsdist.conf` (read-only, never written)
**Parser:** `config.py` → `detect_spoof_ip()`

Read for one purpose: to discover the address listed domains are spoofed to,
when `public_ip = auto`. On a DNAT topology that address lives on the router and
is on no interface here, so it cannot be guessed — but the generator writes it
into this file, which makes it the authoritative source.

```lua
addAction(SuffixMatchNodeRule(proxyNames), SpoofAction("31.24.200.3"))
```

An explicit `Spoof*(...)` directive is treated as authoritative: only
loopback, unspecified and multicast are rejected, so lab and documentation
ranges work. The fallback inferred scan is stricter and skips known public
resolvers and our own interface addresses.

`check` and `doctor` both print where the value came from:

```
spoof target   31.24.200.3   [/etc/dnsdist/dnsdist.conf (spoof)]
```

---

## 6. systemd and `/proc`

**Parser:** `sources/sysinfo.py`

Service state comes from `systemctl show <unit> -p ActiveState,SubState,MainPID,…`.

Process start time is read from **`/proc/<pid>/stat` field 22 plus
`/proc/stat` btime**, not from systemd's `ActiveEnterTimestamp`, because that
string is locale- and timezone-dependent. `comm` can contain spaces and
parentheses, so parsing starts after the last `)`.

This feeds the **staleness check**: if `domains.txt` is newer than the running
sniproxy process, the file on disk looks correct while the process still serves
the old routing table. Invisible from the shell, and it once cost a whole
debugging session — so it is a banner in the header.

---

## 7. tcpdump

**Invocation:**

```bash
tcpdump -l -n -q -i any 'tcp[tcpflags] & tcp-syn != 0 and host <ip> and not port 53 and not port 80 and not port 443'
```

**Parser:** `sources/portwatch.py` → `LINE_RE`
**Tests:** `tests/test_parsers.py::test_tcpdump_line_shapes`

### Two shapes

Older tcpdump, and newer with `-i any` adding an interface/direction prefix:

```
15:17:14.123456 IP 84.241.45.220.39460 > 172.20.46.2.8080: Flags [S], seq 1, win 64240, length 0
15:17:14.323456 eth0  In  IP 84.241.45.220.39461 > 1.2.3.4.8085: Flags [S], seq 1, win 64240, length 0
```

### Traps

- **Ports are separated by a dot, not a colon:** `1.2.3.4.8080`.
- **Flags:** `[S]` is a SYN, `[S.]` is a SYN-ACK — the `.` *is* the ACK.
- **The BPF filter is built from a validated IP only**, never free text, so
  there is no filter-injection surface. `build_filter()` raises on anything
  that is not an address.
- Capture is bounded by `max_runtime_s` so a forgotten watcher cannot run
  forever on a box carrying live traffic.

The signature being hunted: SYNs to a non-80/443 port with no SYN-ACK back.
That is how the CODM downloader problem was found, after hours of manual
tcpdump.

---

## 8. `dig`

**Parser:** `sources/dnsdist.py` → `dig()`

`dig +short @<resolver> <name> <type>`, parsed as one answer per line. Requires
`dnsutils`; degrades to an explanatory message if absent. Used by the Lookup
panel for A, AAAA and HTTPS — AAAA answers for a proxied name are flagged,
because a client that follows IPv6 bypasses the proxy entirely.

---

## 9. DNS wire format (the probe)

**Parser:** `probe.py` → `resolve_via()`

A hand-built A query and a minimal response walk, rather than a dependency.
Handles compression pointers (`0xC0`-prefixed labels). Deliberately does **not**
use `getaddrinfo`, which would hit this server's own dnsdist and return the
spoof address for a listed name — the probe would be testing the proxy against
itself.

---

## 10. X.509 DER (the probe)

**Parser:** `probe.py` → `_names_from_der()`

A targeted scan for the subjectAltName OID (`2.5.29.17`) reading dNSName
entries, with commonName (`2.5.4.3`) as a fallback. Not a real ASN.1 parser.

It exists because the probe must use `verify_mode = CERT_NONE` — it is asking
"does the handshake complete for this SNI", not "do I trust this host" — and
Python then leaves `getpeercert()` empty. `_cert_covers()` returns `None` for
"unknown" rather than `False`, so a parse miss never produces a wrong verdict.

---

## 11. Formats this project *writes*

| File | Format | Notes |
|---|---|---|
| `domains.txt` | as above | atomic write: temp file, mode/owner copied, `os.replace` |
| `/root/smartdns-backups/domains.txt.<stamp>` | verbatim copy | `shutil.copy2`, before every write |
| history database | SQLite, see `store.py` | mode 600, WAL |
| `/metrics` | Prometheus text format | `_render_metrics` in `app.py` |

---

## When a format has changed

1. Run the matching `selftest`. The reference case prints first; if that passes
   and live data fails, the format on your build differs.
2. Capture three real lines.
3. Add them to `tests/test_parsers.py` as a new case — **before** changing the
   regex, so the new behaviour is pinned.
4. Adjust the parser. Keep the old sample passing if the two shapes can coexist;
   tcpdump and the disable marker are both handled that way.
5. Update the section above with the new sample.

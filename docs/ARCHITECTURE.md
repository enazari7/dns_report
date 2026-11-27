# Architecture

Read this before changing anything. It explains not just what the pieces are,
but why several of them look odd — most of the odd parts are odd because
reality is, and a "tidy-up" that removes them reintroduces a bug that has
already been hit once.

---

## 1. The system being observed

The dashboard does not route any traffic. It watches a Smart DNS / SNI-proxy
deployment and can edit one file in it.

```
   Phone / console (restricted network)
        │  DNS query :53
        ▼
   Router (DNAT 53/80/443, source-gated address-list)
        │
        ▼
   Ubuntu server
     ├─ dnsdist    :53        DNS edge. Spoofs A records for listed names,
     │                        suppresses AAAA/HTTPS/SVCB, answers everything
     │                        else from upstream. Keeps a query ring buffer.
     ├─ sniproxy   :80 :443   Reads the TLS SNI or the HTTP Host header and
     │                        connects out to the real destination.
     ├─ unbound    127.0.0.1  local cache
     └─ dashboard  :9443      ← this project
```

### The routing model, in one paragraph

One file drives everything: `/etc/smartdns/domains.txt`. Every active line is a
**domain suffix** matching the root and all subdomains — `example.com` matches
`a.b.example.com`. For a listed name dnsdist answers A with the deployment's own
public address, so the client connects to the proxy, which then reads the SNI to
learn the real destination. Unlisted names resolve normally. **Matching is on
the query name only; CNAME targets are not matched.** There is no exclude
syntax: to proxy `a.example.com` but not `b.example.com`, you list the exact
FQDN and never the root.

### Two failure modes that shape the whole design

Adding a line is **not** free. It means "send this through the proxy", and for a
service already reachable directly it is a regression. Two cases cannot be fixed
by proxying at all:

1. **No SNI and no Host header.** sniproxy routes on one or the other. The Call
   of Duty Mobile downloader speaks a binary Tencent GCloud protocol on TCP
   8080/8085/8013 with neither. Proxying its domain makes the game open and
   never download.
2. **UDP.** sniproxy is TCP-only. Proxying a voice-chat host
   (`*.west-gvoice.codmwest.com`) killed voice entirely.

Three real outages during development came from speculative additions. That is
why the write path is built the way it is (§5) and why the probe (§6) exists.

---

## 2. Module map

```
src/smartdns_dash/
├── __main__.py      CLI: run / doctor / check / reconfigure / make-cert /
│                    selftest / hash-password / secret
├── config.py        INI parsing, env-file parsing, identity auto-detection
├── preflight.py     port safety and environment checks
├── i18n.py          bilingual server-generated messages
├── auth.py          scrypt hashing, signed session token, CSRF, throttle
├── store.py         SQLite diagnostic history (NOT an accounting source)
├── alerts.py        rules → findings → reconcile → notifiers
├── probe.py         active "can sniproxy route this?" test
├── state.py         in-memory feed ring, background pollers, SSE fan-out
├── app.py           FastAPI routes; the only module that knows about HTTP
├── sources/         one module per external text format (see docs/DATA-FORMATS)
│   ├── sniproxy_log.py   access-log parser + rotation-safe tailer
│   ├── dnsdist.py        console wrapper, grepq classifier, dig
│   ├── domains.py        suffix matching + the guarded write path
│   ├── sysinfo.py        service state, config-staleness check
│   ├── peer.py           two-server diff and mirrored write
│   └── portwatch.py      tcpdump SYN watcher
├── templates/       index.html, login.html, triage.html
└── static/          app.js, style.css, sw.js, manifest, icon
```

### Dependency direction

```
app.py ──► state.py ──► sources/*  ──► (external programs and files)
   │           │            │
   │           ├──────► store.py
   │           └──────► alerts.py
   └──► probe.py, preflight.py, auth.py, config.py, i18n.py
```

Nothing in `sources/` imports `app.py` or `state.py`. Each source module is
independently runnable, which is what makes `selftest` possible: on a real
server you run one command, get the parser's view of live data, and know
immediately which single file to fix.

---

## 3. Data flow

### Reads

Three background tasks in `state.py`, each on its own configurable interval:

| Poller | Interval | What it does |
|---|---|---|
| `_poll_logs` | `log_ms` (1s) | Incremental tail of both access logs → feed ring → SSE, plus traffic rollups and the domain registry |
| `_poll_grepq` | `grepq_ms` (5s) | Only while a client is selected: `grepq()` over the dnsdist ring → classify proxied vs upstream |
| `_poll_status` | `status_ms` (15s) | Service state, staleness, allow-list health → alert evaluation → SSE |

Everything else serves from memory. **No endpoint ever re-reads a whole log
file**, and N browser tabs cost the same as one. This matters because the box
also carries live traffic.

### Writes

Exactly one file is ever written: `domains.txt`. Plus the backups directory and
the history database. Nothing else in the deployment is touched except through
the operator's own update script.

---

## 4. Things that look wrong but are not

Each of these has a comment at the site explaining it. Summarised here so a
reviewer sees them before "simplifying" one.

**`sniproxy_log.Tailer` compares a hash of the file's head.** Inode and size
both look unchanged when logrotate uses `copytruncate` and the replacement
content happens to be the same length, so the tailer silently stalled. Appends
never rewrite existing bytes; a replacement does. So the common prefix is
compared. (Fixed in 1.1.0, with a test.)

**The file handle is held open across calls** (`# noqa: SIM115`). The read
offset has to survive between polls; a context manager cannot express that.

**`from_end=True` deliberately skips pre-existing log content.** This is a live
feed, not a backfill. `tail_last()` is the history path. Backfilled rows feed
the domain registry but **not** the traffic rollups, because replaying the same
connections on every restart would inflate the totals.

**`grepq` output is parsed positionally with a shape guard.** Field 3 is the
upstream server only when it looks like `ip:port`; otherwise it is the query id
and everything shifts left by one. A name is *unproxied* if it appears in at
least one row with an upstream populated — not from a single row, because the
same query produces both a Question row and a response row.

**The disable marker uses `|`, not `:`.** The timestamp and the reason both
contain colons, so a colon delimiter cannot be unambiguously undone.
`DISABLED_LEGACY_RE` still parses markers written before 1.2.0.

**The probe resolves through an explicit upstream, never the local resolver.**
The local resolver returns the spoof address for an already-listed name, so the
probe would end up testing the proxy against itself.

**TLS cert names are scraped out of the DER by hand.** With
`verify_mode = CERT_NONE` — which the probe needs, since it is asking "does the
handshake complete", not "do I trust this host" — Python leaves
`getpeercert()` empty. `_cert_covers` returns `None` for "unknown", so a parse
miss never produces a wrong verdict.

**`public_ip = auto` reads the spoof address out of the generated dnsdist
config.** On a DNAT topology the public address lives on the router, not on any
interface here, so it cannot be guessed. The generator writes it into
`dnsdist.conf`, which is the authoritative source, so the dashboard reads it
back rather than asking anyone to keep two files in sync.

**Peer-first ordering in the mirrored write.** If the peer fails, this server is
left untouched and the pair stays matched (both old). Local-first would risk
exactly the divergence the feature exists to prevent.

---

## 5. The guarded write path

This is the part to be most careful with. The invariant:

> **No change to the allow-list without explicit confirmation, and never a
> regenerate without a restart of the services that read the result.**

sniproxy reads its config only at startup. Regenerating without restarting
leaves the stale routing table live in memory while the file on disk looks
correct — a failure mode that once cost an entire debugging session.

### Two phases

```
POST /api/domains/preview   → build_*_plan()  → Plan (token, diff, guards)
POST /api/domains/apply     → apply_plan()    → backup, write, regenerate, restart
```

`Plan.rendered` holds the exact file content the preview was generated from, and
`apply_plan` writes that verbatim — so what was confirmed in the diff is
byte-for-byte what lands on disk.

### Guards, and what each one is for

| Guard | Why |
|---|---|
| already covered by a suffix | the line would change nothing; names the covering suffix |
| bare root | lists the subdomains already observed under it, or says plainly that none have been, so you can see what you are about to capture |
| subsumes existing entries | tells you which become redundant |
| timestamped backup first | if the write or the generator fails, it is restored automatically |
| diff preview | the exact unified diff |
| typed confirmation | the domain itself, not an OK button |
| file changed since preview | refused; re-run the preview |
| single-use 5-minute plan token | a stale browser tab cannot replay a write |
| write lock | one change at a time |
| mandatory restart | the update script and `systemctl restart` run as one unit |

Adding a guard is welcome. **Removing one, or adding a code path that bypasses
them, is the one change this project should refuse.**

### Actions

`add`, `disable`, `enable`, `tag`, `group-disable`, `group-enable`. All of them
produce a `Plan` and go through the same apply path. `restore_backup` is
separate but equally guarded.

---

## 6. The one decision left to a human

Choosing *what* to add is deliberately not automated. The dashboard presents
candidates and evidence; the operator decides.

`probe.py` exists to make that evidence real rather than remembered. From the
server it answers:

1. does a TLS handshake complete with this name as the SNI on 443? (that is
   exactly the mechanism sniproxy routes on, so a completed handshake is proof
   it *can*)
2. does HTTP on 80 answer a Host header?
3. is the host reachable directly right now? (if so, adding it may be a
   regression)
4. are 8080/8085/8013 open? (the GCloud downloader signature)

It never adds anything. If you extend it, keep that property.

---

## 7. Security model

The dashboard **runs as root**. It writes `domains.txt`, runs the update script
and calls `systemctl restart`. Anyone who reaches it and passes the login has
root on the box. Everything below follows from that.

- **Bind loopback by default.** SSH tunnel or a VPN address are the intended
  access paths.
- **`allow_ips`** is enforced in middleware before authentication — the in-app
  equivalent of an nginx `allow`/`deny`, for a box with no proxy on it.
- **Password**: scrypt (n=16384), never stored or logged in plaintext.
- **Session**: HMAC-SHA256-signed token in an HttpOnly cookie. The **role is
  inside the signed payload**, so a viewer cannot become an operator by editing
  a cookie.
- **CSRF**: a token bound to the session's `jti`, required on every
  state-changing POST.
- **Login throttle**: per source address. Behind a proxy, `X-Forwarded-For` is
  trusted *only* when `behind_proxy` is set and the immediate peer is in
  `forwarded_allow_ips` — otherwise a client could mint a fresh bucket per
  guess.
- **CSP**: `default-src 'none'` with everything else `'self'`. No external
  origin anywhere, no CDN, no web fonts. The target box may have no outbound
  HTTP at all, and a dashboard that needs a CDN to render is useless there.
- **The dnsdist console key** is read from `smartdns.env` on every use, never
  cached, and never echoed into an error message or a log line.
- **Port safety**: ports belonging to the DNS/proxy stack are refused at config
  load and again before the server starts. See `preflight.RESERVED`.
- **`/metrics`** exposes aggregate series only. Per-client byte counters there
  would be an accounting record by the back door, since Prometheus retains data
  far longer than the history window.

---

## 8. The history database is not an accounting source

Stated in the module docstring, in the `meta` table inside the database, in
`config.example.ini`, in every API payload that returns figures, and above the
Traffic panel.

Rows are keyed by client IP, and addresses change hands: a user gets a new
address, another user inherits the old one, and the two are indistinguishable
from here. A figure in that database describes **an address over a window of
time**, not a person. Accounting belongs in a system that knows about accounts.

The schema makes the misuse structurally harder: there is no per-connection
table, only time buckets, and retention is short by default. If you extend the
history, keep both properties.

---

## 9. Internationalisation

Two mechanisms, for two different kinds of string.

**Static UI labels** live in the `STR` catalog in `static/app.js` as
`[english, persian]` pairs, applied to `data-i18n` attributes. Switching
language re-renders from memory; nothing is refetched.

**Server-generated text** — guard warnings, lookup verdicts, staleness
messages, probe reasoning — is built in `i18n.py` and returned as
`{"en": ..., "fa": ...}`. The browser picks. This is why switching language is
instant even for a warning that was computed server-side ten minutes ago.

`.github/scripts/check-i18n.mjs` fails CI on a missing key, an unused key, or
an empty string in either language. A dynamic key (`t('groups.' + state)`)
defeats that check, so use an explicit map instead — there is a comment at the
one place this came up.

RTL is a `dir="rtl"` flip on `<html>`, not a second stylesheet. Identifiers,
addresses, log lines and diffs are forced back to LTR, because an IP rendered
right-to-left is unreadable.

---

## 10. Extending it

### Adding a data source

1. New module in `sources/`. Parse into plain dicts; no HTTP, no app imports.
2. Give it a `selftest()` that runs against a documented reference sample first,
   then against live data. Record the sample in `docs/DATA-FORMATS.md`.
3. Tests in `tests/test_parsers.py` using literal lines from a real deployment.
4. Wire it into `state.py` as a poller, or call it on demand from `app.py`.

### Adding a panel

1. Markup in `templates/index.html` with `data-i18n` attributes.
2. `STR` entries for every label, both languages.
3. A render function in `app.js`, and add it to `redrawAll()` so a language
   switch re-renders it.
4. A read-only endpoint in `app.py` behind `require_session`.

### Adding a write action

1. A `build_*_plan()` in `sources/domains.py` returning a `Plan`.
2. Accept the action name in `api_preview` **and** in `_rebuild`'s allowlist.
3. Gate the route with `require_operator`, not `require_session`.
4. Audit the attempt — refusals too.
5. A test per guard in `tests/test_guards.py`.

### Adding a notifier

Subclass `alerts.Notifier`, implement `enabled()` and `send()`, add it to
`build_notifiers()` behind its own config keys. The dispatcher marks an event
notified only when at least one enabled notifier accepted it, so a transient
failure retries instead of losing the alert.

---

## 11. Deliberate non-goals

- **No database for the allow-list.** `domains.txt` is the single source of
  truth, including for groups, which are a comment convention inside it. A
  second store would drift.
- **No automatic domain addition.** Ever. See §6.
- **No JS build step, no CDN, no web fonts.** See §7.
- **No per-connection traffic log.** See §8.
- **No agent on the clients.** Everything is inferred from what the server can
  already see.
- **It does not read the router.** The `Permited` address-list gates the DNAT
  for 80/443 and is not reachable from here. Where that matters — the triage
  page — the wording is a likelihood with its evidence, never a claim of fact.

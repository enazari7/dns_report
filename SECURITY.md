# Security policy

## The threat model in one line

**This dashboard runs as root.** It writes `/etc/smartdns/domains.txt`, runs
the deployment's update script and calls `systemctl restart`. Anyone who
reaches it and gets past the login has root on the box.

Deploy it accordingly: loopback-bound behind an SSH tunnel or a VPN by default,
and if you publish the port, both a long password and a source restriction.

## Reporting a vulnerability

Open a [private security advisory][advisory] on the repository, or email the
maintainer listed in `pyproject.toml`. Please do not open a public issue for
anything that lets someone reach the write path without the password.

[advisory]: https://github.com/enazari7/dns_report/security/advisories/new

Include: what you did, what happened, and the configuration — particularly
`bind`, `behind_proxy`, `allow_ips` and whether TLS is terminated by the app or
a proxy. There is no bounty; this is a small self-hosted tool.

## What is in scope

- Reaching any `/api/*` route, `/metrics`, or the write path without valid
  credentials.
- Escalating from the **read-only viewer** role to the operator role.
- Bypassing the guarded write path: writing `domains.txt` without a plan
  token, replaying a used plan, or regenerating config without the restart.
- Writing or reading a file outside the configured paths — the backup-restore
  and log endpoints take names from the user, and both are constrained.
- Defeating the login rate limiter, for example by forging `X-Forwarded-For`.
- Command injection through any value that reaches a subprocess: the dnsdist
  console, `dig`, `tcpdump`'s BPF filter, or the SSH call to the peer.
- Leaking the dnsdist console key into a response, a log line or an error.
- Stored or reflected XSS in a panel. The CSP is `default-src 'none'` with
  everything else `'self'`, so a bypass of that is interesting on its own.

## What is out of scope

- **Anything reachable only after authenticating as the operator.** That
  account is intended to have root-equivalent power; that is the design, not a
  bug.
- Exposing the port to the internet with no `allow_ips`, no TLS and a weak
  password. The config warns about each, `doctor` reports it, and the login
  page says so.
- Running with `forwarded_allow_ips = *`. A startup warning covers it.
- Self-signed certificate warnings from `make-cert`. Expected; a browser
  warning once is a far smaller problem than a plaintext password.
- The `/triage` page revealing whether the dashboard has seen the **caller's
  own** address. That is its purpose, it is off by default, and it reports
  nothing about any other address to an unauthenticated caller.
- Denial of service by pointing `grepq_limit` or the port watcher at a busy
  box. Both are operator-configurable and documented as costing CPU.

## What the project already does

| Area | Measure |
|---|---|
| Password | scrypt, n=16384; never stored or logged in plaintext |
| Session | HMAC-SHA256-signed token, HttpOnly, `SameSite=Lax`, `Secure` when the browser's connection is HTTPS |
| Role | inside the signed payload, so a cookie edit cannot grant operator |
| CSRF | token bound to the session `jti`, required on every state-changing POST |
| Login throttle | per source address; `X-Forwarded-For` trusted only from an allowed proxy |
| Pre-auth gate | `allow_ips` enforced in middleware before authentication |
| CSP | `default-src 'none'`; no external origin, no CDN, no web fonts |
| Other headers | `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, HSTS when serving TLS |
| Secrets | the dnsdist key is read fresh from `smartdns.env`, never cached, never echoed |
| Subprocesses | argument lists, never a shell; the BPF filter is built from a validated IP only |
| Path handling | backup names and log selectors are constrained; traversal is rejected and tested |
| Port safety | ports owned by the DNS/proxy stack are refused at config load and at startup |
| Write path | backup, diff, typed confirmation, single-use 5-minute token, mtime check, write lock, mandatory restart |
| Peer SSH | `BatchMode=yes`, `IdentitiesOnly=yes`, one fixed remote command |
| Metrics | aggregate series only; no per-client counters |
| File modes | config 600, backups 700, history 700 and 600 |

Tests for most of these live in `tests/test_app.py`,
`tests/test_config_and_ports.py` and `tests/test_features.py`.

## Hardening checklist for an operator

- [ ] `bind = 127.0.0.1` unless you have a reason
- [ ] a long random password; consider a separate read-only account for anyone
      who only needs to look
- [ ] `allow_ips` set if the port is reachable from anywhere but loopback
- [ ] TLS: either `behind_proxy` with a proxy terminating it, or
      `tls_cert`/`tls_key`
- [ ] `forwarded_allow_ips` is the proxy's address, not `*`
- [ ] `/metrics` disabled, or enabled with a token
- [ ] `/triage` disabled unless you want players using it
- [ ] `doctor` exits clean, and `8083`/`9100` are still loopback-only
- [ ] `--reset-secret` run on any cloned VM

## Supported versions

The latest release on `main`. This is a single-deployment tool; there are no
backported branches.

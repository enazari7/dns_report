# Changelog

All notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/).

## [1.2.0]

### Added
- **"Is it safe to proxy?" probe.** For a candidate domain, tested from the
  server: does a TLS handshake complete with that name as the SNI on 443, does
  HTTP answer with a Host header on 80, is it reachable directly, and are
  8080/8085/8013 open (the Tencent GCloud downloader signature). Turns the one
  decision the tool leaves to a human from a guess into a judgement with
  evidence. It never adds anything.
- **Apply to both servers in one action.** The peer is written first: if it
  fails, this server is left untouched and the pair stays matched rather than
  drifting. Refused outright when the two lists already differ, so a mirrored
  write cannot silently overwrite someone else's change. The peer does its own
  backup and its own rollback.
- **Domain groups / per-game profiles.** A group is a `# @group name` comment
  inside `domains.txt`, so the file stays the single source of truth. Switching
  a group off comments out every member through the same guarded flow as a
  single domain - the fast way back out when a whole game got worse after a
  change. Round-trips without losing inline comments.
- **`enable` action**, the inverse of `disable`, so a change made in a hurry
  during an outage can be undone in a hurry too.
- **Persistent diagnostic history** (SQLite): events, audit trail, domain
  first-seen registry, and time-bucketed traffic totals. Explicitly **not an
  accounting source** - rows are keyed by IP address and addresses change
  hands, which is stated in the module, in the config, in the API payloads and
  in the UI. Retention is deliberately short for the same reason.
- **Bandwidth and top-talkers charts**, drawn as inline SVG. No chart library:
  the CSP allows no external origins and the box may have no outbound HTTP.
- **Events and alert rules** with a badge in the header: service down, stale
  config, unreachable dnsdist console, a spike in origin-NONE/no-SNI failures,
  peer divergence, unreadable allow-list. A condition that stays true is one
  event with a duration, not one row per poll, and events close themselves when
  the condition clears. Notifiers are pluggable and in-app only by default;
  webhook and Telegram transports are written and disabled.
- **Audit log on disk.** Every attempt to change something, successful or not -
  a refusal is recorded too, because who tried to add a bare root and was
  stopped is as interesting as what went through.
- **Read-only role.** A second credential that can see everything and change
  nothing. The role travels inside the signed session token, and the
  restriction is enforced server-side rather than by hiding buttons.
- **Prometheus endpoint** at `/metrics`, off by default, token-protected.
  Aggregate series only: no per-client byte counters, because Prometheus keeps
  data far longer than the retention window and that would be an accounting
  record by the back door.
- **Client triage page** at `/triage`, off by default. Reports only what the
  dashboard has observed about the caller's own address. It cannot read the
  MikroTik's `Permited` list, so when DNS clearly works and no proxy connection
  arrives it says that *points at* the Permited list rather than claiming it as
  fact.
- **Mobile layout and PWA**: stacked panels, touch-sized controls, 16px inputs
  so iOS does not zoom, a manifest and an icon, and a service worker that
  caches the shell only - never an API response, because a stale "sniproxy is
  running" is a lie rather than a convenience.

### Fixed
- The disable marker used `:` as its delimiter, which is ambiguous because the
  timestamp and the reason both contain colons - re-enabling could recover the
  wrong text. Now `|`, with a fallback that still parses markers written by the
  previous version.
- The `[services] restart` list could not be set to empty; an empty value fell
  back to the default. `restart = none` is now respected, for a deployment that
  manages restarts elsewhere.

## [1.1.0]

### Added
- **Port safety.** `doctor` reports what is listening, whether the chosen port
  is free and bindable, path and tool availability, and whether the DNS
  machinery still owns its ports. Ports belonging to the DNS/proxy stack
  (53, 80, 443, 5199, 8083, 9100, 22, ...) are refused at config load and again
  before the server starts; `pick_free_port()` suggests a safe alternative and
  the installer uses it rather than writing a config that cannot start.
- **Persian interface** with an EN/فا switch in the header, RTL layout, and a
  Persian font stack. Server-generated text (guard warnings, lookup verdicts,
  staleness messages) ships in both languages, so switching is instant.
- **Light/dark theme** toggle, both remembered per browser.
- **Standalone exposure without a reverse proxy**: `allow_ips` (addresses or
  CIDRs, enforced before authentication) and `make-cert` for a self-signed
  TLS pair with sensible SANs.
- **Reverse-proxy support**: `behind_proxy`, `forwarded_allow_ips`, and
  `root_path` for serving under a sub-path. The login rate limiter sees real
  client addresses instead of the proxy's, and only trusts `X-Forwarded-For`
  from an allowed proxy.
- **`reconfigure`** command to re-point an install after cloning a VM or
  changing an address, with a config backup and automatic rollback if the
  result does not validate.
- **`disable`** action on the allow-list: comments an entry out, regenerates
  and restarts. The fast recovery path when an addition breaks something.
- Standard repository layout: `src/` package, `pyproject.toml` with a console
  script, pytest suite, ruff config, GitHub Actions CI, MIT licence.

### Changed
- **Nothing is hard-coded to a particular server.** `name`, `local_ip` and
  `public_ip` all accept `auto`. The spoof target is read out of the generated
  dnsdist config, which is the authoritative source, so a clone at a new
  address needs no edit.
- The single-file `install.py` no longer contains a table of known servers; it
  detects, prompts, or takes flags, and runs `doctor` before finishing.

### Fixed
- **Log rotation with `copytruncate` and identical size.** Inode and size both
  look unchanged in that case, so the tailer silently stalled. It now also
  compares the common prefix of the file head — appends never rewrite existing
  bytes, a replacement does.
- Partial trailing lines are no longer counted as unparsable.
- A typo in the apply confirmation no longer burns the plan token.
- A virtualenv left half-built by an interrupted install is detected and
  rebuilt instead of being trusted because its directory exists.
- `python3 -m venv` failures are diagnosed properly: the usual Ubuntu
  `ensurepip` complaint goes to stdout, which was not being surfaced.
- The comment typed in the add-domain form now reaches the file; the applied
  content is byte-for-byte what the diff preview showed.

## [1.0.0]

Initial release: live proxy feed over SSE, unproxied-domains panel from the
dnsdist ring buffer, combined per-client debugging view, domain lookup with
suffix explanation, two-server diff, config staleness detection, guarded
add-domain with backups, backup browser, and the tcpdump port watcher.

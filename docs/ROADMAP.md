# Roadmap and known limitations

Honest list of what is missing, what is deliberately absent, and where the
rough edges are — so whoever picks this up next does not rediscover them.

## Known limitations

**It cannot read the router.** The `Permited` address-list gates the DNAT for
80/443 and is not reachable from the server. Where that matters — the triage
page — the wording is a likelihood with its evidence, never a claim of fact. A
read-only RouterOS API client would close this; it was considered and left out
because it needs credentials for a device the dashboard otherwise never
touches.

**The dnsdist ring buffer is the only window on DNS queries.** It holds the
recent past only. `grepq_limit` bounds how much is scanned, and a name's
apparent first-seen time would walk forward as entries age out — which is why
the domain registry exists. There is no query log, and adding one would be a
privacy decision, not just an engineering one.

**The port watcher runs a continuous `tcpdump`.** Opt-in, time-bounded, and not
something to leave on. A permanent version would want eBPF or conntrack rather
than parsing text.

**`registrable_depth()` is not a real Public Suffix List.** A small table of
multi-label TLDs decides "is this a bare root". A miss costs an extra warning,
never a wrong write. Shipping the PSL would be more correct and a dependency.

**The X.509 and DNS parsers in `probe.py` are targeted scans, not real
parsers.** Both are documented as such, and both fail to "unknown" rather than
to a wrong answer. They exist to avoid a crypto dependency on a box that may
have no outbound HTTP.

**`traffic` rollups start when the service starts.** The backfill deliberately
does not feed them, because replaying the same connections on every restart
would inflate the totals. The registry does get the backfill.

**No IPv6 story for the proxy path.** The parsers handle IPv6 addresses, and
AAAA answers for a proxied name are flagged, but the deployment model assumes
A-record spoofing.

**The two-server diff compares the allow-list only.** Not the generated files,
not the service state, not the router.

## Deliberately not done

These are decisions, not gaps. Changing one is a design change.

- **No automatic domain addition, ever.** Three real outages came from
  speculative additions. The tool presents candidates and evidence; a human
  decides and types the domain to confirm.
- **No database for the allow-list.** `domains.txt` is the single source of
  truth, including for groups, which are a comment convention inside it.
- **No per-connection traffic log.** The history schema has only time buckets,
  which makes the misuse structurally harder. See ARCHITECTURE.md §8.
- **No JS build step, no CDN, no web fonts.** The target box may have no
  outbound HTTP, and the CSP forbids external origins.
- **No agent on the clients.** Everything is inferred from what the server can
  already see.
- **No multi-tenant model.** Two roles — operator and read-only viewer — and
  that is the whole of it.

## Candidate next work

Roughly in the order that would pay off.

1. **Scheduled health snapshot.** A periodic record of allow-list diff, service
   state and error rates, so "when did this change?" is answerable without
   anyone watching. The store already has the tables.
2. **RouterOS read-only client**, to turn the triage page's inference into a
   fact and to show the `Permited` list in the UI. Needs a credential story.
3. **More than two servers.** `[peer]` assumes exactly one. A list of peers
   would want a different diff presentation, and `apply-both` becomes
   `apply-all` with partial-failure semantics.
4. **Per-group probe sweep.** Run the probe over every member of a group and
   flag the ones that are no longer proxyable — allow-list rot is invisible
   today.
5. **Alert rule for "an entry stopped being used".** A suffix that nothing has
   queried for weeks is a candidate for removal, and the registry already has
   the data.
6. **`notified_at` per notifier**, rather than one flag per event, so a
   late-added transport can backfill.
7. **Structured log output** (JSON to the journal) for the deployments that
   ship logs somewhere central.
8. **Signed releases.** CI builds `install.py`; it is not signed, so a
   checksum published alongside the release would be worth having.

## If you are picking this up cold

Read in this order:

1. `README.md` — what it does and how to run it
2. `docs/ARCHITECTURE.md` — how it fits together, and §4 for the parts that
   look wrong but are not
3. `docs/DATA-FORMATS.md` — every external format, with samples
4. `CONTRIBUTING.md` — the one rule that matters

Then run `make dev && make test` and read `tests/test_guards.py`. It is the
shortest description of what this tool promises not to do.

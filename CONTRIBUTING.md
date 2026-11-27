# Contributing

## Getting set up

```bash
git clone https://github.com/enazari7/dns_report
cd dns_report
make dev          # venv + editable install with dev extras
make test
make lint
```

Or without make:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check src tests
```

## Running it locally

You do not need a real Smart DNS deployment to work on the UI:

```bash
cp config.example.ini config.ini
python -m smartdns_dash -c config.ini secret          # paste into config.ini
python -m smartdns_dash -c config.ini hash-password   # paste into config.ini
python -m smartdns_dash -c config.ini doctor          # see what is missing
python -m smartdns_dash -c config.ini run
```

Panels whose data source is absent degrade to an explanatory message rather
than an error page, which is deliberate — the same thing happens on a real box
when dnsdist is down.

## The one rule that matters

**This tool must never make a change to the allow-list that the operator did
not explicitly confirm, and must never regenerate config without restarting
the services that read it.**

Adding a domain means "route this through the proxy". For a service already
reachable directly that is a regression, and three real outages during
development came from speculative additions. So:

- Guards may be added. Guards may not be removed or made bypassable.
- Any new write path needs a backup, a diff preview, a typed confirmation, and
  a mandatory restart, in that order.
- sniproxy reads its config only at startup. A code path that regenerates
  without restarting will look like it worked and will not have.

Similarly, this dashboard is a guest on a box whose job is DNS. It binds one
TCP port and must never be able to take one the resolver or the proxy needs;
see `preflight.RESERVED`.

## Parsers

Every module in `src/smartdns_dash/sources/` reads a text format produced by
another program, and those formats drift between builds. Each has:

- a `selftest()` that runs against the documented reference input and then
  against live data, so a mismatch on a real server names one file to fix;
- tests in `tests/test_parsers.py` using literal lines from a real deployment.

If you change a parser, add the input that motivated the change as a test case.

## Translations

Static UI strings live in the `STR` catalog in `static/app.js` as
`[english, persian]` pairs. Text the server generates lives in `i18n.py` and is
returned as `{"en": ..., "fa": ...}` so the browser can switch languages without
refetching.

`node .github/scripts/check-i18n.mjs` fails the build on a missing key, an
unused key, or an empty string in either language. Run `make lint` before
pushing.

## Style

- Python: ruff-clean, 88 columns, standard library preferred over a dependency.
- No JS build step, no external CDN. The target box may have no outbound HTTP
  at all, and the CSP only permits `'self'`.
- Comments explain *why*, especially where the code looks odd because reality
  is odd. The head-fingerprint logic in the tailer is a good example.

## install.py is generated, not written

`install.py` at the repo root is a build artifact: `tools/build_installer.py`
zips `src/smartdns_dash/` plus a few root files, base64-encodes the result and
substitutes it into `tools/installer_template.py`. It exists because the target
servers are sometimes reachable only through a file-transfer client that
corrupts binaries, and a single `.py` file survives that.

It is in `.gitignore`. **Never edit it directly** - change the real files and
run `make installer`. CI rebuilds it on every push and attaches it as an
artifact, so a release never depends on someone remembering to regenerate it.

base64 is an encoding, not obfuscation. `python3 install.py --extract-only`
unpacks the readable tree, and the CI job asserts that a corrupted payload is
detected rather than silently installed.

## Releasing

1. Update `CHANGELOG.md` and the version in `pyproject.toml`.
2. `make lint test installer`
3. Tag `vX.Y.Z`. CI attaches the built `install.py` as an artifact.

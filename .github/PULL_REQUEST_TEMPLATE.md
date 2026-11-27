## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The situation that motivated it. -->

---

## Checks

- [ ] `make lint` passes (ruff, JS syntax, translation catalog complete)
- [ ] `make test` passes
- [ ] New or changed behaviour has a test
- [ ] `CHANGELOG.md` updated under an unreleased heading

## If a parser changed

- [ ] The real input that motivated the change is in `tests/test_parsers.py`
- [ ] `docs/DATA-FORMATS.md` updated with the new sample
- [ ] The previous shape still parses, or the removal is deliberate and noted

## If the write path changed

The invariant: **no change to the allow-list without explicit confirmation, and
never a regenerate without restarting the services that read the result.**

- [ ] No guard was removed or made bypassable
- [ ] Any new action still goes through backup → diff → typed confirmation →
      mandatory restart
- [ ] The attempt is audited, refusals included
- [ ] A test per guard in `tests/test_guards.py`

## If the UI changed

- [ ] Every new string is in the `STR` catalog in both languages
- [ ] No dynamically built translation keys (the CI check cannot see them —
      use an explicit map)
- [ ] The new panel is in `redrawAll()` so a language switch re-renders it
- [ ] Still no external origin: no CDN, no web font, no inline script
- [ ] Checked at a narrow width

## If config options changed

- [ ] Documented in `config.example.ini` with the reasoning, not just the name
- [ ] Validated in `config.py`, with a warning rather than a hard failure where
      that is kinder
- [ ] `reconfigure` can set it, if it is something a clone would need to change

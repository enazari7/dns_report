"""The guarded write path.

Adding a domain means "route this through the proxy", and for a service already
reachable directly that is a regression. Three real outages during development
came from speculative additions. So every guard here is load-bearing, and each
one gets a test.
"""

from __future__ import annotations

import time

from smartdns_dash.sources import domains as dom

OBSERVED = [
    "west-gvoice.codmwest.com",
    "west-tdm.codmwest.com",
    "a.newgame.net",
    "b.newgame.net",
    "voice.newgame.net",
]


def _en(msgs):
    return " ".join(m["en"] for m in msgs)


# --------------------------------------------------------------------------
# refusals
# --------------------------------------------------------------------------

def test_refuses_entry_already_covered_by_a_suffix(deployment):
    p = dom.build_add_plan(str(deployment.domains), "sub.codmwest.com", OBSERVED)
    assert p.ok is False
    assert p.covered_by == "codmwest.com"
    assert "codmwest.com" in _en(p.blockers)
    assert "fa" in p.blockers[0]


def test_refuses_exact_duplicate(deployment):
    p = dom.build_add_plan(str(deployment.domains), "sg.msdkfaas.com", OBSERVED)
    assert p.ok is False
    assert "already listed" in _en(p.blockers)


def test_refuses_non_hostnames(deployment):
    for bad in ["https://x.com/path", "x.com:443", "nodot", ""]:
        p = dom.build_add_plan(str(deployment.domains), bad, OBSERVED)
        assert p.ok is False, bad


def test_refuses_when_the_file_is_unreadable(tmp_path):
    p = dom.build_add_plan(str(tmp_path / "nope.txt"), "a.example.com")
    assert p.ok is False
    assert p.blockers


# --------------------------------------------------------------------------
# warnings
# --------------------------------------------------------------------------

def test_bare_root_warns_and_lists_observed_subdomains(deployment):
    p = dom.build_add_plan(str(deployment.domains), "newgame.net", OBSERVED)
    assert p.ok is True                      # allowed, but loudly
    text = _en(p.warnings)
    assert "bare root" in text
    assert "voice.newgame.net" in text       # what it would silently capture
    assert p.observed_subdomains == ["a.newgame.net", "b.newgame.net",
                                     "voice.newgame.net"]
    assert any("fa" in w for w in p.warnings)


def test_bare_root_with_nothing_observed_says_so(deployment):
    p = dom.build_add_plan(str(deployment.domains), "unseen.net", [])
    assert p.ok is True
    assert "cannot see what you are about to capture" in _en(p.warnings)


def test_warns_when_the_new_suffix_subsumes_existing_entries(deployment):
    deployment.domains.write_text("a.deep.example.org\nb.deep.example.org\n")
    p = dom.build_add_plan(str(deployment.domains), "deep.example.org", [])
    assert p.ok is True
    assert p.would_capture == ["a.deep.example.org", "b.deep.example.org"]
    assert "subsume" in _en(p.warnings)


def test_good_fqdn_has_no_warnings_but_still_carries_the_notes(deployment):
    p = dom.build_add_plan(str(deployment.domains), "dl.newgame.net", OBSERVED)
    assert p.ok is True
    assert p.warnings == []
    text = _en(p.notes)
    assert "SNI" in text                       # the TCP/SNI-only caveat
    assert "real failure" in text              # do not add speculatively
    assert "other server" in text              # keep the pair in sync


# --------------------------------------------------------------------------
# apply
# --------------------------------------------------------------------------

def test_apply_backs_up_writes_and_regenerates(deployment):
    before = deployment.domains.read_text()
    p = dom.build_add_plan(str(deployment.domains), "dl.newgame.net", OBSERVED,
                           comment="observed unproxied")
    r = dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                       str(deployment.update_script), [])
    assert r["ok"] is True
    steps = {s["name"]: s["ok"] for s in r["steps"]}
    assert steps["backup"] and steps["write"] and steps["update-script"]

    after = deployment.domains.read_text()
    assert "dl.newgame.net" in after
    assert "observed unproxied" in after      # the reason is recorded in-file
    backups = list(deployment.backups.iterdir())
    assert len(backups) == 1
    assert backups[0].read_text() == before   # untouched copy of the original


def test_what_you_confirmed_is_what_gets_written(deployment):
    p = dom.build_add_plan(str(deployment.domains), "dl.newgame.net", [],
                           comment="my reason")
    assert "my reason" in p.diff
    dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                   str(deployment.update_script), [])
    written = deployment.domains.read_text().splitlines()[-1]
    assert written in p.rendered
    assert "my reason" in written


def test_replay_is_refused_after_the_file_changes(deployment):
    p = dom.build_add_plan(str(deployment.domains), "dl.newgame.net", [])
    dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                   str(deployment.update_script), [])
    again = dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                           str(deployment.update_script), [])
    assert again["ok"] is False
    assert "en" in again["error"]
    assert "changed" in again["error"]["en"]


def test_failed_update_script_restores_the_backup(deployment, tmp_path):
    bad = tmp_path / "bad.sh"
    bad.write_text("#!/bin/sh\necho boom >&2\nexit 3\n")
    bad.chmod(0o755)
    before = deployment.domains.read_text()

    p = dom.build_add_plan(str(deployment.domains), "dl.newgame.net", [])
    r = dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                       str(bad), [])
    assert r["ok"] is False
    assert deployment.domains.read_text() == before      # rolled back
    assert any(s["name"] == "restore-backup" and s["ok"] for s in r["steps"])


def test_apply_refuses_a_plan_with_blockers(deployment):
    p = dom.build_add_plan(str(deployment.domains), "sg.msdkfaas.com", [])
    r = dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                       str(deployment.update_script), [])
    assert r["ok"] is False
    assert r["error"]["en"]


def test_restart_failure_is_reported_not_swallowed(deployment):
    """A regenerate without a restart leaves sniproxy serving the old table
    while the file on disk looks right. That must never look like success."""
    p = dom.build_add_plan(str(deployment.domains), "dl.newgame.net", [])
    r = dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                       str(deployment.update_script),
                       ["definitely-not-a-real-unit"])
    assert r["ok"] is False
    assert "en" in r["error"]
    assert any(not s["ok"] for s in r["steps"])


# --------------------------------------------------------------------------
# disable / restore
# --------------------------------------------------------------------------

def test_disable_comments_the_line_out(deployment):
    p = dom.build_disable_plan(str(deployment.domains), "example.com",
                               "broke voice chat")
    assert p.ok is True
    assert "DISABLED" in p.diff
    assert "broke voice chat" in p.diff
    dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                   str(deployment.update_script), [])
    text = deployment.domains.read_text()
    assert "# DISABLED" in text
    pf = dom.parse(str(deployment.domains))
    assert "example.com" not in pf.active     # no longer active
    assert "example.com" in text              # but still visible in the file


def test_disable_refuses_a_name_that_is_not_an_active_entry(deployment):
    p = dom.build_disable_plan(str(deployment.domains), "sub.codmwest.com")
    assert p.ok is False
    assert "codmwest.com" in _en(p.blockers)  # names what actually covers it


def test_restore_from_backup_round_trips(deployment):
    original = deployment.domains.read_text()
    p = dom.build_add_plan(str(deployment.domains), "dl.newgame.net", [])
    dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                   str(deployment.update_script), [])
    assert "dl.newgame.net" in deployment.domains.read_text()

    bk = dom.list_backups(str(deployment.backups))[-1]
    r = dom.restore_backup(bk["path"], str(deployment.domains),
                           str(deployment.backups),
                           str(deployment.update_script), [])
    assert r["ok"] is True
    assert deployment.domains.read_text() == original


def test_restore_refuses_paths_outside_the_backup_dir(deployment):
    r = dom.restore_backup("/etc/passwd", str(deployment.domains),
                           str(deployment.backups),
                           str(deployment.update_script), [])
    assert r["ok"] is False
    assert "outside" in r["error"]["en"]


def test_backup_diff_shows_the_change(deployment):
    p = dom.build_add_plan(str(deployment.domains), "dl.newgame.net", [])
    dom.apply_plan(p, str(deployment.domains), str(deployment.backups),
                   str(deployment.update_script), [])
    bk = dom.list_backups(str(deployment.backups))[0]
    d = dom.diff_backup(bk["path"], str(deployment.domains))
    assert "+dl.newgame.net" in d


# --------------------------------------------------------------------------
# plan store
# --------------------------------------------------------------------------

def test_plan_tokens_are_single_use():
    store = dom.PlanStore(ttl_s=300)
    p = dom.Plan(token="tok", action="add", target="a.com", ok=True)
    store.put(p)
    assert store.take("tok") is p
    assert store.take("tok") is None


def test_plans_expire():
    store = dom.PlanStore(ttl_s=0)
    p = dom.Plan(token="tok", action="add", target="a.com", ok=True)
    p.created = time.time() - 10
    store.put(p)
    assert store.take("tok") is None

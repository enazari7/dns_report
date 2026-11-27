"""Parser tests against the documented reference inputs.

These are the tests that matter most: every parser here reads a text format
produced by another program, and the formats are the part most likely to drift
between builds. Each case below is a literal line from a real deployment.
"""

from __future__ import annotations

import pytest

from smartdns_dash.sources import dnsdist as dd
from smartdns_dash.sources import domains as dom
from smartdns_dash.sources import portwatch as pw
from smartdns_dash.sources import sniproxy_log as slog

# --------------------------------------------------------------------------
# sniproxy access log
# --------------------------------------------------------------------------

REFERENCE_LINE = (
    "2026-08-02 15:17:14 84.241.45.220:39460 -> 172.20.46.2:443 -> "
    "129.226.1.156:443 [sg.msdkfaas.com] 4363/4363 bytes tx 1628/1628 "
    "bytes rx 0.751 seconds"
)


def test_reference_line_fields():
    r = slog.parse_line(REFERENCE_LINE)
    assert r is not None
    assert r["client_ip"] == "84.241.45.220"
    assert r["client_port"] == 39460
    assert r["listener_ip"] == "172.20.46.2"
    assert r["listener_port"] == 443
    assert r["origin_ip"] == "129.226.1.156"
    assert r["origin_port"] == 443
    assert r["sni"] == "sg.msdkfaas.com"
    assert r["bytes_tx"] == 4363
    assert r["bytes_rx"] == 1628
    assert r["duration"] == pytest.approx(0.751)
    assert r["problem"] is False


def test_byte_direction_aliases_follow_the_flag():
    """tx is origin->client, rx is client->origin. If that is ever proven
    backwards, flipping one constant must flip both aliases and nothing else."""
    r = slog.parse_line(REFERENCE_LINE)
    assert slog.TX_IS_FROM_ORIGIN is True
    assert r["from_origin"] == r["bytes_tx"]
    assert r["to_origin"] == r["bytes_rx"]


def test_origin_none_is_a_problem():
    line = ("2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443 -> NONE "
            "[x.example.com] 0/0 bytes tx 517/517 bytes rx 0.004 seconds")
    r = slog.parse_line(line)
    assert r["origin_ip"] == "NONE"
    assert r["origin_port"] is None
    assert r["origin_failed"] is True
    assert r["problem"] is True


def test_empty_sni_is_a_problem():
    line = ("2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443 -> NONE []"
            " 0/0 bytes tx 0/0 bytes rx 0.001 seconds")
    r = slog.parse_line(line)
    assert r["sni"] == ""
    assert r["no_sni"] is True
    assert r["problem"] is True


def test_http_log_line():
    line = ("2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:80 -> 5.6.7.8:80 "
            "[api.example.com] 120/120 bytes tx 90/90 bytes rx 0.030 seconds")
    r = slog.parse_line(line)
    assert r["listener_port"] == 80
    assert r["problem"] is False


def test_truncated_transfer_flagged():
    line = ("2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443 -> 5.6.7.8:443 "
            "[a.example.com] 100/4363 bytes tx 90/90 bytes rx 1.0 seconds")
    r = slog.parse_line(line)
    assert r["truncated"] is True
    assert r["bytes_tx"] == 100
    assert r["bytes_tx_total"] == 4363


@pytest.mark.parametrize("junk", [
    "", "   ", "garbage", "2026-08-02 not a log line",
    "2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443",
])
def test_junk_returns_none(junk):
    assert slog.parse_line(junk) is None


def test_sni_is_lowercased_and_dot_stripped():
    line = ("2026-08-02 15:17:14 1.2.3.4:1 -> 172.20.46.2:443 -> 5.6.7.8:443 "
            "[Api.Example.COM.] 1/1 bytes tx 1/1 bytes rx 0.1 seconds")
    assert slog.parse_line(line)["sni"] == "api.example.com"


# --------------------------------------------------------------------------
# tailer
# --------------------------------------------------------------------------

def _write(path, *lines):
    with open(path, "a", encoding="utf-8") as fh:
        for l in lines:
            fh.write(l + "\n")


def test_tailer_incremental_and_rotation(tmp_path):
    log = tmp_path / "https_access.log"
    log.write_text("")
    t = slog.Tailer(str(log), from_end=True)
    assert t.read_new() == []

    _write(log, REFERENCE_LINE)
    got = t.read_new()
    assert len(got) == 1 and got[0]["sni"] == "sg.msdkfaas.com"

    # logrotate: the file is renamed and a new one takes its place.
    log.rename(tmp_path / "https_access.log.1")
    (tmp_path / "https_access.log").write_text("")
    _write(log, REFERENCE_LINE.replace("sg.msdkfaas.com", "after-rotate.com"))
    got = t.read_new()
    assert [r["sni"] for r in got] == ["after-rotate.com"]


def test_tailer_truncation_in_place(tmp_path):
    """logrotate copytruncate: same inode, content replaced."""
    log = tmp_path / "a.log"
    log.write_text("")
    t = slog.Tailer(str(log), from_end=True)
    t.read_new()
    _write(log, REFERENCE_LINE)
    assert len(t.read_new()) == 1

    log.write_text("")  # truncate, same inode
    _write(log, REFERENCE_LINE.replace("sg.msdkfaas.com", "after-trunc.com"))
    assert [r["sni"] for r in t.read_new()] == ["after-trunc.com"]
    assert t.rotations == 1


def test_tailer_survives_same_size_copytruncate(tmp_path):
    """The nasty case: the replacement content is exactly as long as what it
    replaced, so neither the inode nor the size changes. Only a head
    fingerprint catches it."""
    log = tmp_path / "a.log"
    log.write_text("")
    t = slog.Tailer(str(log), from_end=True)
    t.read_new()

    first = REFERENCE_LINE
    second = REFERENCE_LINE.replace("sg.msdkfaas.com", "aaa.bbbbbbb.com")
    _write(log, first)
    assert len(t.read_new()) == 1
    before = log.stat().st_size

    log.write_text("")
    _write(log, second)
    assert log.stat().st_size == before, "test needs an identical size"
    assert [r["sni"] for r in t.read_new()] == ["aaa.bbbbbbb.com"]


def test_tailer_handles_partial_line(tmp_path):
    """A record read mid-write must be buffered, never parsed truncated."""
    log = tmp_path / "a.log"
    log.write_text("")
    t = slog.Tailer(str(log), from_end=True)
    t.read_new()                       # establish the follow position

    head, tail = REFERENCE_LINE[:40], REFERENCE_LINE[40:]
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(head)
    assert t.read_new() == []           # incomplete, buffered
    assert t.lines_unparsed == 0        # and NOT counted as a bad line
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(tail + "\n")
    got = t.read_new()
    assert len(got) == 1                # completed
    assert got[0]["sni"] == "sg.msdkfaas.com"


def test_tailer_skips_preexisting_content_by_design(tmp_path):
    """from_end=True is a live feed, not a backfill: what was already in the
    file when we opened it is not replayed. tail_last() is the history path."""
    log = tmp_path / "a.log"
    _write(log, REFERENCE_LINE)
    t = slog.Tailer(str(log), from_end=True)
    assert t.read_new() == []
    assert len(t.tail_last(10)) == 1


def test_tailer_missing_file_reports_error(tmp_path):
    t = slog.Tailer(str(tmp_path / "nope.log"))
    assert t.read_new() == []
    assert t.error


# --------------------------------------------------------------------------
# dnsdist grepq
# --------------------------------------------------------------------------

GREPQ = (
    "-407.8  84.241.45.220:60004                   32951 "
    "west-tdm.codmwest.com.  A   RD  Question\n"
    "-407.8  84.241.45.220:60004   8.8.4.4:53      32951 "
    "west-tdm.codmwest.com.  A   41.7  RD  No Error. 4 answers\n"
    "-12.1   84.241.45.220:51110                   1044 "
    "sg.msdkfaas.com.  A   RD  Question\n"
)


def test_grepq_column_shift():
    """Field 3 is the upstream only when it looks like ip:port; otherwise the
    row is a Question and everything shifts left by one."""
    rows = dd.parse_grepq(GREPQ)
    assert len(rows) == 3
    assert rows[0]["upstream"] is None
    assert rows[0]["name"] == "west-tdm.codmwest.com"
    assert rows[0]["qtype"] == "A"
    assert rows[0]["is_question"] is True
    assert rows[1]["upstream"] == "8.8.4.4:53"
    assert rows[1]["name"] == "west-tdm.codmwest.com"
    assert rows[1]["latency_ms"] == pytest.approx(41.7)
    assert rows[2]["name"] == "sg.msdkfaas.com"


def test_grepq_classification_is_the_documented_rule():
    """A name that went upstream at least once is NOT proxied, even though it
    also has a Question row with a blank upstream column."""
    c = dd.classify(dd.parse_grepq(GREPQ))
    assert [e["name"] for e in c["unproxied"]] == ["west-tdm.codmwest.com"]
    assert [e["name"] for e in c["proxied"]] == ["sg.msdkfaas.com"]


def test_grepq_ignores_headers_and_noise():
    rows = dd.parse_grepq("Time    Client   Server\nnot a row\n" + GREPQ)
    assert len(rows) == 3


def test_grepq_ipv6_client():
    row = dd.parse_grepq(
        "-1.0  [2001:db8::1]:5353   [2001:db8::2]:53   99 a.example.com.  A  "
        "1.0  RD  No Error. 1 answers\n")
    assert len(row) == 1
    assert row[0]["client_ip"] == "2001:db8::1"
    assert row[0]["upstream"] == "[2001:db8::2]:53"


def test_first_seen_survives_the_ring_ageing_out():
    tr = dd.FirstSeenTracker()
    tr.apply("1.1.1.1", [{"name": "a.com", "first_ts": 1000.0}])
    later = tr.apply("1.1.1.1", [{"name": "a.com", "first_ts": 2000.0}])
    assert later[0]["first_seen"] == 1000.0


def test_top_queries_parsing():
    out = dd.parse_top("1  example.com.  1234  12.3%\n2  b.example.com.  9  1%\n")
    assert out == [("example.com", 1234), ("b.example.com", 9)]


# --------------------------------------------------------------------------
# suffix matching
# --------------------------------------------------------------------------

@pytest.mark.parametrize("host,suffix,expected", [
    ("a.b.example.com", "example.com", True),
    ("example.com", "example.com", True),
    ("notexample.com", "example.com", False),
    ("example.com.evil.net", "example.com", False),
    ("west-gvoice.codmwest.com", "codmwest.com", True),
    ("EXAMPLE.com.", "example.com", True),
    ("", "example.com", False),
    ("example.com", "", False),
])
def test_suffix_matching(host, suffix, expected):
    assert dom.matches(host, suffix) is expected


@pytest.mark.parametrize("name,expected", [
    ("example.com", True),
    ("a.example.com", False),
    ("shop.co.uk", True),
    ("a.shop.co.uk", False),
    ("west-tdm.codmwest.com", False),
    ("site.co.ir", True),
])
def test_bare_root_detection(name, expected):
    assert dom.is_bare_root(name) is expected


@pytest.mark.parametrize("name,valid", [
    ("sg.msdkfaas.com", True),
    ("a-b.example.com", True),
    ("https://x.com/path", False),
    ("x.com:443", False),
    ("nodot", False),
    ("-bad.example.com", False),
    ("*.example.com", True),          # normalize() strips the wildcard
])
def test_hostname_validation(name, valid):
    assert dom.valid_hostname(dom.normalize(name)) is valid


def test_most_specific_suffix_wins(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text("codmwest.com\nwest-tdm.codmwest.com\n")
    pf = dom.parse(str(f))
    assert dom.match_suffix("west-tdm.codmwest.com", pf) == \
        "west-tdm.codmwest.com"
    assert dom.match_suffix("other.codmwest.com", pf) == "codmwest.com"


# --------------------------------------------------------------------------
# allow-list file parsing
# --------------------------------------------------------------------------

SAMPLE_FILE = """\
# a comment
sg.msdkfaas.com
west-tdm.codmwest.com   # inline comment
codmwest.com
sg.msdkfaas.com
not a hostname
# disabled.example.com

"""


def test_parse_file(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text(SAMPLE_FILE)
    pf = dom.parse(str(f))
    assert pf.error is None
    assert pf.active == ["sg.msdkfaas.com", "west-tdm.codmwest.com",
                         "codmwest.com"]
    assert pf.duplicates == [(5, "sg.msdkfaas.com")]
    assert len(pf.invalid) == 1
    assert pf.redundant() == [("west-tdm.codmwest.com", "codmwest.com")]
    # inline comment preserved for display
    entry = next(e for e in pf.entries if e.suffix == "west-tdm.codmwest.com")
    assert entry.comment == "inline comment"


def test_normalize_text_is_canonical():
    a = dom.normalize_text("B.com\na.com # note\n\n# off\nA.COM.\n")
    assert a == ["a.com", "b.com"]


def test_diff_lists_carries_bilingual_message():
    d = dom.diff_lists(["a.com"], ["b.com"], "one", "two")
    assert d["only_mine"] == ["a.com"]
    assert d["only_theirs"] == ["b.com"]
    assert d["in_sync"] is False
    assert "en" in d["message"] and "fa" in d["message"]


# --------------------------------------------------------------------------
# portwatch
# --------------------------------------------------------------------------

@pytest.mark.parametrize("line,src,dport,flags", [
    ("15:17:14.123456 IP 84.241.45.220.39460 > 172.20.46.2.8080: "
     "Flags [S], seq 1, win 64240, length 0", "84.241.45.220", 8080, "S"),
    ("15:17:14.223456 IP 172.20.46.2.8080 > 84.241.45.220.39460: "
     "Flags [S.], seq 2, ack 2, win 65160, length 0", "172.20.46.2", 39460,
     "S."),
    ("15:17:14.323456 eth0  In  IP 84.241.45.220.39461 > 1.2.3.4.8085: "
     "Flags [S], seq 1, win 64240, length 0", "84.241.45.220", 8085, "S"),
])
def test_tcpdump_line_shapes(line, src, dport, flags):
    m = pw.LINE_RE.match(line)
    assert m is not None
    assert m.group("src") == src
    assert int(m.group("dport")) == dport
    assert m.group("flags") == flags


def test_bpf_filter_rejects_injection():
    with pytest.raises(ValueError):
        pw.build_filter("1.2.3.4 or 1=1", [53])


def test_bpf_filter_shape():
    f = pw.build_filter("1.2.3.4", [53, 80, 443])
    assert "host 1.2.3.4" in f
    assert "not port 443" in f
    assert f.startswith("tcp[tcpflags] & tcp-syn != 0")


def test_unanswered_syn_is_reported_with_a_verdict():
    w = pw.PortWatcher(timeout_s=0)
    w._handle("15:17:14.1 IP 1.1.1.1.100 > 2.2.2.2.8080: Flags [S], length 0")
    w._handle("15:17:14.2 IP 1.1.1.1.101 > 2.2.2.2.9999: Flags [S], length 0")
    w._handle("15:17:14.3 IP 2.2.2.2.9999 > 1.1.1.1.101: Flags [S.], length 0")
    snap = w.snapshot()
    rows = {r["dport"]: r for r in snap["rows"]}
    assert rows[8080]["unanswered"] == 1
    assert "8080" in rows[8080]["verdict"]["en"]
    assert "fa" in rows[8080]["verdict"]
    assert 9999 not in rows          # answered, so never reported

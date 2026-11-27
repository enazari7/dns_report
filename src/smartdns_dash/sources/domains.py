"""The allow-list: parsing, suffix matching, and guarded mutation.

Every active line in /etc/smartdns/domains.txt is a **domain suffix**. It
matches the root and every subdomain: ``example.com`` matches
``a.b.example.com``. Listed names get their A record spoofed to this server's
public IP; AAAA/HTTPS/SVCB are suppressed; the client then connects on 80/443
and sniproxy reads the SNI to find the real destination.

There is no exclude syntax. To proxy ``a.example.com`` but not
``b.example.com`` you must list the exact FQDN and never the root.

Adding a line is not free. It means "send this through the UAE", and for
anything already reachable directly from Iran that is a regression. Two
failure modes are known to be unfixable by proxying:

  (a) protocols with no SNI and no Host header - the CODM downloader speaks a
      binary Tencent GCloud protocol on TCP 8080/8085/8013. Proxying it makes
      the game open but never download.
  (b) UDP services - sniproxy is TCP-only. Proxying ``*.west-gvoice.
      codmwest.com`` killed voice chat entirely.

So this module never adds anything on its own. It builds a *plan*, surfaces
every reason the plan might be wrong, and requires an explicit confirmation
token to act. Choosing what to add stays a human decision.
"""

from __future__ import annotations

import difflib
import os
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .. import i18n

# Group markers. domains.txt stays the single source of truth - a group is a
# comment convention inside it, not a second file that can drift out of sync.
#
#   # @group codm            <- everything below belongs to "codm"
#   west-tdm.codmwest.com
#   # @endgroup
#
#   sg.msdkfaas.com  # @group codm     <- or tag one line inline
#
# A line commented out by the dashboard keeps its marker, so disabling a group
# and re-enabling it round-trips.
GROUP_OPEN_RE = re.compile(r"^\s*#\s*@group\s+([A-Za-z0-9._\-]{1,40})\s*$")
GROUP_CLOSE_RE = re.compile(r"^\s*#\s*@endgroup\s*$")
GROUP_INLINE_RE = re.compile(r"@group\s+([A-Za-z0-9._\-]{1,40})")

# What the dashboard writes when it comments a line out:
#
#   # DISABLED via dashboard 2026-08-03 22:49:22 - reason | original line
#
# The metadata and the original line are separated by "|", not ":", because the
# timestamp contains colons and so may the reason - a colon delimiter cannot be
# unambiguously undone. "|" is stripped from reasons on the way in, so it can
# only ever appear as the delimiter.
DISABLED_PREFIX = "# DISABLED via dashboard"
DISABLED_DELIM = " | "
DISABLED_RE = re.compile(r"^\s*#\s*DISABLED via dashboard[^|]*\|\s?(.*)$")

# Lines written by earlier versions used ":" as the delimiter. Greedy up to the
# last ": " so an existing file still round-trips instead of the entry looking
# permanently gone.
DISABLED_LEGACY_RE = re.compile(
    r"^\s*#\s*DISABLED via dashboard.*?: (?P<orig>[^:]*)$")


def _clean_reason(reason: str) -> str:
    """Free text safe to embed in a marker: no newline, no '#', no '|'."""
    return (reason.strip().replace("\n", " ").replace("#", "")
            .replace("|", "/")[:120].strip())


def _undisable(line: str) -> str | None:
    """Recover the original line from a disabled one, or None."""
    m = DISABLED_RE.match(line)
    if m:
        return m.group(1)
    m = DISABLED_LEGACY_RE.match(line)
    if m:
        return m.group("orig")
    return None

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")

# Two-label names under these are still effectively a registry suffix, so
# "shop.co.uk" is a root, not an FQDN. Not a full PSL - just the ones likely to
# show up here. A miss only costs an extra warning, never a wrong write.
MULTI_LABEL_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp",
    "com.cn", "net.cn", "org.cn", "com.br", "com.au", "net.au", "com.tr",
    "co.kr", "com.hk", "com.tw", "com.sg", "co.in", "co.ir", "ac.ir",
}


@dataclass
class Entry:
    lineno: int
    suffix: str            # normalized, lowercase, no trailing dot
    raw: str               # original line including any comment
    comment: str = ""
    group: str = ""        # from a @group marker, "" if ungrouped


@dataclass
class ParsedFile:
    path: str
    lines: list[str] = field(default_factory=list)   # raw, no trailing newline
    entries: list[Entry] = field(default_factory=list)
    duplicates: list[tuple[int, str]] = field(default_factory=list)
    invalid: list[tuple[int, str]] = field(default_factory=list)
    # Lines the dashboard has commented out. Tracked so a group can be
    # re-enabled, and so the UI can show what is switched off rather than gone.
    disabled: list[Entry] = field(default_factory=list)
    mtime: float = 0.0
    error: str | None = None

    @property
    def active(self) -> list[str]:
        return [e.suffix for e in self.entries]

    def normalized(self) -> list[str]:
        """Sorted, deduped, lowercased - the canonical form for the
        two-server diff."""
        return sorted(set(self.active))

    def groups(self) -> list[dict]:
        """Every group present in the file, with counts.

        Disabled entries count too: a group that is entirely switched off must
        still be visible, or there is no way to switch it back on.
        """
        names = {e.group for e in self.entries if e.group}
        names |= {e.group for e in self.disabled if e.group}
        out = []
        for name in sorted(names):
            active = [e.suffix for e in self.entries if e.group == name]
            off = [e.suffix for e in self.disabled if e.group == name]
            out.append({
                "name": name,
                "active": sorted(active),
                "disabled": sorted(off),
                "active_count": len(active),
                "disabled_count": len(off),
                "state": ("on" if active and not off else
                          "off" if off and not active else "mixed"),
            })
        return out

    def group_entries(self, group: str) -> tuple[list[Entry], list[Entry]]:
        """(active, disabled) entries belonging to a group."""
        return ([e for e in self.entries if e.group == group],
                [e for e in self.disabled if e.group == group])

    def ungrouped_count(self) -> int:
        return len([e for e in self.entries if not e.group])

    def redundant(self) -> list[tuple[str, str]]:
        """(entry, covering_suffix) for entries already covered by a shorter
        suffix in the same file. Harmless but noisy."""
        out = []
        pool = set(self.active)
        for s in sorted(pool):
            cover = _match_in(s, pool - {s})
            if cover:
                out.append((s, cover))
        return out


def normalize(name: str) -> str:
    name = (name or "").strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return name


def valid_hostname(name: str) -> bool:
    if not name or "." not in name:
        return False
    if len(name) > 253:
        return False
    return bool(HOSTNAME_RE.match(name))


def matches(host: str, suffix: str) -> bool:
    """A suffix matches its own root and every subdomain of it."""
    host = normalize(host)
    suffix = normalize(suffix)
    if not host or not suffix:
        return False
    return host == suffix or host.endswith("." + suffix)


def _match_in(host: str, suffixes: Iterable[str]) -> str | None:
    """Return the most specific (longest) matching suffix, or None."""
    best = None
    for s in suffixes:
        if matches(host, s) and (best is None or len(s) > len(best)):
            best = s
    return best


def match_suffix(host: str, parsed: ParsedFile) -> str | None:
    return _match_in(host, parsed.active)


def registrable_depth(name: str) -> int:
    """Labels beyond the registry suffix. 1 => a bare root like example.com."""
    labels = name.split(".")
    for tld in MULTI_LABEL_TLDS:
        if name.endswith("." + tld):
            return len(labels) - len(tld.split("."))
    return len(labels) - 1


def is_bare_root(name: str) -> bool:
    return registrable_depth(name) <= 1


def parse(path: str) -> ParsedFile:
    pf = ParsedFile(path=path)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        pf.mtime = os.path.getmtime(path)
    except OSError as exc:
        pf.error = f"{path}: {exc.strerror or exc}"
        return pf

    pf.lines = content.split("\n")
    if pf.lines and pf.lines[-1] == "":
        pf.lines.pop()

    seen: dict[str, int] = {}
    current_group = ""

    for i, raw in enumerate(pf.lines, start=1):
        # Group markers are comments, so they must be examined before the
        # comment stripping below throws them away.
        m = GROUP_OPEN_RE.match(raw)
        if m:
            current_group = m.group(1).lower()
            continue
        if GROUP_CLOSE_RE.match(raw):
            current_group = ""
            continue

        # A line the dashboard commented out. Recorded rather than ignored so
        # the UI can show it as switched off, and so a group round-trips.
        inner = _undisable(raw)
        if inner is not None:
            inner_code, inner_sep, inner_comment = inner.partition("#")
            suffix = normalize(inner_code.strip())
            if valid_hostname(suffix):
                grp = current_group
                if inner_sep:
                    gm = GROUP_INLINE_RE.search(inner_comment)
                    if gm:
                        grp = gm.group(1).lower()
                pf.disabled.append(Entry(
                    lineno=i, suffix=suffix, raw=raw,
                    comment=(inner_comment.strip() if inner_sep else ""),
                    group=grp))
            continue

        code, sep, comment = raw.partition("#")
        code = code.strip()
        if not code:
            continue
        suffix = normalize(code)
        if not valid_hostname(suffix):
            pf.invalid.append((i, raw))
            continue
        if suffix in seen:
            pf.duplicates.append((i, suffix))
            continue
        seen[suffix] = i

        group = current_group
        if sep:
            gm = GROUP_INLINE_RE.search(comment)
            if gm:
                group = gm.group(1).lower()
        pf.entries.append(Entry(lineno=i, suffix=suffix, raw=raw,
                                comment=(comment.strip() if sep else ""),
                                group=group))
    return pf


def normalize_text(text: str) -> list[str]:
    """Normalize a pasted domains.txt into the canonical comparison form.
    Strip inline comments and whitespace, lowercase, sort, dedupe."""
    out = set()
    for raw in text.splitlines():
        code = raw.partition("#")[0].strip()
        if not code:
            continue
        s = normalize(code)
        if valid_hostname(s):
            out.add(s)
    return sorted(out)


# ----------------------------------------------------------------------
# Guarded mutation
# ----------------------------------------------------------------------

@dataclass
class Plan:
    token: str
    action: str                       # "add" | "disable"
    target: str
    ok: bool
    # Each entry is an i18n message dict: {"en": ..., "fa": ...}
    blockers: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    diff: str = ""
    observed_subdomains: list[str] = field(default_factory=list)
    covered_by: str | None = None
    would_capture: list[str] = field(default_factory=list)
    created: float = field(default_factory=time.time)
    file_mtime: float = 0.0
    # Exact file content the preview was generated from. Applied verbatim so
    # what you confirmed is byte-for-byte what gets written.
    rendered: str = ""

    def to_dict(self) -> dict:
        return {
            "token": self.token, "action": self.action, "target": self.target,
            "ok": self.ok, "blockers": self.blockers,
            "warnings": self.warnings, "notes": self.notes, "diff": self.diff,
            "observed_subdomains": self.observed_subdomains,
            "covered_by": self.covered_by,
            "would_capture": self.would_capture,
            "created": self.created,
        }


class PlanStore:
    """Short-lived plans. A plan is single-use and expires, so a stale browser
    tab cannot replay a write."""

    def __init__(self, ttl_s: int = 300):
        self.ttl_s = ttl_s
        self._plans: dict[str, Plan] = {}

    def put(self, plan: Plan) -> None:
        self._sweep()
        self._plans[plan.token] = plan

    def take(self, token: str) -> Plan | None:
        self._sweep()
        return self._plans.pop(token, None)

    def _sweep(self) -> None:
        cutoff = time.time() - self.ttl_s
        for k in [k for k, v in self._plans.items() if v.created < cutoff]:
            self._plans.pop(k, None)


def build_add_plan(path: str, candidate: str,
                   observed_names: Sequence[str] = (),
                   comment: str = "") -> Plan:
    """Assemble everything a human needs to decide, and refuse outright when
    the write would be pointless or clearly wrong."""
    target = normalize(candidate)
    plan = Plan(token=secrets.token_urlsafe(18), action="add", target=target,
                ok=False)

    if not target:
        plan.blockers.append(i18n.empty_domain())
        return plan
    if not valid_hostname(target):
        plan.blockers.append(i18n.invalid_hostname(target))
        return plan

    pf = parse(path)
    if pf.error:
        plan.blockers.append(i18n.plain(pf.error))
        return plan
    plan.file_mtime = pf.mtime

    # Guard 1: already covered.
    cover = match_suffix(target, pf)
    if cover:
        plan.covered_by = cover
        if cover == target:
            plan.blockers.append(i18n.already_listed(target))
        else:
            plan.blockers.append(i18n.already_covered(target, cover))
        return plan

    observed = sorted({normalize(n) for n in observed_names if normalize(n)})

    # Guard 2: bare root. This is the dangerous one - a root silently captures
    # every subdomain, including UDP and non-SNI services.
    subs = [n for n in observed if n != target and matches(n, target)]
    plan.observed_subdomains = subs
    if is_bare_root(target):
        plan.warnings.append(i18n.bare_root_warning(target, subs))
        plan.warnings.append(i18n.safer_alternative(target))

    # Guard 3: entries this new suffix would make redundant.
    captured = sorted(s for s in pf.active if s != target and matches(s, target))
    plan.would_capture = captured
    if captured:
        plan.warnings.append(i18n.subsumes(target, captured))

    # Informational notes.
    plan.notes.append(i18n.SNI_ONLY)
    plan.notes.append(i18n.OBSERVE_FIRST)
    plan.notes.append(i18n.MIRROR_PEER)

    new_lines = list(pf.lines)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    suffix_comment = f"  # added via dashboard {stamp}"
    if comment.strip():
        clean = comment.strip().replace("\n", " ").replace("#", "")
        suffix_comment += f" - {clean[:120]}"
    new_lines.append(target + suffix_comment)

    plan.diff = "".join(difflib.unified_diff(
        [l + "\n" for l in pf.lines],
        [l + "\n" for l in new_lines],
        fromfile=f"a{path}", tofile=f"b{path}", n=3))
    plan.rendered = "\n".join(new_lines) + "\n"
    plan.ok = True
    return plan


def build_disable_plan(path: str, target: str, reason: str = "") -> Plan:
    """Comment a suffix out. This is the recovery path when a recent addition
    breaks something - faster and safer than deleting the line."""
    target = normalize(target)
    plan = Plan(token=secrets.token_urlsafe(18), action="disable",
                target=target, ok=False)
    pf = parse(path)
    if pf.error:
        plan.blockers.append(i18n.plain(pf.error))
        return plan
    plan.file_mtime = pf.mtime

    hits = [e for e in pf.entries if e.suffix == target]
    if not hits:
        plan.blockers.append(
            i18n.not_active_entry(target, match_suffix(target, pf)))
        return plan

    new_lines = list(pf.lines)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    tag = f"{DISABLED_PREFIX} {stamp}"
    if reason.strip():
        tag += " - " + _clean_reason(reason)
    for e in hits:
        new_lines[e.lineno - 1] = (
            f"{tag}{DISABLED_DELIM}{pf.lines[e.lineno - 1]}")

    plan.diff = "".join(difflib.unified_diff(
        [l + "\n" for l in pf.lines],
        [l + "\n" for l in new_lines],
        fromfile=f"a{path}", tofile=f"b{path}", n=3))
    plan.rendered = "\n".join(new_lines) + "\n"
    plan.notes.append(i18n.DISABLE_NOTE)
    plan.ok = True
    return plan


# ----------------------------------------------------------------------
def build_enable_plan(path: str, target: str, reason: str = "") -> Plan:
    """Uncomment a line the dashboard previously disabled.

    The inverse of build_disable_plan, so a change made in a hurry during an
    outage can be undone in a hurry too.
    """
    target = normalize(target)
    plan = Plan(token=secrets.token_urlsafe(18), action="enable",
                target=target, ok=False)
    pf = parse(path)
    if pf.error:
        plan.blockers.append(i18n.plain(pf.error))
        return plan
    plan.file_mtime = pf.mtime

    hits = [e for e in pf.disabled if e.suffix == target]
    if not hits:
        if any(e.suffix == target for e in pf.entries):
            plan.blockers.append(i18n.already_listed(target))
        else:
            plan.blockers.append(i18n.not_disabled(target))
        return plan

    new_lines = list(pf.lines)
    for e in hits:
        orig = _undisable(new_lines[e.lineno - 1])
        if orig is not None:
            new_lines[e.lineno - 1] = orig

    plan.diff = "".join(difflib.unified_diff(
        [line + "\n" for line in pf.lines],
        [line + "\n" for line in new_lines],
        fromfile=f"a{path}", tofile=f"b{path}", n=3))
    plan.rendered = "\n".join(new_lines) + "\n"
    plan.notes.append(i18n.SNI_ONLY)
    plan.notes.append(i18n.MIRROR_PEER)
    plan.ok = True
    return plan


def build_group_plan(path: str, group: str, action: str,
                     reason: str = "") -> Plan:
    """Switch a whole group on or off in one guarded change.

    Groups exist because a game is several hostnames, and when one of them
    turns out to be the wrong thing to proxy you want to back out the whole
    set, not hunt for the lines. The write goes through exactly the same
    backup / diff / typed-confirmation / mandatory-restart path as a single
    domain.
    """
    group = (group or "").strip().lower()
    plan = Plan(token=secrets.token_urlsafe(18),
                action=f"group-{action}", target=group, ok=False)
    if action not in ("disable", "enable"):
        plan.blockers.append(i18n.plain(f"unknown group action {action!r}"))
        return plan
    if not group:
        plan.blockers.append(i18n.no_group_named())
        return plan

    pf = parse(path)
    if pf.error:
        plan.blockers.append(i18n.plain(pf.error))
        return plan
    plan.file_mtime = pf.mtime

    active, disabled = pf.group_entries(group)
    if not active and not disabled:
        plan.blockers.append(i18n.group_not_found(
            group, [g["name"] for g in pf.groups() if g["name"]]))
        return plan

    new_lines = list(pf.lines)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    touched: list[str] = []

    if action == "disable":
        if not active:
            plan.blockers.append(i18n.group_already_off(group))
            return plan
        tag = f"{DISABLED_PREFIX} {stamp}"
        if reason.strip():
            tag += " - " + _clean_reason(reason)
        for e in active:
            new_lines[e.lineno - 1] = (
                f"{tag}{DISABLED_DELIM}{pf.lines[e.lineno - 1]}")
            touched.append(e.suffix)
        plan.warnings.append(i18n.group_disable_warning(group, len(touched)))
    else:
        if not disabled:
            plan.blockers.append(i18n.group_already_on(group))
            return plan
        for e in disabled:
            orig = _undisable(new_lines[e.lineno - 1])
            if orig is not None:
                new_lines[e.lineno - 1] = orig
                touched.append(e.suffix)
        plan.warnings.append(i18n.group_enable_warning(group, len(touched)))

    plan.would_capture = sorted(touched)
    plan.diff = "".join(difflib.unified_diff(
        [line + "\n" for line in pf.lines],
        [line + "\n" for line in new_lines],
        fromfile=f"a{path}", tofile=f"b{path}", n=3))
    plan.rendered = "\n".join(new_lines) + "\n"
    plan.notes.append(i18n.MIRROR_PEER)
    plan.ok = bool(touched)
    if not plan.ok:
        plan.blockers.append(i18n.plain("nothing to change"))
    return plan


def build_tag_plan(path: str, target: str, group: str) -> Plan:
    """Move an existing entry into a group by adding an inline marker.

    Editing the comment rather than reordering lines keeps the diff to one
    line and the file's history readable.
    """
    target = normalize(target)
    group = (group or "").strip().lower()
    plan = Plan(token=secrets.token_urlsafe(18), action="tag",
                target=target, ok=False)
    if group and not re.fullmatch(r"[a-z0-9._\-]{1,40}", group):
        plan.blockers.append(i18n.bad_group_name(group))
        return plan

    pf = parse(path)
    if pf.error:
        plan.blockers.append(i18n.plain(pf.error))
        return plan
    plan.file_mtime = pf.mtime

    hits = [e for e in pf.entries if e.suffix == target]
    if not hits:
        plan.blockers.append(i18n.not_active_entry(
            target, match_suffix(target, pf)))
        return plan

    new_lines = list(pf.lines)
    for e in hits:
        line = new_lines[e.lineno - 1]
        code, sep, comment = line.partition("#")
        comment = GROUP_INLINE_RE.sub("", comment).strip() if sep else ""
        if group:
            comment = (comment + " " if comment else "") + f"@group {group}"
        new_lines[e.lineno - 1] = (
            f"{code.rstrip()}  # {comment}".rstrip() if comment
            else code.rstrip())

    plan.diff = "".join(difflib.unified_diff(
        [line + "\n" for line in pf.lines],
        [line + "\n" for line in new_lines],
        fromfile=f"a{path}", tofile=f"b{path}", n=3))
    plan.rendered = "\n".join(new_lines) + "\n"
    plan.notes.append(i18n.tag_note(target, group))
    plan.ok = True
    return plan


def backup(path: str, backup_dir: str) -> str:
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = os.path.basename(path)
    dest = os.path.join(backup_dir, f"{base}.{stamp}")
    n = 0
    while os.path.exists(dest):
        n += 1
        dest = os.path.join(backup_dir, f"{base}.{stamp}.{n}")
    shutil.copy2(path, dest)
    return dest


def list_backups(backup_dir: str, base: str = "domains.txt") -> list[dict]:
    try:
        names = os.listdir(backup_dir)
    except OSError:
        return []
    out = []
    for n in names:
        if not n.startswith(base):
            continue
        full = os.path.join(backup_dir, n)
        try:
            st = os.stat(full)
        except OSError:
            continue
        if not os.path.isfile(full):
            continue
        out.append({"name": n, "path": full, "mtime": st.st_mtime,
                    "size": st.st_size})
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return out


def diff_backup(backup_path: str, current_path: str) -> str:
    try:
        with open(backup_path, encoding="utf-8", errors="replace") as fh:
            old = fh.readlines()
        with open(current_path, encoding="utf-8", errors="replace") as fh:
            new = fh.readlines()
    except OSError as exc:
        return f"error: {exc}"
    return "".join(difflib.unified_diff(
        old, new, fromfile=os.path.basename(backup_path),
        tofile="current " + os.path.basename(current_path), n=3))


def apply_plan(plan: Plan, path: str, backup_dir: str,
               update_script: str, restart_units: Sequence[str],
               timeout: int = 120) -> dict:
    """Write, regenerate, restart. Never regenerate without restarting.

    sniproxy reads its config only at startup. Regenerating without a restart
    leaves the stale routing table live in memory while the file on disk looks
    correct - a failure mode that cost an entire debugging session.
    """
    result = {"ok": False, "steps": [], "backup": None, "error": None}

    def step(name, ok, detail=""):
        result["steps"].append({"name": name, "ok": bool(ok),
                                "detail": detail[-4000:]})

    if not plan.ok:
        result["error"] = i18n.apply_blocked()
        return result

    # Refuse if the file changed since the plan was built.
    try:
        current_mtime = os.path.getmtime(path)
    except OSError as exc:
        result["error"] = i18n.plain(f"cannot stat {path}: {exc}")
        return result
    if plan.file_mtime and abs(current_mtime - plan.file_mtime) > 0.001:
        result["error"] = i18n.file_changed()
        return result

    try:
        bak = backup(path, backup_dir)
        result["backup"] = bak
        step("backup", True, bak)
    except OSError as exc:
        result["error"] = i18n.backup_failed(str(exc))
        step("backup", False, str(exc))
        return result

    # Rebuild the new content from the plan's diff target rather than trusting
    # a cached copy: re-derive it the same way build_*_plan did.
    try:
        new_content = _rebuild(plan, path)
    except Exception as exc:  # noqa: BLE001 - surfaced to the user
        result["error"] = i18n.plain(f"could not rebuild file content: {exc}")
        step("write", False, str(exc))
        return result

    try:
        _atomic_write(path, new_content)
        step("write", True, f"{len(new_content.splitlines())} lines")
    except OSError as exc:
        result["error"] = i18n.plain(f"write failed: {exc}")
        step("write", False, str(exc))
        _restore(bak, path, result)
        return result

    # Regenerate.
    rc, out = _run([update_script], timeout)
    step("update-script", rc == 0, out)
    if rc != 0:
        result["error"] = i18n.script_failed(update_script, rc)
        _restore(bak, path, result)
        _run([update_script], timeout)
        return result

    # Restart - mandatory, not optional.
    for unit in restart_units:
        rc, out = _run(["systemctl", "restart", unit], timeout)
        step(f"restart {unit}", rc == 0, out)
        if rc != 0:
            result["error"] = i18n.restart_failed(unit)
            return result

    result["ok"] = True
    return result


def _rebuild(plan: Plan, path: str) -> str:
    """Return exactly the content the preview showed.

    apply_plan has already verified the file has not changed since the plan
    was built, so replaying the stored render is both safe and guarantees that
    what you confirmed in the diff is what lands on disk.
    """
    if not plan.rendered:
        raise ValueError("plan carries no rendered content - re-run preview")
    if plan.action not in ("add", "disable", "enable", "tag",
                           "group-disable", "group-enable"):
        raise ValueError(f"unknown action {plan.action!r}")
    return plan.rendered


def _atomic_write(path: str, content: str) -> None:
    tmp = f"{path}.dash.tmp"
    st = None
    try:
        st = os.stat(path)
    except OSError:
        pass
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    if st is not None:
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except (OSError, AttributeError):
            pass
    os.replace(tmp, path)


def _restore(bak: str, path: str, result: dict) -> None:
    try:
        shutil.copy2(bak, path)
        result["steps"].append({"name": "restore-backup", "ok": True,
                                "detail": bak})
    except OSError as exc:
        result["steps"].append({"name": "restore-backup", "ok": False,
                                "detail": str(exc)})


def restore_backup(backup_path: str, path: str, backup_dir: str,
                   update_script: str, restart_units: Sequence[str],
                   timeout: int = 120) -> dict:
    """Restore a backup over the live file, then regenerate and restart."""
    result = {"ok": False, "steps": [], "backup": None, "error": None}
    real_backup_dir = os.path.realpath(backup_dir)
    real_target = os.path.realpath(backup_path)
    if os.path.commonpath([real_backup_dir, real_target]) != real_backup_dir:
        result["error"] = i18n.plain("refusing to restore from outside the backup dir")
        return result
    if not os.path.isfile(real_target):
        result["error"] = i18n.plain("backup file not found")
        return result
    try:
        pre = backup(path, backup_dir)
        result["backup"] = pre
        result["steps"].append({"name": "backup-current", "ok": True,
                                "detail": pre})
        shutil.copy2(real_target, path)
        result["steps"].append({"name": "restore", "ok": True,
                                "detail": real_target})
    except OSError as exc:
        result["error"] = i18n.plain(str(exc))
        return result

    rc, out = _run([update_script], timeout)
    result["steps"].append({"name": "update-script", "ok": rc == 0,
                            "detail": out[-4000:]})
    if rc != 0:
        result["error"] = i18n.plain(f"{update_script} exited {rc}")
        return result
    for unit in restart_units:
        rc, out = _run(["systemctl", "restart", unit], timeout)
        result["steps"].append({"name": f"restart {unit}", "ok": rc == 0,
                                "detail": out[-4000:]})
        if rc != 0:
            result["error"] = i18n.restart_failed(unit)
            return result
    result["ok"] = True
    return result


def _run(cmd: Sequence[str], timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(list(cmd), capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError:
        return 127, f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, f"{cmd[0]}: timed out after {timeout}s"
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def diff_lists(mine: Sequence[str], theirs: Sequence[str],
               my_name: str = "this", their_name: str = "peer") -> dict:
    a, b = set(mine), set(theirs)
    only_mine, only_theirs = sorted(a - b), sorted(b - a)
    return {
        "only_mine": only_mine,
        "only_theirs": only_theirs,
        "both": sorted(a & b),
        "my_name": my_name,
        "their_name": their_name,
        "in_sync": a == b,
        "message": (i18n.peer_in_sync() if a == b else
                    i18n.peer_diverged(len(only_mine), len(only_theirs),
                                       my_name, their_name)),
    }


def selftest(path: str) -> int:
    print("--- suffix matching ---")
    cases = [
        ("a.b.example.com", "example.com", True),
        ("example.com", "example.com", True),
        ("notexample.com", "example.com", False),
        ("example.com.evil.net", "example.com", False),
        ("west-gvoice.codmwest.com", "codmwest.com", True),
    ]
    bad = 0
    for host, suf, want in cases:
        got = matches(host, suf)
        flag = "ok " if got == want else "FAIL"
        if got != want:
            bad += 1
        print(f"  {flag} matches({host!r}, {suf!r}) = {got}")

    print("\n--- bare-root detection ---")
    for name, want in [("example.com", True), ("a.example.com", False),
                       ("shop.co.uk", True), ("a.shop.co.uk", False),
                       ("west-tdm.codmwest.com", False)]:
        got = is_bare_root(name)
        flag = "ok " if got == want else "FAIL"
        if got != want:
            bad += 1
        print(f"  {flag} is_bare_root({name!r}) = {got}")

    print(f"\n--- {path} ---")
    pf = parse(path)
    if pf.error:
        print(f"  error: {pf.error}")
        return 1
    print(f"  {len(pf.entries)} active entries, "
          f"{len(pf.duplicates)} duplicates, {len(pf.invalid)} invalid")
    for lineno, s in pf.duplicates[:10]:
        print(f"    duplicate line {lineno}: {s}")
    for lineno, raw in pf.invalid[:10]:
        print(f"    invalid  line {lineno}: {raw!r}")
    red = pf.redundant()
    if red:
        print(f"  {len(red)} redundant entries (already covered):")
        for s, cover in red[:10]:
            print(f"    {s}  <- covered by {cover}")
    print("  first 10 active:", pf.normalized()[:10])
    return 1 if bad else 0

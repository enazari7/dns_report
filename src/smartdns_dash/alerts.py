"""Alert rules and the notifier interface.

Everything stays inside the dashboard for now: conditions are detected, opened
and closed in the store, and shown in the Events panel with a badge in the
header. Nothing is sent anywhere.

The notifier layer exists so that attaching Telegram later is a new subclass and
a config section, with no change to the rules. `LogNotifier` is the default and
writes to the journal, which means the delivery path is exercised from day one
instead of being written blind when it is first needed.

Rule design: each rule returns a fingerprint plus a bilingual detail when its
condition is true, and nothing when it is not. The store collapses a continuing
condition into one event with a duration, so a service down for an hour is one
row rather than one per poll. That is what makes "when did this start?"
answerable.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from . import i18n
from .i18n import M

log = logging.getLogger("smartdns_dash.alerts")

SEVERITIES = ("critical", "warning", "info")


@dataclass
class Finding:
    """One condition, currently true."""
    fingerprint: str
    kind: str
    severity: str
    subject: str
    detail: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def rule_services_down(status: dict) -> list[Finding]:
    out = []
    for sv in status.get("services") or []:
        unit = sv.get("unit", "?")
        if sv.get("healthy"):
            continue
        state = f"{sv.get('active_state', '?')}/{sv.get('sub_state', '')}"
        out.append(Finding(
            fingerprint=f"service:{unit}:down",
            kind="service", severity="critical", subject=unit,
            detail=M(f"{unit} is not running ({state}). Clients depending on it "
                     "are failing right now.",
                     f"سرویس {unit} در حال اجرا نیست ({state}). کلاینت‌هایی که به "
                     "آن وابسته‌اند همین حالا خطا می‌گیرند.")))
    return out


def rule_config_stale(status: dict) -> list[Finding]:
    st = status.get("staleness") or {}
    if not st.get("stale"):
        return []
    unit = st.get("unit", "?")
    lag = int(st.get("lag_s") or 0)
    mins = max(1, lag // 60)
    return [Finding(
        fingerprint=f"stale:{unit}",
        kind="config", severity="warning", subject=unit,
        detail=M(f"{unit} has been serving a config older than the files on "
                 f"disk for {mins} minute(s). Regenerate and restart, or the "
                 "allow-list you are looking at is not the one in effect.",
                 f"سرویس {unit} به مدت {mins} دقیقه کانفیگی قدیمی‌تر از فایل‌های "
                 "روی دیسک را سرو می‌کند. بازتولید و ری‌استارت کن، وگرنه لیستی "
                 "که می‌بینی همان چیزی نیست که اجرا می‌شود."))]


def rule_console_unreachable(status: dict) -> list[Finding]:
    problem = (status.get("dnsdist") or {}).get("problem")
    if not problem:
        return []
    return [Finding(
        fingerprint="dnsdist:console",
        kind="datasource", severity="warning", subject="dnsdist console",
        detail=M(f"The dnsdist console is unreachable: {problem}. The "
                 "unproxied-domains panel cannot work without it.",
                 f"کنسول dnsdist در دسترس نیست: {problem}. پنل دامنه‌های "
                 "پروکسی‌نشده بدون آن کار نمی‌کند."))]


def rule_problem_rate(rate_info: dict, threshold: float = 0.25,
                      min_conns: int = 20) -> list[Finding]:
    """Origin NONE or empty SNI as a share of recent connections.

    Needs a minimum sample: two failures out of three connections at 4am is
    noise, not an incident.
    """
    conns = rate_info.get("conns") or 0
    rate = rate_info.get("rate") or 0.0
    if conns < min_conns or rate < threshold:
        return []
    pct = int(rate * 100)
    return [Finding(
        fingerprint="traffic:problem_rate",
        kind="traffic", severity="warning", subject="proxy failures",
        detail=M(f"{pct}% of the last {conns} proxied connections failed - "
                 "origin NONE or no SNI. Either an upstream is unreachable "
                 "from the tunnel, or something was added to the allow-list "
                 "that cannot be proxied.",
                 f"{pct} درصد از {conns} اتصال پروکسی‌شده‌ی اخیر شکست خورده — "
                 "مقصد NONE یا بدون SNI. یا یک مقصد بالادست از تونل در دسترس "
                 "نیست، یا چیزی به لیست اضافه شده که پروکسی‌شدنی نیست."))]


def rule_peer_diverged(diff: dict | None) -> list[Finding]:
    if not diff or diff.get("in_sync") is not False:
        return []
    n_mine = len(diff.get("only_mine") or [])
    n_theirs = len(diff.get("only_theirs") or [])
    return [Finding(
        fingerprint="peer:diverged",
        kind="peer", severity="warning", subject=diff.get("their_name", "peer"),
        detail=M(f"The two servers' allow-lists differ: {n_mine} here only, "
                 f"{n_theirs} there only. Clients alternate between the "
                 "nameservers, so this shows up as a game that works every "
                 "other launch.",
                 f"لیست دو سرور یکسان نیست: {n_mine} فقط اینجا، {n_theirs} فقط "
                 "آنجا. کلاینت‌ها بین نیم‌سرورها جابه‌جا می‌شوند، پس این به‌شکل "
                 "بازی‌ای که یک بار در میان کار می‌کند ظاهر می‌شود."))]


def rule_allowlist_issues(status: dict) -> list[Finding]:
    d = status.get("domains") or {}
    out = []
    if d.get("error"):
        out.append(Finding(
            fingerprint="domains:unreadable", kind="config",
            severity="critical", subject="domains.txt",
            detail=i18n.plain(str(d["error"]))))
    invalid = d.get("invalid") or 0
    if invalid:
        out.append(Finding(
            fingerprint="domains:invalid", kind="config", severity="info",
            subject="domains.txt",
            detail=M(f"{invalid} line(s) in the allow-list are not valid "
                     "hostnames and are being ignored by the generator.",
                     f"{invalid} خط در لیست دامنه‌ها نام میزبان معتبر نیست و "
                     "مولد آن‌ها را نادیده می‌گیرد.")))
    return out


def rule_log_unreadable(status: dict) -> list[Finding]:
    out = []
    for lg in status.get("logs") or []:
        if lg.get("error"):
            out.append(Finding(
                fingerprint=f"log:{lg.get('label', '?')}",
                kind="datasource", severity="warning",
                subject=lg.get("label", "log"),
                detail=i18n.plain(str(lg["error"]))))
    return out


def evaluate(status: dict, rate_info: dict,
             peer_diff: dict | None = None,
             problem_threshold: float = 0.25) -> list[Finding]:
    """Run every rule. Returns all currently-true conditions."""
    findings: list[Finding] = []
    findings += rule_services_down(status)
    findings += rule_config_stale(status)
    findings += rule_console_unreachable(status)
    findings += rule_allowlist_issues(status)
    findings += rule_log_unreadable(status)
    findings += rule_problem_rate(rate_info, threshold=problem_threshold)
    findings += rule_peer_diverged(peer_diff)
    return findings


def reconcile(store, findings: list[Finding],
              now: float | None = None) -> dict:
    """Open what is true, close what no longer is.

    Closing matters as much as opening: an event that never resolves teaches
    people to ignore the badge.
    """
    now = now or time.time()
    live = {f.fingerprint for f in findings}
    for f in findings:
        store.open_event(f.fingerprint, f.kind, f.severity, f.subject,
                         f.detail, now=now)
    closed = 0
    for ev in store.open_events():
        if (ev["fingerprint"] not in live
                and store.close_event(ev["fingerprint"], now=now)):
            closed += 1
    return {"open": len(live), "closed": closed}


# ---------------------------------------------------------------------------
# notifiers
# ---------------------------------------------------------------------------

class Notifier:
    """Delivery target for events.

    Subclass and implement `send`. The dispatcher marks an event notified only
    on success, so a transient failure retries on the next poll instead of
    losing the alert.
    """

    name = "base"

    def enabled(self) -> bool:
        return False

    def send(self, event: dict, lang: str = "en") -> bool:
        raise NotImplementedError


class LogNotifier(Notifier):
    """Writes to the journal. The default, and always available.

    Keeping this as the live default means the dispatch path is exercised from
    the start, so wiring up a real transport later is a small change to a
    known-working mechanism.
    """

    name = "log"

    def __init__(self, enabled: bool = True):
        self._enabled = enabled

    def enabled(self) -> bool:
        return self._enabled

    def send(self, event: dict, lang: str = "en") -> bool:
        detail = event.get(f"detail_{lang}") or event.get("detail_en") or ""
        level = {"critical": logging.ERROR,
                 "warning": logging.WARNING}.get(event.get("severity"),
                                                 logging.INFO)
        log.log(level, "[%s] %s: %s", event.get("severity"),
                event.get("subject"), detail)
        return True


class WebhookNotifier(Notifier):
    """Generic JSON POST. Telegram, Slack and Gotify all fit behind this.

    Left disabled by default; a URL in the config turns it on.
    """

    name = "webhook"

    def __init__(self, url: str = "", timeout: float = 8.0,
                 template: str = ""):
        self.url = (url or "").strip()
        self.timeout = timeout
        self.template = template

    def enabled(self) -> bool:
        return bool(self.url)

    def payload(self, event: dict, lang: str) -> bytes:
        detail = event.get(f"detail_{lang}") or event.get("detail_en") or ""
        text = self.template or "[{severity}] {subject}: {detail}"
        body = {
            "severity": event.get("severity"),
            "kind": event.get("kind"),
            "subject": event.get("subject"),
            "detail": detail,
            "started_at": event.get("started_at"),
            "text": text.format(severity=event.get("severity", ""),
                                subject=event.get("subject", ""),
                                detail=detail),
        }
        return json.dumps(body).encode("utf-8")

    def send(self, event: dict, lang: str = "en") -> bool:
        if not self.enabled():
            return False
        req = urllib.request.Request(
            self.url, data=self.payload(event, lang),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("webhook notify failed: %s", exc)
            return False


class TelegramNotifier(Notifier):
    """Telegram bot API. Disabled until a token and chat id are configured.

    Included now so the shape is settled: when you want it, it is two config
    lines rather than new code.
    """

    name = "telegram"

    def __init__(self, token: str = "", chat_id: str = "",
                 timeout: float = 8.0):
        self.token = (token or "").strip()
        self.chat_id = (chat_id or "").strip()
        self.timeout = timeout

    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, event: dict, lang: str = "en") -> bool:
        if not self.enabled():
            return False
        detail = event.get(f"detail_{lang}") or event.get("detail_en") or ""
        icon = {"critical": "⛔", "warning": "⚠️"}.get(
            event.get("severity"), "ℹ️")
        text = f"{icon} {event.get('subject', '')}\n{detail}"
        data = json.dumps({"chat_id": self.chat_id, "text": text,
                           "disable_web_page_preview": True}).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{self.token}/sendMessage",
            data=data, headers={"Content-Type": "application/json"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("telegram notify failed: %s", exc)
            return False


def dispatch(store, notifiers: list[Notifier], lang: str = "en",
             min_severity: str = "warning") -> dict:
    """Send pending events to every enabled notifier.

    An event is marked notified only when at least one enabled notifier
    accepted it, so a failing transport retries rather than silently dropping.
    """
    order = {s: i for i, s in enumerate(SEVERITIES)}
    cutoff = order.get(min_severity, 1)
    active = [n for n in notifiers if n.enabled()]
    sent = 0
    skipped = 0
    if not active:
        return {"sent": 0, "skipped": 0, "notifiers": []}
    for ev in store.events_pending_notification():
        if order.get(ev.get("severity"), 2) > cutoff:
            skipped += 1
            continue
        ok = False
        for n in active:
            try:
                ok = n.send(ev, lang) or ok
            except Exception as exc:  # noqa: BLE001 - a notifier must not kill the poller
                log.warning("notifier %s raised: %s", n.name, exc)
        if ok:
            store.mark_notified(ev["id"])
            sent += 1
    return {"sent": sent, "skipped": skipped,
            "notifiers": [n.name for n in active]}


def build_notifiers(cfg) -> list[Notifier]:
    """Assemble notifiers from config. Only `log` is on by default."""
    out: list[Notifier] = [LogNotifier(enabled=cfg.alerts_log)]
    if getattr(cfg, "alerts_webhook_url", ""):
        out.append(WebhookNotifier(cfg.alerts_webhook_url,
                                   template=cfg.alerts_webhook_template))
    if getattr(cfg, "alerts_telegram_token", ""):
        out.append(TelegramNotifier(cfg.alerts_telegram_token,
                                    cfg.alerts_telegram_chat))
    return out

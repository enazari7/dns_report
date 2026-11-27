"""Bilingual server messages.

Anything the server generates that a human reads - guard blockers, warnings,
lookup verdicts - is returned as ``{"en": ..., "fa": ...}``. The browser picks
the active language and falls back to English. Static UI labels live in the JS
catalog instead; only generated, parameterised text needs to come from here.

Keeping both languages in the payload rather than negotiating a locale means
switching language in the UI is instant and needs no refetch.
"""

from __future__ import annotations

Msg = dict[str, str]
LANGS = ("en", "fa")
DEFAULT_LANG = "en"


def M(en: str, fa: str) -> Msg:
    """One message in both languages."""
    return {"en": en, "fa": fa}


def plain(text: str) -> Msg:
    """A string with no translation available (a path, a shell error).
    Shown as-is in both languages."""
    return {"en": text, "fa": text}


def pick(msg: Msg | str | None, lang: str = DEFAULT_LANG) -> str:
    if msg is None:
        return ""
    if isinstance(msg, str):
        return msg
    return msg.get(lang) or msg.get("en") or ""


def pick_all(msgs: list[Msg | str] | None,
             lang: str = DEFAULT_LANG) -> list[str]:
    return [pick(m, lang) for m in (msgs or [])]


def normalize_lang(value: str | None) -> str:
    v = (value or "").strip().lower()
    if v.startswith("fa") or v in ("persian", "farsi", "ir"):
        return "fa"
    return "en"


# ---------------------------------------------------------------------------
# Messages reused in more than one place. Parameterised ones are built at the
# call site with M(); these are the fixed ones.
# ---------------------------------------------------------------------------

SNI_ONLY = M(
    "sniproxy can only route TLS (via SNI) or HTTP (via a Host header). If "
    "this host speaks a raw binary protocol or uses UDP, proxying it will "
    "make things worse, not better.",
    "sniproxy فقط می‌تواند TLS (از طریق SNI) یا HTTP (از طریق هدر Host) را "
    "مسیریابی کند. اگر این میزبان یک پروتکل باینری خام حرف می‌زند یا از UDP "
    "استفاده می‌کند، پروکسی‌کردنش وضع را بدتر می‌کند، نه بهتر.")

OBSERVE_FIRST = M(
    "Add this only after observing a real failure for this exact name. "
    "Speculative additions are what broke Clash of Clans, the CODM "
    "downloader and CODM voice chat.",
    "این را فقط بعد از مشاهده‌ی یک خرابی واقعی برای همین نام دقیق اضافه کن. "
    "اضافه‌کردن حدسی همان کاری است که Clash of Clans، دانلودر CODM و چت صوتی "
    "CODM را از کار انداخت.")

MIRROR_PEER = M(
    "Remember to make the same change on the other server - clients "
    "alternate between the two nameservers, and a divergent list produces "
    "intermittent behaviour.",
    "یادت باشد همین تغییر را روی سرور دیگر هم اعمال کنی. کلاینت‌ها بین دو "
    "نیم‌سرور جابه‌جا می‌شوند و لیست ناهمگون باعث رفتار متناوب و گیج‌کننده "
    "می‌شود.")

DISABLE_NOTE = M(
    "Disabling stops spoofing this name; clients will resolve it normally "
    "again. Apply the same change on the other server.",
    "غیرفعال‌کردن، جعل پاسخ برای این نام را متوقف می‌کند و کلاینت‌ها دوباره "
    "آن را به شکل عادی resolve می‌کنند. همین تغییر را روی سرور دیگر هم اعمال "
    "کن.")

PERMITTED_HINT = M(
    "If DNS works but nothing appears in the proxy feed for this client, "
    "check that its IP is in the MikroTik 'Permited' address-list. Port 53 is "
    "open to all, but the DNAT for 80/443 is gated on that list.",
    "اگر DNS کار می‌کند ولی هیچ چیزی برای این کلاینت در فید پروکسی ظاهر "
    "نمی‌شود، بررسی کن که آی‌پی‌اش در address-list با نام Permited روی "
    "MikroTik باشد. پورت ۵۳ برای همه باز است، اما DNAT پورت‌های ۸۰ و ۴۴۳ به "
    "آن لیست وابسته است.")

PASTE_HINT = M(
    "Run this on the other server and paste the whole output:\n"
    "    cat /etc/smartdns/domains.txt",
    "این را روی سرور دیگر اجرا کن و تمام خروجی را اینجا بچسبان:\n"
    "    cat /etc/smartdns/domains.txt")


def bare_root_warning(target: str, subs: list[str]) -> Msg:
    en = (f"{target} is a bare root, not an FQDN. It will capture EVERY "
          "subdomain under it, now and in future - including any UDP or "
          "non-SNI service you have not seen yet. This is exactly how CODM "
          "voice chat and the CODM downloader were broken.")
    fa = (f"{target} یک ریشه‌ی خالی است، نه یک FQDN. تمام زیردامنه‌های زیر آن "
          "را می‌گیرد، هم اکنون و هم در آینده — از جمله هر سرویس UDP یا بدون "
          "SNI که هنوز ندیده‌ای. دقیقاً همین کار چت صوتی CODM و دانلودر CODM "
          "را از کار انداخت.")
    if subs:
        shown = ", ".join(subs[:20]) + (" ..." if len(subs) > 20 else "")
        en += f" Subdomains already observed under it ({len(subs)}): {shown}"
        fa += (f" زیردامنه‌هایی که تا حالا زیر آن دیده شده ({len(subs)}): "
               f"{shown}")
    else:
        en += (" No subdomains have been observed under it yet, which means "
               "you cannot see what you are about to capture.")
        fa += (" هنوز هیچ زیردامنه‌ای زیر آن دیده نشده، یعنی نمی‌توانی ببینی "
               "دقیقاً چه چیزی را داری می‌گیری.")
    return M(en, fa)


def safer_alternative(target: str) -> Msg:
    return M(
        f"Safer alternative: list the exact FQDN you saw failing instead of "
        f"{target}.",
        f"گزینه‌ی امن‌تر: به‌جای {target} همان FQDN دقیقی را که خراب دیدی وارد "
        f"کن.")


def already_listed(target: str) -> Msg:
    return M(
        f"{target} is already listed on its own line.",
        f"{target} از قبل روی خط مستقل خودش در لیست هست.")


def already_covered(target: str, cover: str) -> Msg:
    return M(
        f"{target} is already covered by the existing suffix {cover!r} - a "
        "suffix matches every subdomain under it, so this line would change "
        "nothing.",
        f"{target} از قبل توسط پسوند موجود «{cover}» پوشش داده شده. یک پسوند "
        "همه‌ی زیردامنه‌های زیر خودش را می‌گیرد، پس این خط هیچ تغییری ایجاد "
        "نمی‌کند.")


def invalid_hostname(target: str) -> Msg:
    return M(
        f"{target!r} is not a valid hostname. Expected something like "
        "sg.msdkfaas.com - no scheme, no port, no path, no wildcard.",
        f"«{target}» یک نام میزبان معتبر نیست. چیزی مثل sg.msdkfaas.com انتظار "
        "می‌رود — بدون پروتکل، بدون پورت، بدون مسیر، بدون wildcard.")


def subsumes(target: str, captured: list[str]) -> Msg:
    shown = ", ".join(captured[:20]) + (" ..." if len(captured) > 20 else "")
    return M(
        f"{target} is shorter than {len(captured)} existing entries and will "
        f"subsume them: {shown}. They become redundant but stay harmless.",
        f"{target} کوتاه‌تر از {len(captured)} ورودی موجود است و آن‌ها را در "
        f"خود می‌گیرد: {shown}. آن‌ها زائد می‌شوند ولی بی‌خطر باقی می‌مانند.")


def empty_domain() -> Msg:
    return M("Empty domain.", "دامنه خالی است.")


def not_active_entry(target: str, cover: str | None) -> Msg:
    cov_en = cover or "no match"
    cov_fa = cover or "چیزی پیدا نشد"
    return M(
        f"{target} is not an active entry in this file. Suffix matching means "
        f"it may be covered by a broader entry - check: {cov_en}",
        f"{target} یک ورودی فعال در این فایل نیست. به‌خاطر تطبیق پسوندی ممکن "
        f"است توسط یک ورودی گسترده‌تر پوشش داده شده باشد — بررسی: {cov_fa}")


# -- lookup -----------------------------------------------------------------

def verdict_proxied(matched: str, spoof_ip: str) -> Msg:
    ip = spoof_ip or "this server's public IP"
    ip_fa = spoof_ip or "آی‌پی عمومی این سرور"
    return M(
        f"PROXIED - matches the active suffix {matched!r}. dnsdist should be "
        f"answering A with {ip} and suppressing AAAA/HTTPS/SVCB.",
        f"پروکسی می‌شود — با پسوند فعال «{matched}» تطبیق دارد. dnsdist باید "
        f"رکورد A را با {ip_fa} پاسخ بدهد و AAAA/HTTPS/SVCB را حذف کند.")


def verdict_not_proxied() -> Msg:
    return M(
        "NOT PROXIED - no active suffix matches. This name resolves normally "
        "via the upstream resolvers.",
        "پروکسی نمی‌شود — هیچ پسوند فعالی تطبیق ندارد. این نام به‌شکل عادی از "
        "طریق resolverهای بالادست حل می‌شود.")


def warn_matched_not_spoofed(target: str, matched: str, ip: str) -> Msg:
    ip_en = ip or "the expected public IP"
    ip_fa = ip or "آی‌پی عمومی مورد انتظار"
    return M(
        f"{target} matches {matched!r} but the A answer does not contain "
        f"{ip_en}. Either the config on disk has not been applied (check the "
        "staleness banner), or you are querying a resolver that is not this "
        "server.",
        f"{target} با «{matched}» تطبیق دارد اما پاسخ A شامل {ip_fa} نیست. یا "
        "کانفیگ روی دیسک اعمال نشده (بنر بالای صفحه را ببین)، یا داری از "
        "resolverی می‌پرسی که این سرور نیست.")


def warn_spoofed_not_matched(target: str, ip: str) -> Msg:
    return M(
        f"{target} matches no suffix yet resolves to {ip}. A CNAME target is "
        "not matched by this system - matching is on the query name only - so "
        "check whether a broader entry is in the generated file.",
        f"{target} با هیچ پسوندی تطبیق ندارد ولی به {ip} حل می‌شود. این سیستم "
        "هدف CNAME را تطبیق نمی‌دهد — تطبیق فقط روی نام پرسش انجام می‌شود — پس "
        "بررسی کن آیا ورودی گسترده‌تری در فایل تولیدشده هست یا نه.")


def warn_aaaa_present() -> Msg:
    return M(
        "AAAA returned answers for a proxied name. It should be suppressed; "
        "if the client follows IPv6 it will bypass the proxy entirely.",
        "برای یک نام پروکسی‌شده، AAAA پاسخ برگردانده. باید حذف می‌شد؛ اگر "
        "کلاینت سراغ IPv6 برود کلاً از پروکسی عبور می‌کند.")


def warn_bare_root_lookup(target: str) -> Msg:
    return M(
        f"{target} is a bare root. Listing it would capture every subdomain, "
        "including UDP and non-SNI services.",
        f"{target} یک ریشه‌ی خالی است. وارد کردنش همه‌ی زیردامنه‌ها را می‌گیرد، "
        "از جمله سرویس‌های UDP و بدون SNI.")


# -- apply / write path -----------------------------------------------------

def apply_blocked() -> Msg:
    return M("plan has unresolved blockers",
             "این طرح ایرادهای حل‌نشده دارد")


def file_changed() -> Msg:
    return M(
        "domains.txt changed after this plan was built. Re-run the preview so "
        "you are reviewing the current file.",
        "فایل domains.txt بعد از ساختن این طرح تغییر کرده. پیش‌نمایش را دوباره "
        "بگیر تا فایل فعلی را بررسی کنی.")


def backup_failed(err: str) -> Msg:
    return M(f"backup failed, nothing written: {err}",
             f"گرفتن پشتیبان شکست خورد، هیچ چیزی نوشته نشد: {err}")


def script_failed(script: str, rc: int) -> Msg:
    return M(
        f"{script} exited {rc}; restoring backup",
        f"{script} با کد {rc} خارج شد؛ پشتیبان برگردانده می‌شود")


def restart_failed(unit: str) -> Msg:
    return M(
        f"systemctl restart {unit} failed. The config on disk is new but "
        f"{unit} may still be running the old one - fix this before trusting "
        "the dashboard.",
        f"دستور systemctl restart {unit} شکست خورد. کانفیگ روی دیسک جدید است "
        f"اما ممکن است {unit} هنوز نسخه‌ی قدیمی را اجرا کند — قبل از اعتماد به "
        "داشبورد این را درست کن.")


def peer_reminder(peer_name: str) -> Msg:
    return M(
        f"After applying, make the same change on {peer_name} - clients "
        "alternate between the two nameservers.",
        f"بعد از اعمال، همین تغییر را روی {peer_name} هم انجام بده — کلاینت‌ها "
        "بین دو نیم‌سرور جابه‌جا می‌شوند.")


def stale_message(unit: str, started_ago: str, config_ago: str) -> Msg:
    return M(
        f"{unit} started {started_ago} but its config was modified "
        f"{config_ago}. The process is still serving the OLD routing table. "
        f"Run the update script and restart {unit}.",
        f"سرویس {unit} {started_ago} شروع شده اما کانفیگش {config_ago} تغییر "
        f"کرده. این پروسه هنوز جدول مسیریابی قدیمی را سرو می‌کند. اسکریپت "
        f"update را اجرا کن و {unit} را ری‌استارت کن.")


def fresh_message(unit: str) -> Msg:
    return M(f"{unit} is running config no older than itself.",
             f"سرویس {unit} کانفیگی را اجرا می‌کند که از خودش قدیمی‌تر نیست.")


def unknown_start(unit: str) -> Msg:
    return M(f"{unit} start time unknown - is it running?",
             f"زمان شروع {unit} نامعلوم است — آیا در حال اجراست؟")


def portwatch_known_bad(port: int, count: int, what: str) -> Msg:
    return M(
        f"{count} unanswered SYNs to :{port} - {what}. Do NOT proxy this "
        "host; it must stay on the direct path.",
        f"{count} بسته‌ی SYN بی‌پاسخ به پورت {port} — {what}. این میزبان را "
        "پروکسی نکن؛ باید روی مسیر مستقیم بماند.")


def portwatch_unknown(port: int, count: int) -> Msg:
    return M(
        f"{count} unanswered SYNs to :{port}. sniproxy only listens on 80/443, "
        "so if this is the game's real data channel, adding a domain will not "
        "help - the traffic never reaches sniproxy. Check whether the port is "
        "blocked upstream instead.",
        f"{count} بسته‌ی SYN بی‌پاسخ به پورت {port}. sniproxy فقط روی ۸۰ و ۴۴۳ "
        "گوش می‌دهد، پس اگر این کانال دادهٔ واقعی بازی است، اضافه‌کردن دامنه "
        "کمکی نمی‌کند — ترافیک هرگز به sniproxy نمی‌رسد. در عوض بررسی کن آیا "
        "پورت در بالادست بسته شده.")


def portwatch_fine() -> Msg:
    return M("answered - fine", "پاسخ داده شد — مشکلی نیست")


def peer_in_sync() -> Msg:
    return M("Both servers carry an identical active list.",
             "هر دو سرور لیست فعال یکسانی دارند.")


def peer_diverged(n_mine: int, n_theirs: int, mine: str, theirs: str) -> Msg:
    return M(
        f"{n_mine} entries only on {mine}, {n_theirs} only on {theirs}. "
        "Clients alternate between the two nameservers, so this produces "
        "intermittent behaviour.",
        f"{n_mine} ورودی فقط روی {mine}، و {n_theirs} ورودی فقط روی {theirs}. "
        "کلاینت‌ها بین دو نیم‌سرور جابه‌جا می‌شوند، پس این باعث رفتار متناوب "
        "می‌شود.")


# -- groups and enable/disable ---------------------------------------------

def not_disabled(target: str) -> Msg:
    return M(
        f"{target} is not a disabled entry, so there is nothing to re-enable.",
        f"{target} یک ورودی غیرفعال‌شده نیست، پس چیزی برای فعال‌کردن مجدد وجود "
        f"ندارد.")


def no_group_named() -> Msg:
    return M("No group name given.", "نام گروه داده نشده است.")


def bad_group_name(group: str) -> Msg:
    return M(
        f"{group!r} is not a usable group name. Use letters, digits, dot, dash "
        "or underscore, up to 40 characters.",
        f"«{group}» نام گروه قابل استفاده‌ای نیست. از حرف، رقم، نقطه، خط تیره یا "
        "زیرخط استفاده کن، حداکثر ۴۰ نویسه.")


def group_not_found(group: str, known: list) -> Msg:
    have_en = ", ".join(known) if known else "none defined yet"
    have_fa = "، ".join(known) if known else "هنوز هیچ گروهی تعریف نشده"
    return M(
        f"No group called {group!r} in this file. Groups present: {have_en}.",
        f"گروهی با نام «{group}» در این فایل نیست. گروه‌های موجود: {have_fa}.")


def group_already_off(group: str) -> Msg:
    return M(
        f"Every entry in {group!r} is already disabled.",
        f"همه‌ی ورودی‌های گروه «{group}» از قبل غیرفعال هستند.")


def group_already_on(group: str) -> Msg:
    return M(
        f"Every entry in {group!r} is already active.",
        f"همه‌ی ورودی‌های گروه «{group}» از قبل فعال هستند.")


def group_disable_warning(group: str, count: int) -> Msg:
    return M(
        f"This switches OFF all {count} entries in {group!r} at once. Those "
        "names will stop being proxied and will resolve normally again. That is "
        "the right move when a whole game got worse after a change, and the "
        "wrong one if only a single host is at fault.",
        f"این کار هر {count} ورودی گروه «{group}» را یکجا خاموش می‌کند. آن نام‌ها "
        "دیگر پروکسی نمی‌شوند و به‌شکل عادی resolve خواهند شد. اگر یک بازی کامل "
        "بعد از یک تغییر بدتر شده این حرکت درستی است، و اگر فقط یک میزبان "
        "مشکل دارد حرکت اشتباهی است.")


def group_enable_warning(group: str, count: int) -> Msg:
    return M(
        f"This switches ON all {count} disabled entries in {group!r}. Each one "
        "means routing that name through the proxy again - including any that "
        "were disabled because they broke something.",
        f"این کار هر {count} ورودی غیرفعال گروه «{group}» را روشن می‌کند. هر کدام "
        "یعنی عبور دادن آن نام از پروکسی — از جمله آن‌هایی که چون چیزی را خراب "
        "کردند غیرفعال شده بودند.")


def tag_note(target: str, group: str) -> Msg:
    if group:
        return M(
            f"{target} joins the group {group!r}. Grouping only adds a comment "
            "marker; the routing behaviour is unchanged.",
            f"{target} به گروه «{group}» اضافه می‌شود. گروه‌بندی فقط یک نشانه در "
            "توضیح خط اضافه می‌کند؛ رفتار مسیریابی تغییر نمی‌کند.")
    return M(
        f"{target} is removed from its group. Routing behaviour is unchanged.",
        f"{target} از گروهش خارج می‌شود. رفتار مسیریابی تغییر نمی‌کند.")


# -- history and charts ----------------------------------------------------

NOT_ACCOUNTING = M(
    "Diagnostic history only. These totals are keyed by IP address, and "
    "addresses change hands - a figure here describes an address over a window "
    "of time, not a person. This is not an accounting or billing source.",
    "فقط تاریخچه‌ی تشخیصی. این مجموع‌ها بر اساس آدرس آی‌پی هستند و آدرس‌ها "
    "دست‌به‌دست می‌شوند — عددی که اینجا می‌بینی یک آدرس را در یک بازه‌ی زمانی "
    "توصیف می‌کند، نه یک شخص. این منبع اکانتینگ یا صدور صورت‌حساب نیست.")

GROUP_HOWTO = M(
    "Groups are a comment convention inside domains.txt, so the file stays the "
    "single source of truth. Put '# @group codm' above a block and "
    "'# @endgroup' after it, or tag one line with '# @group codm'.",
    "گروه‌ها یک قرارداد در توضیحات خود domains.txt هستند، پس همان فایل تنها "
    "مرجع باقی می‌ماند. بالای یک بلوک «# @group codm» و پایینش «# @endgroup» "
    "بگذار، یا یک خط را با «# @group codm» برچسب بزن.")


# -- client triage ---------------------------------------------------------
#
# The dashboard cannot read the MikroTik's Permited address-list, so every
# verdict here is phrased as evidence and likelihood, never as fact.

TRIAGE_LIMITATION = M(
    "What this page cannot know: the router's 'Permited' address-list is not "
    "readable from this server. When DNS clearly works but no proxy connection "
    "ever arrives, that points at the Permited list - it does not prove it. "
    "Someone with router access still has to look.",
    "چیزی که این صفحه نمی‌تواند بداند: لیست آدرس «Permited» روی روتر از این "
    "سرور قابل خواندن نیست. وقتی DNS واضحاً کار می‌کند اما هیچ اتصال پروکسی "
    "نمی‌رسد، این نشانه‌ای به سمت لیست Permited است — اثبات آن نیست. کسی که به "
    "روتر دسترسی دارد باید نگاه کند.")

TRIAGE_WORKING = M(
    "Your connections are reaching the proxy and completing. From this side "
    "everything looks healthy.",
    "اتصال‌های تو به پروکسی می‌رسند و کامل می‌شوند. از این طرف همه‌چیز سالم "
    "به‌نظر می‌رسد.")

TRIAGE_PARTIAL = M(
    "Some of your connections are reaching the proxy and completing, others are "
    "failing. That usually means one specific service is the problem rather "
    "than your connection as a whole.",
    "بعضی از اتصال‌های تو به پروکسی می‌رسند و کامل می‌شوند و بعضی شکست "
    "می‌خورند. این معمولاً یعنی یک سرویس خاص مشکل دارد، نه کل اتصال تو.")

TRIAGE_ALL_FAILING = M(
    "Your connections are reaching the proxy but every one of them is failing "
    "to complete - the destination could not be resolved or connected to from "
    "here. This is a server-side problem, not something you can fix.",
    "اتصال‌های تو به پروکسی می‌رسند اما هیچ‌کدام کامل نمی‌شوند — مقصد از این "
    "طرف resolve یا connect نشد. این یک مشکل سمت سرور است، نه چیزی که تو "
    "بتوانی درستش کنی.")

TRIAGE_DNS_BUT_NO_PROXY = M(
    "Your DNS queries are arriving, but no proxy connection from your address "
    "has been seen. That is the signature of an address that is not in the "
    "router's allow-list: DNS is open to everyone, the proxy is not. Send this "
    "page to whoever runs the server.",
    "پرسش‌های DNS تو می‌رسند، اما هیچ اتصال پروکسی از آدرس تو دیده نشده. این "
    "امضای آدرسی است که در لیست مجاز روتر نیست: DNS برای همه باز است، پروکسی "
    "نه. این صفحه را برای کسی که سرور را اداره می‌کند بفرست.")

TRIAGE_STALE = M(
    "We have seen your address before, but nothing recently. Try the game again "
    "and reload this page.",
    "آدرس تو را قبلاً دیده‌ایم، اما اخیراً چیزی نبوده. بازی را دوباره امتحان کن "
    "و این صفحه را تازه کن.")

TRIAGE_NOTHING = M(
    "Nothing has been seen from your address at all. Either you are not using "
    "this server for DNS, or your traffic is not reaching it. Check that the "
    "DNS settings on your device point here.",
    "هیچ چیزی از آدرس تو دیده نشده. یا از این سرور برای DNS استفاده نمی‌کنی، یا "
    "ترافیک تو به آن نمی‌رسد. بررسی کن تنظیمات DNS دستگاهت به اینجا اشاره کند.")


def triage_saw_connections(total: int, failed: int) -> Msg:
    return M(
        f"{total} recent connection(s) from your address reached the proxy, "
        f"{failed} of them failed.",
        f"{total} اتصال اخیر از آدرس تو به پروکسی رسیده، که {failed} مورد آن "
        f"شکست خورده است.")


def triage_dns_only() -> Msg:
    return M(
        "DNS queries seen, zero proxy connections.",
        "پرسش DNS دیده شد، هیچ اتصال پروکسی نه.")


# -- mirrored writes -------------------------------------------------------

MIRROR_DIVERGED = M(
    "The two servers' allow-lists already differ, so a mirrored write was "
    "refused - it would have overwritten whatever is different on the peer. "
    "Reconcile them on the Server diff panel first, then try again.",
    "لیست دو سرور از قبل با هم تفاوت دارد، پس نوشتن آینه‌ای رد شد — وگرنه هر "
    "چیزی که روی سرور دیگر متفاوت است پاک می‌شد. اول در پنل مقایسه سرورها "
    "هم‌ترازشان کن، بعد دوباره امتحان کن.")

MIRROR_PEER_FAILED = M(
    "The change failed on the peer, so it was NOT applied here either. Both "
    "servers still carry the old list, which is the safe outcome - they are "
    "still identical.",
    "تغییر روی سرور دیگر شکست خورد، پس اینجا هم اعمال نشد. هر دو سرور همان "
    "لیست قبلی را دارند، که نتیجه‌ی امنی است — هنوز یکسان هستند.")

MIRROR_LOCAL_FAILED = M(
    "The change succeeded on the peer but failed here, so the two servers now "
    "DIFFER. Fix this before leaving it: either retry here, or roll the peer "
    "back from its backup.",
    "تغییر روی سرور دیگر موفق بود اما اینجا شکست خورد، پس اکنون دو سرور "
    "متفاوت‌اند. قبل از رها کردن این را درست کن: یا اینجا دوباره تلاش کن، یا "
    "سرور دیگر را از پشتیبانش برگردان.")

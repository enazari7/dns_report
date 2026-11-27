/* Smart DNS dashboard - vanilla JS, no build step.
 *
 * One SSE connection carries the live feed, the unproxied panel and the status
 * header. Everything else is a fetch on demand.
 *
 * Language: static labels come from the STR catalog below and are applied to
 * [data-i18n] attributes. Text the server generates (guard warnings, lookup
 * verdicts) arrives as {en, fa} objects, so switching language is instant and
 * needs no refetch.
 */
'use strict';

const B = document.body;
const CSRF = B.dataset.csrf;
const BASE = B.dataset.base || '';
const SPOOF_IP = B.dataset.spoofIp || '';
const SPOOF_SOURCE = B.dataset.spoofSource || '';
const LOCAL_IP = B.dataset.localIp || '127.0.0.1';
const PEER_NAME = B.dataset.peerName || 'peer';
const PEER_ENABLED = B.dataset.peerEnabled === '1';
const ROLE = B.dataset.role || 'operator';
const READONLY = ROLE === 'viewer';
const PROBE_ENABLED = B.dataset.probe === '1';
const HISTORY_ENABLED = B.dataset.history === '1';
const ALERTS_ENABLED = B.dataset.alerts === '1';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

/* ================= language ================= */

const STR = {
  'hdr.stream':        ['event stream', 'جریان رویدادها'],
  'hdr.events':        ['open alerts', 'هشدارهای باز'],
  'hdr.theme':         ['Toggle theme', 'تغییر تم'],
  'hdr.signout':       ['Sign out', 'خروج'],
  'brand.spoofTarget': ['spoof target', 'آدرس جعل‌شده'],

  'tab.debug':   ['Debug client', 'عیب‌یابی کلاینت'],
  'tab.feed':    ['Live feed', 'فید زنده'],
  'tab.allow':   ['Allow-list', 'لیست دامنه‌ها'],
  'tab.lookup':  ['Lookup', 'جستجوی دامنه'],
  'tab.peer':    ['Server diff', 'مقایسه سرورها'],
  'tab.backups': ['Backups', 'پشتیبان‌ها'],
  'tab.ports':   ['Port watch', 'رصد پورت'],
  'tab.logs':    ['Logs', 'لاگ‌ها'],
  'tab.traffic': ['Traffic', 'ترافیک'],
  'tab.events':  ['Events', 'رویدادها'],
  'tab.audit':   ['Audit', 'حسابرسی'],

  'btn.reload': ['Reload', 'بارگذاری مجدد'],

  'col.time':        ['time', 'زمان'],
  'col.log':         ['log', 'لاگ'],
  'col.client':      ['client', 'کلاینت'],
  'col.sni':         ['SNI', 'SNI'],
  'col.origin':      ['origin', 'مقصد'],
  'col.fromOrigin':  ['from origin', 'از مقصد'],
  'col.toOrigin':    ['to origin', 'به مقصد'],
  'col.fromOriginT': ['bytes from the origin toward the client',
                      'بایت از مقصد به سمت کلاینت'],
  'col.toOriginT':   ['bytes from the client toward the origin',
                      'بایت از کلاینت به سمت مقصد'],
  'col.sec':         ['sec', 'ثانیه'],
  'col.firstSeen':   ['first seen', 'اولین مشاهده'],
  'col.name':        ['name', 'نام'],
  'col.qty':         ['qty', 'تعداد'],
  'col.types':       ['types', 'نوع'],
  'col.suffix':      ['suffix', 'پسوند'],
  'col.comment':     ['comment', 'توضیح'],
  'col.when':        ['when', 'چه زمانی'],
  'col.action':      ['action', 'عملیات'],
  'col.target':      ['target', 'هدف'],
  'col.result':      ['result', 'نتیجه'],
  'col.backup':      ['backup', 'پشتیبان'],
  'col.backupFile':  ['backup', 'فایل پشتیبان'],
  'col.size':        ['size', 'حجم'],
  'col.dest':        ['destination', 'مقصد'],
  'col.port':        ['port', 'پورت'],
  'col.unans':       ['unanswered', 'بی‌پاسخ'],
  'col.ans':         ['answered', 'پاسخ‌داده'],
  'col.reading':     ['reading', 'تفسیر'],
  'col.conns':       ['conns', 'اتصال'],
  'col.problems':    ['problems', 'مشکل'],
  'col.bytes':       ['bytes', 'بایت'],
  'col.severity':    ['severity', 'شدت'],
  'col.started':     ['started', 'شروع'],
  'col.duration':    ['duration', 'مدت'],
  'col.subject':     ['subject', 'موضوع'],
  'col.detail':      ['detail', 'جزئیات'],
  'col.outcome':     ['outcome', 'نتیجه'],
  'col.who':         ['who', 'چه کسی'],
  'col.lastSeen':    ['last seen', 'آخرین مشاهده'],
  'col.times':       ['times', 'تعداد'],
  'col.listed':      ['listed', 'در لیست'],

  'role.viewer':     ['read-only', 'فقط‌خواندنی'],
  'role.viewerHint': ['This account can see everything and change nothing.',
                      'این حساب همه‌چیز را می‌بیند و چیزی را تغییر نمی‌دهد.'],

  'probe.run':       ['Test first', 'اول تست کن'],
  'probe.running':   ['testing from this server…', 'در حال تست از این سرور…'],
  'probe.disabled':  ['The active probe is disabled in config.ini.',
                      'تست فعال در config.ini غیرفعال است.'],
  'probe.resolved':  ['resolved to', 'حل شد به'],
  'probe.tls':       ['TLS on 443', 'TLS روی ۴۴۳'],
  'probe.http':      ['HTTP on 80', 'HTTP روی ۸۰'],
  'probe.otherPorts':['other open ports', 'پورت‌های باز دیگر'],
  'probe.none':      ['none', 'هیچ'],
  'probe.alreadyListed': ['This name is already covered by %s.',
                          'این نام از قبل توسط %s پوشش داده شده است.'],

  'groups.title':    ['Groups', 'گروه‌ها'],
  'groups.help': [
    'A group is a comment marker inside domains.txt, so the file stays the ' +
    'single source of truth. Switching a group off comments out every line in ' +
    'it through the same guarded flow as a single domain — the fast way back ' +
    'out when a whole game got worse after a change.',
    'گروه یک نشانه در توضیحات خودِ domains.txt است، پس همان فایل تنها مرجع ' +
    'باقی می‌ماند. خاموش‌کردن یک گروه همه‌ی خطوط آن را از همان مسیر محافظت‌شده‌ی ' +
    'یک دامنه‌ی تنها کامنت می‌کند — راه سریع برگشت وقتی یک بازی کامل بعد از یک ' +
    'تغییر بدتر شده است.'],
  'groups.disabledTitle': ['Disabled entries', 'ورودی‌های غیرفعال'],
  'groups.on':       ['on', 'روشن'],
  'groups.off':      ['off', 'خاموش'],
  'groups.mixed':    ['mixed', 'مختلط'],
  'groups.turnOff':  ['turn off', 'خاموش کن'],
  'groups.turnOn':   ['turn on', 'روشن کن'],
  'groups.none':     ['No groups defined yet.', 'هنوز گروهی تعریف نشده است.'],
  'groups.ungrouped':['%n ungrouped entries', '%n ورودی بدون گروه'],
  'groups.enableOne':['enable', 'فعال کن'],
  'groups.noneDisabled': ['Nothing is disabled.', 'چیزی غیرفعال نیست.'],

  'traffic.window':  ['Window', 'بازه'],
  'traffic.client':  ['Client IP', 'آی‌پی کلاینت'],
  'traffic.chartTitle': ['Bytes over time', 'بایت در طول زمان'],
  'traffic.topClients': ['Top clients', 'پرمصرف‌ترین کلاینت‌ها'],
  'traffic.topSnis': ['Top destinations', 'پرمصرف‌ترین مقاصد'],
  'traffic.notAccounting': [
    'Diagnostic history only. These totals are keyed by IP address, and ' +
    'addresses change hands — a figure here describes an address over a window ' +
    'of time, not a person. This is not an accounting or billing source.',
    'فقط تاریخچه‌ی تشخیصی. این مجموع‌ها بر اساس آدرس آی‌پی هستند و آدرس‌ها ' +
    'دست‌به‌دست می‌شوند — عددی که اینجا می‌بینی یک آدرس را در یک بازه‌ی زمانی ' +
    'توصیف می‌کند، نه یک شخص. این منبع اکانتینگ یا صدور صورت‌حساب نیست.'],
  'traffic.summary': ['%c connections, %p problems (%r%)',
                      '%c اتصال، %p مشکل (%r%)'],
  'traffic.empty':   ['No traffic recorded in this window yet.',
                      'در این بازه هنوز ترافیکی ثبت نشده است.'],
  'traffic.historyOff': [
    'History is disabled in config.ini, so there is nothing to chart. Set ' +
    '[history] enabled = true to collect it.',
    'تاریخچه در config.ini غیرفعال است، پس چیزی برای نمودار نیست. برای جمع‌آوری ' +
    '[history] enabled = true را تنظیم کن.'],
  'traffic.fromOrigin': ['from origin', 'از مقصد'],
  'traffic.toOrigin':   ['to origin', 'به مقصد'],

  'events.help': [
    'A condition that stays true is one event with a duration, not one row per ' +
    'poll — so "when did this start?" has an answer. Events close themselves ' +
    'when the condition clears.',
    'شرطی که برقرار می‌ماند یک رویداد با یک مدت است، نه یک ردیف در هر بررسی — ' +
    'پس «این از کِی شروع شد؟» جواب دارد. رویدادها وقتی شرط برطرف شود خودشان ' +
    'بسته می‌شوند.'],
  'events.openTitle':   ['Open now', 'باز در این لحظه'],
  'events.historyTitle':['History', 'تاریخچه'],
  'events.none':        ['Nothing wrong right now.', 'در این لحظه مشکلی نیست.'],
  'events.ack':         ['acknowledge', 'تأیید دیدن'],
  'events.acked':       ['acknowledged', 'دیده شد'],
  'events.since':       ['for %d', 'به مدت %d'],
  'events.notifiers':   ['notifying via: %n', 'اطلاع‌رسانی از طریق: %n'],
  'events.inAppOnly':   ['in-app only', 'فقط داخل برنامه'],
  'events.disabled':    ['Alerting is disabled in config.ini.',
                         'هشداردهی در config.ini غیرفعال است.'],

  'audit.action':   ['Action', 'عملیات'],
  'audit.who':      ['Who', 'چه کسی'],
  'audit.help': [
    'Every attempt to change something, successful or not. A refusal is ' +
    'recorded too — who tried to add a bare root and was stopped is as ' +
    'interesting as what went through.',
    'هر تلاش برای تغییر، موفق یا ناموفق. رد شدن هم ثبت می‌شود — اینکه چه کسی ' +
    'تلاش کرد یک ریشه‌ی خالی اضافه کند و متوقف شد به‌اندازه‌ی آنچه انجام شد ' +
    'اهمیت دارد.'],
  'audit.registryTitle': ['Domains ever seen', 'دامنه‌هایی که تا حالا دیده شده'],
  'audit.registryHelp': [
    'The dnsdist ring buffer forgets; this does not. First-seen times here ' +
    'survive restarts, which is what makes "is this new?" answerable.',
    'حلقه‌ی dnsdist فراموش می‌کند؛ این نه. زمان اولین مشاهده اینجا از ری‌استارت ' +
    'جان سالم می‌برد، و همین است که به «آیا این جدید است؟» جواب می‌دهد.'],
  'audit.upstreamOnly': ['went upstream only', 'فقط آن‌هایی که به بالادست رفتند'],
  'audit.historyOff': [
    'History is disabled, so nothing is being recorded.',
    'تاریخچه غیرفعال است، پس چیزی ثبت نمی‌شود.'],

  'mirror.both':    ['Apply to both servers', 'اعمال روی هر دو سرور'],
  'mirror.hint': [
    'Writes the peer first, then here. If the peer fails, nothing changes ' +
    'here either — so the two stay identical rather than drifting apart.',
    'اول روی سرور دیگر می‌نویسد، بعد اینجا. اگر سرور دیگر شکست بخورد، اینجا هم ' +
    'چیزی تغییر نمی‌کند — پس هر دو یکسان می‌مانند نه واگرا.'],
  'mirror.running': ['applying to both…', 'در حال اعمال روی هر دو…'],
  'mirror.peerOk':  ['peer: applied', 'سرور دیگر: اعمال شد'],
  'mirror.peerFail':['peer: failed', 'سرور دیگر: شکست خورد'],

  'dbg.clientIp':      ['Client IP', 'آی‌پی کلاینت'],
  'dbg.watch':         ['Watch', 'رصد کن'],
  'dbg.stop':          ['Stop watching', 'توقف رصد'],
  'dbg.recent':        ['Recent clients', 'کلاینت‌های اخیر'],
  'dbg.recentPh':      ['recent clients…', 'کلاینت‌های اخیر…'],
  'dbg.proxiedTag':    ['proxied', 'پروکسی‌شده'],
  'dbg.unproxiedTag':  ['not proxied', 'پروکسی‌نشده'],
  'dbg.proxiedTitle':  ['sniproxy access log', 'لاگ دسترسی sniproxy'],
  'dbg.unproxiedTitle':['dnsdist ring — went upstream',
                        'حلقه dnsdist — به بالادست رفته'],
  'dbg.help': [
    'Left is what sniproxy actually routed. Right is what this client asked ' +
    'for that went <em>upstream</em> — those names are <strong>not</strong> ' +
    'proxied. The candidate you want is usually a name on the right that ' +
    'appears right when the game fails. Deciding which of them genuinely ' +
    'need proxying stays your call: most do not, and adding the wrong one ' +
    'breaks things.',
    'سمت راست آنچه sniproxy واقعاً مسیریابی کرده است. سمت چپ آن چیزی است که ' +
    'این کلاینت پرسیده و به <em>بالادست</em> رفته — آن نام‌ها ' +
    '<strong>پروکسی نمی‌شوند</strong>. کاندیدای مورد نظر معمولاً نامی است که ' +
    'دقیقاً همان لحظه‌ای که بازی خراب می‌شود آن سمت ظاهر می‌شود. تصمیم اینکه ' +
    'کدام‌شان واقعاً به پروکسی نیاز دارند با خودت است: بیشترشان ندارند، و ' +
    'اضافه‌کردن نام اشتباه چیزها را خراب می‌کند.'],
  'dbg.noProxied': [
    'no proxied connections from this client in the buffer',
    'هیچ اتصال پروکسی‌شده‌ای از این کلاینت در بافر نیست'],
  'dbg.noUnproxied': [
    'nothing went upstream for this client in the ring window',
    'در بازه‌ی حلقه، چیزی برای این کلاینت به بالادست نرفته'],
  'dbg.loading':  ['loading…', 'در حال بارگذاری…'],
  'dbg.notWatching': ['not watching', 'در حال رصد نیست'],
  'dbg.grepqFailed': ['grepq failed', 'اجرای grepq شکست خورد'],
  'dbg.summary': ['%u unproxied / %p answered locally, from %r ring rows',
                  '%u پروکسی‌نشده / %p پاسخ محلی، از %r ردیف حلقه'],
  'dbg.addBtn': ['add…', 'اضافه…'],
  'dbg.listedTag': ['listed?', 'در لیست؟'],
  'dbg.listedTitle': [
    'matches an active suffix but still went upstream - the running config may be stale',
    'با یک پسوند فعال تطبیق دارد ولی به بالادست رفته — کانفیگ در حال اجرا ممکن است قدیمی باشد'],
  'dbg.alsoProxied': ['proxied too', 'پروکسی هم شده'],
  'dbg.alsoProxiedT': ['also seen as an SNI in the proxy log',
                       'به‌عنوان SNI در لاگ پروکسی هم دیده شده'],
  'dbg.noteFor': ['observed unproxied for', 'پروکسی‌نشده مشاهده شد برای'],

  'feed.client':   ['Client IP', 'آی‌پی کلاینت'],
  'feed.sni':      ['SNI contains', 'SNI شامل'],
  'feed.problems': ['problems only', 'فقط مشکل‌دارها'],
  'feed.pause':    ['pause', 'توقف'],
  'feed.clear':    ['Clear', 'پاک کن'],
  'feed.help': [
    'Rows are flagged when the origin is <code>NONE</code> (sniproxy could ' +
    'not resolve or connect) or the SNI is empty (the client sent none — ' +
    'sniproxy has nothing to route on). <strong>from origin</strong> is the ' +
    '<code>tx</code> field and <strong>to origin</strong> is <code>rx</code>; ' +
    'if <code>ss -ti</code> ever shows the opposite, flip ' +
    '<code>TX_IS_FROM_ORIGIN</code> in <code>sniproxy_log.py</code>.',
    'ردیف‌ها وقتی علامت‌گذاری می‌شوند که مقصد <code>NONE</code> باشد ' +
    '(sniproxy نتوانسته resolve یا connect کند) یا SNI خالی باشد (کلاینت ' +
    'چیزی نفرستاده — sniproxy مبنایی برای مسیریابی ندارد). ' +
    '<strong>از مقصد</strong> همان فیلد <code>tx</code> و ' +
    '<strong>به مقصد</strong> همان <code>rx</code> است؛ اگر ' +
    '<code>ss -ti</code> عکسش را نشان داد، مقدار ' +
    '<code>TX_IS_FROM_ORIGIN</code> را در <code>sniproxy_log.py</code> برگردان.'],
  'feed.buffered': ['%n buffered', '%n در بافر'],
  'feed.shown':    ['%s shown / %n buffered', '%s نمایش / %n در بافر'],
  'feed.empty':    ['nothing yet — traffic will appear here as it happens',
                    'هنوز چیزی نیست — ترافیک به‌محض وقوع اینجا ظاهر می‌شود'],
  'feed.noSni':    ['no SNI', 'بدون SNI'],

  'allow.addTitle': ['Add a domain', 'افزودن دامنه'],
  'allow.addWarn': [
    'Every line here means “route this through the proxy.” For a service ' +
    'already reachable directly, adding it is a regression. sniproxy is ' +
    'TCP-only and needs an SNI or a Host header — UDP services and binary ' +
    'protocols cannot be proxied at all. Add only after observing a real ' +
    'failure for this exact name.',
    'هر خط اینجا یعنی «این را از مسیر پروکسی عبور بده». برای سرویسی که از ' +
    'قبل مستقیم قابل دسترسی است، اضافه‌کردنش یک پس‌رفت است. sniproxy فقط TCP ' +
    'است و به SNI یا هدر Host نیاز دارد — سرویس‌های UDP و پروتکل‌های باینری ' +
    'اصلاً پروکسی‌شدنی نیستند. فقط بعد از مشاهده‌ی یک خرابی واقعی برای همین ' +
    'نام دقیق اضافه کن.'],
  'allow.notePh':   ['why (goes in the comment)', 'دلیل (در توضیح خط ذخیره می‌شود)'],
  'allow.preview':  ['Preview change', 'پیش‌نمایش تغییر'],
  'allow.listTitle':['Active suffixes', 'پسوندهای فعال'],
  'allow.filterPh': ['filter…', 'فیلتر…'],
  'allow.history':  ['Change history (this process)', 'تاریخچه تغییرات (این پروسه)'],
  'allow.noHistory':['no changes made in this process',
                     'در این پروسه تغییری اعمال نشده'],
  'allow.disableBtn':['disable…', 'غیرفعال…'],
  'allow.disableNote':['disabled from dashboard', 'از داشبورد غیرفعال شد'],
  'allow.dupes':    ['%n duplicate line(s)', '%n خط تکراری'],
  'allow.invalid':  ['%n unparsable line(s)', '%n خط غیرقابل تفسیر'],
  'allow.redundant':['%n entr(ies) already covered by a broader suffix',
                     '%n ورودی که از قبل توسط پسوند گسترده‌تری پوشش داده شده'],
  'allow.building': ['building plan…', 'در حال ساخت طرح…'],
  'allow.refused':  ['Refused.', 'رد شد.'],
  'allow.applyWarn': [
    'This will: write the file (after a timestamped backup to <code>%b</code>), ' +
    'run <code>%s</code>, then restart <code>%u</code>. The restart is not ' +
    'optional — sniproxy only reads its config at startup.',
    'این کار: فایل را می‌نویسد (پس از یک پشتیبان زمان‌دار در <code>%b</code>)، ' +
    '<code>%s</code> را اجرا می‌کند، و بعد <code>%u</code> را ری‌استارت می‌کند. ' +
    'ری‌استارت اختیاری نیست — sniproxy کانفیگش را فقط در زمان شروع می‌خواند.'],
  'allow.typeToConfirm': ['Type <code>%t</code> to confirm:',
                          'برای تأیید <code>%t</code> را تایپ کن:'],
  'allow.applyBtn': ['Apply &amp; restart', 'اعمال و ری‌استارت'],
  'allow.applying': ['applying…', 'در حال اعمال…'],
  'allow.applied':  ['Applied.', 'اعمال شد.'],
  'allow.failed':   ['Failed.', 'شکست خورد.'],
  'allow.observedUnder': ['Subdomains already observed under %t (%n)',
                          'زیردامنه‌های مشاهده‌شده زیر %t (%n)'],

  'lk.resolver': ['resolver', 'resolver'],
  'lk.check':    ['Check', 'بررسی'],
  'lk.help': [
    'Matching is on the <em>query name only</em> — CNAME targets are never ' +
    'matched. A suffix matches its own root and every subdomain under it.',
    'تطبیق فقط روی <em>نام پرسش</em> انجام می‌شود — هدف CNAME هرگز تطبیق ' +
    'داده نمی‌شود. یک پسوند، خود ریشه و همه‌ی زیردامنه‌های زیر آن را می‌گیرد.'],
  'lk.querying': ['querying…', 'در حال پرسش…'],
  'lk.queryName':['query name', 'نام پرسش'],
  'lk.matched':  ['matched suffix', 'پسوند تطبیق‌یافته'],
  'lk.none':     ['none', 'هیچ'],
  'lk.bareRoot': ['bare root', 'ریشه‌ی خالی'],
  'lk.spoofedTo':['answered with one of our addresses',
                  'با یکی از آدرس‌های ما پاسخ داده شد'],
  'lk.expected': ['expected spoof target', 'آدرس جعل مورد انتظار'],
  'lk.covering': ['Active suffixes that cover this name',
                  'پسوندهای فعالی که این نام را پوشش می‌دهند'],
  'lk.noAnswer': ['(no answer)', '(بدون پاسخ)'],
  'lk.shouldSuppress': ['should be suppressed', 'باید حذف می‌شد'],

  'peer.probe':    ['Probe peer', 'بررسی اتصال'],
  'peer.fetch':    ['Fetch & diff over SSH', 'دریافت و مقایسه با SSH'],
  'peer.pasteMode':['Paste mode (no SSH needed)', 'حالت paste (بدون نیاز به SSH)'],
  'peer.pasteGo':  ['Diff pasted list', 'مقایسه لیست چسبانده‌شده'],
  'peer.help': [
    'Both servers must carry an identical list. Clients alternate between ' +
    'the two nameservers, so any divergence shows up as intermittent ' +
    'behaviour — a game that works every other launch.',
    'هر دو سرور باید لیست یکسانی داشته باشند. کلاینت‌ها بین دو نیم‌سرور ' +
    'جابه‌جا می‌شوند، پس هر ناهمگونی به‌شکل رفتار متناوب ظاهر می‌شود — بازی‌ای ' +
    'که یک بار در میان کار می‌کند.'],
  'peer.fetching': ['fetching over SSH…', 'در حال دریافت با SSH…'],
  'peer.onlyOn':   ['Only on %s (%n)', 'فقط روی %s (%n)'],
  'peer.counts':   ['%a: %x entries · %b: %y entries',
                    '%a: %x ورودی · %b: %y ورودی'],
  'peer.reachable':['reachable', 'قابل دسترسی'],
  'peer.unreachable':['unreachable', 'غیرقابل دسترسی'],

  'bk.diffTitle': ['Diff vs current', 'مقایسه با نسخه فعلی'],
  'bk.select':    ['select a backup', 'یک پشتیبان انتخاب کن'],
  'bk.identical': ['(identical)', '(یکسان)'],
  'bk.count':     ['%n backup(s) in %d', '%n پشتیبان در %d'],
  'bk.none':      ['none yet', 'هنوز هیچ'],
  'bk.diffBtn':   ['diff', 'مقایسه'],
  'bk.restoreHint': [
    'Type <code>RESTORE</code> to put this back, regenerate and restart:',
    'برای برگرداندن این نسخه، بازتولید و ری‌استارت، <code>RESTORE</code> را تایپ کن:'],
  'bk.restoreBtn':['Restore %n', 'بازگردانی %n'],
  'bk.restored':  ['Restored, regenerated and restarted.',
                   'بازگردانی شد، بازتولید و ری‌استارت انجام شد.'],

  'pw.client': ['Client IP', 'آی‌پی کلاینت'],
  'pw.start':  ['Start capture', 'شروع ضبط'],
  'pw.stop':   ['Stop', 'توقف'],
  'pw.help': [
    'Shows TCP SYNs to ports other than 53/80/443 that never got a SYN-ACK. ' +
    'This is the signature of the CODM downloader problem: a binary Tencent ' +
    'GCloud protocol on 8080/8085/8013 with no SNI and no Host header, which ' +
    'sniproxy cannot route. Hosts appearing here must stay on the direct ' +
    'path — proxying them makes things worse.',
    'بسته‌های SYN به پورت‌هایی غیر از ۵۳/۸۰/۴۴۳ را نشان می‌دهد که هرگز ' +
    'SYN-ACK نگرفته‌اند. این امضای مشکل دانلودر CODM است: یک پروتکل باینری ' +
    'Tencent GCloud روی ۸۰۸۰/۸۰۸۵/۸۰۱۳ بدون SNI و بدون هدر Host، که sniproxy ' +
    'نمی‌تواند مسیریابی‌اش کند. میزبان‌هایی که اینجا ظاهر می‌شوند باید روی مسیر ' +
    'مستقیم بمانند — پروکسی‌کردنشان وضع را بدتر می‌کند.'],
  'pw.capturing': ['capturing', 'در حال ضبط'],
  'pw.stopped':   ['stopped', 'متوقف'],
  'pw.detail':    ['on %i, %s elapsed (max %m s), %p SYNs in flight',
                   'روی %i، %s ثانیه گذشته (حداکثر %m ثانیه)، %p بسته SYN در پرواز'],
  'pw.ignoring':  ['ignoring ports %p', 'نادیده‌گرفتن پورت‌های %p'],
  'pw.disabled': [
    'Port watch is disabled in config.ini. It runs a continuous packet ' +
    'capture, so it is opt-in: set <code>[portwatch] enabled = true</code> ' +
    'and restart the dashboard.',
    'رصد پورت در config.ini غیرفعال است. یک ضبط پیوسته‌ی بسته اجرا می‌کند، پس ' +
    'باید صریحاً فعال شود: <code>[portwatch] enabled = true</code> را تنظیم کن ' +
    'و داشبورد را ری‌استارت کن.'],
  'pw.noneYet': ['No unanswered SYNs yet. Reproduce the failure on the device now.',
                 'هنوز هیچ SYN بی‌پاسخی نیست. الان خرابی را روی دستگاه بازتولید کن.'],

  'logs.lines': ['lines', 'تعداد خط'],
  'logs.load':  ['Load', 'بارگذاری'],
  'logs.loading': ['loading…', 'در حال بارگذاری…'],

  'sv.stale': ['Stale config.', 'کانفیگ قدیمی.'],
  'sv.staleExtra': [
    'sniproxy reads its config only at startup, so the file on disk can look ' +
    'correct while the old routing table is still live.',
    'sniproxy کانفیگش را فقط در زمان شروع می‌خواند، پس فایل روی دیسک ' +
    'می‌تواند درست به نظر برسد در حالی که جدول مسیریابی قدیمی هنوز فعال است.'],
  'sv.suffixes': ['%n suffixes', '%n پسوند'],
  'sv.console':  ['dnsdist console', 'کنسول dnsdist'],
  'sv.buffered': ['%n rows buffered', '%n ردیف در بافر'],
  'sv.dupInvalid': ['%d duplicate and %i invalid line(s) in %p',
                    '%d خط تکراری و %i خط نامعتبر در %p'],
  'sv.spoofUnknown': ['spoof target unknown', 'آدرس جعل نامعلوم'],
  'sv.singleServer': ['single server', 'تک‌سروری'],
};

let LANG = localStorage.getItem('sd_lang') || B.dataset.lang || 'en';
if (LANG !== 'fa') LANG = 'en';

function t(key, vars) {
  const row = STR[key];
  let s = row ? (LANG === 'fa' ? row[1] : row[0]) : key;
  if (vars) for (const k in vars) s = s.split('%' + k).join(vars[k]);
  return s;
}

/** Server-generated bilingual message -> current language. */
function msg(m) {
  if (m == null) return '';
  if (typeof m === 'string') return m;
  return m[LANG] || m.en || '';
}

function applyLang() {
  document.documentElement.lang = LANG;
  document.documentElement.dir = LANG === 'fa' ? 'rtl' : 'ltr';
  B.dataset.lang = LANG;
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-html]').forEach((el) => {
    el.innerHTML = t(el.dataset.i18nHtml);
  });
  document.querySelectorAll('[data-i18n-ph]').forEach((el) => {
    el.placeholder = t(el.dataset.i18nPh);
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    el.title = t(el.dataset.i18nTitle);
  });
  document.querySelectorAll('.seg-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.lang === LANG);
  });
  const known = $('dbgKnown');
  if (known && known.options.length) known.options[0].textContent = t('dbg.recentPh');
  $('peerPasteHint').textContent = PASTE_HINT ? msg(PASTE_HINT) : '';
  $('peerProbe').textContent = t('peer.probe') + ' ' + PEER_NAME;
  if (!$('bkDiff').dataset.loaded) $('bkDiff').textContent = t('bk.select');
  redrawAll();
}

document.querySelectorAll('.seg-btn').forEach((b) => {
  b.addEventListener('click', () => {
    LANG = b.dataset.lang;
    localStorage.setItem('sd_lang', LANG);
    applyLang();
  });
});

/* ================= theme ================= */
let THEME = localStorage.getItem('sd_theme') || 'dark';
function applyTheme() {
  document.documentElement.dataset.theme = THEME;
  $('themeBtn').textContent = THEME === 'dark' ? '◐' : '◑';
}
$('themeBtn').addEventListener('click', () => {
  THEME = THEME === 'dark' ? 'light' : 'dark';
  localStorage.setItem('sd_theme', THEME);
  applyTheme();
});

/* ================= helpers ================= */
function hhmmss(ts) {
  if (!ts) return '-';
  return new Date(ts * 1000).toTimeString().slice(0, 8);
}
function ago(ts) {
  if (!ts) return '-';
  const d = Math.max(0, Date.now() / 1000 - ts);
  if (d < 90) return Math.round(d) + 's';
  if (d < 5400) return Math.round(d / 60) + 'm';
  if (d < 172800) return (d / 3600).toFixed(1) + 'h';
  return (d / 86400).toFixed(1) + 'd';
}
function bytes(n) {
  if (n == null) return '-';
  if (n < 1024) return String(n);
  if (n < 1048576) return (n / 1024).toFixed(1) + 'K';
  return (n / 1048576).toFixed(1) + 'M';
}
function emptyRow(cols, text) {
  return `<tr><td colspan="${cols}"><div class="empty">${esc(text)}</div></td></tr>`;
}

async function api(path, opts) {
  const o = Object.assign({ headers: {} }, opts || {});
  if (o.body !== undefined && typeof o.body !== 'string') {
    o.body = JSON.stringify(o.body);
    o.headers['Content-Type'] = 'application/json';
  }
  if (o.method && o.method !== 'GET') o.headers['X-CSRF-Token'] = CSRF;
  const r = await fetch(BASE + path, o);
  const text = await r.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  if (!r.ok) {
    const d = data && data.detail;
    throw new Error(typeof d === 'object' ? msg(d) : (d || text || r.status));
  }
  return data;
}

function diffHtml(text) {
  return String(text || '').split('\n').map((l) => {
    const c = l.startsWith('+') && !l.startsWith('+++') ? 'add'
      : l.startsWith('-') && !l.startsWith('---') ? 'del'
      : l.startsWith('@@') ? 'hdr' : '';
    return `<span class="${c}">${esc(l)}</span>`;
  }).join('\n');
}

/* ================= tabs ================= */
document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    $('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'allow') { loadAllow(); loadChanges(); loadGroups(); }
    if (btn.dataset.tab === 'backups') loadBackups();
    if (btn.dataset.tab === 'ports') pollPortwatch();
    if (btn.dataset.tab === 'peer' && PEER_ENABLED) peerProbe();
    if (btn.dataset.tab === 'traffic') loadTraffic();
    if (btn.dataset.tab === 'events') loadEvents();
    if (btn.dataset.tab === 'audit') { loadAudit(); loadRegistry(); }
  });
});

/* ================= status header ================= */
let LAST_STATUS = null;

function renderStatus(s) {
  if (!s || s.error) return;
  LAST_STATUS = s;
  const chips = [];
  (s.services || []).forEach((sv) => {
    chips.push(`<span class="chip ${sv.healthy ? 'ok' : 'bad'}" title="pid ${sv.pid}">` +
      `${esc(sv.unit)}: ${esc(sv.active_state)}</span>`);
  });
  const d = s.domains || {};
  const dcls = d.error ? 'bad' : (d.duplicates || d.invalid ? 'warn' : '');
  chips.push(`<span class="chip ${dcls}" title="${esc(d.path)}">${t('sv.suffixes', { n: d.count })}</span>`);
  if (s.dnsdist && s.dnsdist.problem) {
    chips.push(`<span class="chip bad" title="${esc(s.dnsdist.problem)}">${t('sv.console')}</span>`);
  } else {
    chips.push(`<span class="chip ok">${t('sv.console')}</span>`);
  }
  const srv = s.server || {};
  if (!srv.spoof_ip) {
    chips.push(`<span class="chip warn">${t('sv.spoofUnknown')}</span>`);
  }
  if (srv.single_server) {
    chips.push(`<span class="chip">${t('sv.singleServer')}</span>`);
  }
  chips.push(`<span class="chip">${t('sv.buffered', { n: s.feed_len })}</span>`);
  $('statusChips').innerHTML = chips.join('');

  if (srv.name) $('brandName').textContent = srv.name;
  if (srv.spoof_ip) {
    $('brandSpoof').textContent = srv.spoof_ip;
    $('brandSpoof').title = srv.spoof_source || '';
  }

  const banner = $('staleBanner');
  const st = s.staleness || {};
  if (st.stale) {
    banner.className = 'banner';
    banner.innerHTML = `<strong>${t('sv.stale')}</strong> ${esc(msg(st.message))} — ${t('sv.staleExtra')}`;
  } else if (d.error) {
    banner.className = 'banner';
    banner.textContent = d.error;
  } else if (d.duplicates || d.invalid) {
    banner.className = 'banner note';
    banner.textContent = t('sv.dupInvalid', { d: d.duplicates, i: d.invalid, p: d.path });
  } else {
    banner.className = 'banner hidden';
  }

  const cb = $('cfgBanner');
  const warns = s.config_warnings || [];
  if (warns.length) {
    cb.className = 'banner note';
    cb.innerHTML = '<ul>' + warns.map((w) => `<li>${esc(w)}</li>`).join('') + '</ul>';
  } else {
    cb.className = 'banner note hidden';
  }
}

/* ================= SSE ================= */
let es = null;
function connectSSE() {
  if (es) es.close();
  es = new EventSource(BASE + '/events');
  es.addEventListener('open', () => $('sseDot').classList.add('live'));
  es.addEventListener('error', () => {
    $('sseDot').classList.remove('live');
    setTimeout(connectSSE, 4000);
  });
  es.addEventListener('status', (e) => renderStatus(JSON.parse(e.data)));
  es.addEventListener('feed', (e) => onFeed(JSON.parse(e.data)));
  es.addEventListener('unproxied', (e) => onUnproxied(JSON.parse(e.data)));
  es.addEventListener('events', (e) => onEvents(JSON.parse(e.data)));
}

/* ================= live feed ================= */
const feedRows = [];
const FEED_MAX = 800;

function feedMatches(r) {
  const c = $('fClient').value.trim();
  const s = $('fSni').value.trim().toLowerCase();
  if (c && r.client_ip !== c) return false;
  if (s && !(r.sni || '').includes(s)) return false;
  if ($('fProblems').checked && !r.problem) return false;
  return true;
}

function sniCell(r) {
  return r.sni ? esc(r.sni) : `<span class="tag bad">${t('feed.noSni')}</span>`;
}
function originCell(r, withPort) {
  if (r.origin_failed) return '<span class="tag bad">NONE</span>';
  return esc(withPort ? r.origin_ip + ':' + (r.origin_port || '') : r.origin_ip);
}

function feedRowHtml(r, fresh) {
  const cls = (r.problem ? 'problem ' : '') + (fresh ? 'fresh' : '');
  return `<tr class="${cls}">
    <td>${esc(r.time)}</td><td>${esc(r.source)}</td>
    <td>${esc(r.client_ip)}</td><td class="name">${sniCell(r)}</td>
    <td>${originCell(r, true)}</td>
    <td class="num">${bytes(r.from_origin)}</td>
    <td class="num">${bytes(r.to_origin)}</td>
    <td class="num">${r.duration.toFixed(2)}</td></tr>`;
}

function onFeed(batch) {
  batch.forEach((r) => feedRows.push(r));
  while (feedRows.length > FEED_MAX) feedRows.shift();

  if (!$('fPause').checked) {
    const body = $('feedBody');
    const shown = batch.filter(feedMatches);
    if (shown.length) {
      if (body.querySelector('.empty')) body.innerHTML = '';
      body.insertAdjacentHTML('afterbegin',
        shown.map((r) => feedRowHtml(r, true)).join(''));
      while (body.rows.length > FEED_MAX) body.deleteRow(body.rows.length - 1);
    }
    $('fMeta').textContent = t('feed.buffered', { n: feedRows.length });
  }

  const dbg = ($('dbgClient').value || '').trim();
  if (dbg) {
    const mine = batch.filter((r) => r.client_ip === dbg);
    if (mine.length) {
      const tb = $('dbgProxied');
      if (tb.querySelector('.empty')) tb.innerHTML = '';
      tb.insertAdjacentHTML('afterbegin',
        mine.map((r) => dbgProxiedRow(r, true)).join(''));
    }
  }
}

function redrawFeed() {
  const rows = feedRows.filter(feedMatches).slice().reverse();
  $('feedBody').innerHTML = rows.length
    ? rows.map((r) => feedRowHtml(r, false)).join('')
    : emptyRow(8, t('feed.empty'));
  $('fMeta').textContent = t('feed.shown', { s: rows.length, n: feedRows.length });
}

['fClient', 'fSni'].forEach((id) => $(id).addEventListener('input', redrawFeed));
$('fProblems').addEventListener('change', redrawFeed);
$('fClear').addEventListener('click', () => {
  feedRows.length = 0; redrawFeed();
});

/* ================= debug client ================= */
let LAST_GREPQ = null;
let LAST_CLIENT_ROWS = null;

function dbgProxiedRow(r, fresh) {
  const cls = (r.problem ? 'problem ' : '') + (fresh ? 'fresh' : '');
  return `<tr class="${cls}"><td>${esc(r.time)}</td><td class="name">${sniCell(r)}</td>
    <td>${originCell(r, false)}</td><td class="num">${bytes(r.from_origin)}</td>
    <td class="num">${bytes(r.to_origin)}</td>
    <td class="num">${r.duration.toFixed(2)}</td></tr>`;
}

function onUnproxied(d) {
  const cur = ($('dbgClient').value || '').trim();
  if (!d || d.client_ip !== cur) return;
  LAST_GREPQ = d;
  renderUnproxied(d);
}

function renderUnproxied(d) {
  if (!d) return;
  const tb = $('dbgUnproxied');
  if (d.error) {
    tb.innerHTML = emptyRow(5, t('dbg.grepqFailed') + ': ' + d.error);
    return;
  }
  const rows = d.unproxied || [];
  if (!rows.length) {
    tb.innerHTML = emptyRow(5, t('dbg.noUnproxied'));
  } else {
    tb.innerHTML = rows.map((e) => {
      const listed = e.matched_suffix
        ? `<span class="tag warn" title="${esc(t('dbg.listedTitle'))}">${t('dbg.listedTag')}</span>`
        : '';
      const seen = e.seen_in_proxy_log
        ? `<span class="tag ok" title="${esc(t('dbg.alsoProxiedT'))}">${t('dbg.alsoProxied')}</span>`
        : '';
      return `<tr>
        <td title="${esc(new Date(e.first_seen * 1000).toLocaleString())}">${hhmmss(e.first_seen)}</td>
        <td class="name">${esc(e.name)}${listed}${seen}</td>
        <td class="num">${e.count}</td>
        <td>${esc((e.qtypes || []).join(','))}</td>
        <td><button class="ghost" data-add="${esc(e.name)}">${t('dbg.addBtn')}</button></td>
      </tr>`;
    }).join('');
    tb.querySelectorAll('button[data-add]').forEach((b) => {
      b.addEventListener('click', () => {
        document.querySelector('.tab[data-tab="allow"]').click();
        $('addDomain').value = b.dataset.add;
        $('addNote').value = t('dbg.noteFor') + ' ' + ($('dbgClient').value || '');
        $('addDomain').focus();
      });
    });
  }
  $('dbgMeta').textContent = t('dbg.summary', {
    u: (d.unproxied || []).length,
    p: (d.proxied || []).length,
    r: d.rows,
  }) + ' · ' + ago(d.ts);
}

function renderClientRows(rows) {
  LAST_CLIENT_ROWS = rows;
  $('dbgProxied').innerHTML = rows && rows.length
    ? rows.map((r) => dbgProxiedRow(r, false)).join('')
    : emptyRow(6, t('dbg.noProxied'));
}

async function dbgLoad(ip) {
  if (!ip) return;
  $('dbgProxied').innerHTML = emptyRow(6, t('dbg.loading'));
  $('dbgUnproxied').innerHTML = emptyRow(5, t('dbg.loading'));
  try {
    await api('/api/watch', { method: 'POST', body: { client_ip: ip } });
    const d = await api('/api/client/' + encodeURIComponent(ip));
    renderClientRows((d.proxy_rows || []).slice().reverse());
    LAST_GREPQ = d.grepq;
    renderUnproxied(d.grepq);

    const hint = $('dbgPermitHint');
    if (!(d.proxy_rows || []).length && (d.grepq.unproxied || []).length) {
      hint.className = 'alert info';
      hint.dataset.msgEn = d.permitted_hint.en;
      hint.dataset.msgFa = d.permitted_hint.fa;
      hint.textContent = msg(d.permitted_hint);
    } else {
      hint.className = 'alert info hidden';
    }
  } catch (e) {
    $('dbgUnproxied').innerHTML = emptyRow(5, e.message);
  }
}

$('dbgGo').addEventListener('click', () => dbgLoad($('dbgClient').value.trim()));
$('dbgClient').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') dbgLoad($('dbgClient').value.trim());
});
$('dbgStop').addEventListener('click', async () => {
  $('dbgClient').value = '';
  await api('/api/watch', { method: 'POST', body: { client_ip: '' } });
  $('dbgMeta').textContent = t('dbg.notWatching');
});
$('dbgKnown').addEventListener('change', (e) => {
  if (!e.target.value) return;
  $('dbgClient').value = e.target.value;
  dbgLoad(e.target.value);
});

async function loadClients() {
  try {
    const d = await api('/api/clients');
    const sel = $('dbgKnown');
    const cur = sel.value;
    sel.innerHTML = `<option value="">${esc(t('dbg.recentPh'))}</option>` +
      d.clients.map((c) =>
        `<option value="${esc(c.client_ip)}">${esc(c.client_ip)} — ${c.count}` +
        (c.problems ? ' / ' + c.problems + '!' : '') + '</option>'
      ).join('');
    sel.value = cur;
  } catch (e) { /* transient */ }
}

/* ================= allow-list ================= */
let ALLOW = [];

async function loadAllow() {
  try {
    const d = await api('/api/domains');
    ALLOW = d.entries;
    window.__allowMeta = d;
    renderAllowIssues(d);
    renderAllow();
  } catch (e) {
    $('allowIssues').innerHTML = `<div class="alert error">${esc(e.message)}</div>`;
  }
}

function renderAllowIssues(d) {
  if (!d) return;
  $('allowCount').textContent = '(' + d.entries.length + ')';
  const issues = [];
  if (d.error) issues.push(`<div class="alert error">${esc(d.error)}</div>`);
  if (d.duplicates.length) {
    issues.push(`<div class="alert warn">${t('allow.dupes', { n: d.duplicates.length })}: ` +
      esc(d.duplicates.map((x) => `${x[0]}:${x[1]}`).join(', ')) + '</div>');
  }
  if (d.invalid.length) {
    issues.push(`<div class="alert warn">${t('allow.invalid', { n: d.invalid.length })}: ` +
      esc(d.invalid.map((x) => x[0]).join(', ')) + '</div>');
  }
  if (d.redundant.length) {
    issues.push(`<div class="alert info">${t('allow.redundant', { n: d.redundant.length })}: ` +
      esc(d.redundant.slice(0, 8).map((x) => `${x[0]} ⊂ ${x[1]}`).join(', ')) +
      (d.redundant.length > 8 ? ' …' : '') + '</div>');
  }
  $('allowIssues').innerHTML = issues.join('');
}

function renderAllow() {
  const f = $('allowFilter').value.trim().toLowerCase();
  const rows = ALLOW.filter((e) => !f || e.suffix.includes(f));
  $('allowBody').innerHTML = rows.length ? rows.map((e) => `<tr>
    <td>${e.lineno}</td>
    <td class="name">${esc(e.suffix)}</td>
    <td class="name">${esc(e.comment)}</td>
    <td><button class="ghost" data-dis="${esc(e.suffix)}">${t('allow.disableBtn')}</button></td>
  </tr>`).join('') : emptyRow(4, '—');
  $('allowBody').querySelectorAll('button[data-dis]').forEach((b) => {
    b.addEventListener('click', () =>
      preview('disable', b.dataset.dis, t('allow.disableNote')));
  });
}
$('allowFilter').addEventListener('input', renderAllow);
$('allowReload').addEventListener('click', loadAllow);

let LAST_PLAN = null;

async function preview(action, domain, note) {
  const box = $('planBox');
  box.innerHTML = `<div class="alert info">${t('allow.building')}</div>`;
  let p;
  try {
    p = await api('/api/domains/preview', {
      method: 'POST',
      body: { action, domain, comment: note !== undefined ? note : $('addNote').value },
    });
  } catch (e) {
    box.innerHTML = `<div class="alert error">${esc(e.message)}</div>`;
    return;
  }
  LAST_PLAN = p;
  renderPlan(p);
}

function renderPlan(p) {
  if (!p) return;
  const box = $('planBox');
  const parts = [];
  if (p.blockers.length) {
    parts.push(`<div class="alert error"><strong>${t('allow.refused')}</strong><ul>` +
      p.blockers.map((b) => `<li>${esc(msg(b))}</li>`).join('') + '</ul></div>');
  }
  p.warnings.forEach((w) => {
    parts.push(`<div class="alert warn">${esc(msg(w))}</div>`);
  });
  if (p.notes.length) {
    parts.push('<div class="alert info"><ul>' +
      p.notes.map((n) => `<li>${esc(msg(n))}</li>`).join('') + '</ul></div>');
  }
  if (p.observed_subdomains && p.observed_subdomains.length) {
    parts.push('<details><summary>' +
      esc(t('allow.observedUnder', { t: p.target, n: p.observed_subdomains.length })) +
      '</summary><pre class="diff">' + esc(p.observed_subdomains.join('\n')) +
      '</pre></details>');
  }
  if (p.diff) parts.push(`<pre class="diff">${diffHtml(p.diff)}</pre>`);

  if (p.ok) {
    parts.push('<div class="alert warn">' + t('allow.applyWarn', {
      b: esc(p.backup_dir), s: esc(p.update_script),
      u: esc((p.restart_units || []).join(' ')),
    }) + '</div>');
    if (p.peer_reminder) {
      parts.push(`<div class="alert info">${esc(msg(p.peer_reminder))}</div>`);
    }
    parts.push(`<div class="confirm-row">
      <span class="lbl">${t('allow.typeToConfirm', { t: esc(p.target) })}</span>
      <input id="applyConfirm" size="28" autocomplete="off" dir="ltr">
      <button id="applyGo" class="danger">${t('allow.applyBtn')}</button>
      ${PEER_ENABLED ? `<button id="applyBoth" class="danger"
          title="${esc(t('mirror.hint'))}">${t('mirror.both')}</button>` : ''}
    </div>
    ${PEER_ENABLED ? `<p class="hint">${t('mirror.hint')}</p>` : ''}
    <div id="applyOut"></div>`);
  }
  box.innerHTML = parts.join('');

  if (p.ok) {
    $('applyGo').addEventListener('click', () => applyPlan(p));
    if ($('applyBoth')) {
      $('applyBoth').addEventListener('click', () => applyPlan(p, true));
    }
    $('applyConfirm').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') applyPlan(p);
    });
    $('applyConfirm').focus();
  }
}

function stepList(steps) {
  return (steps || []).map((s) =>
    `<li>${s.ok ? '✓' : '✗'} ${esc(s.name)}` +
    (s.detail ? ' — <code>' + esc(String(s.detail).slice(0, 300)) + '</code>' : '') +
    '</li>').join('');
}

async function applyPlan(p, both) {
  const btn = both ? $('applyBoth') : $('applyGo');
  if ($('applyGo')) $('applyGo').disabled = true;
  if ($('applyBoth')) $('applyBoth').disabled = true;
  $('applyOut').innerHTML =
    `<div class="alert info">${both ? t('mirror.running') : t('allow.applying')}</div>`;
  try {
    const r = await api(both ? '/api/domains/apply-both' : '/api/domains/apply', {
      method: 'POST',
      body: { token: p.token, confirm: $('applyConfirm').value.trim() },
    });
    const out = [];
    if (both) {
      const peer = r.peer || {};
      out.push(`<div class="alert ${peer.ok ? 'ok' : 'error'}">
        <strong>${peer.ok ? t('mirror.peerOk') : t('mirror.peerFail')}</strong>
        ${peer.error ? esc(String(peer.error)) : ''}
        <ul>${stepList(peer.steps)}</ul></div>`);
      const loc = r.local;
      if (loc) {
        out.push(`<div class="alert ${loc.ok ? 'ok' : 'error'}">
          <strong>${loc.ok ? t('allow.applied') : t('allow.failed')}</strong>
          ${loc.error ? esc(msg(loc.error)) : ''}
          <ul>${stepList(loc.steps)}</ul></div>`);
      }
      if (r.error) out.push(`<div class="alert warn">${esc(msg(r.error))}</div>`);
    } else {
      out.push(`<div class="alert ${r.ok ? 'ok' : 'error'}">
        <strong>${r.ok ? t('allow.applied') : t('allow.failed')}</strong>
        ${r.error ? esc(msg(r.error)) : ''}
        <ul>${stepList(r.steps)}</ul></div>`);
    }
    $('applyOut').innerHTML = out.join('');
    LAST_PLAN = null;
    loadAllow(); loadChanges(); loadGroups();
  } catch (e) {
    $('applyOut').innerHTML = `<div class="alert error">${esc(e.message)}</div>`;
    if (btn) btn.disabled = false;
  }
}

$('addPreview').addEventListener('click', () =>
  preview('add', $('addDomain').value.trim(), $('addNote').value));
$('addDomain').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('addPreview').click();
});

let CHANGES = [];
async function loadChanges() {
  try {
    CHANGES = (await api('/api/changes')).changes;
    renderChanges();
  } catch (e) { /* ignore */ }
}
function renderChanges() {
  $('changeBody').innerHTML = CHANGES.length ? CHANGES.map((c) => `<tr>
    <td>${hhmmss(c.ts)}</td><td>${esc(c.action)}</td>
    <td class="name">${esc(c.target)}</td>
    <td>${c.ok ? '<span class="tag ok">ok</span>'
               : '<span class="tag bad">' + esc(msg(c.error) || '!') + '</span>'}</td>
    <td class="name">${esc(c.backup || '')}</td></tr>`).join('')
    : emptyRow(5, t('allow.noHistory'));
}

/* ================= lookup ================= */
let LAST_LOOKUP = null;
$('lkResolver').value = LOCAL_IP;
$('lkGo').addEventListener('click', doLookup);
$('lkName').addEventListener('keydown', (e) => { if (e.key === 'Enter') doLookup(); });

async function doLookup() {
  const name = $('lkName').value.trim();
  if (!name) return;
  $('lkOut').innerHTML = `<div class="card"><div class="alert info">${t('lk.querying')}</div></div>`;
  try {
    LAST_LOOKUP = await api('/api/lookup?name=' + encodeURIComponent(name) +
      '&resolver=' + encodeURIComponent($('lkResolver').value.trim()));
    renderLookup(LAST_LOOKUP);
  } catch (e) {
    $('lkOut').innerHTML = `<div class="card"><div class="alert error">${esc(e.message)}</div></div>`;
  }
}

function renderLookup(d) {
  if (!d) return;
  const parts = ['<div class="card">'];
  parts.push(`<div class="alert ${d.is_proxied ? 'ok' : 'info'}"><strong>${esc(msg(d.verdict))}</strong></div>`);
  d.warnings.forEach((w) => parts.push(`<div class="alert warn">${esc(msg(w))}</div>`));

  parts.push('<dl class="kv">' +
    `<dt>${t('lk.queryName')}</dt><dd>${esc(d.name)}</dd>` +
    `<dt>${t('lk.matched')}</dt><dd>${d.matched_suffix ? esc(d.matched_suffix) : t('lk.none')}</dd>` +
    `<dt>${t('lk.bareRoot')}</dt><dd>${d.is_bare_root}</dd>` +
    `<dt>${t('lk.resolver')}</dt><dd>${esc(d.resolver)}</dd>` +
    `<dt>${t('lk.expected')}</dt><dd>${esc(d.spoof_ip || '—')}</dd>` +
    `<dt>${t('lk.spoofedTo')}</dt><dd>${d.spoofed_now ? esc((d.spoofed_to || []).join(', ')) : 'no'}</dd>` +
    '</dl>');

  ['A', 'AAAA', 'HTTPS'].forEach((qt) => {
    const r = d.dig[qt] || {};
    const ans = (r.answers || []).length ? esc(r.answers.join('\n')) : t('lk.noAnswer');
    const note = (qt !== 'A' && d.is_proxied && (r.answers || []).length)
      ? ` <span class="tag bad">${t('lk.shouldSuppress')}</span>` : '';
    parts.push(`<h2>dig ${qt}${note}</h2><pre class="diff">` +
      (r.error ? esc(r.error) + '\n' : '') + ans + '</pre>');
  });

  if (d.covering_candidates.length) {
    parts.push(`<h2>${t('lk.covering')}</h2><pre class="diff">` +
      esc(d.covering_candidates.join('\n')) + '</pre>');
  }
  parts.push('</div>');
  $('lkOut').innerHTML = parts.join('');
}

/* ================= peer diff ================= */
let PASTE_HINT = null;
let LAST_PEER = null;

async function peerProbe() {
  try {
    const d = await api('/api/peer/probe');
    PASTE_HINT = d.paste_hint;
    $('peerPasteHint').textContent = msg(PASTE_HINT);
    $('peerMeta').textContent = d.enabled
      ? `${d.name} @ ${d.host}: ` +
        (d.reachable ? t('peer.reachable') : t('peer.unreachable') + ' — ' + msg(d.message))
      : msg(d.message);
    $('peerFetch').disabled = !(d.enabled && d.reachable);
  } catch (e) { $('peerMeta').textContent = e.message; }
}

function renderPeer(d) {
  if (!d) return;
  const parts = ['<div class="card">'];
  parts.push(`<div class="alert ${d.in_sync ? 'ok' : 'warn'}"><strong>${esc(msg(d.message))}</strong></div>`);
  parts.push(`<p class="meta">${esc(t('peer.counts', {
    a: d.my_name, x: d.my_count, b: d.their_name, y: d.their_count }))}</p>`);
  if (d.only_mine.length) {
    parts.push(`<h2>${esc(t('peer.onlyOn', { s: d.my_name, n: d.only_mine.length }))}</h2>` +
      '<pre class="diff">' + d.only_mine.map((s) => `<span class="del">${esc(s)}</span>`).join('\n') + '</pre>');
  }
  if (d.only_theirs.length) {
    parts.push(`<h2>${esc(t('peer.onlyOn', { s: d.their_name, n: d.only_theirs.length }))}</h2>` +
      '<pre class="diff">' + d.only_theirs.map((s) => `<span class="add">${esc(s)}</span>`).join('\n') + '</pre>');
  }
  parts.push('</div>');
  $('peerOut').innerHTML = parts.join('');
}

$('peerProbe').addEventListener('click', peerProbe);
$('peerFetch').addEventListener('click', async () => {
  $('peerOut').innerHTML = `<div class="card"><div class="alert info">${t('peer.fetching')}</div></div>`;
  try { LAST_PEER = await api('/api/peer/diff'); renderPeer(LAST_PEER); }
  catch (e) { $('peerOut').innerHTML = `<div class="card"><div class="alert error">${esc(e.message)}</div></div>`; }
});
$('peerPasteGo').addEventListener('click', async () => {
  try {
    LAST_PEER = await api('/api/peer/paste', {
      method: 'POST', body: { text: $('peerPaste').value, peer_name: PEER_NAME },
    });
    renderPeer(LAST_PEER);
  } catch (e) {
    $('peerOut').innerHTML = `<div class="card"><div class="alert error">${esc(e.message)}</div></div>`;
  }
});

/* ================= backups ================= */
let BACKUPS = null;
async function loadBackups() {
  try {
    BACKUPS = await api('/api/backups');
    renderBackups();
  } catch (e) { $('bkMeta').textContent = e.message; }
}
function renderBackups() {
  if (!BACKUPS) return;
  const d = BACKUPS;
  $('bkMeta').textContent = t('bk.count', { n: d.backups.length, d: d.dir });
  $('bkBody').innerHTML = d.backups.length ? d.backups.map((b) => `<tr>
    <td class="name">${esc(b.name)}</td><td>${ago(b.mtime)}</td>
    <td class="num">${bytes(b.size)}</td>
    <td><button class="ghost" data-bk="${esc(b.name)}">${t('bk.diffBtn')}</button></td>
  </tr>`).join('') : emptyRow(4, t('bk.none'));
  $('bkBody').querySelectorAll('button[data-bk]').forEach((b) => {
    b.addEventListener('click', () => showBackup(b.dataset.bk));
  });
}

async function showBackup(name) {
  const r = await fetch(BASE + '/api/backups/diff?name=' + encodeURIComponent(name));
  const text = await r.text();
  const el = $('bkDiff');
  el.dataset.loaded = '1';
  el.innerHTML = text.trim() ? diffHtml(text) : esc(t('bk.identical'));
  $('bkRestore').innerHTML = `<div class="confirm-row">
    <span class="lbl">${t('bk.restoreHint')}</span>
    <input id="bkConfirm" size="12" autocomplete="off" dir="ltr">
    <button id="bkGo" class="danger">${esc(t('bk.restoreBtn', { n: name }))}</button>
  </div><div id="bkOut"></div>`;
  $('bkGo').addEventListener('click', async () => {
    $('bkGo').disabled = true;
    try {
      const r2 = await api('/api/backups/restore', {
        method: 'POST', body: { name, confirm: $('bkConfirm').value.trim() },
      });
      $('bkOut').innerHTML = `<div class="alert ${r2.ok ? 'ok' : 'error'}">` +
        (r2.ok ? t('bk.restored') : esc(msg(r2.error) || t('allow.failed'))) + '</div>';
      loadBackups();
    } catch (e) {
      $('bkOut').innerHTML = `<div class="alert error">${esc(e.message)}</div>`;
      $('bkGo').disabled = false;
    }
  });
}
$('bkReload').addEventListener('click', loadBackups);

/* ================= port watch ================= */
let pwTimer = null;
let LAST_PW = null;

async function pollPortwatch() {
  try { LAST_PW = await api('/api/portwatch'); renderPortwatch(LAST_PW); }
  catch (e) { $('pwOut').innerHTML = `<div class="card"><div class="alert error">${esc(e.message)}</div></div>`; }
}

function renderPortwatch(d) {
  if (!d) return;
  const parts = ['<div class="card">'];
  if (!d.available) parts.push(`<div class="alert error">${esc(d.unavailable_reason)}</div>`);
  if (!d.config_enabled) parts.push(`<div class="alert info">${t('pw.disabled')}</div>`);
  if (d.error) parts.push(`<div class="alert warn">${esc(d.error)}</div>`);

  let line = d.running ? t('pw.capturing') : t('pw.stopped');
  if (d.running) {
    line += ' ' + t('pw.detail', {
      i: d.interface, s: Math.round(d.runtime_s), m: d.max_runtime_s, p: d.pending });
  }
  line += ' · ' + t('pw.ignoring', { p: (d.ignore_ports || []).join(', ') });
  parts.push(`<p class="meta">${esc(line)}</p>`);

  if (d.rows && d.rows.length) {
    parts.push('<div class="scroll tall"><table class="t"><thead><tr>' +
      `<th>${t('col.client')}</th><th>${t('col.dest')}</th><th>${t('col.port')}</th>` +
      `<th>${t('col.unans')}</th><th>${t('col.ans')}</th><th>${t('col.reading')}</th>` +
      '</tr></thead><tbody>' +
      d.rows.map((r) => `<tr class="${r.unanswered ? 'problem' : ''}">
        <td>${esc(r.client_ip)}</td><td>${esc(r.dst_ip)}</td>
        <td class="num">${r.dport}</td><td class="num">${r.unanswered}</td>
        <td class="num">${r.answered}</td>
        <td class="wrap">${esc(msg(r.verdict))}</td></tr>`).join('') +
      '</tbody></table></div>');
  } else if (d.running) {
    parts.push(`<p class="meta">${t('pw.noneYet')}</p>`);
  }
  parts.push('</div>');
  $('pwOut').innerHTML = parts.join('');

  clearTimeout(pwTimer);
  if (d.running && $('tab-ports').classList.contains('active')) {
    pwTimer = setTimeout(pollPortwatch, 2000);
  }
}

$('pwStart').addEventListener('click', async () => {
  try {
    LAST_PW = await api('/api/portwatch', {
      method: 'POST', body: { action: 'start', client_ip: $('pwClient').value.trim() },
    });
    renderPortwatch(LAST_PW);
  } catch (e) { $('pwOut').innerHTML = `<div class="card"><div class="alert error">${esc(e.message)}</div></div>`; }
});
$('pwStop').addEventListener('click', async () => {
  try {
    LAST_PW = await api('/api/portwatch', { method: 'POST', body: { action: 'stop' } });
    renderPortwatch(LAST_PW);
  } catch (e) { /* ignore */ }
});

/* ================= logs ================= */
$('logGo').addEventListener('click', async () => {
  const which = $('logWhich').value;
  const lines = $('logLines').value;
  $('logOut').textContent = t('logs.loading');
  const r = await fetch(BASE + `/api/logs/${encodeURIComponent(which)}?lines=${encodeURIComponent(lines)}`);
  $('logOut').textContent = await r.text();
});


/* ================= role ================= */
/* Buttons are hidden for a viewer as a courtesy; the server enforces it. */
function applyRole() {
  const chip = $('roleChip');
  if (READONLY) {
    chip.textContent = t('role.viewer');
    chip.className = 'chip warn';
    chip.title = t('role.viewerHint');
    document.querySelectorAll('[data-writes]').forEach((el) => {
      el.disabled = true;
      el.title = t('role.viewerHint');
    });
  } else {
    chip.className = 'chip hidden';
  }
}

/* ================= events ================= */
let EVENTS = null;

function severityClass(sev) {
  return sev === 'critical' ? 'error' : sev === 'warning' ? 'warn' : 'info';
}
function dur(from, to) {
  const secs = Math.max(0, (to || Date.now() / 1000) - from);
  if (secs < 90) return Math.round(secs) + 's';
  if (secs < 5400) return Math.round(secs / 60) + 'm';
  if (secs < 172800) return (secs / 3600).toFixed(1) + 'h';
  return (secs / 86400).toFixed(1) + 'd';
}

function onEvents(d) {
  if (!d) return;
  updateEventBadge(d.open || []);
  if (EVENTS) { EVENTS.open = d.open; renderEvents(); }
}

function updateEventBadge(open) {
  const btn = $('eventsBtn');
  const n = (open || []).length;
  $('eventsCount').textContent = n;
  btn.classList.toggle('hidden', n === 0);
  const worst = (open || []).some((e) => e.severity === 'critical') ? 'crit'
    : (open || []).some((e) => e.severity === 'warning') ? 'warn' : 'info';
  btn.className = 'badge-btn ' + worst + (n === 0 ? ' hidden' : '');
}

$('eventsBtn').addEventListener('click', () => {
  document.querySelector('.tab[data-tab="events"]').click();
});

async function loadEvents() {
  try { EVENTS = await api('/api/events?limit=200'); renderEvents(); }
  catch (e) { $('evOpen').innerHTML = `<div class="alert error">${esc(e.message)}</div>`; }
}

function renderEvents() {
  if (!EVENTS) return;
  const d = EVENTS;
  if (!d.enabled) {
    $('evOpen').innerHTML = `<div class="alert info">${t('events.disabled')}</div>`;
    $('evHistory').innerHTML = emptyRow(5, '—');
    return;
  }
  const open = d.open || [];
  updateEventBadge(open);

  $('evOpen').innerHTML = open.length ? open.map((e) => `
    <div class="alert ${severityClass(e.severity)}">
      <strong>${esc(e.subject || e.kind)}</strong>
      <span class="tag">${esc(t('events.since', { d: dur(e.started_at) }))}</span>
      ${e.acked_at ? `<span class="tag ok">${t('events.acked')}</span>` : ''}
      <div>${esc(LANG === 'fa' ? (e.detail_fa || e.detail_en) : e.detail_en)}</div>
      ${e.acked_at || READONLY ? '' :
        `<button class="ghost ev-ack" data-id="${e.id}">${t('events.ack')}</button>`}
    </div>`).join('')
    : `<div class="alert ok">${t('events.none')}</div>`;

  $('evOpen').querySelectorAll('.ev-ack').forEach((b) => {
    b.addEventListener('click', async () => {
      b.disabled = true;
      try { await api('/api/events/ack', { method: 'POST', body: { id: +b.dataset.id } }); }
      catch (e) { /* surfaced on reload */ }
      loadEvents();
    });
  });

  const rows = d.recent || [];
  $('evHistory').innerHTML = rows.length ? rows.map((e) => `<tr>
    <td><span class="tag ${e.severity === 'critical' ? 'bad'
      : e.severity === 'warning' ? 'warn' : ''}">${esc(e.severity)}</span></td>
    <td>${hhmmss(e.started_at)}</td>
    <td>${esc(dur(e.started_at, e.resolved_at))}${e.resolved_at ? '' : ' …'}</td>
    <td class="name">${esc(e.subject || e.kind)}</td>
    <td class="wrap">${esc(LANG === 'fa' ? (e.detail_fa || e.detail_en) : e.detail_en)}</td>
  </tr>`).join('') : emptyRow(5, t('events.none'));

  const notif = (d.notifiers || []).filter((n) => n !== 'log');
  $('evMeta').textContent = notif.length
    ? t('events.notifiers', { n: notif.join(', ') })
    : t('events.inAppOnly');
}
$('evReload').addEventListener('click', loadEvents);

/* ================= traffic ================= */
let TRAFFIC = null;

/* Inline SVG rather than a chart library: the CSP forbids external scripts and
   the box may have no outbound HTTP at all. */
function sparkChart(series, opts) {
  const w = 900, h = 180, pad = 34;
  if (!series.length) {
    return `<div class="empty">${esc(opts.empty)}</div>`;
  }
  const maxV = Math.max(1, ...series.map((p) => (p.from_origin || 0) + (p.to_origin || 0)));
  const n = series.length;
  const bw = Math.max(1, (w - pad * 2) / n);
  const bars = series.map((p, i) => {
    const total = (p.from_origin || 0) + (p.to_origin || 0);
    const fh = ((p.from_origin || 0) / maxV) * (h - pad * 2);
    const th = ((p.to_origin || 0) / maxV) * (h - pad * 2);
    const x = pad + i * bw;
    const problem = (p.problems || 0) > 0;
    const title = `${new Date(p.bucket * 1000).toLocaleString()}\n` +
      `${opts.fromLabel}: ${bytes(p.from_origin)}\n${opts.toLabel}: ${bytes(p.to_origin)}\n` +
      `${opts.connLabel}: ${p.conns}${problem ? ' / ' + p.problems + '!' : ''}`;
    return `<g><title>${esc(title)}</title>` +
      `<rect x="${x.toFixed(1)}" y="${(h - pad - fh).toFixed(1)}" ` +
      `width="${Math.max(1, bw - 1).toFixed(1)}" height="${fh.toFixed(1)}" ` +
      `class="bar-from"/>` +
      `<rect x="${x.toFixed(1)}" y="${(h - pad - fh - th).toFixed(1)}" ` +
      `width="${Math.max(1, bw - 1).toFixed(1)}" height="${th.toFixed(1)}" ` +
      `class="bar-to"/>` +
      (problem ? `<rect x="${x.toFixed(1)}" y="${h - pad + 2}" ` +
        `width="${Math.max(1, bw - 1).toFixed(1)}" height="3" class="bar-bad"/>` : '') +
      `</g>`;
  }).join('');
  const first = new Date(series[0].bucket * 1000).toLocaleTimeString().slice(0, 5);
  const last = new Date(series[n - 1].bucket * 1000).toLocaleTimeString().slice(0, 5);
  return `<svg viewBox="0 0 ${w} ${h}" class="chart" preserveAspectRatio="none"
               role="img" aria-label="${esc(opts.empty)}">
    <line x1="${pad}" y1="${h - pad}" x2="${w - pad}" y2="${h - pad}" class="axis"/>
    <text x="${pad}" y="18" class="axis-text">${esc(bytes(maxV))}</text>
    <text x="${pad}" y="${h - 8}" class="axis-text">${esc(first)}</text>
    <text x="${w - pad}" y="${h - 8}" class="axis-text" text-anchor="end">${esc(last)}</text>
    ${bars}
  </svg>
  <div class="legend">
    <span><i class="sw sw-from"></i>${esc(opts.fromLabel)}</span>
    <span><i class="sw sw-to"></i>${esc(opts.toLabel)}</span>
    <span><i class="sw sw-bad"></i>${esc(opts.problemLabel)}</span>
  </div>`;
}

async function loadTraffic() {
  if (!HISTORY_ENABLED) {
    $('trChart').innerHTML = `<div class="alert info">${t('traffic.historyOff')}</div>`;
    $('trClients').innerHTML = emptyRow(5, '—');
    $('trSnis').innerHTML = emptyRow(4, '—');
    return;
  }
  const hours = $('trHours').value;
  const ip = $('trClient').value.trim();
  try {
    TRAFFIC = await api(`/api/traffic?hours=${encodeURIComponent(hours)}` +
      (ip ? `&client_ip=${encodeURIComponent(ip)}` : ''));
    renderTraffic();
  } catch (e) {
    $('trChart').innerHTML = `<div class="alert error">${esc(e.message)}</div>`;
  }
}

function renderTraffic() {
  if (!TRAFFIC) return;
  const d = TRAFFIC;
  $('trChart').innerHTML = sparkChart(d.series || [], {
    empty: t('traffic.empty'),
    fromLabel: t('traffic.fromOrigin'),
    toLabel: t('traffic.toOrigin'),
    connLabel: t('col.conns'),
    problemLabel: t('col.problems'),
  });
  const pr = d.problem_rate || {};
  $('trMeta').textContent = t('traffic.summary', {
    c: pr.conns || 0, p: pr.problems || 0,
    r: Math.round((pr.rate || 0) * 100),
  });

  $('trClients').innerHTML = (d.top_clients || []).length
    ? d.top_clients.map((r) => `<tr class="${r.problems ? 'problem' : ''}">
        <td>${esc(r.client_ip)}</td>
        <td class="num">${r.conns}</td>
        <td class="num">${r.problems}</td>
        <td class="num">${bytes((r.from_origin || 0) + (r.to_origin || 0))}</td>
        <td><button class="ghost" data-dbg="${esc(r.client_ip)}">${t('dbg.watch')}</button></td>
      </tr>`).join('')
    : emptyRow(5, t('traffic.empty'));
  $('trClients').querySelectorAll('button[data-dbg]').forEach((b) => {
    b.addEventListener('click', () => {
      document.querySelector('.tab[data-tab="debug"]').click();
      $('dbgClient').value = b.dataset.dbg;
      dbgLoad(b.dataset.dbg);
    });
  });

  $('trSnis').innerHTML = (d.top_snis || []).length
    ? d.top_snis.map((r) => `<tr class="${r.problems ? 'problem' : ''}">
        <td class="name">${esc(r.sni)}</td>
        <td class="num">${r.conns}</td>
        <td class="num">${r.problems}</td>
        <td class="num">${bytes((r.from_origin || 0) + (r.to_origin || 0))}</td>
      </tr>`).join('')
    : emptyRow(4, t('traffic.empty'));
}
$('trReload').addEventListener('click', loadTraffic);
$('trHours').addEventListener('change', loadTraffic);
$('trClient').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadTraffic(); });

/* ================= audit ================= */
let AUDIT = null, REGISTRY = null;

async function loadAudit() {
  try {
    AUDIT = await api('/api/audit?limit=300' +
      `&action=${encodeURIComponent($('auAction').value.trim())}` +
      `&who=${encodeURIComponent($('auWho').value.trim())}`);
    renderAudit();
  } catch (e) { $('auBody').innerHTML = emptyRow(6, e.message); }
}

function renderAudit() {
  if (!AUDIT) return;
  if (!AUDIT.history_enabled) {
    $('auBody').innerHTML = emptyRow(6, t('audit.historyOff'));
    return;
  }
  const rows = AUDIT.entries || [];
  $('auBody').innerHTML = rows.length ? rows.map((a) => {
    const cls = a.outcome === 'applied' || a.outcome === 'ok' ? 'ok'
      : a.outcome === 'refused' ? 'warn' : 'bad';
    return `<tr>
      <td title="${esc(new Date(a.ts * 1000).toLocaleString())}">${hhmmss(a.ts)}</td>
      <td>${esc(a.actor)}${a.actor_ip ? ' <span class="dim">' + esc(a.actor_ip) + '</span>' : ''}</td>
      <td>${esc(a.action)}</td>
      <td class="name">${esc(a.target)}</td>
      <td><span class="tag ${cls}">${esc(a.outcome)}</span></td>
      <td class="wrap">${esc((a.detail || '').slice(0, 200))}</td>
    </tr>`;
  }).join('') : emptyRow(6, '—');
  $('auMeta').textContent = `${rows.length}`;
}
$('auReload').addEventListener('click', loadAudit);
['auAction', 'auWho'].forEach((id) =>
  $(id).addEventListener('keydown', (e) => { if (e.key === 'Enter') loadAudit(); }));

async function loadRegistry() {
  try {
    REGISTRY = await api('/api/registry?limit=400' +
      `&contains=${encodeURIComponent($('regFilter').value.trim())}` +
      `&upstream_only=${$('regUpstream').checked}`);
    renderRegistry();
  } catch (e) { $('regBody').innerHTML = emptyRow(5, e.message); }
}

function renderRegistry() {
  if (!REGISTRY) return;
  if (!REGISTRY.history_enabled) {
    $('regBody').innerHTML = emptyRow(5, t('audit.historyOff'));
    return;
  }
  const rows = REGISTRY.domains || [];
  $('regBody').innerHTML = rows.length ? rows.map((r) => `<tr>
    <td class="name">${esc(r.name)}</td>
    <td title="${esc(new Date(r.first_seen * 1000).toLocaleString())}">${ago(r.first_seen)}</td>
    <td>${ago(r.last_seen)}</td>
    <td class="num">${r.times_seen}</td>
    <td>${r.matched_suffix
      ? '<span class="tag ok">' + esc(r.matched_suffix) + '</span>'
      : '<span class="dim">—</span>'}</td>
  </tr>`).join('') : emptyRow(5, '—');
}
$('regReload').addEventListener('click', loadRegistry);
$('regFilter').addEventListener('input', () => { clearTimeout(window.__rt);
  window.__rt = setTimeout(loadRegistry, 300); });
$('regUpstream').addEventListener('change', loadRegistry);

/* ================= groups ================= */
let GROUPS = null;

async function loadGroups() {
  try { GROUPS = await api('/api/groups'); renderGroups(); }
  catch (e) { $('groupsBox').innerHTML = `<div class="alert error">${esc(e.message)}</div>`; }
}

function renderGroups() {
  if (!GROUPS) return;
  const g = GROUPS.groups || [];
  $('groupCount').textContent = `(${g.length})`;
  $('groupsBox').innerHTML = g.length ? `<div class="group-list">` + g.map((x) => {
    const cls = x.state === 'on' ? 'ok' : x.state === 'off' ? 'warn' : '';
    // Explicit map rather than a built key, so the translation-completeness
    // check in CI can see every string that is actually reachable.
    const label = x.state === 'on' ? t('groups.on')
      : x.state === 'off' ? t('groups.off') : t('groups.mixed');
    const act = x.state === 'off' ? 'group-enable' : 'group-disable';
    const actLabel = x.state === 'off' ? t('groups.turnOn') : t('groups.turnOff');
    return `<div class="group-row">
      <span class="pill ${cls}">${esc(label)}</span>
      <strong class="mono">${esc(x.name)}</strong>
      <span class="meta">${x.active_count} on / ${x.disabled_count} off</span>
      <button class="ghost" data-writes data-grp="${esc(x.name)}"
              data-act="${act}">${esc(actLabel)}</button>
      <details><summary class="meta">${x.active.concat(x.disabled).length} entries</summary>
        <pre class="diff">${esc(x.active.map((s) => '+ ' + s)
          .concat(x.disabled.map((s) => '- ' + s)).join('\n'))}</pre></details>
    </div>`;
  }).join('') + '</div>'
    : `<div class="empty">${t('groups.none')}</div>`;

  if (GROUPS.ungrouped) {
    $('groupsBox').insertAdjacentHTML('beforeend',
      `<p class="meta">${esc(t('groups.ungrouped', { n: GROUPS.ungrouped }))}</p>`);
  }
  $('groupsBox').querySelectorAll('button[data-grp]').forEach((b) => {
    b.addEventListener('click', () => {
      document.querySelector('.tab[data-tab="allow"]').click();
      preview(b.dataset.act, b.dataset.grp, t('allow.disableNote'));
      $('planBox').scrollIntoView({ block: 'nearest' });
    });
  });

  const dis = GROUPS.disabled || [];
  $('disabledBox').innerHTML = dis.length ? `<div class="scroll short">
    <table class="t"><tbody>${dis.map((e) => `<tr>
      <td class="name">${esc(e.suffix)}</td>
      <td class="dim">${esc(e.group || '')}</td>
      <td><button class="ghost" data-writes data-en="${esc(e.suffix)}">${t('groups.enableOne')}</button></td>
    </tr>`).join('')}</tbody></table></div>`
    : `<div class="empty">${t('groups.noneDisabled')}</div>`;
  $('disabledBox').querySelectorAll('button[data-en]').forEach((b) => {
    b.addEventListener('click', () => preview('enable', b.dataset.en, ''));
  });
  applyRole();
}

/* ================= probe ================= */
let PROBE = null;

$('probeBtn').addEventListener('click', runProbe);

async function runProbe() {
  const name = $('addDomain').value.trim();
  if (!name) return;
  if (!PROBE_ENABLED) {
    $('probeBox').innerHTML = `<div class="alert info">${t('probe.disabled')}</div>`;
    return;
  }
  $('probeBox').innerHTML = `<div class="alert info">${t('probe.running')}</div>`;
  try { PROBE = await api('/api/probe', { method: 'POST', body: { domain: name } }); renderProbe(); }
  catch (e) { $('probeBox').innerHTML = `<div class="alert error">${esc(e.message)}</div>`; }
}

function renderProbe() {
  if (!PROBE) return;
  const p = PROBE;
  const cls = p.proxyable === true ? 'ok' : p.proxyable === false ? 'error' : 'warn';
  const parts = [`<div class="alert ${cls}"><strong>${esc(msg(p.verdict))}</strong>`];
  if (p.recommendation) parts.push(`<div>${esc(msg(p.recommendation))}</div>`);
  parts.push('</div>');

  if (p.already_listed) {
    parts.push(`<div class="alert info">${esc(
      t('probe.alreadyListed', { s: p.matched_suffix }))}</div>`);
  }
  const r = p.resolve || {};
  const tls = p.tls || {}, http = p.http || {};
  const openPorts = (p.ports || []).filter((x) => x.open).map((x) => x.port);
  parts.push('<dl class="kv">' +
    `<dt>${t('probe.resolved')}</dt><dd>${esc((r.addresses || []).join(', ') || '—')}</dd>` +
    `<dt>${t('probe.tls')}</dt><dd>${tls.ok ? '✓ ' + esc(tls.protocol || '')
      : '✗ ' + esc(tls.error || '')}</dd>` +
    `<dt>${t('probe.http')}</dt><dd>${http.ok ? '✓ ' + (http.status || '')
      : '✗ ' + esc(http.error || '')}</dd>` +
    `<dt>${t('probe.otherPorts')}</dt><dd>${openPorts.length
      ? esc(openPorts.join(', ')) : t('probe.none')}</dd>` +
    '</dl>');
  if ((p.reasons || []).length) {
    parts.push('<ul class="reasons">' +
      p.reasons.map((x) => `<li>${esc(msg(x))}</li>`).join('') + '</ul>');
  }
  $('probeBox').innerHTML = parts.join('');
}

/* ================= re-render on language change ================= */
function redrawAll() {
  redrawFeed();
  renderClientRows(LAST_CLIENT_ROWS);
  renderUnproxied(LAST_GREPQ);
  renderAllowIssues(window.__allowMeta);
  renderAllow();
  renderChanges();
  renderPlan(LAST_PLAN);
  renderLookup(LAST_LOOKUP);
  renderPeer(LAST_PEER);
  renderBackups();
  renderPortwatch(LAST_PW);
  renderStatus(LAST_STATUS);
  renderGroups();
  renderTraffic();
  renderEvents();
  renderAudit();
  renderRegistry();
  renderProbe();
  applyRole();
  const hint = $('dbgPermitHint');
  if (hint.dataset.msgEn) {
    hint.textContent = LANG === 'fa' ? hint.dataset.msgFa : hint.dataset.msgEn;
  }
}

/* ================= boot ================= */
applyTheme();
applyLang();
connectSSE();
api('/api/status').then(renderStatus).catch(() => {});
api('/api/peer/probe').then((d) => {
  PASTE_HINT = d.paste_hint;
  $('peerPasteHint').textContent = msg(PASTE_HINT);
}).catch(() => {});
loadClients();
setInterval(loadClients, 20000);
applyRole();

/* Install to a phone home screen. Only over a secure context, which a service
   worker requires anyway - plain HTTP over an SSH tunnel counts as secure
   because the origin is localhost. */
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register(BASE + '/static/sw.js',
                                     { scope: BASE + '/' })
      .catch(() => { /* not fatal: the dashboard works without it */ });
  });
}
if (ALERTS_ENABLED) loadEvents();

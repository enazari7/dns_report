"""Active probe: can this host actually be proxied?

Choosing what to add to the allow-list is the one decision the dashboard
deliberately leaves to a human, because getting it wrong breaks things — the
CODM downloader, CODM voice chat and Clash of Clans were each broken by a
speculative addition. This module does not take the decision away. It gathers
the evidence the decision needs, which was previously guesswork.

Three questions decide it, and all three can be answered from the server:

1. **Does it speak TLS with an SNI on 443?** sniproxy routes by reading the SNI
   out of the ClientHello. If a real TLS handshake completes when we send that
   name as the SNI, sniproxy will be able to route it. If the port accepts a
   connection but the handshake fails, it is something else wearing port 443.

2. **Does it answer HTTP with a Host header on 80?** The other thing sniproxy
   can route on.

3. **Is it already reachable directly?** If it is, proxying it is a regression,
   not a fix — this is the question people forget to ask.

Plus one more that catches the specific trap:

4. **Are there other ports involved?** A host whose 443 is dead but which has
   8080/8085/8013 open is the Tencent GCloud signature. Proxying the domain
   makes the game open and never download.

Everything is done with stdlib sockets, short timeouts, and no data sent beyond
what a handshake requires. Nothing here writes anything or changes any state.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket
import ssl
import time

from . import i18n
from .i18n import M

# Ports checked for reachability beyond 80/443. 8080/8085/8013 are the CODM
# downloader; the rest are common game data channels.
EXTRA_PORTS = (8080, 8085, 8013, 8000, 8443, 7000, 10012, 17500)

DEFAULT_TIMEOUT = 4.0


def _resolve(name: str, timeout: float = 4.0) -> dict:
    """Resolve without going through the local (spoofing) resolver.

    getaddrinfo would hit this server's own dnsdist, which for a listed name
    returns the spoof address - so the probe would end up testing the proxy
    against itself. Resolution therefore uses an explicit upstream.
    """
    out = {"addresses": [], "error": None, "resolver": "system"}
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(name, None, socket.AF_INET,
                                   socket.SOCK_STREAM)
        out["addresses"] = sorted({i[4][0] for i in infos})
    except (OSError, socket.gaierror) as exc:
        out["error"] = str(exc)
    finally:
        socket.setdefaulttimeout(None)
    return out


def resolve_via(name: str, resolver: str, timeout: float = 3.0) -> dict:
    """Resolve A records by asking a specific server, using a hand-built query.

    Small enough not to justify a dependency, and it keeps the probe honest
    about which resolver produced the answer.
    """
    out = {"addresses": [], "error": None, "resolver": resolver}
    try:
        qname = b"".join(bytes([len(p)]) + p
                         for p in name.encode("idna").split(b".")) + b"\x00"
        msg = (b"\x12\x34"          # id
               b"\x01\x00"          # standard query, recursion desired
               b"\x00\x01\x00\x00\x00\x00\x00\x00"
               + qname + b"\x00\x01\x00\x01")   # A, IN
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(msg, (resolver, 53))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()

        # Skip the header and the echoed question, then walk the answers.
        ancount = int.from_bytes(data[6:8], "big")
        i = 12
        while i < len(data) and data[i]:
            i += data[i] + 1
        i += 5                                   # null label + qtype + qclass
        addrs = []
        for _ in range(ancount):
            if i + 12 > len(data):
                break
            if data[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while i < len(data) and data[i]:
                    i += data[i] + 1
                i += 1
            rtype = int.from_bytes(data[i:i + 2], "big")
            rdlen = int.from_bytes(data[i + 8:i + 10], "big")
            rdata = data[i + 10:i + 10 + rdlen]
            if rtype == 1 and rdlen == 4:
                addrs.append(str(ipaddress.IPv4Address(rdata)))
            i += 10 + rdlen
        out["addresses"] = sorted(set(addrs))
    except (OSError, UnicodeError, ValueError, IndexError) as exc:
        out["error"] = str(exc)
    return out


def tcp_connect(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    t0 = time.monotonic()
    res = {"port": port, "open": False, "ms": None, "error": None}
    try:
        with socket.create_connection((host, port), timeout=timeout):
            res["open"] = True
    except OSError as exc:
        res["error"] = exc.strerror or str(exc)
    res["ms"] = round((time.monotonic() - t0) * 1000)
    return res


def tls_with_sni(host_ip: str, sni: str, port: int = 443,
                 timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Complete a TLS handshake presenting `sni`, and report what came back.

    A completed handshake is the proof sniproxy needs: it means the server
    selected a certificate based on the SNI, which is exactly the mechanism
    sniproxy relies on to route.
    """
    res = {"ok": False, "error": None, "protocol": None, "cipher": None,
           "cert_names": [], "sni_respected": None, "ms": None}
    t0 = time.monotonic()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Not verifying: we are asking "does the handshake complete for this SNI",
    # not "do I trust this host". Verification failures would mask the answer.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host_ip, port),
                                     timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=sni) as tls:
            res["ok"] = True
            res["protocol"] = tls.version()
            cipher = tls.cipher()
            res["cipher"] = cipher[0] if cipher else None
            # With verify_mode = CERT_NONE, Python leaves getpeercert()
            # empty, so read the names out of the DER ourselves.
            names = _names_from_der(tls.getpeercert(binary_form=True))
            res["cert_names"] = names
            res["sni_respected"] = _cert_covers(sni, names)
    except ssl.SSLError as exc:
        res["error"] = f"TLS: {exc.reason or exc}"
    except OSError as exc:
        res["error"] = exc.strerror or str(exc)
    res["ms"] = round((time.monotonic() - t0) * 1000)
    return res


def _names_from_der(der: bytes | None) -> list[str]:
    """Pull DNS names out of a certificate's DER without a crypto library.

    Targeted scan rather than a real ASN.1 parser: find the subjectAltName
    extension by its OID and read the dNSName entries, then fall back to the
    commonName. Good enough for a display hint, and `_cert_covers` returns
    None - "unknown", not "no" - when nothing is found, so a parse miss never
    produces a wrong verdict.
    """
    if not der:
        return []
    names: list[str] = []
    try:
        # subjectAltName = OID 2.5.29.17
        san_oid = b"\x06\x03\x55\x1d\x11"
        idx = der.find(san_oid)
        if idx >= 0:
            # The extension value is an OCTET STRING wrapping a SEQUENCE of
            # GeneralNames; dNSName is context tag 0x82.
            window = der[idx:idx + 4096]
            i = 0
            while i < len(window) - 2:
                if window[i] == 0x82:
                    ln = window[i + 1]
                    if 0 < ln < 254 and i + 2 + ln <= len(window):
                        try:
                            val = window[i + 2:i + 2 + ln].decode("ascii")
                        except UnicodeDecodeError:
                            i += 1
                            continue
                        if val and all(c.isalnum() or c in ".-*_" for c in val):
                            names.append(val)
                        i += 2 + ln
                        continue
                i += 1

        # commonName = OID 2.5.4.3
        cn_oid = b"\x06\x03\x55\x04\x03"
        pos = der.find(cn_oid)
        while pos >= 0 and len(names) < 12:
            j = pos + len(cn_oid)
            if j + 2 <= len(der) and der[j] in (0x0C, 0x13, 0x16):  # UTF8/Printable/IA5
                ln = der[j + 1]
                if 0 < ln < 254 and j + 2 + ln <= len(der):
                    try:
                        val = der[j + 2:j + 2 + ln].decode("utf-8")
                        if val and "." in val:
                            names.append(val)
                    except UnicodeDecodeError:
                        pass
            pos = der.find(cn_oid, pos + 1)
    except (IndexError, ValueError):
        return sorted(set(names))[:12]
    return sorted(set(names))[:12]


def _cert_covers(name: str, cert_names: list[str]) -> bool | None:
    if not cert_names:
        return None
    name = name.lower().rstrip(".")
    for cn in cert_names:
        cn = cn.lower().rstrip(".")
        if cn == name:
            return True
        if cn.startswith("*.") and name.endswith(cn[1:]):
            return True
    return False


def http_with_host(host_ip: str, host_header: str, port: int = 80,
                   timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Send a minimal HEAD with a Host header and read the status line."""
    res = {"ok": False, "status": None, "server": None, "error": None,
           "ms": None}
    t0 = time.monotonic()
    req = (f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\n"
           "User-Agent: smartdns-dashboard-probe/1\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n").encode()
    try:
        with socket.create_connection((host_ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
            buf = b""
            while b"\r\n\r\n" not in buf and len(buf) < 8192:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                buf += chunk
        text = buf.decode("latin-1", errors="replace")
        first = text.split("\r\n", 1)[0]
        if first.upper().startswith("HTTP/"):
            res["ok"] = True
            parts = first.split(None, 2)
            res["status"] = int(parts[1]) if len(parts) > 1 and \
                parts[1].isdigit() else None
        for line in text.split("\r\n")[1:]:
            if line.lower().startswith("server:"):
                res["server"] = line.split(":", 1)[1].strip()[:80]
                break
    except OSError as exc:
        res["error"] = exc.strerror or str(exc)
    res["ms"] = round((time.monotonic() - t0) * 1000)
    return res


def probe(name: str, resolver: str = "1.1.1.1",
          extra_ports: tuple = EXTRA_PORTS,
          timeout: float = DEFAULT_TIMEOUT,
          spoof_ips: set | None = None) -> dict:
    """Everything the operator needs in order to decide, in one call."""
    name = name.strip().lower().rstrip(".")
    result: dict = {
        "name": name,
        "ts": time.time(),
        "resolve": None,
        "tls": None,
        "http": None,
        "ports": [],
        "verdict": None,
        "recommendation": None,
        "reasons": [],
        "proxyable": None,
    }
    if not name or "." not in name:
        result["verdict"] = i18n.plain("not a hostname")
        return result

    # Resolve upstream, not locally: the local resolver would hand back the
    # spoof address for an already-listed name and the probe would test the
    # proxy against itself.
    r = resolve_via(name, resolver, timeout=min(timeout, 3.0))
    if not r["addresses"]:
        r2 = _resolve(name, timeout=timeout)
        if r2["addresses"]:
            r = r2
    result["resolve"] = r

    spoof_ips = spoof_ips or set()
    real = [a for a in r["addresses"] if a not in spoof_ips]
    if not real:
        result["verdict"] = M(
            "Could not resolve this name to a real address. "
            + (f"It resolves only to {', '.join(r['addresses'])}, which is this "
               "deployment's own address - so the answer came from a spoofing "
               "resolver, not upstream."
               if r["addresses"] else (r.get("error") or "No A records.")),
            "این نام به هیچ آدرس واقعی resolve نشد. "
            + (f"فقط به {', '.join(r['addresses'])} حل می‌شود که آدرس خود این "
               "سامانه است — یعنی پاسخ از resolver جعل‌کننده آمده، نه از بالادست."
               if r["addresses"] else (r.get("error") or "رکورد A ندارد.")))
        result["proxyable"] = None
        return result

    target = real[0]

    # Run the checks concurrently: a probe that takes 30 seconds will not get
    # used while someone is on the phone with a player.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        f_tls = pool.submit(tls_with_sni, target, name, 443, timeout)
        f_http = pool.submit(http_with_host, target, name, 80, timeout)
        f_ports = {p: pool.submit(tcp_connect, target, p, min(timeout, 3.0))
                   for p in extra_ports}
        result["tls"] = f_tls.result()
        result["http"] = f_http.result()
        result["ports"] = [f_ports[p].result() for p in extra_ports]

    _decide(result, target)
    return result


def _decide(result: dict, target: str) -> None:
    """Turn the measurements into a recommendation, with its reasoning shown.

    Deliberately opinionated but never automatic: the UI presents this next to
    the raw numbers and still requires a typed confirmation to act.
    """
    tls = result["tls"] or {}
    http = result["http"] or {}
    open_extra = [p["port"] for p in result["ports"] if p["open"]]
    reasons: list[dict] = []

    tls_ok = bool(tls.get("ok"))
    http_ok = bool(http.get("ok"))
    codm_ports = [p for p in open_extra if p in (8080, 8085, 8013)]

    if tls_ok:
        cov = tls.get("sni_respected")
        proto = tls.get("protocol") or "TLS"
        reasons.append(M(
            f"TLS handshake completed on 443 with {name_of(result)} as the SNI "
            f"({proto}). sniproxy can read that SNI and route on it."
            + ("" if cov is not False else
               " The certificate does not cover this name, which is normal "
               "behind a CDN and does not stop sniproxy."),
            f"دست‌دهی TLS روی ۴۴۳ با {name_of(result)} به‌عنوان SNI کامل شد "
            f"({proto}). sniproxy می‌تواند این SNI را بخواند و بر اساسش "
            "مسیریابی کند."
            + ("" if cov is not False else
               " گواهی این نام را پوشش نمی‌دهد، که پشت CDN عادی است و مانع "
               "sniproxy نمی‌شود.")))
    else:
        reasons.append(M(
            f"No TLS handshake on 443 ({tls.get('error') or 'failed'}). "
            "sniproxy has no SNI to route on.",
            f"دست‌دهی TLS روی ۴۴۳ انجام نشد ({tls.get('error') or 'خطا'}). "
            "sniproxy هیچ SNI برای مسیریابی ندارد."))

    if http_ok:
        reasons.append(M(
            f"HTTP on 80 answered with a Host header (status "
            f"{http.get('status')}). sniproxy can route that too.",
            f"HTTP روی ۸۰ با هدر Host پاسخ داد (کد {http.get('status')}). "
            "sniproxy می‌تواند این را هم مسیریابی کند."))

    if codm_ports:
        reasons.append(M(
            f"Ports {', '.join(map(str, codm_ports))} are open. That is the "
            "Tencent GCloud downloader signature: a binary protocol with no "
            "SNI and no Host header, which sniproxy cannot route at all. "
            "Adding the domain will not move this traffic - the game will open "
            "and never download.",
            f"پورت‌های {', '.join(map(str, codm_ports))} باز هستند. این امضای "
            "دانلودر Tencent GCloud است: پروتکل باینری بدون SNI و بدون هدر "
            "Host که sniproxy اصلاً نمی‌تواند مسیریابی‌اش کند. اضافه‌کردن دامنه "
            "این ترافیک را جابه‌جا نمی‌کند — بازی باز می‌شود و هرگز دانلود "
            "نمی‌کند."))
    elif open_extra:
        reasons.append(M(
            f"Other ports open: {', '.join(map(str, open_extra))}. sniproxy "
            "only listens on 80 and 443, so any traffic on those ports keeps "
            "going direct whatever the allow-list says.",
            f"پورت‌های دیگر باز: {', '.join(map(str, open_extra))}. sniproxy "
            "فقط روی ۸۰ و ۴۴۳ گوش می‌دهد، پس ترافیک این پورت‌ها هر چه در لیست "
            "باشد مستقیم می‌رود."))

    reachable = tls_ok or http_ok or bool(open_extra)
    if reachable:
        reasons.append(M(
            f"{target} is reachable from this server right now. If it is also "
            "reachable from the client, adding it is a regression rather than "
            "a fix - the point of the allow-list is names the client cannot "
            "reach directly.",
            f"آدرس {target} همین حالا از این سرور در دسترس است. اگر از سمت "
            "کلاینت هم در دسترس باشد، اضافه‌کردنش یک پس‌رفت است نه راه‌حل — "
            "کاربرد لیست، نام‌هایی است که کلاینت مستقیم به آن‌ها نمی‌رسد."))

    if tls_ok or http_ok:
        result["proxyable"] = True
        if codm_ports:
            result["verdict"] = M(
                "PROXYABLE, BUT NOT ENOUGH",
                "پروکسی‌شدنی است، ولی کافی نیست")
            result["recommendation"] = M(
                "sniproxy can route this host's 80/443 traffic, but it is also "
                f"using {', '.join(map(str, codm_ports))}, which cannot be "
                "proxied. Expect the handshake to work and the payload not to. "
                "Adding it may fix part of the problem and hide the rest.",
                "sniproxy می‌تواند ترافیک ۸۰/۴۴۳ این میزبان را مسیریابی کند، "
                f"اما از پورت‌های {', '.join(map(str, codm_ports))} هم استفاده "
                "می‌کند که پروکسی‌شدنی نیستند. انتظار داشته باش دست‌دهی کار کند "
                "و محتوا نه. اضافه‌کردنش ممکن است بخشی را درست کند و بقیه را "
                "پنهان.")
        else:
            result["verdict"] = M("PROXYABLE", "پروکسی‌شدنی")
            result["recommendation"] = M(
                "sniproxy will be able to route this host. That does not mean "
                "it needs proxying - only add it if the client is actually "
                "failing to reach it directly.",
                "sniproxy می‌تواند این میزبان را مسیریابی کند. این یعنی "
                "پروکسی‌شدنی است، نه اینکه لازم است — فقط وقتی اضافه کن که "
                "کلاینت واقعاً در رسیدن مستقیم به آن ناکام است.")
    else:
        result["proxyable"] = False
        result["verdict"] = M("NOT PROXYABLE", "پروکسی‌شدنی نیست")
        result["recommendation"] = M(
            "Neither a TLS handshake on 443 nor an HTTP response on 80. "
            "sniproxy routes on the SNI or the Host header and would have "
            "neither, so adding this domain cannot help and will break the "
            "direct path that does work."
            + (f" Traffic appears to be on {', '.join(map(str, open_extra))} "
               "instead." if open_extra else ""),
            "نه دست‌دهی TLS روی ۴۴۳ و نه پاسخ HTTP روی ۸۰. sniproxy بر اساس "
            "SNI یا هدر Host مسیریابی می‌کند و هیچ‌کدام را نخواهد داشت، پس "
            "اضافه‌کردن این دامنه کمکی نمی‌کند و مسیر مستقیمی را که کار می‌کند "
            "خراب می‌کند."
            + (f" ترافیک به‌نظر روی {', '.join(map(str, open_extra))} است."
               if open_extra else ""))

    result["reasons"] = reasons
    result["target"] = target


def name_of(result: dict) -> str:
    return result.get("name", "")


def selftest(name: str = "example.com", resolver: str = "1.1.1.1") -> int:
    print(f"--- probing {name} via {resolver} ---")
    r = probe(name, resolver=resolver)
    print(f"  resolve  : {r['resolve']}")
    if r.get("tls"):
        t = r["tls"]
        print(f"  tls 443  : ok={t['ok']} proto={t['protocol']} "
              f"sni_respected={t['sni_respected']} err={t['error']}")
    if r.get("http"):
        h = r["http"]
        print(f"  http 80  : ok={h['ok']} status={h['status']} err={h['error']}")
    open_ports = [p["port"] for p in r.get("ports", []) if p["open"]]
    print(f"  other    : open={open_ports or 'none'}")
    print(f"  verdict  : {i18n.pick(r.get('verdict'))}")
    print(f"  advice   : {i18n.pick(r.get('recommendation'))}")
    for reason in r.get("reasons", []):
        print(f"    - {i18n.pick(reason)}")
    return 0 if r.get("verdict") else 1

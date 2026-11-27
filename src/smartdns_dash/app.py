"""FastAPI application: routes, auth, SSE.

Everything that changes state goes through a two-phase preview/apply with a
CSRF token and a single-use plan token. Everything else is read-only.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth, i18n
from . import config as configmod
from . import probe as probemod
from .config import Config
from .sources import dnsdist as dd
from .sources import domains as dom
from .sources import peer as peermod
from .sources import portwatch as pwmod
from .sources import sysinfo
from .state import AppState

HERE = os.path.dirname(os.path.abspath(__file__))


def create_app(cfg: Config) -> FastAPI:
    state = AppState(cfg)
    throttle = auth.LoginThrottle(max_attempts=cfg.max_login_attempts)
    templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await state.start()
        try:
            yield
        finally:
            await state.stop()

    app = FastAPI(title="Smart DNS Dashboard", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan,
                  root_path=cfg.root_path)
    app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")),
              name="static")
    app.state.cfg = cfg
    app.state.dash = state

    serving_https = cfg.serving_https
    # A proxy in front may be terminating TLS even though we speak HTTP.
    cookie_secure = serving_https or cfg.behind_proxy

    # -- helpers -------------------------------------------------------
    def client_addr(request: Request) -> str:
        """Real client address, for the login rate limiter.

        Behind a reverse proxy every request appears to come from the proxy,
        which would make the per-IP lockout global. Trust X-Forwarded-For only
        when behind_proxy is set and the immediate peer is an allowed proxy -
        otherwise a client could set the header itself and sidestep the limit.
        """
        peer = request.client.host if request.client else "?"
        if not cfg.behind_proxy:
            return peer
        allowed = {a.strip() for a in cfg.forwarded_allow_ips.split(",")
                   if a.strip()}
        if "*" not in allowed and peer not in allowed:
            return peer
        fwd = request.headers.get("x-forwarded-for", "")
        first = fwd.split(",")[0].strip()
        return first or peer

    def session_of(request: Request) -> dict | None:
        token = request.cookies.get(auth.COOKIE_NAME)
        return auth.read_token(cfg.secret_key, token)

    def require_session(request: Request) -> dict:
        sess = session_of(request)
        if not sess:
            raise HTTPException(status_code=401, detail="not authenticated")
        return sess

    def require_operator(request: Request) -> dict:
        """A session allowed to change things.

        The read-only role exists so someone can be given the dashboard to look
        at without being able to touch the allow-list. Enforced on the server,
        not by hiding buttons.
        """
        sess = require_session(request)
        if sess.get("r") == "viewer":
            raise HTTPException(
                status_code=403,
                detail=i18n.M(
                    "This account is read-only. Sign in as the operator to "
                    "make changes.",
                    "این حساب فقط‌خواندنی است. برای اعمال تغییر با حساب اپراتور "
                    "وارد شو.").get("en"))
        return sess

    def actor(sess: dict, request: Request) -> tuple:
        return (sess.get("u") or "?", client_addr(request))

    def require_csrf(request: Request, sess: dict) -> None:
        given = request.headers.get("X-CSRF-Token")
        if not auth.check_csrf(cfg.secret_key, sess.get("jti", ""), given):
            raise HTTPException(status_code=403, detail="bad or missing CSRF token")

    @app.middleware("http")
    async def ip_allowlist(request: Request, call_next):
        """Reject disallowed source addresses before auth even runs.

        This is the substitute for a reverse proxy's `allow`/`deny` when there
        is no proxy on the box. It is a second lock in front of the password,
        never a replacement for it.
        """
        if cfg.allow_ips:
            addr = client_addr(request)
            if not configmod.allowed_client(cfg, addr):
                return PlainTextResponse("forbidden", status_code=403)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # Still no external origins anywhere: manifest-src and worker-src are
        # needed for the installable-to-home-screen behaviour and are 'self'
        # like everything else.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
            "manifest-src 'self'; worker-src 'self'; "
            "base-uri 'none'; frame-ancestors 'none'")
        if serving_https:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    # -- auth ----------------------------------------------------------
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, error: str = ""):
        if session_of(request):
            return RedirectResponse(cfg.root_path + "/", status_code=302)
        return templates.TemplateResponse(request, "login.html", {
            "error": error,
            "server_name": cfg.display_name,
            "base": cfg.root_path,
            "lang": i18n.normalize_lang(cfg.language),
            "insecure": (cfg.is_public_bind and not serving_https
                         and not cfg.behind_proxy),
        })

    @app.post("/login")
    async def login(request: Request, username: str = Form(""),
                    password: str = Form("")):
        ip = client_addr(request)
        wait = throttle.locked_for(ip)
        if wait > 0:
            return RedirectResponse(
                cfg.root_path + "/login?error=Too+many+failed+attempts."
                f"+Try+again+in+{int(wait / 60) + 1}+minutes.",
                status_code=302)

        role = None
        if (auth.constant_time_user_check(username, cfg.username)
                and auth.verify_password(password, cfg.password_hash)):
            role = "operator"
        elif (cfg.viewer_username
              and auth.constant_time_user_check(username, cfg.viewer_username)
              and auth.verify_password(password, cfg.viewer_password_hash)):
            role = "viewer"
        ok = role is not None
        if not ok:
            throttle.record_failure(ip)
            await asyncio.sleep(0.5)  # blunt the guessing rate
            return RedirectResponse(
                cfg.root_path + "/login?error=Invalid+credentials",
                status_code=302)

        throttle.reset(ip)
        token = auth.make_token(cfg.secret_key, username, cfg.session_hours,
                                role=role)
        state.store.audit(username, "login", "ok", actor_ip=ip, detail=role)
        resp = RedirectResponse(cfg.root_path + "/", status_code=302)
        resp.set_cookie(auth.COOKIE_NAME, token,
                        max_age=cfg.session_hours * 3600,
                        **auth.secure_cookie_kwargs(
                            cfg.exposed, cookie_secure,
                            (cfg.root_path or "") + "/"))
        return resp

    @app.post("/logout")
    async def logout():
        resp = RedirectResponse(cfg.root_path + "/login", status_code=302)
        resp.delete_cookie(auth.COOKIE_NAME, path=(cfg.root_path or "") + "/")
        return resp

    # -- page ----------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        sess = session_of(request)
        if not sess:
            return RedirectResponse(cfg.root_path + "/login", status_code=302)
        return templates.TemplateResponse(request, "index.html", {
            "server_name": cfg.display_name,
            "spoof_ip": cfg.spoof_ip,
            "spoof_source": cfg.spoof_source,
            "local_ip": cfg.resolved_local_ip,
            "peer_name": cfg.peer_name,
            "peer_enabled": cfg.peer_enabled,
            "portwatch_enabled": cfg.pw_enabled,
            "csrf": auth.csrf_token(cfg.secret_key, sess.get("jti", "")),
            "lang": i18n.normalize_lang(cfg.language),
            "base": cfg.root_path,
            "single_server": not cfg.peer_enabled,
            "role": sess.get("r") or "operator",
            "probe_enabled": cfg.probe_enabled,
            "history_enabled": state.store.enabled,
            "alerts_enabled": cfg.alerts_enabled,
            "triage_enabled": cfg.triage_enabled,
            "metrics_enabled": cfg.metrics_enabled,
        })

    @app.get("/api/doctor")
    async def api_doctor(sess: dict = Depends(require_session)):
        from . import preflight
        return await asyncio.to_thread(preflight.run, cfg)


    # -- groups --------------------------------------------------------
    @app.get("/api/groups")
    async def api_groups(sess: dict = Depends(require_session)):
        pf = dom.parse(cfg.domains)
        return {
            "groups": pf.groups(),
            "ungrouped": pf.ungrouped_count(),
            "disabled": [{"suffix": e.suffix, "lineno": e.lineno,
                          "group": e.group, "comment": e.comment}
                         for e in pf.disabled],
            "error": pf.error,
            "howto": i18n.GROUP_HOWTO,
        }

    # -- history, charts, events ---------------------------------------
    @app.get("/api/history")
    async def api_history(sess: dict = Depends(require_session)):
        return state.store.stats()

    @app.get("/api/traffic")
    async def api_traffic(sess: dict = Depends(require_session),
                          hours: float = 6, client_ip: str = ""):
        hours = max(0.25, min(float(hours), 24 * 30))
        if client_ip and not _plausible_ip(client_ip):
            raise HTTPException(400, "not a plausible IP address")
        return {
            "hours": hours,
            "client_ip": client_ip,
            "bucket_seconds": _bucket_seconds(),
            "series": state.store.traffic_series(hours, client_ip),
            "top_clients": state.store.top_talkers(hours),
            "top_snis": state.store.top_snis(hours),
            "problem_rate": state.store.problem_rate(minutes=hours * 60),
            "disclaimer": i18n.NOT_ACCOUNTING,
        }

    @app.get("/api/events")
    async def api_events(sess: dict = Depends(require_session),
                         limit: int = 100, open_only: bool = False):
        limit = max(1, min(int(limit), 500))
        return {
            "enabled": cfg.alerts_enabled,
            "open": state.store.open_events(),
            "recent": [] if open_only else state.store.recent_events(limit),
            "summary": state.alert_summary,
            "notifiers": [n.name for n in state.notifiers if n.enabled()],
            "min_severity": cfg.alerts_min_severity,
        }

    @app.post("/api/events/ack")
    async def api_event_ack(request: Request,
                            sess: dict = Depends(require_operator)):
        require_csrf(request, sess)
        body = await request.json()
        ok = state.store.ack_event(int(body.get("id") or 0))
        who, ip = actor(sess, request)
        state.store.audit(who, "ack-event", "ok" if ok else "not-found",
                          str(body.get("id")), actor_ip=ip)
        return {"ok": ok}

    @app.get("/api/audit")
    async def api_audit(sess: dict = Depends(require_session),
                        limit: int = 200, action: str = "", who: str = ""):
        return {
            "entries": state.store.audit_log(max(1, min(int(limit), 1000)),
                                             action=action.strip(),
                                             actor=who.strip()),
            "history_enabled": state.store.enabled,
        }

    @app.get("/api/registry")
    async def api_registry(sess: dict = Depends(require_session),
                           limit: int = 300, contains: str = "",
                           upstream_only: bool = False):
        pf = dom.parse(cfg.domains)
        rows = state.store.domains_seen(max(1, min(int(limit), 2000)),
                                        contains.strip(), upstream_only)
        for r in rows:
            r["matched_suffix"] = dom.match_suffix(r["name"], pf)
        return {"domains": rows, "history_enabled": state.store.enabled,
                "disclaimer": i18n.NOT_ACCOUNTING}

    # -- probe ---------------------------------------------------------
    @app.post("/api/probe")
    async def api_probe(request: Request,
                        sess: dict = Depends(require_session)):
        """Active reachability test for a candidate domain.

        Read-only and side-effect free, so a viewer may run it - the point is
        to make the human decision better informed, and that helps whoever is
        looking.
        """
        require_csrf(request, sess)
        if not cfg.probe_enabled:
            raise HTTPException(
                403, "the active probe is disabled in config.ini")
        body = await request.json()
        name = dom.normalize(body.get("domain") or "")
        if not name or not dom.valid_hostname(name):
            raise HTTPException(400, "not a hostname")
        resolver = (body.get("resolver") or cfg.probe_resolver).strip()
        if not _plausible_ip(resolver):
            raise HTTPException(400, "resolver must be an IP address")
        result = await asyncio.to_thread(
            probemod.probe, name, resolver, probemod.EXTRA_PORTS,
            cfg.probe_timeout, cfg.self_ips())
        pf = dom.parse(cfg.domains)
        result["matched_suffix"] = dom.match_suffix(name, pf)
        result["already_listed"] = bool(result["matched_suffix"])
        who, ip = actor(sess, request)
        state.store.audit(who, "probe", str(result.get("proxyable")), name,
                          actor_ip=ip,
                          detail=i18n.pick(result.get("verdict")))
        return result

    # -- metrics -------------------------------------------------------
    @app.get("/metrics", response_class=PlainTextResponse)
    async def api_metrics(request: Request, token: str = ""):
        """Prometheus text format. Off unless enabled in config.

        Deliberately not behind the session cookie, because a scraper cannot
        log in; a token is the access control instead.
        """
        if not cfg.metrics_enabled:
            raise HTTPException(404, "metrics are disabled")
        if cfg.metrics_token:
            given = token or request.headers.get("Authorization", "")
            given = given.replace("Bearer ", "").strip()
            if not auth.constant_time_user_check(given, cfg.metrics_token):
                raise HTTPException(403, "bad metrics token")
        return await asyncio.to_thread(_render_metrics, cfg, state)

    # -- client triage -------------------------------------------------
    @app.get("/triage", response_class=HTMLResponse)
    async def triage_page(request: Request):
        """Unauthenticated self-service page for a player.

        It reports only what the dashboard has observed about the caller's own
        address, and is careful about what it can and cannot know: the
        MikroTik's Permited list is not readable from here, so the verdict is
        phrased as a likelihood with the evidence shown, never as a fact.
        """
        if not cfg.triage_enabled:
            raise HTTPException(404, "the triage page is disabled")
        ip = client_addr(request)
        data = await asyncio.to_thread(_triage_for, state, cfg, ip)
        return templates.TemplateResponse(request, "triage.html", {
            "lang": i18n.normalize_lang(cfg.language),
            "base": cfg.root_path,
            "server_name": cfg.display_name,
            "d": data,
        })

    @app.get("/api/triage")
    async def api_triage(request: Request, client_ip: str = "",
                         sess: dict | None = None):
        """Same data as the triage page. Operators may ask about any address;
        an anonymous caller only ever gets their own."""
        s = session_of(request)
        target = client_addr(request)
        if s and client_ip:
            if not _plausible_ip(client_ip):
                raise HTTPException(400, "not a plausible IP address")
            target = client_ip
        elif not s and not cfg.triage_enabled:
            raise HTTPException(404, "the triage page is disabled")
        return await asyncio.to_thread(_triage_for, state, cfg, target)

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz():
        return "ok"

    # -- read-only API -------------------------------------------------
    @app.get("/api/status")
    async def api_status(sess: dict = Depends(require_session)):
        if not state.status_cache.get("ts"):
            state.status_cache = await asyncio.to_thread(state._status_once)
        return state.status_cache

    @app.get("/api/feed")
    async def api_feed(sess: dict = Depends(require_session),
                       limit: int = 200, client_ip: str = "", sni: str = "",
                       problems_only: bool = False, since_seq: int = 0):
        limit = max(1, min(limit, 2000))
        rows = state.recent(limit=limit, client_ip=client_ip.strip(),
                            sni=sni.strip().lower(),
                            problems_only=problems_only, since_seq=since_seq)
        return {"rows": rows, "seq": state.feed_seq,
                "total": len(state.feed)}

    @app.get("/api/clients")
    async def api_clients(sess: dict = Depends(require_session)):
        return {"clients": state.feed_clients()}

    @app.get("/api/watch")
    async def api_watch_get(sess: dict = Depends(require_session)):
        return {"client_ip": state.watch_client, "cache": state.grepq_cache}

    @app.post("/api/watch")
    async def api_watch_set(request: Request,
                            sess: dict = Depends(require_session)):
        require_csrf(request, sess)
        body = await request.json()
        ip = (body.get("client_ip") or "").strip()
        if ip and not _plausible_ip(ip):
            raise HTTPException(400, "not a plausible IP address")
        state.watch_client = ip or None
        if ip:
            try:
                state.grepq_cache = await asyncio.to_thread(
                    state._grepq_once, ip)
            except Exception as exc:  # noqa: BLE001
                state.grepq_cache = {"client_ip": ip, "ts": time.time(),
                                     "unproxied": [], "proxied": [],
                                     "rows": 0, "error": str(exc)}
        return {"client_ip": state.watch_client, "cache": state.grepq_cache}

    @app.get("/api/client/{client_ip}")
    async def api_client(client_ip: str,
                         sess: dict = Depends(require_session),
                         limit: int = 300):
        """The combined view: proxied traffic and unproxied queries for one
        client, side by side. This is the primary debugging workflow."""
        if not _plausible_ip(client_ip):
            raise HTTPException(400, "not a plausible IP address")
        proxied_rows = state.recent(limit=limit, client_ip=client_ip)
        if state.watch_client != client_ip:
            try:
                grep = await asyncio.to_thread(state._grepq_once, client_ip)
            except Exception as exc:  # noqa: BLE001
                grep = {"client_ip": client_ip, "ts": time.time(),
                        "unproxied": [], "proxied": [], "rows": 0,
                        "error": str(exc)}
        else:
            grep = state.grepq_cache

        seen_snis = {r["sni"] for r in proxied_rows if r["sni"]}
        for e in grep.get("unproxied", []):
            e["seen_in_proxy_log"] = e["name"] in seen_snis
        return {
            "client_ip": client_ip,
            "proxy_rows": proxied_rows,
            "grepq": grep,
            "proxy_sni_count": len(seen_snis),
            "permitted_hint": i18n.PERMITTED_HINT,
        }

    @app.get("/api/domains")
    async def api_domains(sess: dict = Depends(require_session)):
        pf = dom.parse(cfg.domains)
        return {
            "path": cfg.domains,
            "error": pf.error,
            "mtime": pf.mtime,
            "entries": [{"lineno": e.lineno, "suffix": e.suffix,
                         "comment": e.comment} for e in pf.entries],
            "duplicates": pf.duplicates,
            "invalid": pf.invalid,
            "redundant": pf.redundant(),
        }

    @app.get("/api/lookup")
    async def api_lookup(name: str, sess: dict = Depends(require_session),
                         resolver: str = ""):
        target = dom.normalize(name)
        if not target:
            raise HTTPException(400, "empty name")
        pf = dom.parse(cfg.domains)
        matched = dom.match_suffix(target, pf)
        server = resolver.strip() or cfg.resolved_local_ip or "127.0.0.1"
        if not _plausible_ip(server):
            raise HTTPException(400, "resolver must be an IP address")

        results = {}
        for qtype in ("A", "AAAA", "HTTPS"):
            results[qtype] = await asyncio.to_thread(dd.dig, target, server,
                                                     qtype)
        a_answers = [a for a in results["A"]["answers"] if _plausible_ip(a)]
        # "Is this being spoofed to us?" is judged against every address that
        # counts as this deployment, so a clone with a different public IP
        # needs no config change.
        ours = cfg.self_ips()
        spoofed_to = [a for a in a_answers if a in ours]
        spoofed = bool(spoofed_to)
        spoof_ip = cfg.spoof_ip

        verdict = (i18n.verdict_proxied(matched, spoof_ip) if matched
                   else i18n.verdict_not_proxied())

        warns = []
        if matched and not spoofed:
            warns.append(i18n.warn_matched_not_spoofed(target, matched,
                                                       spoof_ip))
        if not matched and spoofed:
            warns.append(i18n.warn_spoofed_not_matched(target,
                                                       spoofed_to[0]))
        if matched and results["AAAA"]["answers"]:
            warns.append(i18n.warn_aaaa_present())
        if dom.is_bare_root(target) and not matched:
            warns.append(i18n.warn_bare_root_lookup(target))

        return {
            "name": target,
            "matched_suffix": matched,
            "is_proxied": bool(matched),
            "is_bare_root": dom.is_bare_root(target),
            "resolver": server,
            "dig": results,
            "spoofed_now": spoofed,
            "spoofed_to": spoofed_to,
            "spoof_ip": spoof_ip,
            "spoof_source": cfg.spoof_source,
            "verdict": verdict,
            "warnings": warns,
            "covering_candidates": sorted(
                s for s in pf.active if dom.matches(target, s)),
        }

    @app.get("/api/dnsdist/top")
    async def api_top(sess: dict = Depends(require_session), n: int = 50):
        try:
            rows = await asyncio.to_thread(state.console.top_queries,
                                           max(1, min(n, 200)))
        except dd.DnsdistError as exc:
            return {"error": str(exc), "rows": []}
        pf = dom.parse(cfg.domains)
        return {"error": None, "rows": [
            {"name": n_, "count": c,
             "matched_suffix": dom.match_suffix(n_, pf)} for n_, c in rows]}

    @app.get("/api/dnsdist/servers")
    async def api_servers(sess: dict = Depends(require_session)):
        try:
            return {"error": None,
                    "rows": await asyncio.to_thread(state.console.show_servers)}
        except dd.DnsdistError as exc:
            return {"error": str(exc), "rows": []}

    @app.get("/api/logs/{which}", response_class=PlainTextResponse)
    async def api_logs(which: str, sess: dict = Depends(require_session),
                       lines: int = 200):
        lines = max(10, min(lines, 2000))
        mapping = {
            "sniproxy-error": cfg.error_log,
            "update": cfg.update_log,
        }
        if which in mapping:
            return await asyncio.to_thread(sysinfo.tail_file, mapping[which],
                                           lines)
        units = set(cfg.restart) | {cfg.staleness_unit, "unbound"}
        if which in units:
            return await asyncio.to_thread(sysinfo.journal, which, lines)
        raise HTTPException(404, "unknown log")

    # -- two-server diff -----------------------------------------------
    @app.get("/api/peer/probe")
    async def api_peer_probe(sess: dict = Depends(require_session)):
        if not cfg.peer_enabled or not cfg.peer_host:
            return {"enabled": False, "reachable": False,
                    "message": i18n.M("Peer not configured - use paste mode.",
                                      "سرور دوم تنظیم نشده — از حالت paste "
                                      "استفاده کن."),
                    "paste_hint": i18n.PASTE_HINT}
        ok, msg = await asyncio.to_thread(
            peermod.check_ssh, cfg.peer_host, cfg.peer_ssh_user,
            cfg.peer_ssh_port, cfg.peer_ssh_key, cfg.peer_ssh_timeout)
        return {"enabled": True, "reachable": ok,
                "message": i18n.plain(msg),
                "host": cfg.peer_host, "name": cfg.peer_name,
                "paste_hint": i18n.PASTE_HINT}

    @app.get("/api/peer/diff")
    async def api_peer_diff(sess: dict = Depends(require_session)):
        if not cfg.peer_enabled or not cfg.peer_host:
            raise HTTPException(400, "peer not configured - use paste mode")
        try:
            text = await asyncio.to_thread(
                peermod.fetch_via_ssh, cfg.peer_host, cfg.peer_ssh_user,
                cfg.peer_ssh_port, cfg.peer_ssh_key, cfg.peer_ssh_timeout,
                cfg.domains)
            diff = peermod.compare(cfg.domains, text, cfg.display_name,
                                   cfg.peer_name)
            # Remembered so the alert rule can flag divergence without doing
            # its own SSH round trip on every status poll.
            state.last_peer_diff = diff
            return diff
        except peermod.PeerError as exc:
            raise HTTPException(502, str(exc))

    @app.post("/api/peer/paste")
    async def api_peer_paste(request: Request,
                             sess: dict = Depends(require_session)):
        require_csrf(request, sess)
        body = await request.json()
        text = body.get("text") or ""
        if len(text) > 2_000_000:
            raise HTTPException(400, "pasted list is implausibly large")
        try:
            return peermod.compare(cfg.domains, text, cfg.display_name,
                                   body.get("peer_name") or cfg.peer_name)
        except peermod.PeerError as exc:
            raise HTTPException(400, str(exc))

    # -- guarded write path --------------------------------------------
    @app.post("/api/domains/preview")
    async def api_preview(request: Request,
                          sess: dict = Depends(require_operator)):
        require_csrf(request, sess)
        body = await request.json()
        action = (body.get("action") or "add").strip()
        target = (body.get("domain") or "").strip()
        note = (body.get("comment") or "").strip()

        if action == "add":
            observed = _observed_names(state)
            plan = await asyncio.to_thread(dom.build_add_plan, cfg.domains,
                                           target, observed, note)
        elif action == "disable":
            plan = await asyncio.to_thread(dom.build_disable_plan,
                                           cfg.domains, target, note)
        elif action == "enable":
            plan = await asyncio.to_thread(dom.build_enable_plan,
                                           cfg.domains, target, note)
        elif action in ("group-disable", "group-enable"):
            plan = await asyncio.to_thread(
                dom.build_group_plan, cfg.domains, target,
                action.split("-", 1)[1], note)
        elif action == "tag":
            plan = await asyncio.to_thread(
                dom.build_tag_plan, cfg.domains, target,
                (body.get("group") or "").strip())
        else:
            raise HTTPException(
                400, "action must be add, disable, enable, tag, "
                     "group-disable or group-enable")

        who, ip = actor(sess, request)
        if plan.ok:
            state.plans.put(plan)
        else:
            # Refusals are recorded too: "who tried to add a bare root and was
            # stopped" is as interesting as what succeeded.
            state.store.audit(
                who, f"preview:{action}", "refused", target, actor_ip=ip,
                detail=" | ".join(i18n.pick(b) for b in plan.blockers)[:2000])
        payload = plan.to_dict()
        payload["restart_units"] = cfg.restart
        payload["update_script"] = cfg.update_script
        payload["backup_dir"] = cfg.backup_dir
        payload["peer_reminder"] = (i18n.peer_reminder(cfg.peer_name)
                                    if cfg.peer_enabled else None)
        return payload

    @app.post("/api/domains/apply")
    async def api_apply(request: Request,
                        sess: dict = Depends(require_operator)):
        require_csrf(request, sess)
        body = await request.json()
        token = body.get("token") or ""
        confirm = (body.get("confirm") or "").strip()

        plan = state.plans.take(token)
        if plan is None:
            raise HTTPException(
                400, "plan not found or expired - re-run the preview")
        if confirm != plan.target:
            # A typo should not force a re-preview; put the plan back. It is
            # still CSRF-protected and expires on its own.
            state.plans.put(plan)
            raise HTTPException(
                400, f"type {plan.target!r} exactly to confirm")

        if not state.write_lock.acquire(blocking=False):
            raise HTTPException(409, "another change is already running")
        try:
            result = await asyncio.to_thread(
                dom.apply_plan, plan, cfg.domains, cfg.backup_dir,
                cfg.update_script, cfg.restart)
        finally:
            state.write_lock.release()

        who, ip = actor(sess, request)
        state.record_change({
            "action": plan.action, "target": plan.target,
            "ok": result["ok"], "backup": result.get("backup"),
            "error": result.get("error"), "by": who,
        })
        state.store.audit(
            who, plan.action, "applied" if result["ok"] else "failed",
            plan.target, actor_ip=ip,
            detail=i18n.pick(result.get("error")) if result.get("error") else "",
            diff=plan.diff, backup=result.get("backup") or "")
        result["plan"] = plan.to_dict()

        # Mirror to the peer when asked. Peer first, local second, so a peer
        # failure leaves a matched pair rather than the divergence this exists
        # to prevent - see the note in peer.py.
        if body.get("mirror") and result["ok"]:
            result["peer"] = {"ok": False, "error": "not attempted"}
        state.status_cache = await asyncio.to_thread(state._status_once)
        return result

    @app.post("/api/domains/apply-both")
    async def api_apply_both(request: Request,
                             sess: dict = Depends(require_operator)):
        """Apply one change to this server and the peer in a single action.

        Order matters: the peer is written first. If it fails, this server is
        left untouched and the pair stays matched (both old). Writing locally
        first would risk ending up with exactly the divergence this feature
        exists to prevent.
        """
        require_csrf(request, sess)
        if not (cfg.peer_enabled and cfg.peer_host):
            raise HTTPException(400, "no peer configured")
        body = await request.json()
        token = body.get("token") or ""
        confirm = (body.get("confirm") or "").strip()

        plan = state.plans.take(token)
        if plan is None:
            raise HTTPException(
                400, "plan not found or expired - re-run the preview")
        if confirm != plan.target:
            state.plans.put(plan)
            raise HTTPException(400, f"type {plan.target!r} exactly to confirm")

        who, ip = actor(sess, request)
        out: dict = {"ok": False, "peer": None, "local": None,
                     "plan": plan.to_dict()}

        if not state.write_lock.acquire(blocking=False):
            raise HTTPException(409, "another change is already running")
        try:
            # Refuse if the two files already differ: a mirrored write assumes
            # a common starting point, and silently overwriting a peer that
            # someone else edited would destroy their change.
            peer_text = await asyncio.to_thread(
                peermod.fetch_via_ssh, cfg.peer_host, cfg.peer_ssh_user,
                cfg.peer_ssh_port, cfg.peer_ssh_key, cfg.peer_ssh_timeout,
                cfg.domains)
            local = dom.parse(cfg.domains)
            if dom.normalize_text(peer_text) != local.normalized():
                out["error"] = i18n.MIRROR_DIVERGED
                return out

            out["peer"] = await asyncio.to_thread(
                peermod.apply_remote, cfg.peer_host, cfg.peer_ssh_user,
                cfg.peer_ssh_port, cfg.peer_ssh_key, cfg.peer_ssh_timeout,
                cfg.domains, cfg.backup_dir, cfg.update_script, cfg.restart,
                plan.rendered)
            if not out["peer"]["ok"]:
                out["error"] = i18n.MIRROR_PEER_FAILED
                state.store.audit(
                    who, f"mirror:{plan.action}", "peer-failed", plan.target,
                    actor_ip=ip, detail=str(out["peer"].get("error"))[:2000])
                return out

            out["local"] = await asyncio.to_thread(
                dom.apply_plan, plan, cfg.domains, cfg.backup_dir,
                cfg.update_script, cfg.restart)
            out["ok"] = bool(out["local"]["ok"])
            if not out["ok"]:
                out["error"] = i18n.MIRROR_LOCAL_FAILED
        except peermod.PeerError as exc:
            out["error"] = i18n.plain(str(exc))
        finally:
            state.write_lock.release()

        state.record_change({
            "action": f"{plan.action} (both)", "target": plan.target,
            "ok": out["ok"], "error": out.get("error"), "by": who,
            "backup": (out.get("local") or {}).get("backup"),
        })
        state.store.audit(
            who, f"mirror:{plan.action}",
            "applied" if out["ok"] else "failed", plan.target, actor_ip=ip,
            detail=i18n.pick(out.get("error")) if out.get("error") else "",
            diff=plan.diff,
            backup=(out.get("local") or {}).get("backup") or "")
        state.status_cache = await asyncio.to_thread(state._status_once)
        return out

    @app.get("/api/backups")
    async def api_backups(sess: dict = Depends(require_session)):
        base = os.path.basename(cfg.domains)
        return {"dir": cfg.backup_dir,
                "backups": dom.list_backups(cfg.backup_dir, base)}

    @app.get("/api/backups/diff", response_class=PlainTextResponse)
    async def api_backup_diff(name: str,
                              sess: dict = Depends(require_session)):
        path = _safe_backup_path(cfg.backup_dir, name)
        return dom.diff_backup(path, cfg.domains) or "(identical)"

    @app.post("/api/backups/restore")
    async def api_backup_restore(request: Request,
                                 sess: dict = Depends(require_operator)):
        require_csrf(request, sess)
        body = await request.json()
        name = body.get("name") or ""
        if (body.get("confirm") or "") != "RESTORE":
            raise HTTPException(400, "type RESTORE to confirm")
        path = _safe_backup_path(cfg.backup_dir, name)
        if not state.write_lock.acquire(blocking=False):
            raise HTTPException(409, "another change is already running")
        try:
            result = await asyncio.to_thread(
                dom.restore_backup, path, cfg.domains, cfg.backup_dir,
                cfg.update_script, cfg.restart)
        finally:
            state.write_lock.release()
        who, ip = actor(sess, request)
        state.record_change({"action": "restore", "target": name,
                             "ok": result["ok"], "error": result.get("error"),
                             "by": who})
        state.store.audit(
            who, "restore", "applied" if result["ok"] else "failed", name,
            actor_ip=ip,
            detail=i18n.pick(result.get("error")) if result.get("error") else "",
            backup=result.get("backup") or "")
        state.status_cache = await asyncio.to_thread(state._status_once)
        return result

    @app.get("/api/changes")
    async def api_changes(sess: dict = Depends(require_session)):
        return {"changes": list(state.change_log)}

    # -- port watcher --------------------------------------------------
    @app.get("/api/portwatch")
    async def api_portwatch(sess: dict = Depends(require_session)):
        snap = state.portwatcher.snapshot()
        snap["available"] = pwmod.available() is None
        snap["unavailable_reason"] = pwmod.available()
        snap["config_enabled"] = cfg.pw_enabled
        return snap

    @app.post("/api/portwatch")
    async def api_portwatch_ctl(request: Request,
                                sess: dict = Depends(require_operator)):
        require_csrf(request, sess)
        body = await request.json()
        action = body.get("action")
        if action == "stop":
            state.portwatcher.stop()
            return state.portwatcher.snapshot()
        if action != "start":
            raise HTTPException(400, "action must be 'start' or 'stop'")
        if not cfg.pw_enabled:
            raise HTTPException(
                403, "portwatch is disabled in config.ini - it runs a "
                     "continuous packet capture, so it is opt-in")
        ip = (body.get("client_ip") or "").strip() or None
        if ip and not _plausible_ip(ip):
            raise HTTPException(400, "not a plausible IP address")
        try:
            await asyncio.to_thread(state.portwatcher.start, ip)
        except RuntimeError as exc:
            raise HTTPException(500, str(exc))
        return state.portwatcher.snapshot()

    # -- SSE -----------------------------------------------------------
    @app.get("/events")
    async def events(request: Request, sess: dict = Depends(require_session)):
        async def gen():
            q = await state.broadcaster.subscribe()
            try:
                yield _sse("hello", {"ts": time.time(),
                                     "seq": state.feed_seq})
                if state.status_cache.get("ts"):
                    yield _sse("status", state.status_cache)
                last_ping = time.time()
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event, data = await asyncio.wait_for(q.get(),
                                                             timeout=15)
                        yield _sse(event, data)
                    except asyncio.TimeoutError:
                        pass
                    if time.time() - last_ping > 15:
                        last_ping = time.time()
                        yield ": ping\n\n"
            finally:
                await state.broadcaster.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no",
                                          "Connection": "keep-alive"})

    return app


# ----------------------------------------------------------------------
def _sse(event: str, data) -> str:
    payload = json.dumps(data, default=str)
    return f"event: {event}\ndata: {payload}\n\n"



def _bucket_seconds() -> int:
    from .store import BUCKET_SECONDS
    return BUCKET_SECONDS


def _esc_label(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _render_metrics(cfg, state) -> str:
    """Prometheus text format from what the dashboard already computes.

    Only aggregate series: no per-connection detail, and no per-client byte
    counters, because those would be an accounting record by the back door.
    """
    st = state.status_cache or {}
    lines: list[str] = []

    def metric(name, typ, help_text, samples):
        if not samples:
            return
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {typ}")
        for labels, value in samples:
            lbl = ("{" + ",".join(f'{k}="{_esc_label(v)}"'
                                  for k, v in labels.items()) + "}") if labels else ""
            lines.append(f"{name}{lbl} {value}")

    server = _esc_label(cfg.display_name)

    metric("smartdns_dashboard_up", "gauge",
           "1 when the dashboard is serving.",
           [({"server": server}, 1)])

    metric("smartdns_service_healthy", "gauge",
           "1 when a managed unit is active and running.",
           [({"server": server, "unit": sv.get("unit", "?")},
             1 if sv.get("healthy") else 0)
            for sv in st.get("services") or []])

    stale = (st.get("staleness") or {})
    metric("smartdns_config_stale", "gauge",
           "1 when a service is running a config older than the files on disk.",
           [({"server": server, "unit": stale.get("unit", "?")},
             1 if stale.get("stale") else 0)])
    metric("smartdns_config_stale_seconds", "gauge",
           "How far behind the running config is.",
           [({"server": server}, int(stale.get("lag_s") or 0))])

    d = st.get("domains") or {}
    metric("smartdns_allowlist_entries", "gauge",
           "Active suffixes in the allow-list.",
           [({"server": server}, d.get("count") or 0)])
    metric("smartdns_allowlist_problems", "gauge",
           "Duplicate, invalid or redundant allow-list lines.",
           [({"server": server, "kind": k}, d.get(k) or 0)
            for k in ("duplicates", "invalid", "redundant")])

    metric("smartdns_events_open", "gauge",
           "Currently open alert conditions.",
           [({"server": server, "severity": sev},
             len([e for e in state.store.open_events()
                  if e["severity"] == sev]))
            for sev in ("critical", "warning", "info")])

    rate = state.store.problem_rate(minutes=15)
    metric("smartdns_proxy_connections_recent", "gauge",
           "Proxied connections seen in the last 15 minutes.",
           [({"server": server}, rate.get("conns") or 0)])
    metric("smartdns_proxy_failures_recent", "gauge",
           "Of those, ones with no origin or no SNI.",
           [({"server": server}, rate.get("problems") or 0)])
    metric("smartdns_proxy_failure_ratio", "gauge",
           "Failure share of recent proxied connections.",
           [({"server": server}, round(rate.get("rate") or 0.0, 4))])

    metric("smartdns_feed_buffered_rows", "gauge",
           "Access-log rows held in memory.",
           [({"server": server}, st.get("feed_len") or 0)])
    metric("smartdns_log_unparsed_lines", "counter",
           "Access-log lines the parser did not recognise.",
           [({"server": server, "log": lg.get("label", "?")},
             lg.get("lines_unparsed") or 0)
            for lg in st.get("logs") or []])
    metric("smartdns_log_rotations", "counter",
           "Log rotations detected by the tailer.",
           [({"server": server, "log": lg.get("label", "?")},
             lg.get("rotations") or 0)
            for lg in st.get("logs") or []])

    return "\n".join(lines) + "\n"


def _triage_for(state, cfg, ip: str) -> dict:
    """What the dashboard can honestly say about one client address.

    The important limitation, stated plainly: the MikroTik's `Permited`
    address-list gates the DNAT for 80/443 and is NOT readable from this
    server. So when DNS is clearly working and no proxy connection ever
    arrives, that is *evidence pointing at* the Permited list, not proof. The
    wording reflects that.
    """
    proxied = state.recent(limit=50, client_ip=ip)
    grep = state.grepq_cache if state.watch_client == ip else None
    dns_seen = bool(grep and (grep.get("unproxied") or grep.get("proxied")))

    hours_of_traffic = state.store.traffic_series(hours=6, client_ip=ip)
    ever_seen = bool(proxied or hours_of_traffic or dns_seen)

    findings = []
    verdict = None
    if proxied:
        failures = [r for r in proxied if r["problem"]]
        if failures and len(failures) == len(proxied):
            verdict = i18n.TRIAGE_ALL_FAILING
        elif failures:
            verdict = i18n.TRIAGE_PARTIAL
        else:
            verdict = i18n.TRIAGE_WORKING
        findings.append(i18n.triage_saw_connections(len(proxied),
                                                    len(failures)))
    elif dns_seen:
        verdict = i18n.TRIAGE_DNS_BUT_NO_PROXY
        findings.append(i18n.triage_dns_only())
    elif ever_seen:
        verdict = i18n.TRIAGE_STALE
    else:
        verdict = i18n.TRIAGE_NOTHING

    return {
        "client_ip": ip,
        "server": cfg.display_name,
        "ts": time.time(),
        "seen": ever_seen,
        "proxied_count": len(proxied),
        "failed_count": len([r for r in proxied if r["problem"]]),
        "dns_seen": dns_seen,
        "recent": [{"time": r["time"], "sni": r["sni"],
                    "ok": not r["problem"]} for r in proxied[-10:]],
        "verdict": verdict,
        "findings": findings,
        "limitation": i18n.TRIAGE_LIMITATION,
    }


def _plausible_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _safe_backup_path(backup_dir: str, name: str) -> str:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise HTTPException(400, "bad backup name")
    path = os.path.realpath(os.path.join(backup_dir, name))
    root = os.path.realpath(backup_dir)
    if os.path.commonpath([root, path]) != root or not os.path.isfile(path):
        raise HTTPException(404, "backup not found")
    return path


def _observed_names(state: AppState) -> list:
    """Every hostname this server has actually seen, from both the proxy log
    and the dnsdist ring. Used to show what a bare root would capture."""
    names = set()
    for rec in state.feed:
        if rec["sni"]:
            names.add(rec["sni"])
    cache = state.grepq_cache or {}
    for key in ("unproxied", "proxied"):
        for e in cache.get(key, []) or []:
            names.add(e["name"])
    return sorted(names)

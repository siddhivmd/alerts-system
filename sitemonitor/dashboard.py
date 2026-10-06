"""Password-protected Flask dashboard and JSON API.

Routes
  GET /                 HTML dashboard (auto-refreshes every 30 s via /api/*)
  GET /api/status       current status of every site + VPS (JSON)
  GET /api/history      response times per site and VPS metrics, last N hours (default 24)
  GET /api/incidents    incident history
  POST /api/incidents/<id>/ack   acknowledge an open incident ("I'm on it")
  GET /api/reliability  MTTA / MTTR / downtime / top causes, last N days (default 30)
  GET /healthz          unauthenticated liveness probe (no monitoring data)

Public (no login, only when status_page.enabled):
  GET /status, /status/<client>, /status/<client>.json   read-only status pages
  Requests whose Host is a client's status_domain get that client's page at "/".
"""
from __future__ import annotations

import hmac
import logging
import time
from functools import wraps
from typing import Any, Callable

from flask import Flask, Response, abort, jsonify, render_template, request

from . import sla, status_page
from .alerts import Formatter, format_duration
from .config import Config
from .storage import Storage

log = logging.getLogger(__name__)
_STATUS_ORDER = {"down": 0, "warning": 1, "up": 2, None: 3}


def _requires_auth(cfg: Config) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    user = cfg.dashboard.username
    password = cfg.dashboard.password or ""

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        if not password:
            # No password configured: config.py already limited the dashboard to 127.0.0.1.
            return view

        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            auth = request.authorization
            ok = bool(auth and auth.username is not None and auth.password is not None
                      and hmac.compare_digest(auth.username.encode(), user.encode())
                      and hmac.compare_digest(auth.password.encode(), password.encode()))
            if not ok:
                return Response("Authentication required", 401,
                                {"WWW-Authenticate": 'Basic realm="Site Monitor", charset="UTF-8"'})
            return view(*args, **kwargs)
        return wrapped
    return decorator


def build_status(cfg: Config, storage: Storage) -> dict[str, Any]:
    now = time.time()
    configured = {s.name: s for s in cfg.sites}
    summary = storage.site_summary(now - 86400)
    open_incidents = {i["site_name"]: i for i in storage.incidents(limit=500) if i["ended_at"] is None}

    sites = []
    for c in storage.latest_checks():
        if c["name"] not in configured:
            continue
        details = c.get("details") or {}
        diag = details.get("diagnosis") or {}
        s = summary.get(c["site_id"], {})
        inc = open_incidents.get(c["name"])
        sites.append({
            "name": c["name"], "url": c["url"], "status": c["status"], "summary": c["summary"],
            "cause_code": c["cause_code"], "http_status": c["http_status"], "response_ms": c["response_ms"],
            "last_check": c["ts"], "ssl_days_left": details.get("ssl_days_left"),
            "domain_days_left": details.get("domain_days_left"),
            "warnings": details.get("warnings", []), "fixes": diag.get("fixes", []),
            "evidence": diag.get("evidence", []),
            "uptime_24h": s.get("uptime_pct"), "avg_ms_24h": s.get("avg_ms"),
            "incident_since": inc["started_at"] if inc else None,
            "slow_threshold_ms": configured[c["name"]].slow_threshold_ms,
        })
    sites.sort(key=lambda x: (_STATUS_ORDER.get(x["status"], 3), x["name"].lower()))

    counts = {k: sum(1 for x in sites if x["status"] == k) for k in ("up", "warning", "down")}
    servers = []
    for server in cfg.servers.values():
        v = storage.latest_vps(server.name) or {}
        servers.append({
            "name": server.name, "host": server.host, "ts": v.get("ts"), "reachable": bool(v.get("reachable")),
            "ports": v.get("ports") or {}, "ram_percent": v.get("ram_percent"), "cpu_load": v.get("cpu_load"),
            "cpu_cores": v.get("cpu_cores"), "disk_percent": v.get("disk_percent"),
            "inode_percent": v.get("inode_percent"), "oom_kills": v.get("oom_kills"),
            "services": v.get("services") or {}, "error": v.get("error"), "ssh_configured": server.ssh is not None,
            "sites": [s.name for s in cfg.sites if s.server == server.name],
            "thresholds": {"ram": cfg.thresholds.ram_percent, "disk": cfg.thresholds.disk_percent,
                           "disk_warn": cfg.thresholds.disk_warn_percent,
                           "inode": cfg.thresholds.inode_percent, "inode_warn": cfg.thresholds.inode_warn_percent,
                           "load_per_core": cfg.thresholds.cpu_load_per_core}})
    vps = servers[0] if servers else None  # kept for single-server API users
    conn = storage.get_kv("connectivity") or {}
    recent = [p for p in conn.get("periods") or [] if p["until"] >= now - 86400]
    monitor_state = {"offline": bool(conn.get("offline")), "offline_since": conn.get("since"),
                     "offline_periods_24h": recent}
    server = storage.get_kv("server_status") or {}
    security = {"enabled": cfg.security.enabled, "ts": server.get("ts"),
                "warnings": server.get("warnings", []), **(server.get("security") or {})}
    return {"generated_at": now, "check_interval_minutes": cfg.general.check_interval_minutes,
            "timezone": cfg.general.timezone, "counts": {**counts, "total": len(sites)},
            "sites": sites, "vps": vps, "servers": servers, "security": security, "monitor": monitor_state}


def create_app(cfg: Config, storage: Storage, last_cycle: Callable[[], float | None] | None = None,
               last_problems: Callable[[], list[str]] | None = None) -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    auth = _requires_auth(cfg)
    fmt = Formatter(cfg.general.timezone)
    app.jinja_env.filters["when"] = fmt.when
    app.jinja_env.filters["duration"] = lambda v: "-" if v is None else format_duration(v)
    app.jinja_env.filters["pct"] = lambda v: "n/a" if v is None else f"{v:.2f}%"
    status_domains = {c.status_domain: cid for cid, c in cfg.clients.items() if c.status_domain and c.status_page}

    def dashboard_only(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not cfg.dashboard.enabled:  # web server may run only for the public status page
                abort(404)
            return view(*args, **kwargs)
        return wrapped

    def _status_response(client_id: str | None, as_json: bool) -> Any:
        if not cfg.status_page.enabled:
            abort(404)
        if client_id is not None and (client_id not in cfg.clients or not cfg.clients[client_id].status_page):
            abort(404)
        page = status_page.build(cfg, storage, client_id)
        if as_json:
            resp = jsonify(page)
            resp.headers["Access-Control-Allow-Origin"] = "*"  # public data, embeddable on the client's site
            return resp
        return render_template("status.html", page=page)

    @app.before_request
    def _status_domain() -> Any:
        """status.client.com -> that client's status page (the reverse proxy forwards the Host header)."""
        host = (request.host or "").split(":")[0].lower()
        if host in status_domains and request.path in ("/", "/status.json"):
            return _status_response(status_domains[host], request.path.endswith(".json"))
        return None

    @app.get("/status")
    def public_status() -> Any:
        return _status_response(None, False)

    @app.get("/status.json")
    def public_status_json() -> Any:
        return _status_response(None, True)

    @app.get("/status/<client_id>")
    def client_status(client_id: str) -> Any:
        if client_id.endswith(".json"):
            return _status_response(client_id[:-5], True)
        return _status_response(client_id, False)

    @app.after_request
    def _headers(resp: Response) -> Response:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/")
    @dashboard_only
    @auth
    def index() -> str:
        return render_template("dashboard.html", refresh_seconds=30)

    @app.get("/api/status")
    @dashboard_only
    @auth
    def api_status() -> Response:
        return jsonify(build_status(cfg, storage))

    @app.get("/api/history")
    @dashboard_only
    @auth
    def api_history() -> Response:
        hours = max(1, min(int(request.args.get("hours", 24)), 24 * 90))
        since = time.time() - hours * 3600
        series: dict[str, list[list[Any]]] = {}
        configured = {s.name for s in cfg.sites}
        for row in storage.response_history(since):
            if row["name"] in configured:
                series.setdefault(row["name"], []).append([row["ts"], row["response_ms"], row["status"]])
        return jsonify({"since": since, "sites": series, "vps": storage.vps_history(since)})

    @app.get("/api/incidents")
    @dashboard_only
    @auth
    def api_incidents() -> Response:
        limit = max(1, min(int(request.args.get("limit", 50)), 500))
        keys = ("id", "site_name", "url", "started_at", "ended_at", "cause_code", "cause",
                "acknowledged_at", "acknowledged_by")
        rows = [{k: i.get(k) for k in keys} for i in storage.incidents(limit=limit)]
        return jsonify({"incidents": rows})

    @app.post("/api/incidents/<int:incident_id>/ack")
    @dashboard_only
    @auth
    def api_ack(incident_id: int) -> Any:
        # A custom header cannot be sent by a plain cross-site form, so this blocks CSRF.
        if request.headers.get("X-Requested-With") != "SiteMonitor":
            abort(403)
        incident = storage.get_incident(incident_id)
        if incident is None:
            abort(404)
        if incident["ended_at"] is not None:
            return jsonify({"ok": False, "error": "incident already resolved"}), 409
        body = request.get_json(silent=True) or {}
        by = str(body.get("by") or (request.authorization.username if request.authorization else "") or "dashboard")
        if not storage.acknowledge_incident(incident_id, by.strip() or "dashboard", time.time()):
            return jsonify({"ok": False, "error": "already acknowledged"}), 409
        log.info("Incident %s acknowledged by %s", incident_id, by)
        return jsonify({"ok": True})

    @app.get("/api/reliability")
    @dashboard_only
    @auth
    def api_reliability() -> Response:
        days = max(1, min(int(request.args.get("days", 30)), 90))
        now = time.time()
        return jsonify({"days": days, **sla.reliability(sla.compute(cfg, storage, now - days * 86400, now, now))})

    @app.get("/healthz")
    def healthz() -> tuple[Response, int]:  # always available (watchdogs, load balancers)
        ts = last_cycle() if last_cycle else None
        stale_after = cfg.general.check_interval_minutes * 60 * 3 + 120
        fresh = ts is not None and time.time() - ts < stale_after
        broken = bool(last_problems and last_problems())  # e.g. disk full: running but not recording
        healthy = fresh and not broken
        # Unauthenticated endpoint: say THAT something is wrong, never the internal details.
        reason = None if healthy else ("no recent check cycle" if not fresh else "internal error (see the log)")
        return jsonify({"ok": healthy, "last_cycle": ts, "reason": reason}), (200 if healthy else 503)

    return app


def serve(app: Flask, host: str, port: int) -> None:
    """Serve with waitress (production WSGI server); fall back to Flask's server if missing."""
    try:
        from waitress import serve as waitress_serve
        log.info("Dashboard listening on http://%s:%d", host, port)
        waitress_serve(app, host=host, port=port, threads=8, ident="SiteMonitor")
    except ImportError:
        log.warning("waitress not installed; using Flask's development server")
        app.run(host=host, port=port, threaded=True, use_reloader=False)

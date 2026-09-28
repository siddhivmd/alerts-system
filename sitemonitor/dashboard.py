"""Password-protected Flask dashboard and JSON API.

Routes
  GET /                 HTML dashboard (auto-refreshes every 30 s via /api/*)
  GET /api/status       current status of every site + VPS (JSON)
  GET /api/history      response times per site and VPS metrics, last N hours (default 24)
  GET /api/incidents    incident history
  GET /healthz          unauthenticated liveness probe (no monitoring data)
"""
from __future__ import annotations

import hmac
import logging
import time
from functools import wraps
from typing import Any, Callable

from flask import Flask, Response, jsonify, render_template, request

from .config import Config
from .storage import Storage

log = logging.getLogger(__name__)
_STATUS_ORDER = {"down": 0, "warning": 1, "up": 2, None: 3}


def _requires_auth(cfg: Config) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    user = cfg.dashboard.username
    password = cfg.dashboard.password or ""

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
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
    vps = None
    if cfg.vps:
        v = storage.latest_vps() or {}
        vps = {"name": cfg.vps.name, "host": cfg.vps.host, "ts": v.get("ts"), "reachable": bool(v.get("reachable")),
               "ports": v.get("ports") or {}, "ram_percent": v.get("ram_percent"), "cpu_load": v.get("cpu_load"),
               "cpu_cores": v.get("cpu_cores"), "disk_percent": v.get("disk_percent"),
               "oom_kills": v.get("oom_kills"), "services": v.get("services") or {}, "error": v.get("error"),
               "ssh_configured": cfg.vps.ssh is not None,
               "thresholds": {"ram": cfg.thresholds.ram_percent, "disk": cfg.thresholds.disk_percent,
                              "disk_warn": cfg.thresholds.disk_warn_percent,
                              "load_per_core": cfg.thresholds.cpu_load_per_core}}
    return {"generated_at": now, "check_interval_minutes": cfg.general.check_interval_minutes,
            "timezone": cfg.general.timezone, "counts": {**counts, "total": len(sites)},
            "sites": sites, "vps": vps}


def create_app(cfg: Config, storage: Storage, last_cycle: Callable[[], float | None] | None = None) -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    auth = _requires_auth(cfg)

    @app.after_request
    def _headers(resp: Response) -> Response:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.get("/")
    @auth
    def index() -> str:
        return render_template("dashboard.html", refresh_seconds=30)

    @app.get("/api/status")
    @auth
    def api_status() -> Response:
        return jsonify(build_status(cfg, storage))

    @app.get("/api/history")
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
    @auth
    def api_incidents() -> Response:
        limit = max(1, min(int(request.args.get("limit", 50)), 500))
        rows = [{k: i[k] for k in ("id", "site_name", "url", "started_at", "ended_at", "cause_code", "cause")}
                for i in storage.incidents(limit=limit)]
        return jsonify({"incidents": rows})

    @app.get("/healthz")
    def healthz() -> tuple[Response, int]:
        ts = last_cycle() if last_cycle else None
        stale_after = cfg.general.check_interval_minutes * 60 * 3 + 120
        healthy = ts is not None and time.time() - ts < stale_after
        return jsonify({"ok": healthy, "last_cycle": ts}), (200 if healthy else 503)

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

"""Public, read-only status pages: one per client (/status/<client>), or one for all (/status).

Built for strangers on the internet, so it only exposes: the public name of each
service, Operational / Degraded / Down, daily uptime bars, and when past
disruptions started and how long they lasted. Never URLs, causes or server data.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from .config import Config
from .storage import Storage

OPERATIONAL, DEGRADED, OUTAGE = "operational", "degraded", "outage"
LABELS = {OPERATIONAL: "Operational", DEGRADED: "Degraded performance", OUTAGE: "Outage"}


def visible_sites(cfg: Config, client_id: str | None) -> list:
    if client_id is not None:
        return [s for s in cfg.sites if s.client == client_id]
    names = set(cfg.status_page.sites)
    return [s for s in cfg.sites if not names or s.name in names]


def _state(check: dict[str, Any] | None) -> str:
    if not check or not check.get("status"):
        return OPERATIONAL
    if check["status"] == "down":
        return OUTAGE
    codes = [w.get("code") for w in (check.get("details") or {}).get("warnings", [])]
    return DEGRADED if "slow" in codes else OPERATIONAL  # SSL/domain warnings are internal matters


def build(cfg: Config, storage: Storage, client_id: str | None = None, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    days = max(7, min(cfg.status_page.days, 90))
    tz = ZoneInfo(cfg.general.timezone)
    offset = datetime.fromtimestamp(now, tz).utcoffset() or timedelta(0)
    since = now - days * 86400
    sites = visible_sites(cfg, client_id)
    ids = storage.sync_sites([(s.name, s.url) for s in cfg.sites])
    latest = {c["name"]: c for c in storage.latest_checks()}
    daily = storage.daily_uptime(since, offset.total_seconds())
    summary = storage.site_summary(since)
    today = int((now + offset.total_seconds()) // 86400)

    services = []
    for s in sites:
        sid = ids.get(s.name)
        check = latest.get(s.name)
        per_day = daily.get(sid, {})
        bars = []
        for day in range(today - days + 1, today + 1):
            label = (datetime(1970, 1, 1) + timedelta(days=day)).strftime("%d %b %Y")
            pct = per_day.get(day)
            bars.append({"date": label, "uptime": pct,
                         "level": "none" if pct is None else "ok" if pct >= 99.9 else "minor" if pct >= 99 else "major"})
        state = _state(check)
        services.append({"name": s.public_name or s.name, "state": state, "label": LABELS[state],
                         "uptime": (summary.get(sid) or {}).get("uptime_pct"), "bars": bars})

    states = {svc["state"] for svc in services}
    overall = OUTAGE if OUTAGE in states else DEGRADED if DEGRADED in states else OPERATIONAL
    headline = {OUTAGE: "Some services are experiencing an outage", DEGRADED: "Some services are slower than usual",
                OPERATIONAL: "All systems operational"}[overall]

    incidents = []
    if cfg.status_page.show_incidents:
        public = {s.name: (s.public_name or s.name) for s in sites}
        for inc in storage.incidents_between(since, now + 1):
            if inc["site_name"] not in public:
                continue
            ended = inc["ended_at"]
            status = "Resolved" if ended else ("Identified - being fixed" if inc.get("acknowledged_at")
                                               else "Investigating")
            incidents.append({"service": public[inc["site_name"]], "started_at": inc["started_at"],
                              "ended_at": ended, "duration_s": (ended or now) - inc["started_at"], "status": status})
        incidents.sort(key=lambda i: i["started_at"], reverse=True)

    checked = [c["ts"] for name, c in latest.items() if c.get("ts") and name in {s.name for s in sites}]
    last_checked = max(checked) if checked else None
    conn = storage.get_kv("connectivity") or {}
    stale = bool(conn.get("offline")) or last_checked is None or \
        now - last_checked > cfg.general.check_interval_minutes * 60 * 3
    client = cfg.clients.get(client_id) if client_id else None
    return {"title": f"{client.name} status" if client else cfg.status_page.title, "overall": overall,
            "headline": headline, "services": services, "incidents": incidents[:10], "days": days,
            "last_checked": last_checked, "stale": stale, "generated_at": now}

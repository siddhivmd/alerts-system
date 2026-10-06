"""Monthly SLA reports per client, and reliability metrics for you (MTTA, MTTR, top causes).

Numbers come from data already stored:
* uptime %     = share of checks in the period that were not DOWN (monitor-offline time has no
                 checks, so it never counts against a site)
* incidents    = outages that overlap the period; downtime is clipped to the period
* MTTR         = mean time from first failed check to recovery (incidents that ended)
* MTTA         = mean time from first failed check to someone pressing "Acknowledge"
* top causes   = incidents grouped by diagnosis cause code (e.g. service_down:php8.2-fpm)
"""
from __future__ import annotations

import logging
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .alerts import Formatter, format_duration
from .config import ClientConfig, Config, SiteConfig
from .storage import Storage

log = logging.getLogger(__name__)
TEMPLATES = Path(__file__).parent / "templates"
NO_CLIENT = "_unassigned"


# --------------------------------------------------------------------------- periods

def parse_month(text: str) -> tuple[int, int]:
    """'2026-09' -> (2026, 9)"""
    try:
        year, month = (int(x) for x in text.split("-"))
        datetime(year, month, 1)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid month {text!r}: use YYYY-MM, e.g. 2026-09") from None
    return year, month


def previous_month(now: float, tz_name: str) -> tuple[int, int]:
    d = datetime.fromtimestamp(now, ZoneInfo(tz_name))
    return (d.year - 1, 12) if d.month == 1 else (d.year, d.month - 1)


def month_range(year: int, month: int, tz_name: str) -> tuple[float, float, str]:
    tz = ZoneInfo(tz_name)
    start = datetime(year, month, 1, tzinfo=tz)
    end = datetime(year + (month == 12), 1 if month == 12 else month + 1, 1, tzinfo=tz)
    return start.timestamp(), end.timestamp(), start.strftime("%B %Y")


# --------------------------------------------------------------------------- per-site numbers

@dataclass
class SiteStats:
    name: str
    public_name: str
    url: str
    client: str
    server: str
    sla_target: float
    checks: int = 0
    uptime_pct: float | None = None
    avg_ms: int | None = None
    incidents: list[dict[str, Any]] = field(default_factory=list)
    downtime_s: float = 0.0
    longest_s: float = 0.0
    mttr_s: float | None = None
    mtta_s: float | None = None
    unacknowledged: int = 0
    ssl_days_left: int | None = None
    domain_days_left: int | None = None

    @property
    def sla_met(self) -> bool | None:
        return None if self.uptime_pct is None else self.uptime_pct >= self.sla_target


def _mean(values: list[float]) -> float | None:
    return sum(values) / len(values) if values else None


def cause_label(incident: dict[str, Any]) -> str:
    text = (incident.get("cause") or incident.get("cause_code") or "unknown").removeprefix("Site down: ")
    return text if len(text) <= 90 else text[:87] + "..."


def compute(cfg: Config, storage: Storage, start: float, end: float, now: float | None = None,
            sites: list[SiteConfig] | None = None) -> list[SiteStats]:
    """Statistics for every configured site (or ``sites``) over [start, end)."""
    now = time.time() if now is None else now
    sites = cfg.sites if sites is None else sites
    ids = storage.sync_sites([(s.name, s.url) for s in cfg.sites])
    summary = storage.site_summary(start, end)
    latest = {c["name"]: c for c in storage.latest_checks()}
    by_site: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for inc in storage.incidents_between(start, end):
        by_site[inc["site_name"]].append(inc)

    out = []
    for site in sites:
        client = cfg.clients.get(site.client or "")
        st = SiteStats(name=site.name, public_name=site.public_name or site.name, url=site.url,
                       client=site.client or NO_CLIENT,
                       server=site.server or "External hosting",
                       sla_target=client.sla_target if client else 99.9)
        s = summary.get(ids.get(site.name), {})
        st.checks, st.uptime_pct, st.avg_ms = s.get("total", 0), s.get("uptime_pct"), s.get("avg_ms")
        fixes, acks = [], []
        for inc in by_site.get(site.name, []):
            ended = inc["ended_at"]
            duration = (ended or now) - inc["started_at"]
            st.downtime_s += max(0.0, min(end, ended or now) - max(start, inc["started_at"]))
            st.longest_s = max(st.longest_s, duration)
            if ended is not None:
                fixes.append(duration)
            if inc.get("acknowledged_at"):
                acks.append(inc["acknowledged_at"] - inc["started_at"])
            else:
                st.unacknowledged += 1
            st.incidents.append({**inc, "duration_s": duration, "ongoing": ended is None,
                                 "cause_label": cause_label(inc)})
        st.mttr_s, st.mtta_s = _mean(fixes), _mean(acks)
        details = (latest.get(site.name) or {}).get("details") or {}
        st.ssl_days_left, st.domain_days_left = details.get("ssl_days_left"), details.get("domain_days_left")
        out.append(st)
    return out


def top_causes(stats: list[SiteStats], limit: int = 5) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    downtime: dict[str, float] = defaultdict(float)
    label: dict[str, str] = {}
    for st in stats:
        for inc in st.incidents:
            code = inc.get("cause_code") or "unknown"
            counts[code] += 1
            downtime[code] += inc["duration_s"]
            label[code] = inc["cause_label"]
    return [{"code": c, "label": label[c], "count": n, "downtime_s": downtime[c]}
            for c, n in counts.most_common(limit)]


def reliability(stats: list[SiteStats]) -> dict[str, Any]:
    """MTTA / MTTR / downtime / top causes overall, per site and per server."""
    def summarise(group: list[SiteStats]) -> dict[str, Any]:
        incidents = [i for s in group for i in s.incidents]
        fixes = [i["duration_s"] for i in incidents if not i["ongoing"]]
        acks = [i["acknowledged_at"] - i["started_at"] for i in incidents if i.get("acknowledged_at")]
        return {"incidents": len(incidents), "downtime_s": sum(s.downtime_s for s in group),
                "mttr_s": _mean(fixes), "mtta_s": _mean(acks),
                "unacknowledged": sum(s.unacknowledged for s in group), "top_causes": top_causes(group)}

    servers: dict[str, list[SiteStats]] = defaultdict(list)
    for st in stats:
        servers[st.server].append(st)
    return {
        "overall": summarise(stats),
        "sites": {st.name: summarise([st]) | {"uptime_pct": st.uptime_pct} for st in stats},
        "servers": {name: summarise(group) for name, group in servers.items()},
    }


# --------------------------------------------------------------------------- rendering

def _env(tz_name: str) -> Environment:
    fmt = Formatter(tz_name)
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html"]))
    env.filters["duration"] = lambda s: "-" if s is None else format_duration(s)
    env.filters["when"] = fmt.when
    env.filters["pct"] = lambda v: "n/a" if v is None else f"{v:.2f}%"
    return env


def _days(v: int | None) -> str:
    return "n/a" if v is None else ("EXPIRED" if v < 0 else f"{v} days")


def render_text(title: str, period: str, stats: list[SiteStats], fmt: Formatter,
                rel: dict[str, Any] | None = None) -> str:
    lines = [title, f"Period: {period}", ""]
    for st in stats:
        verdict = {True: "target met", False: "TARGET MISSED", None: "no data"}[st.sla_met]
        lines.append(f"{st.public_name} ({st.url})")
        lines.append(f"  Uptime: {'n/a' if st.uptime_pct is None else f'{st.uptime_pct:.2f}%'} "
                     f"(target {st.sla_target}%: {verdict}) | avg response "
                     f"{'-' if st.avg_ms is None else f'{st.avg_ms} ms'}")
        lines.append(f"  Incidents: {len(st.incidents)} | downtime {format_duration(st.downtime_s)} | "
                     f"SSL {_days(st.ssl_days_left)} | domain {_days(st.domain_days_left)}")
        for inc in st.incidents:
            fixed = "ONGOING" if inc["ongoing"] else f"fixed in {format_duration(inc['duration_s'])}"
            lines.append(f"    - {fmt.when(inc['started_at'])}: {fixed} - {inc['cause_label']}")
        lines.append("")
    if rel:
        o = rel["overall"]
        lines += ["Reliability (internal)",
                  f"  Incidents {o['incidents']} | MTTR {format_duration(o['mttr_s']) if o['mttr_s'] else '-'} | "
                  f"MTTA {format_duration(o['mtta_s']) if o['mtta_s'] else '-'} | "
                  f"not acknowledged {o['unacknowledged']}"]
        for server, data in rel["servers"].items():
            causes = ", ".join(f"{c['label']} x{c['count']}" for c in data["top_causes"]) or "none"
            lines.append(f"  {server}: {data['incidents']} incident(s); top causes: {causes}")
    return "\n".join(lines)


@dataclass
class Report:
    client_id: str
    subject: str
    text: str
    html: str
    recipients: list[str]
    preview: bool  # True: goes to the owner for review instead of the client
    path: str | None = None


def build_reports(cfg: Config, storage: Storage, year: int, month: int, now: float | None = None,
                  only_client: str | None = None) -> list[Report]:
    """One report per client (+ one internal report with all sites and reliability metrics)."""
    start, end, period = month_range(year, month, cfg.general.timezone)
    stats = compute(cfg, storage, start, end, now)
    env, fmt = _env(cfg.general.timezone), Formatter(cfg.general.timezone)
    owner = list(cfg.alerts.email.to) if cfg.alerts.email else []
    reports: list[Report] = []

    for cid, client in cfg.clients.items():
        if only_client and cid != only_client:
            continue
        mine = [s for s in stats if s.client == cid]
        if not mine:
            continue
        reports.append(_client_report(cfg, env, fmt, client, mine, period, owner))

    if not only_client:
        rel = reliability(stats)
        html = env.get_template("sla_report.html").render(
            title="Monthly reliability report (internal)", period=period, stats=stats, internal=True, rel=rel,
            client=None, clients=cfg.clients, days=_days, generated=fmt.when(time.time()))
        reports.append(Report("internal", f"[MONTHLY] Reliability report - {period}",
                              render_text("Monthly reliability report (internal)", period, stats, fmt, rel),
                              html, owner, preview=False))
    return reports


def _client_report(cfg: Config, env: Environment, fmt: Formatter, client: ClientConfig, stats: list[SiteStats],
                   period: str, owner: list[str]) -> Report:
    title = f"{client.name} - service report"
    html = env.get_template("sla_report.html").render(
        title=title, period=period, stats=stats, internal=False, rel=None, client=client, clients=cfg.clients,
        days=_days, generated=fmt.when(time.time()))
    missed = [s for s in stats if s.sla_met is False]
    status = "target missed" if missed else "all targets met"
    send_to_client = cfg.monthly_report.send_to_clients and bool(client.report_to)
    subject = f"{client.name}: uptime report {period} ({status})"
    if not send_to_client:
        subject = f"[PREVIEW for {client.name}] {subject}"
    return Report(client.id, subject, render_text(title, period, stats, fmt), html,
                  list(client.report_to) if send_to_client else owner, preview=not send_to_client)


def save(report: Report, cfg: Config, year: int, month: int) -> str:
    folder = Path(cfg.monthly_report.reports_dir) / f"{year:04d}-{month:02d}"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{report.client_id}.html"
    path.write_text(report.html, encoding="utf-8")
    report.path = str(path)
    return report.path


def send_monthly(cfg: Config, storage: Storage, notifier: Any, year: int | None = None, month: int | None = None,
                 send: bool = True, only_client: str | None = None) -> list[Report]:
    """Build, save and (optionally) send the monthly reports. Never raises on delivery problems."""
    if year is None or month is None:
        year, month = previous_month(time.time(), cfg.general.timezone)
    reports = build_reports(cfg, storage, year, month, only_client=only_client)
    for r in reports:
        if cfg.monthly_report.save_html:
            try:
                save(r, cfg, year, month)
            except OSError:
                log.exception("Could not save report %s", r.client_id)
        if not send:
            continue
        email = next((ch for ch in notifier.channels if ch.name == "email"), None)
        if "email" in cfg.monthly_report.channels and email and r.recipients:
            try:
                email.send_rich(r.subject, r.text, r.html, to=r.recipients)
                log.info("Monthly report %s sent to %s", r.client_id, ", ".join(r.recipients))
            except Exception as exc:  # noqa: BLE001
                log.error("Sending monthly report %s failed: %s", r.client_id, exc)
        elif "email" in cfg.monthly_report.channels:
            log.warning("Monthly report %s not emailed: email alerts or recipients not configured", r.client_id)
    others = [c for c in cfg.monthly_report.channels if c != "email"]
    internal = next((r for r in reports if r.client_id == "internal"), None)
    if send and others and internal:  # short version on chat channels, owner only
        notifier.send(internal.subject, internal.text, internal.text, only=others)
    return reports

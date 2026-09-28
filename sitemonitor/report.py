"""Daily summary: status, 24h uptime %, average response time, incidents, warnings, VPS health."""
from __future__ import annotations

import time

from .alerts import Formatter, format_duration
from .config import Config
from .storage import Storage


def build_daily_report(cfg: Config, storage: Storage, now: float | None = None) -> tuple[str, str]:
    """Return (subject, plain-text body) covering the last 24 hours."""
    now = now or time.time()
    since = now - 86400
    fmt = Formatter(cfg.general.timezone)
    configured = {s.name for s in cfg.sites}
    latest = [c for c in storage.latest_checks() if c["name"] in configured]
    summary = storage.site_summary(since)
    incidents = [i for i in storage.incidents(limit=200, since=since) if i["site_name"] in configured]

    counts = {"up": 0, "warning": 0, "down": 0, None: 0}
    rows = []
    warnings: list[str] = []
    for c in latest:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
        s = summary.get(c["site_id"], {})
        uptime = f"{s['uptime_pct']:.2f}%" if s.get("uptime_pct") is not None else "n/a"
        avg = f"{s['avg_ms']} ms" if s.get("avg_ms") is not None else "-"
        status = (c["status"] or "no data").upper()
        rows.append(f"{c['name'][:28]:<28} {status:<8} {uptime:>9} {avg:>9}   {c['url']}")
        if c["status"] == "down":
            warnings.append(f"{c['name']}: DOWN - {c['summary']}")
        for w in (c.get("details") or {}).get("warnings", []):
            warnings.append(f"{c['name']}: {w['message']}")

    total = len(latest)
    lines = [f"Daily site report - {fmt.when(now)}",
             f"{counts['up']} up, {counts['warning']} with warnings, {counts['down']} down (of {total} sites)", "",
             f"{'SITE':<28} {'STATUS':<8} {'UPTIME 24h':>9} {'AVG':>9}   URL", "-" * 90, *rows, ""]

    lines.append(f"Incidents in the last 24h: {len(incidents)}")
    for i in incidents:
        end = fmt.when(i["ended_at"]) if i["ended_at"] else "ONGOING"
        dur = format_duration((i["ended_at"] or now) - i["started_at"])
        lines.append(f"  - {i['site_name']}: {fmt.when(i['started_at'])} -> {end} ({dur}) - {i['cause']}")
    lines.append("")

    if cfg.vps:
        v = storage.latest_vps()
        if v:
            lines.append(f"VPS {cfg.vps.name} ({cfg.vps.host}) at {fmt.when(v['ts'])}: "
                         f"{'reachable' if v['reachable'] else 'UNREACHABLE'}")
            if v["ram_percent"] is not None:
                load = f"{v['cpu_load']:.2f} on {v['cpu_cores']} cores" if v["cpu_load"] is not None else "n/a"
                lines.append(f"  RAM {v['ram_percent']:.0f}% | CPU load {load} | Disk {v['disk_percent'] or 0:.0f}% | "
                             f"OOM kills: {v['oom_kills']}")
                services = v.get("services") or {}
                bad = [n for n, s in services.items() if s.get("active") == "failed" or (
                    s.get("active") == "inactive" and s.get("enabled") == "enabled")]
                states = [f"{name}={st.get('active')}" for name, st in services.items()]
                lines.append(f"  Services: {', '.join(states) or 'n/a'}")
                if bad:
                    warnings.append(f"VPS: service(s) not running: {', '.join(bad)}")
            elif v["error"]:
                lines.append(f"  Stats unavailable: {v['error']}")
        else:
            lines.append("VPS: no data yet")
        lines.append("")

    lines.append("Needs attention:" if warnings else "Needs attention: nothing")
    lines += [f"  - {w}" for w in warnings]

    if counts["down"]:
        subject = f"[DAILY] {counts['down']} site(s) DOWN, {len(warnings)} issue(s)"
    elif warnings:
        subject = f"[DAILY] All {total} sites up - {len(warnings)} warning(s)"
    else:
        subject = f"[DAILY] All {total} sites healthy"
    return subject, "\n".join(lines)

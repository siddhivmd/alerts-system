#!/usr/bin/env python3
"""Website + VPS monitor - command line entry point.

  python monitor.py run            start the scheduler and the dashboard (long-running)
  python monitor.py check          one-off check of every site, print the diagnosis
  python monitor.py test-alerts    send a test email / Telegram message
  python monitor.py report         print (or --send) the daily summary; --monthly for SLA reports
  python monitor.py ack SITE       acknowledge a site's open incident ("I'm on it")
  python monitor.py pause 30m      maintenance mode: mute alerts (all sites or --site); resume to end
  python monitor.py accept-content accept an intended page redesign (defacement baseline)

Run it on a machine that is NOT the monitored VPS (see README).
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from typing import Any

from sitemonitor.alerts import Notifier
from sitemonitor.config import Config, ConfigError, load_config
from sitemonitor.logging_setup import setup_logging
from sitemonitor.runner import CycleResult, Monitor
from sitemonitor.storage import Storage

log = logging.getLogger("monitor")


def _load(args: argparse.Namespace) -> Config:
    try:
        cfg = load_config(args.config, args.env_file)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(2)
    setup_logging(cfg.general.log_file, "DEBUG" if args.verbose else cfg.general.log_level)
    for warning in cfg.warnings:
        log.warning("Config: %s", warning)
    return cfg


def _supports_color() -> bool:
    return sys.stdout.isatty()


def print_cycle(cycle: CycleResult, cfg: Config) -> None:
    color = _supports_color()
    paint = {"up": "\033[32m", "warning": "\033[33m", "down": "\033[31m"} if color else {}
    reset = "\033[0m" if color else ""

    if cycle.reach is not None:
        ports = ", ".join(f"{p}:{'open' if ok else 'CLOSED'}" for p, ok in cycle.reach.ports.items())
        print(f"VPS {cfg.vps.name} ({cycle.reach.host}): {'reachable' if cycle.reach.reachable else 'UNREACHABLE'} [{ports}]")
        st = cycle.stats
        if st is None:
            print("  SSH stats: not configured")
        elif not st.ok:
            print(f"  SSH stats unavailable: {st.error}")
        else:
            print(f"  RAM {st.ram_percent}% | load {st.cpu_load} on {st.cpu_cores} cores | disk / {st.disk_percent}% "
                  f"| OOM kills ({st.oom_window}): {st.oom_kills}")
            services = ", ".join(f"{name}={s.get('active')}" for name, s in st.services.items())
            print(f"  services: {services or 'none found'}")
        print()

    sec = cycle.security
    if sec.get("enabled"):
        print("Security:")
        for line in sec.get("blacklists") or ["no IP to check (enable vps or add security.extra_ips)"]:
            print(f"  Spam blacklists: {line}")
        print(f"  Google Safe Browsing: {sec.get('safe_browsing') or 'off (needs GOOGLE_SAFE_BROWSING_KEY)'}")
        print(f"  Server checks over SSH: {'on' if sec.get('ssh_checks') else 'off (needs vps.ssh)'}")
    if cycle.vps_warnings:
        print("Server warnings:")
        for w in cycle.vps_warnings:
            print(f"  {'CRITICAL' if w.severity == 'critical' else 'warning '} {w.message}")
            if w.fix:
                print(f"           fix: {w.fix}")
    if sec.get("enabled") or cycle.vps_warnings:
        print()

    for r, d in zip(cycle.results, cycle.diagnoses):
        timing = f"{r.response_ms} ms" if r.response_ms is not None else "no response"
        status = f"HTTP {r.http_status}" if r.http_status else ""
        print(f"{paint.get(d.status, '')}[{d.status.upper():^7}]{reset} {r.site}  {r.url}  {status} {timing}")
        if r.redirects:
            print(f"          redirects: {' -> '.join(r.redirects)} -> {r.final_url}")
        extras = []
        if r.ssl_days_left is not None:
            extras.append(f"SSL {r.ssl_days_left}d left")
        if r.domain_days_left is not None:
            extras.append(f"domain {r.domain} {r.domain_days_left}d left")
        elif r.domain_error:
            extras.append(f"domain: {r.domain_error}")
        if extras:
            print(f"          {' | '.join(extras)}")
        if d.status == "down":
            print(f"          CAUSE: {d.cause}")
            for e in d.evidence:
                print(f"            - {e}")
            for f in d.fixes:
                print(f"          FIX: {f}")
            for line in d.error_log[-5:]:
                print(f"            log| {line}")
        for w in d.warnings:
            print(f"          WARNING: {w.message}" + (f"  (fix: {w.fix})" if w.fix else ""))
    print(f"\n{len(cycle.results)} site(s) checked in {cycle.duration:.1f}s: "
          f"{sum(d.status == 'up' for d in cycle.diagnoses)} up, "
          f"{sum(d.status == 'warning' for d in cycle.diagnoses)} warning, {len(cycle.down)} down")
    if cycle.events:
        print(f"{len(cycle.events)} alert event(s): {'delivered' if cycle.alerts_delivered else 'NOT delivered'}")


def cmd_check(args: argparse.Namespace) -> int:
    cfg = _load(args)
    if not args.verbose:
        logging.getLogger().handlers[0].setLevel(logging.WARNING)  # keep console output readable
    storage = Storage(cfg.general.database)
    monitor = Monitor(cfg, storage)
    unknown = set(args.site or []) - {s.name for s in cfg.sites}
    if unknown:
        print(f"Unknown site(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    cycle = monitor.run_cycle(save=args.save, alert=args.alert, only=args.site)
    if cycle.offline:
        print("MONITOR OFFLINE: this machine has no internet connection, so no site was checked.")
        print("None of the canary hosts answered:")
        for host, error in cycle.offline_details.items():
            print(f"  - {host}: {error}")
        print("Fix this machine's network (or general.canary_hosts) and run the check again.")
        return 2
    if args.json:
        out: dict[str, Any] = {
            "vps": cycle.reach.to_dict() if cycle.reach else None,
            "vps_stats": cycle.stats.to_dict() if cycle.stats else None,
            "vps_warnings": [w.__dict__ for w in cycle.vps_warnings],
            "sites": [{"result": r.to_dict(), "diagnosis": d.to_dict()} for r, d in zip(cycle.results, cycle.diagnoses)],
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        print_cycle(cycle, cfg)
    return 1 if cycle.down else 0


def cmd_test_alerts(args: argparse.Namespace) -> int:
    cfg = _load(args)
    for warning in cfg.warnings:
        if "alerts off" in warning:
            print(f"skipped   {warning}")
    results = Notifier(cfg.alerts, cfg.general.timezone).test()
    if not results:
        print("No alert channels are enabled. Enable alerts.email, alerts.telegram or alerts.console in config.yaml.")
        return 1
    for channel, error in results.items():
        ok = "OK - printed above" if channel == "console" else "OK - check your inbox/chat"
        print(f"{channel:<9} {ok if error is None else 'FAILED: ' + error}")
    return 0 if all(e is None for e in results.values()) else 1


def cmd_report(args: argparse.Namespace) -> int:
    from sitemonitor.report import build_daily_report
    cfg = _load(args)
    storage = Storage(cfg.general.database)
    storage.sync_sites([(s.name, s.url) for s in cfg.sites])
    if args.monthly or args.month:
        return _monthly_report(cfg, storage, args)
    subject, body = build_daily_report(cfg, storage)
    print(subject, "\n", body, sep="\n")
    if args.send:
        results = Notifier(cfg.alerts, cfg.general.timezone).send(subject, body, only=cfg.daily_report.channels)
        print(f"\nSent: {results or 'no matching channels configured'}")
    return 0


def _monthly_report(cfg: Config, storage: Storage, args: argparse.Namespace) -> int:
    from sitemonitor import sla
    try:
        year, month = sla.parse_month(args.month) if args.month else sla.previous_month(time.time(),
                                                                                         cfg.general.timezone)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    if args.client and args.client not in cfg.clients:
        print(f"Unknown client {args.client!r}. Defined clients: {', '.join(cfg.clients) or 'none'}", file=sys.stderr)
        return 2
    reports = sla.send_monthly(cfg, storage, Notifier(cfg.alerts, cfg.general.timezone), year, month,
                               send=args.send, only_client=args.client)
    for r in reports:
        print("=" * 78)
        print(r.subject)
        print(f"To: {', '.join(r.recipients) or '(no recipients)'}" + ("  [preview: client not emailed]" if r.preview
                                                                      else ""))
        if r.path:
            print(f"Saved: {r.path}  (open in a browser; Print > Save as PDF)")
        print("-" * 78)
        print(r.text)
    if not reports:
        print("No sites to report on.")
    elif not args.send:
        print("\n(Not sent. Add --send to email these reports.)")
    return 0


def cmd_ack(args: argparse.Namespace) -> int:
    cfg = _load(args)
    storage = Storage(cfg.general.database)
    incident = storage.open_incident_for(args.site)
    if incident is None:
        print(f"No open incident for {args.site!r}.")
        return 1
    if not storage.acknowledge_incident(incident["id"], args.by, time.time()):
        print(f"Incident for {args.site!r} was already acknowledged by {incident.get('acknowledged_by')}.")
        return 1
    print(f"Acknowledged {args.site!r} (down since {time.strftime('%Y-%m-%d %H:%M', time.localtime(incident['started_at']))}) "
          f"as {args.by}. Reminders and escalation are stopped; you will still get the RECOVERED alert.")
    return 0


def cmd_pause(args: argparse.Namespace) -> int:
    from sitemonitor import maintenance
    cfg = _load(args)
    try:
        minutes = maintenance.parse_duration(args.duration)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    unknown = set(args.site or []) - {s.name for s in cfg.sites}
    if unknown:
        print(f"Unknown site(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    record = maintenance.start(Storage(cfg.general.database), minutes, args.site, args.reason or "")
    until = time.strftime("%Y-%m-%d %H:%M", time.localtime(record["until"]))
    print(f"Maintenance mode until {until}: alerts paused for {', '.join(record['sites']) or 'ALL sites and the server'}. "
          "Checks keep running. End early with: python monitor.py resume")
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    from sitemonitor import maintenance
    cfg = _load(args)
    was_active = maintenance.end(Storage(cfg.general.database))
    print("Maintenance mode ended: alerts are active again." if was_active else "Maintenance mode was not active.")
    return 0


def cmd_accept_content(args: argparse.Namespace) -> int:
    from sitemonitor import content
    cfg = _load(args)
    if args.site and args.site not in {s.name for s in cfg.sites}:
        print(f"Unknown site {args.site!r}", file=sys.stderr)
        return 2
    content.accept(Storage(cfg.general.database), args.site)
    print(f"Page-text baseline reset for {args.site or 'all sites'}: the next healthy check records the current "
          "page as the new normal.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from sitemonitor.dashboard import create_app, serve
    from sitemonitor.scheduler import build_scheduler

    cfg = _load(args)
    storage = Storage(cfg.general.database)
    monitor = Monitor(cfg, storage)
    sched = build_scheduler(cfg, monitor)

    stop = threading.Event()

    def _terminate(signum: int, _frame: Any) -> None:
        log.info("Received signal %s, shutting down", signum)
        stop.set()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)

    log.info("Starting monitor: %d site(s), every %d min, VPS=%s, SSH=%s, email=%s, telegram=%s",
             len(cfg.sites), cfg.general.check_interval_minutes, cfg.vps.host if cfg.vps else "none",
             bool(cfg.vps and cfg.vps.ssh), bool(cfg.alerts.email), bool(cfg.alerts.telegram))
    if not cfg.alerts.email and not cfg.alerts.telegram:
        log.warning("No email/Telegram alerts enabled - problems will only show in the log%s and dashboard",
                    " (console alerts on)" if cfg.alerts.console else "")
    sched.start()
    try:
        dash = cfg.dashboard
        # The web server also serves the public status page, so it runs if either is enabled.
        if (dash.enabled or cfg.status_page.enabled) and not args.no_dashboard:
            app = create_app(cfg, storage, lambda: monitor.last_cycle.ts if monitor.last_cycle else None,
                             lambda: monitor.last_cycle.problems if monitor.last_cycle else [])
            serve(app, dash.host, dash.port)
            return 0
        stop.wait()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        # Let a check cycle that is already running finish (at most a few seconds), so its
        # results and alerts are saved and "Monitor stopped" really is the last log line.
        log.info("Stopping: waiting for any running check cycle to finish...")
        sched.shutdown(wait=True)
        log.info("Monitor stopped")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Website and VPS monitor with root-cause diagnosis")
    p.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml (default: ./config.yaml)")
    p.add_argument("--env-file", default=None, help="path to .env (default: next to config.yaml)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="start scheduler + dashboard (long-running)")
    r.add_argument("--no-dashboard", action="store_true", help="run checks only, no web dashboard")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="run one check cycle now and print the results")
    c.add_argument("--site", action="append", help="only check this site (repeatable)")
    c.add_argument("--save", action="store_true", help="store results in the database")
    c.add_argument("--alert", action="store_true", help="store results AND send alerts like the scheduler does")
    c.add_argument("--json", action="store_true", help="print raw results as JSON")
    c.set_defaults(func=cmd_check)

    t = sub.add_parser("test-alerts", help="send a test message on every enabled channel")
    t.set_defaults(func=cmd_test_alerts)

    rep = sub.add_parser("report", help="print the daily summary, or the monthly SLA reports (--monthly)")
    rep.add_argument("--send", action="store_true", help="also send it (daily: daily_report channels)")
    rep.add_argument("--monthly", action="store_true", help="monthly SLA report per client + internal reliability")
    rep.add_argument("--month", help="which month, YYYY-MM (default: last month); implies --monthly")
    rep.add_argument("--client", help="only this client id (monthly)")
    rep.set_defaults(func=cmd_report)

    a = sub.add_parser("ack", help="acknowledge a site's open incident: stops reminders and escalation")
    a.add_argument("site", help="site name as in config.yaml")
    a.add_argument("--by", default="cli", help="your name (shown on the incident)")
    a.set_defaults(func=cmd_ack)

    pz = sub.add_parser("pause", help="maintenance mode: mute alerts for a while (checks keep running)")
    pz.add_argument("duration", help="e.g. 30m, 2h, 1d")
    pz.add_argument("--site", action="append", help="only this site (repeatable); default: everything")
    pz.add_argument("--reason", help="shown in the log, e.g. 'server upgrade'")
    pz.set_defaults(func=cmd_pause)

    rs = sub.add_parser("resume", help="end maintenance mode now")
    rs.set_defaults(func=cmd_resume)

    ac = sub.add_parser("accept-content", help="accept an intended page change (resets the defacement baseline)")
    ac.add_argument("--site", help="only this site (default: all)")
    ac.set_defaults(func=cmd_accept_content)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())

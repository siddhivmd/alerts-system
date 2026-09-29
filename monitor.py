#!/usr/bin/env python3
"""Website + VPS monitor - command line entry point.

  python monitor.py run            start the scheduler and the dashboard (long-running)
  python monitor.py check          one-off check of every site, print the diagnosis
  python monitor.py test-alerts    send a test email / Telegram message
  python monitor.py report         print (or --send) the daily summary

Run it on a machine that is NOT the monitored VPS (see README).
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
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
        for w in cycle.vps_warnings:
            print(f"  ! {w.message}")
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
    subject, body = build_daily_report(cfg, storage)
    print(subject, "\n", body, sep="\n")
    if args.send:
        results = Notifier(cfg.alerts, cfg.general.timezone).send(subject, body, only=cfg.daily_report.channels)
        print(f"\nSent: {results or 'no matching channels configured'}")
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
        if dash.enabled and not args.no_dashboard:
            app = create_app(cfg, storage, lambda: monitor.last_cycle.ts if monitor.last_cycle else None)
            serve(app, dash.host, dash.port)
            return 0
        stop.wait()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        sched.shutdown(wait=False)
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

    rep = sub.add_parser("report", help="print the daily summary (from stored history)")
    rep.add_argument("--send", action="store_true", help="also send it on the daily_report channels")
    rep.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())

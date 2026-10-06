"""APScheduler jobs: periodic checks, the daily report and nightly data retention."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Callable

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from .config import Config
from .report import build_daily_report
from .runner import Monitor

log = logging.getLogger(__name__)


def _guard(name: str, fn: Callable[[], object]) -> Callable[[], None]:
    """A job that raises would only be logged by APScheduler; we log with context and move on."""
    def job() -> None:
        try:
            fn()
        except Exception:  # noqa: BLE001
            log.exception("Scheduled job %s failed", name)
    job.__name__ = name
    return job


def send_daily_report(cfg: Config, monitor: Monitor) -> None:
    subject, body = build_daily_report(cfg, monitor.storage)
    results = monitor.notifier.send(subject, body, only=cfg.daily_report.channels)
    if not results:
        log.warning("Daily report not sent: none of the channels %s is configured", cfg.daily_report.channels)


def send_monthly_reports(cfg: Config, monitor: Monitor) -> None:
    from . import sla
    reports = sla.send_monthly(cfg, monitor.storage, monitor.notifier)  # last month
    log.info("Monthly reports done: %s", ", ".join(r.client_id for r in reports) or "none")


def purge_old_data(cfg: Config, monitor: Monitor) -> None:
    removed = monitor.storage.purge(cfg.general.retention_days)
    log.info("Retention: removed %s row(s) older than %d days", removed, cfg.general.retention_days)


def build_scheduler(cfg: Config, monitor: Monitor) -> BackgroundScheduler:
    tz = cfg.general.timezone
    sched = BackgroundScheduler(timezone=tz, job_defaults={
        "coalesce": True,          # after a pause, run once instead of catching up every missed run
        "max_instances": 1,        # never overlap cycles
        "misfire_grace_time": 120,
    })
    sched.add_job(_guard("checks", monitor.run_cycle),
                  IntervalTrigger(minutes=cfg.general.check_interval_minutes, timezone=tz),
                  id="checks", name="checks", next_run_time=datetime.now(sched.timezone))
    if cfg.daily_report.enabled:
        hour, minute = (int(x) for x in cfg.daily_report.time.split(":"))
        sched.add_job(_guard("daily_report", lambda: send_daily_report(cfg, monitor)),
                      CronTrigger(hour=hour, minute=minute, timezone=tz), id="daily_report", name="daily_report")
    if cfg.monthly_report.enabled:
        hour, minute = (int(x) for x in cfg.monthly_report.time.split(":"))
        sched.add_job(_guard("monthly_report", lambda: send_monthly_reports(cfg, monitor)),
                      CronTrigger(day=cfg.monthly_report.day, hour=hour, minute=minute, timezone=tz),
                      id="monthly_report", name="monthly_report")
    sched.add_job(_guard("purge", lambda: purge_old_data(cfg, monitor)),
                  CronTrigger(hour=3, minute=30, timezone=tz), id="purge", name="purge")
    log.info("Scheduled: checks every %d min, daily report %s, purge 03:30 (%s)",
             cfg.general.check_interval_minutes,
             cfg.daily_report.time if cfg.daily_report.enabled else "disabled", tz)
    return sched

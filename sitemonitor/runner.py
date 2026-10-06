"""One monitoring cycle: check everything concurrently, diagnose, store, alert."""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, TypeVar

from . import content, maintenance
from .alerts import AlertEvent, AlertManager, Notifier, escalation_notifier
from .backups import backup_summary, backup_warnings
from .checks import SiteCheckResult, VpsReachability, WhoisLookup, check_site, check_vps_ports
from .config import Config, SiteConfig
from .diagnosis import DOWN, UP, WARNING, Diagnosis, Warn, diagnose, is_failing, vps_warnings
from .heartbeat import Heartbeat
from .security import SecurityChecker
from .ssh_stats import VpsStats, collect_stats, fetch_error_logs
from .storage import Storage

log = logging.getLogger(__name__)
T = TypeVar("T")


@dataclass
class CycleResult:
    ts: float
    results: list[SiteCheckResult]
    diagnoses: list[Diagnosis]
    reach: VpsReachability | None = None
    stats: VpsStats | None = None
    vps_warnings: list[Warn] = field(default_factory=list)  # server health + security warnings
    security: dict[str, Any] = field(default_factory=dict)  # human-readable security status
    events: list[AlertEvent] = field(default_factory=list)
    alerts_delivered: bool | None = None
    maintenance: dict[str, Any] | None = None  # active maintenance window, if any
    duration: float = 0.0

    @property
    def down(self) -> list[Diagnosis]:
        return [d for d in self.diagnoses if d.status == DOWN]


def _safe_result(future: Future[T] | None, what: str) -> T | None:
    if future is None:
        return None
    try:
        return future.result()
    except Exception:  # noqa: BLE001
        log.exception("%s failed unexpectedly", what)
        return None


class Monitor:
    """Owns the long-lived pieces (storage, WHOIS cache, alert state) and runs cycles."""

    def __init__(self, cfg: Config, storage: Storage, notifier: Notifier | None = None) -> None:
        self.cfg = cfg
        self.storage = storage
        self.site_ids = storage.sync_sites([(s.name, s.url) for s in cfg.sites])
        self.whois = WhoisLookup(storage)
        self.alerts = AlertManager(storage, cfg.alerts)
        self.notifier = notifier or Notifier(cfg.alerts, cfg.general.timezone)
        self.escalation_notifier = escalation_notifier(cfg.alerts, cfg.general.timezone)
        self.security = SecurityChecker(cfg)
        self.heartbeat = Heartbeat(cfg.heartbeat)
        # Alert key for server-level warnings (works even without a VPS, e.g. security.extra_ips).
        self.server_key = cfg.vps.name if cfg.vps else "Server"
        self.last_cycle: CycleResult | None = None
        self._cycle_lock = threading.Lock()

    # ------------------------------------------------------------------ public
    def run_cycle(self, save: bool = True, alert: bool = True, only: list[str] | None = None) -> CycleResult:
        """Run all checks. ``save`` writes history; ``alert`` (implies save) sends notifications."""
        if not self._cycle_lock.acquire(blocking=False):
            log.warning("Previous check cycle still running; skipping this one")
            return self.last_cycle or CycleResult(ts=time.time(), results=[], diagnoses=[])
        try:
            cycle = self._run(save=save or alert, alert=alert, only=only)
        except Exception as exc:
            if alert:  # scheduled cycle crashed: tell the watchdog right away
                self.heartbeat.ping(ok=False, message=f"Check cycle crashed: {type(exc).__name__}: {exc}")
            raise
        finally:
            self._cycle_lock.release()
        if alert:  # only real (scheduled / --alert) cycles count as "alive"
            up = sum(d.status != DOWN for d in cycle.diagnoses)
            self.heartbeat.ping(ok=True, message=f"{up} up, {len(cycle.down)} down, "
                                                 f"{len(cycle.events)} alert event(s)")
        return cycle

    # ------------------------------------------------------------------ internals
    def _run(self, save: bool, alert: bool, only: list[str] | None) -> CycleResult:
        started = time.time()
        sites = [s for s in self.cfg.sites if not only or s.name in only]
        vps = self.cfg.vps
        workers = max(1, min(self.cfg.general.max_workers, len(sites) + 2))

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="check") as ex:
            reach_f = ex.submit(check_vps_ports, vps) if vps else None
            stats_f = (ex.submit(collect_stats, vps.host, vps.ssh, self.cfg.security, self.cfg.backups)
                       if vps and vps.ssh else None)
            security_f = ex.submit(self.security.refresh, started)  # blacklists / Safe Browsing (cached)
            site_fs = [(s, ex.submit(check_site, s, self.whois, self.cfg.general.user_agent)) for s in sites]
            results = []
            for site, fut in site_fs:
                res = _safe_result(fut, f"Check of {site.name}")
                results.append(res or SiteCheckResult(site=site.name, url=site.url, on_vps=site.on_vps,
                                                      error_kind="internal", error_message="check crashed"))
            reach = _safe_result(reach_f, "VPS port check")
            stats = _safe_result(stats_f, "VPS stats")
            _safe_result(security_f, "Security lookups")

        logs_by_site = self._error_logs(sites, results, reach, stats)
        th = self.cfg.thresholds
        diagnoses = []
        for r in results:
            try:
                diagnoses.append(diagnose(r, reach if r.on_vps else None, stats if r.on_vps else None, th,
                                          logs_by_site.get(r.site)))
            except Exception as exc:  # noqa: BLE001
                log.exception("Diagnosis failed for %s", r.site)
                diagnoses.append(Diagnosis(site=r.site, url=r.url, status=DOWN if is_failing(r) else "up",
                                           cause_code="diagnosis_error", cause=f"Could not diagnose: {exc}"))
        vps_warns = vps_warnings(stats, reach, th) if vps else []
        security_status: dict[str, Any] = {}
        try:
            vps_warns += self.security.server_warnings(stats)
            flagged = self.security.site_warnings()
            for d in diagnoses:
                if d.site in flagged:
                    d.warnings += flagged[d.site]
                    if d.status == UP:
                        d.status = WARNING
            security_status = self.security.summary()
        except Exception:  # noqa: BLE001 - security checks must never break the site checks
            log.exception("Security evaluation failed")
        try:
            vps_warns += backup_warnings(stats, self.cfg.backups)
            security_status["backups"] = backup_summary(stats, self.cfg.backups)
        except Exception:  # noqa: BLE001
            log.exception("Backup check failed")
        self._check_content(sites, results, diagnoses, save)

        cycle = CycleResult(ts=started, results=results, diagnoses=diagnoses, reach=reach, stats=stats,
                            vps_warnings=vps_warns, security=security_status)
        if save:
            self._save(cycle)
        if alert:
            self._alert(cycle)
        cycle.duration = time.time() - started
        self.last_cycle = cycle
        log.info("Cycle done in %.1fs: %d site(s), %d down, %d alert event(s)",
                 cycle.duration, len(results), len(cycle.down), len(cycle.events))
        return cycle

    def _check_content(self, sites: list[SiteConfig], results: list[SiteCheckResult],
                       diagnoses: list[Diagnosis], save: bool) -> None:
        """Defacement detection on every page that loaded fine. Never raises."""
        by_name = {s.name: s for s in sites}
        for r, d in zip(results, diagnoses):
            site = by_name.get(r.site)
            if site is None or d.status == DOWN:
                continue
            try:
                extra = content.check_content(self.storage, site, r.page_words, r.defacement_text, save=save,
                                              now=r.ts)
            except Exception:  # noqa: BLE001
                log.exception("Content check failed for %s", r.site)
                continue
            if extra:
                d.warnings += extra
                if d.status == UP:
                    d.status = WARNING

    def _error_logs(self, sites: list[SiteConfig], results: list[SiteCheckResult],
                    reach: VpsReachability | None, stats: VpsStats | None) -> dict[str, list[str]]:
        """Fetch web server error-log tails, only when a VPS-hosted site is failing."""
        vps = self.cfg.vps
        if not vps or not vps.ssh or not stats or not stats.ok or (reach and reach.all_down):
            return {}
        by_name = {s.name: s for s in sites}
        failing = [by_name[r.site] for r in results if r.on_vps and is_failing(r) and r.site in by_name]
        if not failing:
            return {}
        paths = list(vps.ssh.error_logs) + [s.error_log for s in failing if s.error_log]
        try:
            logs = fetch_error_logs(vps.host, vps.ssh, paths)
        except Exception:  # noqa: BLE001
            log.exception("Fetching error logs failed")
            return {}
        stats.error_logs = logs
        default_lines: list[str] = []
        for path in vps.ssh.error_logs:
            if logs.get(path):
                default_lines += [f"==> {path} <=="] + logs[path]
        out = {}
        for s in failing:
            out[s.name] = logs.get(s.error_log, []) if s.error_log and logs.get(s.error_log) else default_lines
        return out

    def _save(self, cycle: CycleResult) -> None:
        try:
            for r, d in zip(cycle.results, cycle.diagnoses):
                site_id = self.site_ids.get(r.site)
                if site_id is None:
                    continue
                details: dict[str, Any] = {
                    "ssl_days_left": r.ssl_days_left, "domain_days_left": r.domain_days_left,
                    "final_url": r.final_url, "warnings": [w.__dict__ for w in d.warnings],
                }
                if d.status != "up":  # full detail only when something is wrong
                    details["result"] = r.to_dict()
                    details["diagnosis"] = d.to_dict()
                code = d.cause_code or (d.warnings[0].code if d.warnings else None)
                self.storage.record_check(site_id, r.ts, d.status, r.http_status, r.response_ms, code,
                                          d.summary, details)
            if cycle.reach is not None:
                st = cycle.stats
                self.storage.record_vps(
                    cycle.ts, cycle.reach.reachable, cycle.reach.ports,
                    st.to_dict() if st and st.ok else None, st.error if st and not st.ok else None)
            # Latest server/security warnings for the dashboard and daily report.
            self.storage.set_kv("server_status", {
                "ts": cycle.ts, "name": self.server_key, "security": cycle.security,
                "warnings": [w.__dict__ for w in cycle.vps_warnings]})
        except Exception:  # noqa: BLE001
            log.exception("Saving check results failed")

    def _alert(self, cycle: CycleResult) -> None:
        events: list[AlertEvent] = []
        window = maintenance.active(self.storage, cycle.ts)
        cycle.maintenance = window
        try:
            for d in cycle.diagnoses:
                site_id = self.site_ids.get(d.site)
                if site_id is None or maintenance.mutes(window, d.site):
                    continue  # maintenance: alert state is frozen, nothing is sent
                events += self.alerts.evaluate_site(site_id, d, cycle.ts)
                if d.status != DOWN:  # a DOWN alert already lists everything that matters
                    events += self.alerts.evaluate_warnings(d.site, d.warnings, cycle.ts)
            if not maintenance.mutes(window, None):
                events += self.alerts.evaluate_warnings(self.server_key, cycle.vps_warnings, cycle.ts)
        except Exception:  # noqa: BLE001
            log.exception("Alert evaluation failed")
        if window:
            log.info("Maintenance mode until %s: alerts paused for %s", time.strftime(
                "%H:%M", time.localtime(window["until"])), ", ".join(window["sites"]) or "all sites")
        cycle.events = events

        # A retried RECOVERED message may only be owed to the escalation contacts.
        normal = [e for e in events if e.kind != "escalation" and not (e.kind == "recovered" and not e.notify_normal)]
        if normal:
            cycle.alerts_delivered = self.notifier.dispatch(normal)
            if cycle.alerts_delivered:
                self._mark_sent(normal)

        # Escalation contacts get the escalation itself and, optionally, the recovery.
        esc_cfg = self.cfg.alerts.escalation
        escalations = [e for e in events if e.kind == "escalation"]
        recoveries = [e for e in events if e.kind == "recovered" and e.escalated] \
            if esc_cfg and esc_cfg.notify_recovery else []
        if self.escalation_notifier and (escalations or recoveries):
            if self.escalation_notifier.dispatch(escalations + recoveries):
                self._mark_sent(escalations + recoveries, escalation=True)

    def _mark_sent(self, events: list[AlertEvent], escalation: bool = False) -> None:
        try:
            self.alerts.mark_sent(events, escalation=escalation)
        except Exception:  # noqa: BLE001
            log.exception("Recording sent alerts failed")

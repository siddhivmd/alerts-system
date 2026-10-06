"""One monitoring cycle: check everything concurrently, diagnose, store, alert.

Every cycle first checks that the monitor itself is online (canary hosts). If it
is not, the cycle is skipped: no site checks, no alert evaluation, no incidents,
nothing recorded against uptime. Otherwise a network outage on the monitor's
side would mark every site DOWN and later send RECOVERED for an outage that
never happened.
"""
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
from .checks import SiteCheckResult, VpsReachability, WhoisLookup, check_internet, check_site, check_vps_ports
from .config import Config, SiteConfig
from .diagnosis import DOWN, UP, WARNING, Diagnosis, Warn, diagnose, is_failing, vps_warnings
from .heartbeat import Heartbeat
from .security import EXTRA_KEY, SecurityChecker
from .ssh_stats import VpsStats, collect_stats, fetch_error_logs
from .storage import Storage
from .trends import disk_forecast_warning

log = logging.getLogger(__name__)
T = TypeVar("T")
CONNECTIVITY_KEY = "connectivity"  # kv record: current offline state + recent offline periods
MAX_OFFLINE_PERIODS = 50


@dataclass
class ServerResult:
    """One monitored server in one cycle."""

    name: str
    host: str
    reach: VpsReachability | None = None
    stats: VpsStats | None = None
    warnings: list[Warn] = field(default_factory=list)  # health + security + backups + disk trend


@dataclass
class CycleResult:
    ts: float
    results: list[SiteCheckResult]
    diagnoses: list[Diagnosis]
    servers: dict[str, ServerResult] = field(default_factory=dict)
    extra_warnings: list[Warn] = field(default_factory=list)  # e.g. blacklisted security.extra_ips
    security: dict[str, Any] = field(default_factory=dict)  # human-readable security status
    events: list[AlertEvent] = field(default_factory=list)
    alerts_delivered: bool | None = None
    maintenance: dict[str, Any] | None = None  # active maintenance window, if any
    offline: bool = False  # the monitor had no internet: nothing was checked or recorded
    offline_details: dict[str, str] = field(default_factory=dict)  # canary host -> error
    problems: list[str] = field(default_factory=list)  # internal failures (e.g. disk full): heartbeat says FAIL
    duration: float = 0.0

    @property
    def down(self) -> list[Diagnosis]:
        return [d for d in self.diagnoses if d.status == DOWN]

    # Shortcuts for the common single-server setup.
    @property
    def reach(self) -> VpsReachability | None:
        first = next(iter(self.servers.values()), None)
        return first.reach if first else None

    @property
    def stats(self) -> VpsStats | None:
        first = next(iter(self.servers.values()), None)
        return first.stats if first else None

    @property
    def vps_warnings(self) -> list[Warn]:
        """All server-level warnings, every server."""
        return [w for s in self.servers.values() for w in s.warnings] + self.extra_warnings


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
        if cfg.vps:  # history written before multi-server support belongs to the first server
            storage.claim_unnamed_vps_rows(cfg.vps.name)
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
        if alert and not cycle.offline:  # only real cycles count as "alive"; offline: the ping can't arrive
            if cycle.problems:
                # The process runs but is not doing its job (e.g. disk full, database locked):
                # that must not look like "all fine" to the watchdog.
                self.heartbeat.ping(ok=False, message="Monitor is running but broken: " + "; ".join(cycle.problems))
            else:
                up = sum(d.status != DOWN for d in cycle.diagnoses)
                self.heartbeat.ping(ok=True, message=f"{up} up, {len(cycle.down)} down, "
                                                     f"{len(cycle.events)} alert event(s)")
        return cycle

    # ------------------------------------------------------------------ internals
    def _run(self, save: bool, alert: bool, only: list[str] | None) -> CycleResult:
        started = time.time()
        general = self.cfg.general
        if general.connectivity_check:
            online, details = check_internet(general.canary_hosts, timeout=general.canary_timeout)
            if not online:
                return self._offline_cycle(started, details, save)
            if save:
                self._record_online(started)
        sites = [s for s in self.cfg.sites if not only or s.name in only]
        servers = self.cfg.servers
        workers = max(1, min(self.cfg.general.max_workers, len(sites) + 2 * len(servers) + 1))

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="check") as ex:
            reach_fs = {n: ex.submit(check_vps_ports, sv) for n, sv in servers.items()}
            stats_fs = {n: ex.submit(collect_stats, sv.host, sv.ssh, self.cfg.security, self.cfg.backups)
                        for n, sv in servers.items() if sv.ssh}
            security_f = ex.submit(self.security.refresh, started)  # blacklists / Safe Browsing (cached)
            site_fs = [(s, ex.submit(check_site, s, self.whois, self.cfg.general.user_agent)) for s in sites]
            results = []
            for site, fut in site_fs:
                res = _safe_result(fut, f"Check of {site.name}")
                results.append(res or SiteCheckResult(site=site.name, url=site.url, on_vps=site.on_vps,
                                                      error_kind="internal", error_message="check crashed"))
            server_results = {n: ServerResult(name=n, host=sv.host,
                                              reach=_safe_result(reach_fs[n], f"Port check of {n}"),
                                              stats=_safe_result(stats_fs.get(n), f"Stats of {n}"))
                              for n, sv in servers.items()}
            _safe_result(security_f, "Security lookups")

        server_of = {s.name: s.server for s in sites}
        logs_by_site = self._error_logs(sites, results, server_results)
        th = self.cfg.thresholds
        diagnoses = []
        for r in results:
            sr = server_results.get(server_of.get(r.site) or "")
            try:
                diagnoses.append(diagnose(r, sr.reach if sr else None, sr.stats if sr else None, th,
                                          logs_by_site.get(r.site)))
            except Exception as exc:  # noqa: BLE001
                log.exception("Diagnosis failed for %s", r.site)
                diagnoses.append(Diagnosis(site=r.site, url=r.url, status=DOWN if is_failing(r) else "up",
                                           cause_code="diagnosis_error", cause=f"Could not diagnose: {exc}"))

        for sr in server_results.values():
            sr.warnings = vps_warnings(sr.stats, sr.reach, th)
        security_status: dict[str, Any] = {}
        extra: list[Warn] = []
        try:
            per_server = self.security.server_warnings({n: sr.stats for n, sr in server_results.items()})
            for name, warns in per_server.items():
                if name in server_results:
                    server_results[name].warnings += warns
                else:
                    extra += warns  # e.g. a blacklisted security.extra_ips address
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
            security_status["backups"] = []
            for sr in server_results.values():
                sr.warnings += backup_warnings(sr.stats, self.cfg.backups)
                security_status["backups"] += [f"{sr.name}: {line}" if len(server_results) > 1 else line
                                               for line in backup_summary(sr.stats, self.cfg.backups)]
        except Exception:  # noqa: BLE001
            log.exception("Backup check failed")
        for sr in server_results.values():
            try:
                warning = disk_forecast_warning(self.storage, sr.name, sr.stats, started,
                                                self.cfg.thresholds.disk_full_warn_days)
                if warning:
                    sr.warnings.append(warning)
            except Exception:  # noqa: BLE001
                log.exception("Disk trend check failed for %s", sr.name)
        self._check_content(sites, results, diagnoses, save)

        cycle = CycleResult(ts=started, results=results, diagnoses=diagnoses, servers=server_results,
                            extra_warnings=extra, security=security_status)
        if save:
            self._save(cycle)
        if alert:
            self._alert(cycle)
        cycle.duration = time.time() - started
        self.last_cycle = cycle
        log.info("Cycle done in %.1fs: %d site(s), %d down, %d alert event(s)",
                 cycle.duration, len(results), len(cycle.down), len(cycle.events))
        return cycle

    def _offline_cycle(self, ts: float, details: dict[str, str], save: bool) -> CycleResult:
        """The monitor is offline: check nothing, judge nothing, record only the offline period."""
        cycle = CycleResult(ts=ts, results=[], diagnoses=[], offline=True, offline_details=details)
        state = self.storage.get_kv(CONNECTIVITY_KEY) or {}
        if not state.get("offline"):
            log.error("MONITOR OFFLINE: none of the canary hosts answer (%s). Skipping checks and alerts until "
                      "the connection is back, so the outage is not blamed on the sites.",
                      "; ".join(f"{h}: {e}" for h, e in details.items()))
        else:
            log.warning("Monitor still offline (since %s): cycle skipped",
                        time.strftime("%H:%M", time.localtime(state.get("since", ts))))
        if save:
            state.update(offline=True, since=state.get("since") if state.get("offline") else ts, last_seen=ts,
                         details=details)
            self.storage.set_kv(CONNECTIVITY_KEY, state)
        self.last_cycle = cycle
        return cycle

    def _record_online(self, ts: float) -> None:
        """Close an open offline period (keeps a short history for the dashboard and daily report)."""
        state = self.storage.get_kv(CONNECTIVITY_KEY)
        if not state or not state.get("offline"):
            return
        since = state.get("since", ts)
        log.warning("Monitor back online after %.0f min offline; checks resume (that period is not counted "
                    "as site downtime)", (ts - since) / 60)
        periods = (state.get("periods") or []) + [{"from": since, "until": ts}]
        self.storage.set_kv(CONNECTIVITY_KEY, {"offline": False, "periods": periods[-MAX_OFFLINE_PERIODS:]})

    def _check_content(self, sites: list[SiteConfig], results: list[SiteCheckResult],
                       diagnoses: list[Diagnosis], save: bool) -> None:
        """Defacement detection on every page that loaded fine. Never raises."""
        by_name = {s.name: s for s in sites}
        for r, d in zip(results, diagnoses, strict=True):
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
                    server_results: dict[str, ServerResult]) -> dict[str, list[str]]:
        """Fetch web server error-log tails from each server that hosts a failing site."""
        by_name = {s.name: s for s in sites}
        failing_by_server: dict[str, list[SiteConfig]] = {}
        for r in results:
            site = by_name.get(r.site)
            if site and site.server and r.on_vps and is_failing(r):
                failing_by_server.setdefault(site.server, []).append(site)
        out: dict[str, list[str]] = {}
        for name, failing in failing_by_server.items():
            server, sr = self.cfg.servers.get(name), server_results.get(name)
            if not server or not server.ssh or not sr or not sr.stats or not sr.stats.ok or \
                    (sr.reach and sr.reach.all_down):
                continue
            paths = list(server.ssh.error_logs) + [s.error_log for s in failing if s.error_log]
            try:
                logs = fetch_error_logs(server.host, server.ssh, paths)
            except Exception:  # noqa: BLE001
                log.exception("Fetching error logs from %s failed", name)
                continue
            sr.stats.error_logs = logs
            default_lines: list[str] = []
            for path in server.ssh.error_logs:
                if logs.get(path):
                    default_lines += [f"==> {path} <=="] + logs[path]
            for s in failing:
                out[s.name] = logs.get(s.error_log, []) if s.error_log and logs.get(s.error_log) else default_lines
        return out

    def _save(self, cycle: CycleResult) -> None:
        try:
            rows = []
            for r, d in zip(cycle.results, cycle.diagnoses, strict=True):
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
                rows.append((site_id, r.ts, d.status, r.http_status, r.response_ms, code, d.summary, details))
            self.storage.record_checks(rows)  # one transaction for the whole cycle
            for sr in cycle.servers.values():
                if sr.reach is None:
                    continue
                st = sr.stats
                self.storage.record_vps(cycle.ts, sr.reach.reachable, sr.reach.ports,
                                        st.to_dict() if st and st.ok else None, st.error if st and not st.ok else None,
                                        server=sr.name)
            # Latest server/security warnings for the dashboard and daily report.
            warnings = [{**w.__dict__, "server": sr.name} for sr in cycle.servers.values() for w in sr.warnings]
            warnings += [{**w.__dict__, "server": EXTRA_KEY} for w in cycle.extra_warnings]
            self.storage.set_kv("server_status", {"ts": cycle.ts, "security": cycle.security, "warnings": warnings})
        except Exception as exc:  # noqa: BLE001
            log.exception("Saving check results failed")
            cycle.problems.append(f"saving results failed ({type(exc).__name__}: {exc}) - disk full?")

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
                for sr in cycle.servers.values():
                    events += self.alerts.evaluate_warnings(sr.name, sr.warnings, cycle.ts)
                events += self.alerts.evaluate_warnings(EXTRA_KEY, cycle.extra_warnings, cycle.ts)
        except Exception as exc:  # noqa: BLE001
            log.exception("Alert evaluation failed")
            cycle.problems.append(f"alert evaluation failed ({type(exc).__name__}: {exc})")
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

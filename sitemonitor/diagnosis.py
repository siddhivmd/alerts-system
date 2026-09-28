"""Diagnosis engine: turn raw check results into a plain-English root cause and fixes.

Pure functions only (no I/O), so every rule can be unit-tested with hand-built
results. Priority when a site is failing:

  1. DNS failure                -> domain expired or DNS misconfigured
  2. All VPS ports unreachable  -> VPS down or ACCOUNT SUSPENDED
  3. SSL error                  -> certificate expired / invalid
  4. VPS up, site down          -> failed services, disk, OOM kills, RAM, CPU, error log
  5. HTTP 5xx/4xx, redirect loop, keyword problems

Warnings (the site still counts as up): slow response, SSL/domain expiring soon.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .checks import SiteCheckResult, VpsReachability
from .config import Thresholds
from .ssh_stats import VpsStats

UP, WARNING, DOWN = "up", "warning", "down"

_NOT_REGISTERED = re.compile(r"no match for|not found|no data found|no entries found|status:\s*free|available for registration", re.I)
_WEB_SERVERS = ("nginx", "apache2", "httpd", "caddy", "lsws", "litespeed")
_DATABASES = ("mysql", "mysqld", "mariadb", "postgresql", "redis", "redis-server", "mongod")


@dataclass
class Finding:
    """One piece of evidence with its remedy."""

    code: str
    message: str
    fixes: list[str] = field(default_factory=list)


@dataclass
class Warn:
    code: str
    message: str
    severity: str = "warning"  # warning | critical
    fix: str | None = None


@dataclass
class Diagnosis:
    site: str
    url: str
    status: str                       # up | warning | down
    cause_code: str | None = None
    cause: str = ""
    fixes: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    warnings: list[Warn] = field(default_factory=list)
    error_log: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        if self.status == DOWN:
            return self.cause
        if self.warnings:
            return "; ".join(w.message for w in self.warnings)
        return "OK"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["summary"] = self.summary
        return d


# --------------------------------------------------------------------------- helpers

def _fmt_date(iso: str | None) -> str:
    return iso[:10] if iso else "unknown date"


def _restart_fix(service: str) -> str:
    return f"Restart {service}: sudo systemctl restart {service}  (then check why: sudo journalctl -u {service} -n 50 --no-pager)"


def _service_rank(name: str) -> int:
    if name in _WEB_SERVERS:
        return 0
    if "fpm" in name or name in ("docker", "containerd"):
        return 1
    if name in _DATABASES:
        return 2
    return 3


# Known error-log / page signatures -> (code, explanation, fix)
_LOG_PATTERNS: list[tuple[re.Pattern[str], str, str, str]] = [
    (re.compile(r"No space left on device", re.I), "log_disk_full",
     "Error log shows 'No space left on device' (disk full)",
     "Free disk space: sudo du -xh / --max-depth=2 | sort -rh | head -20"),
    (re.compile(r"php[\d.]*-fpm\.sock.*(failed|No such file|Connection refused)|connect\(\) to unix:.*fpm", re.I),
     "log_php_fpm", "Web server cannot reach PHP-FPM (php-fpm socket down)",
     "Restart PHP-FPM: sudo systemctl restart php*-fpm  (check the exact unit: systemctl list-units '*fpm*')"),
    (re.compile(r"upstream timed out", re.I), "log_upstream_timeout",
     "Error log shows 'upstream timed out' (the app is too slow or stuck)",
     "Check app/DB load: top, and the MySQL slow query log; consider raising fastcgi_read_timeout/proxy_read_timeout"),
    (re.compile(r"connect\(\) failed \(111: Connection refused\) while connecting to upstream", re.I),
     "log_upstream_refused", "Web server's upstream app (Node/pm2/container) refuses connections",
     "Check the app process: pm2 list / docker ps -a, then restart it"),
    (re.compile(r"Too many open files", re.I), "log_open_files",
     "Error log shows 'Too many open files'",
     "Raise limits (worker_rlimit_nofile / LimitNOFILE) and restart the service"),
    (re.compile(r"Allowed memory size of \d+ bytes exhausted", re.I), "log_php_memory",
     "PHP scripts hit memory_limit", "Increase memory_limit in php.ini or fix the leaking plugin/script"),
    (re.compile(r"SQLSTATE\[HY000\] \[2002\]|Can't connect to (local )?MySQL server|Error establishing a database connection",
                re.I), "log_db_connect", "Application cannot connect to the database",
     "Check MySQL/MariaDB: sudo systemctl status mysql mariadb; restart it if stopped"),
    (re.compile(r"Too many connections", re.I), "log_db_too_many",
     "Database refused connections: 'Too many connections'",
     "Raise max_connections or find the connection leak: SHOW PROCESSLIST;"),
]


def _scan_text(lines: list[str]) -> list[Finding]:
    found: dict[str, Finding] = {}
    for line in lines:
        for pattern, code, message, fix in _LOG_PATTERNS:
            if code not in found and pattern.search(line):
                found[code] = Finding(code, message, [fix])
    return list(found.values())


def vps_findings(stats: VpsStats | None, reach: VpsReachability | None, t: Thresholds,
                 include_load: bool = True) -> list[Finding]:
    """Server-side problems that can explain a failing site, most root-cause-like first."""
    out: list[Finding] = []
    if stats is not None and stats.ok:
        if stats.disk_percent is not None and stats.disk_percent >= t.disk_percent:
            out.append(Finding("disk_full", f"Disk is {stats.disk_percent:.0f}% full (threshold {t.disk_percent:.0f}%)", [
                "Find what is using space: sudo du -xh / --max-depth=2 | sort -rh | head -20",
                "Quick wins: sudo journalctl --vacuum-size=200M; sudo apt clean; remove old backups/logs in /var/log",
            ]))
        for name in sorted(stats.failed_services, key=lambda n: (_service_rank(n), n)):
            state = stats.services[name]
            out.append(Finding(f"service_down:{name}",
                               f"Service {name} is {state.get('active')} ({state.get('sub')})",
                               [_restart_fix(name)]))
        for proc in stats.pm2_problems:
            out.append(Finding(f"pm2_down:{proc['name']}", f"pm2 app '{proc['name']}' is {proc['status']}",
                               [f"pm2 restart {proc['name']}  (logs: pm2 logs {proc['name']} --lines 50)"]))
        for c in stats.docker_problems:
            out.append(Finding(f"container_down:{c['name']}", f"Docker container '{c['name']}' is {c['status']}",
                               [f"docker restart {c['name']}  (logs: docker logs --tail 50 {c['name']})"]))
        if stats.oom_kills:
            out.append(Finding("oom_kills",
                               f"Out-of-memory killer ended {stats.oom_kills} process(es) ({stats.oom_window})"
                               + (f"; last: {stats.oom_last}" if stats.oom_last else ""), [
                "Reduce memory use: lower php-fpm pm.max_children and MySQL innodb_buffer_pool_size",
                "Add swap (sudo fallocate -l 2G /swapfile ...) or upgrade the VPS plan",
            ]))
        if include_load and stats.ram_percent is not None and stats.ram_percent >= t.ram_percent:
            out.append(Finding("ram_high", f"RAM usage is {stats.ram_percent:.0f}% (threshold {t.ram_percent:.0f}%)", [
                "See the biggest processes: ps aux --sort=-%mem | head -15",
                "Restart the heaviest service (often mysql or php-fpm) to free memory, then tune it",
            ]))
        per_core = stats.load_per_core
        if include_load and per_core is not None and per_core >= t.cpu_load_per_core:
            out.append(Finding("cpu_high",
                               f"CPU load {stats.cpu_load:.2f} on {stats.cpu_cores} core(s) ({per_core:.1f} per core)", [
                "See what is using CPU: top -o %CPU (unknown processes may be malware/crypto-miners)",
            ]))
    web_ports = [p for p in (80, 443) if reach is not None and p in reach.ports]
    if reach is not None and reach.ports.get(22) and web_ports and not any(reach.ports[p] for p in web_ports):
        out.append(Finding("web_ports_closed", "VPS answers on SSH but ports 80/443 are closed (web server not listening or firewall)", [
            "Check the web server: sudo systemctl status nginx apache2",
            "Check listeners and firewall: sudo ss -tlnp | grep -E ':80|:443'; sudo ufw status",
        ]))
    return out


# --------------------------------------------------------------------------- warnings

def site_warnings(r: SiteCheckResult, t: Thresholds) -> list[Warn]:
    out: list[Warn] = []
    if r.response_ms is not None and r.slow_threshold_ms and r.response_ms > r.slow_threshold_ms and r.responded:
        out.append(Warn("slow", f"Slow response: {r.response_ms} ms (threshold {r.slow_threshold_ms} ms)",
                        fix="Check server load (CPU/RAM), enable caching, look for slow DB queries"))
    if r.ssl_days_left is not None and 0 <= r.ssl_days_left <= t.ssl_warn_days:
        critical = r.ssl_days_left <= t.ssl_critical_days
        out.append(Warn("ssl_expiring_critical" if critical else "ssl_expiring",
                        f"SSL certificate expires in {r.ssl_days_left} day(s) ({_fmt_date(r.ssl_expires_at)})",
                        "critical" if critical else "warning",
                        "Renew now: sudo certbot renew && sudo systemctl reload nginx; check the certbot timer"))
    if r.domain_days_left is not None and r.domain_days_left <= t.domain_warn_days:
        if r.domain_days_left < 0:
            out.append(Warn("domain_expired", f"Domain {r.domain} EXPIRED on {_fmt_date(r.domain_expires_at)} "
                            "(may be in registrar grace period)", "critical", "Renew the domain at your registrar today"))
        else:
            out.append(Warn("domain_expiring", f"Domain {r.domain} expires in {r.domain_days_left} day(s) "
                            f"({_fmt_date(r.domain_expires_at)})",
                            "critical" if r.domain_days_left <= 7 else "warning",
                            "Renew the domain at your registrar (enable auto-renew)"))
    if r.ssl_error and not r.verify_ssl:
        out.append(Warn("ssl_invalid_ignored", f"SSL certificate problem (verification disabled for this site): {r.ssl_error}"))
    return out


def vps_warnings(stats: VpsStats | None, reach: VpsReachability | None, t: Thresholds) -> list[Warn]:
    """Server health warnings independent of any site (alerted with warning throttling)."""
    out: list[Warn] = []
    # "Unreachable on all ports" is deliberately not a warning here: every site on the VPS
    # raises it as its DOWN cause, with the consecutive-failure protection.
    if stats is None or (reach is not None and reach.all_down):
        return out
    if not stats.ok:
        out.append(Warn("ssh_failed", f"Could not read VPS stats: {stats.error}"))
        return out
    if stats.disk_percent is not None and stats.disk_percent >= t.disk_warn_percent:
        crit = stats.disk_percent >= t.disk_percent
        out.append(Warn("disk_critical" if crit else "disk_high", f"Disk {stats.disk_percent:.0f}% full",
                        "critical" if crit else "warning", "sudo du -xh / --max-depth=2 | sort -rh | head -20"))
    if stats.ram_percent is not None and stats.ram_percent >= t.ram_percent:
        out.append(Warn("ram_high", f"RAM usage {stats.ram_percent:.0f}%", fix="ps aux --sort=-%mem | head -15"))
    if stats.load_per_core is not None and stats.load_per_core >= t.cpu_load_per_core:
        out.append(Warn("cpu_high", f"CPU load {stats.cpu_load:.2f} on {stats.cpu_cores} core(s)",
                        fix="top -o %CPU (unexpected processes can mean malware - a common suspension reason)"))
    if stats.oom_kills:
        out.append(Warn("oom_kills", f"{stats.oom_kills} out-of-memory kill(s) ({stats.oom_window})"
                        + (f"; last: {stats.oom_last}" if stats.oom_last else ""),
                        fix="Tune php-fpm/mysql memory or add swap"))
    for name in stats.failed_services:
        out.append(Warn(f"service_down:{name}", f"Service {name} is {stats.services[name].get('active')}",
                        "critical", f"sudo systemctl restart {name}"))
    for p in stats.pm2_problems:
        out.append(Warn(f"pm2_down:{p['name']}", f"pm2 app {p['name']} is {p['status']}", fix=f"pm2 restart {p['name']}"))
    for c in stats.docker_problems:
        out.append(Warn(f"container_down:{c['name']}", f"Container {c['name']}: {c['status']}",
                        fix=f"docker restart {c['name']}"))
    return out


# --------------------------------------------------------------------------- main entry point

def _ssl_diagnosis(r: SiteCheckResult) -> tuple[str, str, list[str]]:
    msg = (r.ssl_error or r.error_message or "").lower()
    host = r.url.split("/")[2] if "//" in r.url else r.url
    renew = "Renew: sudo certbot renew --force-renewal && sudo systemctl reload nginx (or apache2)"
    if "expired" in msg:
        return ("ssl_expired", f"SSL certificate EXPIRED ({_fmt_date(r.ssl_expires_at)}): browsers block the site",
                [renew, "Make sure auto-renewal runs: systemctl list-timers | grep certbot"])
    if "hostname mismatch" in msg or "doesn't match" in msg or "not valid for" in msg:
        return ("ssl_hostname_mismatch", f"SSL certificate does not cover {host}",
                [f"Issue a certificate that includes it: sudo certbot --nginx -d {host}"])
    if "self-signed" in msg or "self signed" in msg:
        return ("ssl_self_signed", "Server presents a self-signed certificate",
                [f"Install a real certificate: sudo certbot --nginx -d {host}"])
    if "local issuer" in msg or "unable to get" in msg:
        return ("ssl_chain_incomplete", "SSL certificate chain is incomplete (intermediate certificate missing)",
                ["Point ssl_certificate at fullchain.pem (not cert.pem) and reload the web server"])
    return ("ssl_invalid", f"SSL/TLS error: {r.ssl_error or r.error_message}", [renew])


def _http_diagnosis(r: SiteCheckResult) -> tuple[str, str, list[str]] | None:
    code = r.http_status
    if code is None or r.status_ok:
        return None
    if code == 502:
        return ("http_502", "HTTP 502 Bad Gateway: web server is up but the app behind it (PHP-FPM / Node / container) is down", [
            "Restart the app runtime: sudo systemctl restart php*-fpm, or pm2 restart all, or docker restart <app>",
            "Check the web server error log for the upstream error"])
    if code == 503:
        return ("http_503", "HTTP 503 Service Unavailable: app overloaded or in maintenance mode", [
            "WordPress: delete a stuck .maintenance file in the site root",
            "Check php-fpm 'max_children reached' in its log and server load"])
    if code == 504:
        return ("http_504", "HTTP 504 Gateway Timeout: the app/database is too slow to answer", [
            "Check CPU/RAM (top) and slow DB queries; restart php-fpm/mysql if stuck"])
    if code == 500:
        return ("http_500", "HTTP 500 Internal Server Error: the application is crashing", [
            "Read the PHP/app error log; a recent deploy, plugin update or .htaccess change is the usual cause"])
    if 500 <= code < 600:
        return (f"http_{code}", f"HTTP {code} server error", ["Check the web server and application error logs"])
    if code == 404:
        return ("http_404", "HTTP 404 Not Found: page missing, wrong document root or vhost", [
            "Check the vhost root / server_name and that the site files are still in place"])
    if code == 403:
        return ("http_403", "HTTP 403 Forbidden: file permissions, .htaccess rule, or firewall/WAF blocking", [
            "Check ownership (chown -R www-data:www-data) and permissions; check WAF/Cloudflare rules"])
    if code == 401:
        return ("http_401", "HTTP 401 Unauthorized: page needs authentication",
                ["If expected, add auth headers in the site config or monitor a public URL"])
    if code == 429:
        return ("http_429", "HTTP 429 Too Many Requests: the site is rate-limiting (maybe this monitor)",
                ["Whitelist the monitor's IP or lower the check frequency"])
    if 400 <= code < 500:
        return (f"http_{code}", f"HTTP {code} client error", ["Check the URL and access rules"])
    expected = ", ".join(map(str, r.expected_status or [])) or "< 400"
    return ("unexpected_status", f"Unexpected HTTP {code} (expected {expected})",
            ["Check redirects and the expected_status setting for this site"])


def diagnose(r: SiteCheckResult, reach: VpsReachability | None, stats: VpsStats | None,
             t: Thresholds, error_log: list[str] | None = None) -> Diagnosis:
    """Explain one site's result. ``reach``/``stats`` describe the VPS (None if not monitored)."""
    d = Diagnosis(site=r.site, url=r.url, status=UP)
    d.warnings = site_warnings(r, t)
    error_log = error_log or []
    uses_vps = r.on_vps and reach is not None

    def down(code: str, cause: str, fixes: list[str]) -> Diagnosis:
        d.status, d.cause_code, d.cause, d.fixes = DOWN, code, cause, fixes
        return d

    # 0) The monitor itself failed: say so instead of blaming the server.
    if r.error_kind == "internal":
        return down("monitor_error", f"Monitor could not check this site: {r.error_message}", [
            "See logs/monitor.log for the traceback; open the site manually to confirm it works"])

    # 1) DNS
    if r.dns_ok is False:
        d.evidence.append(f"DNS error: {r.dns_error}")
        if r.domain_days_left is not None and r.domain_days_left < 0:
            return down("domain_expired", f"Domain {r.domain} EXPIRED on {_fmt_date(r.domain_expires_at)}: DNS no longer resolves",
                        ["Renew the domain at your registrar; DNS returns within a few hours",
                         "Turn on auto-renew so it cannot happen again"])
        if r.domain_error:
            d.evidence.append(r.domain_error)
            if _NOT_REGISTERED.search(r.domain_error):
                return down("domain_not_registered",
                            f"Domain {r.domain} is NOT REGISTERED (WHOIS has no record): it expired and was released, or the URL has a typo",
                            ["Check the domain in your registrar account and re-register it immediately if it lapsed",
                             "If this is a typo, fix the url in config.yaml"])
        host = r.url.split("/")[2] if "//" in r.url else r.url
        return down("dns_failure", "DNS not resolving: domain expired or DNS misconfigured", [
            "Check the domain has not expired (registrar panel / whois)",
            f"Check nameservers and the A record in your DNS panel; `nslookup {host}` must return your server's IP"])

    # 2) VPS unreachable on every port -> down or suspended
    failing = is_failing(r)
    if failing and uses_vps and reach.all_down:
        ports = ", ".join(str(p) for p in reach.ports)
        d.evidence.append(f"TCP ports {ports} on {reach.host} all unreachable")
        return down("vps_unreachable", "VPS unreachable on all ports: VPS is DOWN or the ACCOUNT IS SUSPENDED", [
            "Log in to the Hostinger panel (hPanel > VPS) and check the server status",
            "Check your email INCLUDING SPAM for Hostinger suspension/abuse notices",
            "If stopped: start it from hPanel. If suspended: open a support ticket and ask for the abuse report",
            "Before reinstatement, clean the server: scan for malware (e.g. ClamAV/maldet), update CMS/plugins, rotate passwords and SSH keys"])

    # 3) SSL
    if r.error_kind == "ssl" or (r.ssl_error and r.verify_ssl):
        code, cause, fixes = _ssl_diagnosis(r)
        if r.ssl_error:
            d.evidence.append(f"Certificate verification: {r.ssl_error}")
        return down(code, cause, fixes)

    if not failing:
        d.status = WARNING if d.warnings else UP
        return d

    # Collect evidence shared by rules 4 and 5.
    if r.http_status is not None:
        d.evidence.append(f"HTTP {r.http_status} in {r.response_ms} ms")
    if r.error_message:
        d.evidence.append(r.error_message)
    if stats is not None and not stats.ok and uses_vps:
        d.evidence.append(f"VPS stats unavailable: {stats.error}")
    d.error_log = error_log[-20:]
    log_findings = _scan_text(error_log)

    hard_failure = r.error_kind in ("timeout", "connection", "request") or (
        r.http_status is not None and r.http_status >= 500) or bool(r.forbidden_found)

    # 4) VPS up but the site is failing: look for the server-side root cause
    server = vps_findings(stats, reach, t) if uses_vps else []
    if uses_vps and hard_failure:
        findings = server + [f for f in log_findings if f.code not in {s.code for s in server}]
        if r.forbidden_found:
            findings = findings or _scan_text(r.forbidden_found)
        if findings:
            primary = findings[0]
            for extra in findings[1:]:
                d.evidence.append(f"Also: {extra.message}")
            fixes = [fx for f in findings for fx in f.fixes]
            return down(primary.code, f"Site down: {primary.message}", list(dict.fromkeys(fixes))[:6])

    # 5) HTTP status / content / connection problems
    for f in server:  # context only, not primary cause
        d.evidence.append(f"VPS: {f.message}")
    if r.error_kind == "too_many_redirects":
        return down("redirect_loop", "Redirect loop: the site keeps redirecting and never loads", [
            "Check http->https and www redirects in the vhost/.htaccess",
            "WordPress: check siteurl/home; Cloudflare: use 'Full' SSL mode, not 'Flexible'"])
    if r.error_kind in ("timeout", "connection", "request"):
        if uses_vps and reach.reachable:
            return down("vps_up_site_down",
                        "VPS is up but the site is not responding: web server/app crashed or overloaded", [
                            "Check the web server: sudo systemctl status nginx apache2",
                            "Check load and memory: top; free -m", "Read the web server error log"])
        label = {"timeout": "Site timed out", "connection": "Could not connect to the site"}.get(
            r.error_kind or "", "Request failed")
        return down(f"site_{r.error_kind}", f"{label}: {r.error_message}", [
            "Check the hosting server and web server status", "Check firewall rules for ports 80/443"])
    http = _http_diagnosis(r)
    if http:
        fixes = http[2] + [fx for f in log_findings for fx in f.fixes]
        for f in log_findings:
            d.evidence.append(f"Error log: {f.message}")
        return down(http[0], http[1], fixes)
    if r.forbidden_found:
        return down("error_text_found", f"Page shows error text: {', '.join(repr(k) for k in r.forbidden_found)}",
                    ["Open the page in a browser and check the application/PHP error log"])
    if r.keyword and r.keyword_found is False:
        return down("keyword_missing",
                    f"Page loads (HTTP {r.http_status}) but expected text '{r.keyword}' is missing: "
                    "error page, defaced/hacked page, or changed template", [
                        "Open the page in a browser and compare with the normal content",
                        "If content looks injected/unknown, treat as a compromise: scan for malware now",
                        "If the template changed on purpose, update the keyword in config.yaml"])
    return down("unknown", "Site failed for an unknown reason", ["Open the site in a browser and check the logs"])


def is_failing(r: SiteCheckResult) -> bool:
    """True if the raw result shows the site is not working (before any interpretation)."""
    return bool(
        r.error_kind
        or r.status_ok is False
        or (r.keyword and r.keyword_found is False)
        or r.forbidden_found
        or (r.ssl_error and r.verify_ssl)
    )

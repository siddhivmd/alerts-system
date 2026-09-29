"""Early warning of "malicious activity" - the usual reason hosts suspend a VPS.

Hosts suspend accounts when a server sends spam, attacks others or hosts
malware - almost always after a site was hacked. These checks try to notice
that before the host does:

* Blacklists (DNSBL): is the server IP listed on spam blacklists? No SSH needed.
* Google Safe Browsing: has Google flagged a site as malware/phishing?
* Over SSH (data collected by ssh_stats): crypto-miner processes, programs
  running from /tmp, new PHP files in web roots, SSH brute force, and
  outbound mail connections (a hacked site sending spam).

Everything produces ``Warn`` objects, so the normal alert rules apply
(two sightings before alerting, repeat at most every warning_repeat_hours).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

import requests

from . import __version__
from .config import Config, SecurityConfig
from .diagnosis import Warn
from .ssh_stats import VpsStats

log = logging.getLogger(__name__)

BLACKLIST_INFO = {
    "zen.spamhaus.org": ("Spamhaus ZEN", "https://check.spamhaus.org/"),
    "bl.spamcop.net": ("SpamCop", "https://www.spamcop.net/bl.shtml"),
    "psbl.surriel.com": ("PSBL", "https://psbl.org/"),
    "dnsbl-1.uceprotect.net": ("UCEPROTECT level 1", "https://www.uceprotect.net/en/rblcheck.php"),
    "b.barracudacentral.org": ("Barracuda", "https://www.barracudacentral.org/lookups"),
}

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing / deceptive site",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful app",
}

# Well-known crypto-miner names, and the mining-pool protocol that appears on miners' command lines.
MINER_SIGNATURES = (
    "xmrig", "xmr-stak", "minerd", "cpuminer", "ccminer", "ethminer", "nbminer", "lolminer",
    "srbminer", "phoenixminer", "nanominer", "kdevtmpfsi", "kinsing", "kthreaddi", "sysrv",
    "watchbog", "dbused", "stratum+tcp", "stratum+ssl",
)
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
MAX_PROCESS_WARNINGS = 5
MAX_FILE_WARNINGS = 10


# --------------------------------------------------------------------------- blacklists

@dataclass
class BlacklistResult:
    ip: str
    listed: dict[str, str] = field(default_factory=dict)   # zone -> answer (e.g. 127.0.0.2)
    clean: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)   # zone -> why it could not be checked

    def summary(self) -> str:
        total = len(self.listed) + len(self.clean) + len(self.errors)
        if self.listed:
            names = ", ".join(BLACKLIST_INFO.get(z, (z, ""))[0] for z in self.listed)
            text = f"{self.ip}: LISTED on {len(self.listed)} of {total} blacklists ({names})"
        else:
            text = f"{self.ip}: not listed ({len(self.clean)} of {total} blacklists checked)"
        if self.errors:
            text += f"; {len(self.errors)} could not be checked"
        return text


def dnsbl_query_name(ip: str, zone: str) -> str:
    """1.2.3.4 + zen.spamhaus.org -> 4.3.2.1.zen.spamhaus.org"""
    return ".".join(reversed(ip.split("."))) + "." + zone


def _interpret_answer(zone: str, answer: str) -> tuple[bool, str | None]:
    """Return (listed, error). DNSBLs answer 127.0.0.x for a listing."""
    if answer.startswith("127.255.255."):
        # Spamhaus refuses queries from big public resolvers (8.8.8.8, 1.1.1.1) with 127.255.255.254.
        return False, (f"{zone} refused the query ({answer}); the monitor's DNS resolver is probably a "
                       "public one - use your provider's resolver or a free Spamhaus DQS key")
    if answer.startswith("127."):
        return True, None
    # Some ISPs answer non-existent names with an advert server instead of NXDOMAIN.
    return False, f"{zone} returned an unexpected answer ({answer}); DNS may be hijacked by the ISP"


def check_blacklists(ip: str, zones: list[str], resolve: Callable[[str], str] = socket.gethostbyname,
                     timeout: float = 8.0) -> BlacklistResult:
    """Look ``ip`` up in each DNSBL zone concurrently. Never raises."""
    result = BlacklistResult(ip=ip)
    try:
        if ipaddress.ip_address(ip).version != 4:
            result.errors = {z: "only IPv4 addresses can be checked" for z in zones}
            return result
    except ValueError:
        result.errors = {z: f"not an IP address: {ip}" for z in zones}
        return result

    ex = ThreadPoolExecutor(max_workers=max(1, len(zones)), thread_name_prefix="dnsbl")
    try:
        futures = {z: ex.submit(resolve, dnsbl_query_name(ip, z)) for z in zones}
        for zone, fut in futures.items():
            try:
                answer = fut.result(timeout=timeout)
            except socket.gaierror:
                result.clean.append(zone)  # NXDOMAIN: not listed
                continue
            except FutureTimeout:
                result.errors[zone] = f"no answer within {timeout:.0f}s"
                continue
            except Exception as exc:  # noqa: BLE001
                result.errors[zone] = f"lookup failed: {exc}"
                continue
            listed, error = _interpret_answer(zone, answer)
            if listed:
                result.listed[zone] = answer
            elif error:
                result.errors[zone] = error
            else:
                result.clean.append(zone)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return result


def blacklist_warnings(result: BlacklistResult) -> list[Warn]:
    out = []
    for zone, answer in result.listed.items():
        name, url = BLACKLIST_INFO.get(zone, (zone, ""))
        out.append(Warn(
            f"blacklisted:{result.ip}:{zone}",
            f"IP {result.ip} is on the {name} spam blacklist ({answer}): the server is probably sending spam",
            "critical",
            "Find the sender: sudo ss -tnp '( dport = :25 )' and mailq; scan sites for malware and "
            f"remove it FIRST, then request delisting{' at ' + url if url else ''}"))
    return out


# --------------------------------------------------------------------------- Google Safe Browsing

def check_safe_browsing(urls: list[str], api_key: str, post: Callable[..., Any] = requests.post,
                        timeout: float = 15.0) -> tuple[dict[str, list[str]], str | None]:
    """Return ({url: [threat types]}, error). One request covers every URL. Never raises."""
    if not urls:
        return {}, None
    body = {
        "client": {"clientId": "site-monitor", "clientVersion": __version__},
        "threatInfo": {
            "threatTypes": list(THREAT_LABELS),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        resp = post(SAFE_BROWSING_URL, params={"key": api_key}, json=body, timeout=timeout)
        if resp.status_code != 200:
            return {}, f"Safe Browsing API returned HTTP {resp.status_code}: {resp.text[:200]}"
        matches = (resp.json() or {}).get("matches", [])
    except Exception as exc:  # noqa: BLE001
        return {}, f"Safe Browsing lookup failed: {str(exc).replace(api_key, '***')}"

    by_host = {urlparse(u).hostname: u for u in urls}
    flagged: dict[str, list[str]] = {}
    for m in matches:
        url = (m.get("threat") or {}).get("url", "")
        # Google may echo a normalised URL; fall back to matching on the hostname.
        key = url if url in urls else by_host.get(urlparse(url).hostname)
        if key:
            threat = m.get("threatType", "UNKNOWN")
            if threat not in flagged.setdefault(key, []):
                flagged[key].append(threat)
    return flagged, None


def safe_browsing_warning(threats: list[str]) -> Warn:
    labels = ", ".join(THREAT_LABELS.get(t, t.lower()) for t in threats)
    return Warn("safe_browsing", f"Google Safe Browsing flags this site as {labels}: "
                "browsers show visitors a red warning page", "critical",
                "The site is likely hacked: clean it, then check Google Search Console > "
                "Security issues and request a review")


# --------------------------------------------------------------------------- server checks (SSH data)

def _matches(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def process_warnings(stats: VpsStats, sec: SecurityConfig) -> list[Warn]:
    out: list[Warn] = []
    for p in stats.top_processes:
        comm, args = p.get("comm", ""), p.get("args", "")
        cpu, pid, user = p.get("cpu", 0.0), p.get("pid"), p.get("user")
        haystack = f"{comm} {args}".lower()
        where = f"pid {pid}, user {user}, {cpu:.0f}% CPU"
        investigate = (f"Investigate: sudo ls -l /proc/{pid}/exe; sudo crontab -l -u {user}; "
                       f"then sudo kill -9 {pid} and treat the server as compromised")
        signature = next((sig for sig in MINER_SIGNATURES if sig in haystack), None)
        exe = args.split()[0] if args else ""
        if signature:
            out.append(Warn(f"miner:{comm}", f"Possible crypto-miner running: {comm} ({where}, matched "
                            f"'{signature}')", "critical", investigate))
        elif exe.startswith(TEMP_DIRS):
            out.append(Warn(f"tmp_process:{comm}", f"Program running from a temp folder: {exe} ({where}) - "
                            "a common sign of malware", "critical", investigate))
        elif cpu >= sec.cpu_process_percent and not _matches(comm, sec.known_processes):
            out.append(Warn(f"unknown_cpu:{comm}", f"Unknown process using a lot of CPU: {comm} ({where})",
                            "warning", f"Check what it is: ps -fp {pid}. If it is legitimate, add "
                            f"'{comm}' to security.known_processes"))
        if len(out) >= MAX_PROCESS_WARNINGS:
            break
    return out


def php_file_warnings(stats: VpsStats, sec: SecurityConfig) -> list[Warn]:
    files = [f for f in stats.new_php_files if not _matches(f, sec.php_watch_ignore)]
    if not files:
        return []
    window = f"last {sec.php_watch_minutes} min"
    fix = ("If nobody deployed code just now, open the file: webshells often use eval(), base64_decode() "
           "or gzinflate(). Remove it and find how it was uploaded")
    if len(files) > MAX_FILE_WARNINGS:
        sample = ", ".join(files[:5])
        return [Warn("new_php_bulk", f"{len(files)} PHP files changed in the {window} (e.g. {sample}) - "
                     "a deployment, or a site being infected", "warning",
                     "If this was not a deployment, compare against your code repository")]
    out = []
    for f in files:
        in_uploads = "/uploads/" in f  # PHP files in upload folders are almost never legitimate
        out.append(Warn(f"new_php:{f}", f"New or changed PHP file ({window}): {f}"
                        + (" - inside an uploads folder" if in_uploads else ""),
                        "critical" if in_uploads else "warning", fix))
    return out


def ssh_login_warnings(stats: VpsStats, sec: SecurityConfig) -> list[Warn]:
    n = stats.failed_ssh_logins
    if n is None or n < sec.failed_ssh_logins_per_hour:
        return []
    top = ", ".join(f"{ip} ({count})" for ip, count in stats.failed_ssh_top_ips[:3])
    return [Warn("ssh_bruteforce", f"{n} failed SSH logins ({stats.failed_ssh_window})"
                 + (f"; top sources: {top}" if top else "") + " - someone is guessing passwords",
                 "warning", "Install fail2ban (sudo apt install fail2ban) and set PasswordAuthentication no "
                 "in /etc/ssh/sshd_config")]


def outbound_mail_warnings(stats: VpsStats, sec: SecurityConfig) -> list[Warn]:
    n = stats.outbound_smtp
    if n is None or n < sec.outbound_smtp_connections:
        return []
    return [Warn("outbound_smtp", f"{n} open outbound mail connections (ports 25/465/587): typical of a hacked "
                 "site sending spam - the most common reason hosts suspend accounts", "critical",
                 "See which process: sudo ss -tnp '( dport = :25 or dport = :587 )'; check the queue: mailq")]


def server_security_warnings(stats: VpsStats | None, sec: SecurityConfig) -> list[Warn]:
    """All SSH-based security warnings. Empty if SSH data is unavailable."""
    if stats is None or not stats.ok or not sec.enabled:
        return []
    return (process_warnings(stats, sec) + php_file_warnings(stats, sec)
            + ssh_login_warnings(stats, sec) + outbound_mail_warnings(stats, sec))


# --------------------------------------------------------------------------- scheduling / caching

class SecurityChecker:
    """Runs the external lookups at their own (slower) interval and caches the results.

    Blacklists and Safe Browsing change slowly and are rate-limited, so they
    run every ``*_interval_minutes``; cached results are re-reported every cycle
    so warnings stay active (and clear) correctly.
    """

    def __init__(self, cfg: Config, resolve: Callable[[str], str] = socket.gethostbyname,
                 post: Callable[..., Any] = requests.post) -> None:
        self.cfg = cfg
        self.sec = cfg.security
        self._resolve = resolve
        self._post = post
        self._blacklist_at: float | None = None  # None = never run yet
        self.blacklist_results: list[BlacklistResult] = []
        self._sb_at: float | None = None
        self.safe_browsing_flags: dict[str, list[str]] = {}
        self.safe_browsing_error: str | None = None

    def _blacklist_ips(self) -> list[str]:
        ips: list[str] = []
        if self.cfg.vps:
            host = self.cfg.vps.host
            try:
                ipaddress.ip_address(host)
                ips.append(host)
            except ValueError:
                try:
                    ips.append(self._resolve(host))
                except OSError as exc:
                    log.warning("Blacklist check: could not resolve VPS host %s: %s", host, exc)
        ips += [ip for ip in self.sec.extra_ips if ip not in ips]
        return ips

    @staticmethod
    def _due(last: float | None, now: float, interval_minutes: int) -> bool:
        return last is None or now - last >= interval_minutes * 60

    def refresh(self, now: float | None = None) -> None:
        """Re-run the lookups whose interval has elapsed. Never raises."""
        now = time.time() if now is None else now
        if not self.sec.enabled:
            return
        if self.sec.blacklist_check and self._due(self._blacklist_at, now, self.sec.blacklist_interval_minutes):
            self._blacklist_at = now
            try:
                self.blacklist_results = [check_blacklists(ip, self.sec.blacklists, self._resolve)
                                          for ip in self._blacklist_ips()]
                for r in self.blacklist_results:
                    (log.warning if r.listed else log.info)("Blacklist check %s", r.summary())
                    for zone, err in r.errors.items():
                        log.warning("Blacklist %s: %s", zone, err)
            except Exception:  # noqa: BLE001
                log.exception("Blacklist check failed")
        if self.sec.safe_browsing_key and self._due(self._sb_at, now, self.sec.safe_browsing_interval_minutes):
            self._sb_at = now
            flags, error = check_safe_browsing([s.url for s in self.cfg.sites], self.sec.safe_browsing_key,
                                               self._post)
            self.safe_browsing_error = error
            if error:
                log.warning("%s", error)  # keep previous flags rather than forgetting them on an API hiccup
            else:
                self.safe_browsing_flags = flags

    def server_warnings(self, stats: VpsStats | None) -> list[Warn]:
        out: list[Warn] = []
        for r in self.blacklist_results:
            out += blacklist_warnings(r)
        return out + server_security_warnings(stats, self.sec)

    def site_warnings(self) -> dict[str, list[Warn]]:
        by_url = {s.url: s.name for s in self.cfg.sites}
        return {by_url[u]: [safe_browsing_warning(t)] for u, t in self.safe_browsing_flags.items() if u in by_url}

    def summary(self) -> dict[str, Any]:
        """Human-readable status for the dashboard and `check` output."""
        sb = None
        if self.sec.safe_browsing_key:
            flagged = len(self.safe_browsing_flags)
            sb = self.safe_browsing_error or (
                f"{flagged} site(s) flagged" if flagged else f"no site flagged ({len(self.cfg.sites)} checked)")
        return {
            "enabled": self.sec.enabled,
            "blacklists": [r.summary() for r in self.blacklist_results],
            "safe_browsing": sb,
            "ssh_checks": bool(self.cfg.vps and self.cfg.vps.ssh and self.sec.enabled),
        }

"""Load and validate configuration.

Non-secret settings live in ``config.yaml``. Secrets are read only from the
environment (typically populated from a ``.env`` file next to the config):

    SMTP_PASSWORD, TELEGRAM_BOT_TOKEN, DASHBOARD_PASSWORD, SSH_KEY_PASSPHRASE

Every feature is optional. A section that is missing, or has ``enabled: false``,
is simply off. A feature that is enabled but lacks a required value or secret
is switched off with a warning (``Config.warnings``) instead of stopping the
monitor. Real mistakes - unknown keys, invalid values - still raise ConfigError.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from dotenv import load_dotenv


class ConfigError(ValueError):
    """Raised when the configuration is missing or invalid."""


@dataclass
class SiteConfig:
    """One monitored website or portal."""

    name: str
    url: str
    keyword: str = ""
    forbidden_keywords: list[str] = field(default_factory=list)
    timeout: float = 15.0
    expected_status: list[int] | None = None  # None -> any status < 400 is fine
    headers: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    max_redirects: int = 10
    slow_threshold_ms: int = 3000
    check_ssl: bool = True
    check_domain: bool = True
    domain: str | None = None  # registered domain for WHOIS; derived from url if omitted
    on_vps: bool = True  # hosted on the monitored VPS (enables VPS-based diagnosis)
    error_log: str | None = None  # per-site web server error log path on the VPS
    verify_ssl: bool = True
    public_name: str | None = None  # name shown on the public status page (default: name)
    content_change_alert: float = 70.0  # % of page words that must change suddenly -> defacement warning; 0 = off

    @property
    def hostname(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def is_https(self) -> bool:
        return self.url.lower().startswith("https://")


@dataclass
class Thresholds:
    ram_percent: float = 90.0
    disk_percent: float = 95.0
    disk_warn_percent: float = 85.0
    cpu_load_per_core: float = 2.0
    ssl_warn_days: int = 14
    ssl_critical_days: int = 3
    domain_warn_days: int = 30


@dataclass
class SshConfig:
    user: str
    key_file: str
    port: int = 22
    key_passphrase: str | None = None
    known_hosts: str | None = None
    timeout: float = 10.0
    use_sudo: bool = False
    services: list[str] = field(default_factory=lambda: [
        "nginx", "apache2", "httpd", "mysql", "mysqld", "mariadb", "php*-fpm", "docker",
    ])
    check_pm2: bool = True
    check_docker_containers: bool = True
    error_logs: list[str] = field(default_factory=lambda: [
        "/var/log/nginx/error.log", "/var/log/apache2/error.log", "/var/log/httpd/error_log",
    ])
    error_log_lines: int = 20


@dataclass
class VpsConfig:
    host: str
    name: str = "VPS"
    ports: list[int] = field(default_factory=lambda: [22, 80, 443])
    port_timeout: float = 8.0
    ssh: SshConfig | None = None


@dataclass
class EmailConfig:
    host: str = ""
    port: int | None = None  # default: 465 for ssl, 587 for starttls, 25 for none
    from_addr: str | None = None  # default: username
    to: list[str] = field(default_factory=list)
    username: str | None = None
    password: str | None = None
    security: str = "ssl"  # ssl | starttls | none
    timeout: float = 20.0


@dataclass
class TelegramConfig:
    bot_token: str
    chat_ids: list[str]
    timeout: float = 15.0


@dataclass
class WhatsAppConfig:
    """WhatsApp via Twilio (easy sandbox for testing) or Meta's WhatsApp Cloud API."""

    provider: str = "twilio"  # twilio | meta
    to: list[str] = field(default_factory=list)  # numbers in international format, e.g. +919812345678
    from_number: str | None = None  # twilio: your WhatsApp sender, e.g. +14155238886 (sandbox)
    phone_number_id: str | None = None  # meta: the sender's phone number ID
    template: str | None = None  # meta: approved template with one {{1}} text parameter
    template_language: str = "en"
    timeout: float = 15.0
    account_sid: str | None = None  # twilio, from .env
    auth_token: str | None = None  # twilio, from .env
    access_token: str | None = None  # meta, from .env


@dataclass
class EscalationConfig:
    """Alert extra people when an outage lasts too long (once per incident)."""

    after_minutes: int = 30
    email_to: list[str] = field(default_factory=list)
    telegram_chat_ids: list[str] = field(default_factory=list)
    whatsapp_to: list[str] = field(default_factory=list)
    notify_recovery: bool = True  # also tell them when it is fixed


@dataclass
class AlertsConfig:
    consecutive_failures: int = 2
    throttle_minutes: int = 30
    warning_repeat_hours: int = 24
    console: bool = False  # also write alert messages to the log/console (handy for testing)
    email: EmailConfig | None = None
    telegram: TelegramConfig | None = None
    whatsapp: WhatsAppConfig | None = None
    escalation: EscalationConfig | None = None


@dataclass
class DailyReportConfig:
    enabled: bool = True
    time: str = "08:00"
    channels: list[str] = field(default_factory=lambda: ["email"])


@dataclass
class DashboardConfig:
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080
    username: str = "admin"
    password: str | None = None


@dataclass
class HeartbeatConfig:
    """Watchdog: ping an external service after every check cycle (e.g. healthchecks.io).
    If the pings stop, that service alerts you - so a dead monitor is never silent."""

    enabled: bool = False
    url: str | None = None  # from .env HEARTBEAT_URL
    timeout: float = 10.0
    fail_suffix: str = "/fail"  # healthchecks.io and Better Stack accept <url>/fail; "" to never report failure


@dataclass
class MonthlyReportConfig:
    enabled: bool = True
    day: int = 1  # day of the month to send last month's report
    time: str = "09:00"
    channels: list[str] = field(default_factory=lambda: ["email"])


@dataclass
class StatusPageConfig:
    """Public, read-only /status page for clients. Shows names and up/down only."""

    enabled: bool = False
    title: str = "Service status"
    sites: list[str] = field(default_factory=list)  # site names to show; empty = all
    show_incidents: bool = True
    days: int = 30


@dataclass
class BackupsConfig:
    """Over SSH: newest file matching each pattern must be recent and not tiny."""

    enabled: bool = False
    paths: list[str] = field(default_factory=list)  # glob patterns, e.g. /var/backups/db-*.sql.gz
    max_age_hours: float = 26.0
    min_size_mb: float = 1.0


@dataclass
class SecurityConfig:
    """Early warning of the 'malicious activity' that gets VPS accounts suspended."""

    enabled: bool = True
    # Spam blacklists (DNSBL) for the VPS IP - free, no account, no SSH.
    blacklist_check: bool = True
    blacklists: list[str] = field(default_factory=lambda: [
        "zen.spamhaus.org", "bl.spamcop.net", "psbl.surriel.com", "dnsbl-1.uceprotect.net",
    ])
    blacklist_interval_minutes: int = 60
    extra_ips: list[str] = field(default_factory=list)  # other IPs to check, e.g. a mail server
    # Google Safe Browsing - needs GOOGLE_SAFE_BROWSING_KEY in .env.
    safe_browsing: bool = False
    safe_browsing_interval_minutes: int = 60
    safe_browsing_key: str | None = None
    # Over SSH (only when vps.ssh is configured).
    cpu_process_percent: float = 80.0
    known_processes: list[str] = field(default_factory=lambda: [
        "nginx", "apache2", "httpd", "php*", "mysqld", "mariadbd", "mysql", "postgres*", "redis-server",
        "memcached", "mongod", "node", "nodejs", "PM2*", "pm2*", "dockerd", "containerd*", "java", "python*",
        "gunicorn", "uwsgi", "ruby", "puma", "sshd", "systemd*", "kworker*", "ksoftirqd*", "jbd2*", "cron",
        "clamd", "clamscan", "freshclam", "maldet", "apt*", "dpkg", "unattended-upgr*", "snapd",
        "fail2ban-server", "certbot", "composer", "wp", "tar", "gzip", "rsync",
    ])
    web_roots: list[str] = field(default_factory=lambda: ["/var/www"])
    php_watch_minutes: int = 60
    php_watch_ignore: list[str] = field(default_factory=lambda: ["*/cache/*", "*/wp-content/upgrade/*"])
    failed_ssh_logins_per_hour: int = 100
    outbound_smtp_connections: int = 20


@dataclass
class GeneralConfig:
    check_interval_minutes: int = 5
    max_workers: int = 20
    database: str = "data/monitor.db"
    log_file: str = "logs/monitor.log"
    log_level: str = "INFO"
    retention_days: int = 90
    timezone: str = "UTC"
    user_agent: str = "SiteMonitor/1.0 (+uptime check)"


@dataclass
class Config:
    general: GeneralConfig
    thresholds: Thresholds
    alerts: AlertsConfig
    daily_report: DailyReportConfig
    dashboard: DashboardConfig
    sites: list[SiteConfig]
    vps: VpsConfig | None = None
    security: SecurityConfig = field(default_factory=SecurityConfig)
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)
    monthly_report: MonthlyReportConfig = field(default_factory=MonthlyReportConfig)
    status_page: StatusPageConfig = field(default_factory=StatusPageConfig)
    backups: BackupsConfig = field(default_factory=BackupsConfig)
    base_dir: Path = Path(".")
    warnings: list[str] = field(default_factory=list)  # features switched off because of missing settings


# --------------------------------------------------------------------------- helpers

_TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
_BACKUP_GLOB_RE = re.compile(r"^/[A-Za-z0-9_./*?-]+$")
_PHONE_RE = re.compile(r"^\+?[0-9]{8,15}$")


def _phone(value: Any) -> str:
    """Normalise a phone number to +<digits>. Accepts spaces/dashes and an optional 'whatsapp:' prefix."""
    raw = str(value).strip()
    raw = raw[len("whatsapp:"):] if raw.lower().startswith("whatsapp:") else raw
    digits = re.sub(r"[\s()-]", "", raw)
    if not _PHONE_RE.match(digits):
        raise ConfigError(f"Invalid phone number {value!r}: use international format, e.g. +919812345678")
    return digits if digits.startswith("+") else "+" + digits


def _section(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key) or {}
    if not isinstance(value, dict):
        raise ConfigError(f"'{key}' must be a mapping")
    return value


def _pick(data: dict[str, Any], cls: type, where: str) -> dict[str, Any]:
    """Return the keys of ``data`` that ``cls`` accepts; reject unknown keys to catch typos."""
    allowed = set(cls.__dataclass_fields__)
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"Unknown key(s) in {where}: {', '.join(sorted(unknown))}")
    return dict(data)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def _resolve(base: Path, path: str) -> str:
    p = Path(os.path.expanduser(path))
    return str(p if p.is_absolute() else (base / p).resolve())


def _build_site(raw: dict[str, Any], defaults: dict[str, Any], index: int) -> SiteConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"sites[{index}] must be a mapping")
    merged = {**defaults, **raw}
    where = f"sites[{index}] ({raw.get('name', '?')})"
    data = _pick(merged, SiteConfig, where)
    if not data.get("name") or not data.get("url"):
        raise ConfigError(f"{where}: 'name' and 'url' are required")
    parsed = urlparse(str(data["url"]))
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"{where}: url must be http(s)://host/..., got {data['url']!r}")
    if "expected_status" in data and data["expected_status"] is not None:
        data["expected_status"] = [int(s) for s in _as_list(data["expected_status"])]
    data["forbidden_keywords"] = [str(k) for k in _as_list(data.get("forbidden_keywords"))]
    data["headers"] = {str(k): str(v) for k, v in (data.get("headers") or {}).items()}
    site = SiteConfig(**data)
    if site.timeout <= 0:
        raise ConfigError(f"{where}: timeout must be > 0")
    return site


def load_config(path: str | os.PathLike[str] = "config.yaml", env_file: str | None = None) -> Config:
    """Load ``config.yaml`` plus secrets from the environment / ``.env``.

    Relative paths (database, log file, SSH key) are resolved against the
    directory that contains the config file.
    """
    cfg_path = Path(path).resolve()
    if not cfg_path.exists():
        raise ConfigError(f"Config file not found: {cfg_path} (copy config.example.yaml to config.yaml)")
    base = cfg_path.parent
    load_dotenv(env_file or base / ".env", override=False)

    try:
        raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {cfg_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("Top level of config.yaml must be a mapping")

    general = GeneralConfig(**_pick(_section(raw, "general"), GeneralConfig, "general"))
    general.database = _resolve(base, general.database)
    general.log_file = _resolve(base, general.log_file)
    if general.check_interval_minutes < 1:
        raise ConfigError("general.check_interval_minutes must be >= 1")

    thresholds = Thresholds(**_pick(_section(raw, "thresholds"), Thresholds, "thresholds"))

    # --- VPS
    warnings: list[str] = []
    vps: VpsConfig | None = None
    vps_raw = _section(raw, "vps")
    vps_enabled = vps_raw.pop("enabled", True)
    if vps_enabled and not vps_raw.get("host"):
        if vps_raw:
            warnings.append("VPS checks off: vps.host is not set")
    elif vps_enabled:
        ssh_raw = vps_raw.pop("ssh", None)
        vps = VpsConfig(**_pick(vps_raw, VpsConfig, "vps"))
        vps.ports = [int(p) for p in vps.ports]
        if ssh_raw and ssh_raw.get("enabled", True) and not (ssh_raw.get("user") and ssh_raw.get("key_file")):
            warnings.append("SSH stats off: vps.ssh needs both 'user' and 'key_file'")
        elif ssh_raw and ssh_raw.get("enabled", True):
            ssh_raw = {k: v for k, v in ssh_raw.items() if k != "enabled"}
            ssh = SshConfig(**_pick(ssh_raw, SshConfig, "vps.ssh"))
            ssh.key_file = _resolve(base, ssh.key_file)
            ssh.known_hosts = _resolve(base, ssh.known_hosts) if ssh.known_hosts else str(
                Path(general.database).parent / "known_hosts")
            ssh.key_passphrase = _env("SSH_KEY_PASSPHRASE")
            if Path(ssh.key_file).exists():
                vps.ssh = ssh
            else:
                warnings.append(f"SSH stats off: key file not found: {ssh.key_file}")

    # --- alerts
    alerts_raw = _section(raw, "alerts")
    email_raw = alerts_raw.pop("email", None) or {}
    tg_raw = alerts_raw.pop("telegram", None) or {}
    wa_raw = alerts_raw.pop("whatsapp", None) or {}
    esc_raw = alerts_raw.pop("escalation", None) or {}
    alerts = AlertsConfig(**_pick(alerts_raw, AlertsConfig, "alerts"))
    if alerts.consecutive_failures < 1:
        raise ConfigError("alerts.consecutive_failures must be >= 1")

    if email_raw.get("enabled", False):
        email_raw = {k: v for k, v in email_raw.items() if k != "enabled"}
        email = EmailConfig(**_pick(email_raw, EmailConfig, "alerts.email"))
        email.to = [str(a) for a in _as_list(email.to)]
        email.password = _env("SMTP_PASSWORD")
        email.username = email.username or _env("SMTP_USERNAME")
        if email.security not in ("ssl", "starttls", "none"):
            raise ConfigError("alerts.email.security must be ssl, starttls or none")
        email.port = int(email.port or {"ssl": 465, "starttls": 587, "none": 25}[email.security])
        email.from_addr = email.from_addr or email.username
        missing = [name for name, ok in (
            ("alerts.email.host", email.host), ("alerts.email.to", email.to),
            ("alerts.email.from_addr (or username)", email.from_addr),
            ("SMTP_PASSWORD in .env", email.password or not email.username)) if not ok]
        if missing:
            warnings.append(f"Email alerts off: missing {', '.join(missing)}")
        else:
            alerts.email = email

    if tg_raw.get("enabled", False):
        token = _env("TELEGRAM_BOT_TOKEN")
        chat_ids = [str(c) for c in _as_list(tg_raw.get("chat_ids"))]
        missing = [name for name, ok in (("TELEGRAM_BOT_TOKEN in .env", token),
                                         ("alerts.telegram.chat_ids", chat_ids)) if not ok]
        if missing:
            warnings.append(f"Telegram alerts off: missing {', '.join(missing)}")
        else:
            alerts.telegram = TelegramConfig(bot_token=token, chat_ids=chat_ids,
                                             timeout=float(tg_raw.get("timeout", 15)))

    if wa_raw.get("enabled", False):
        wa = WhatsAppConfig(**_pick({k: v for k, v in wa_raw.items() if k != "enabled"}, WhatsAppConfig,
                                    "alerts.whatsapp"))
        wa.provider = wa.provider.lower()
        wa.to = [_phone(n) for n in _as_list(wa.to)]
        if wa.provider not in ("twilio", "meta"):
            raise ConfigError("alerts.whatsapp.provider must be twilio or meta")
        for secret in ("account_sid", "auth_token", "access_token"):
            if getattr(wa, secret):
                raise ConfigError(f"Put alerts.whatsapp.{secret} in .env, not in config.yaml")
        if wa.provider == "twilio":
            wa.account_sid, wa.auth_token = _env("TWILIO_ACCOUNT_SID"), _env("TWILIO_AUTH_TOKEN")
            wa.from_number = _phone(wa.from_number) if wa.from_number else None
            needed = (("TWILIO_ACCOUNT_SID in .env", wa.account_sid), ("TWILIO_AUTH_TOKEN in .env", wa.auth_token),
                      ("alerts.whatsapp.from_number", wa.from_number), ("alerts.whatsapp.to", wa.to))
        else:
            wa.access_token = _env("WHATSAPP_ACCESS_TOKEN")
            needed = (("WHATSAPP_ACCESS_TOKEN in .env", wa.access_token),
                      ("alerts.whatsapp.phone_number_id", wa.phone_number_id), ("alerts.whatsapp.to", wa.to))
        missing = [name for name, ok in needed if not ok]
        if missing:
            warnings.append(f"WhatsApp alerts off: missing {', '.join(missing)}")
        else:
            alerts.whatsapp = wa

    if esc_raw.get("enabled", False):
        esc = EscalationConfig(**_pick({k: v for k, v in esc_raw.items() if k != "enabled"}, EscalationConfig,
                                       "alerts.escalation"))
        esc.email_to = [str(a) for a in _as_list(esc.email_to)]
        esc.telegram_chat_ids = [str(c) for c in _as_list(esc.telegram_chat_ids)]
        esc.whatsapp_to = [_phone(n) for n in _as_list(esc.whatsapp_to)]
        if esc.after_minutes < 1:
            raise ConfigError("alerts.escalation.after_minutes must be >= 1")
        if not (esc.email_to or esc.telegram_chat_ids or esc.whatsapp_to):
            warnings.append("Escalation off: add email_to, telegram_chat_ids or whatsapp_to")
        else:
            alerts.escalation = esc

    daily = DailyReportConfig(**_pick(_section(raw, "daily_report"), DailyReportConfig, "daily_report"))
    if not _TIME_RE.match(daily.time):
        raise ConfigError(f"daily_report.time must be HH:MM, got {daily.time!r}")
    daily.channels = [str(c).strip().lower() for c in _as_list(daily.channels)]
    bad = [c for c in daily.channels if c not in ("email", "telegram", "whatsapp", "console")]
    if bad:
        raise ConfigError(f"daily_report.channels takes channel names (email, telegram, whatsapp, console), "
                          f"not {bad}. "
                          "Recipients go under alerts.email.to")

    monthly = MonthlyReportConfig(**_pick(_section(raw, "monthly_report"), MonthlyReportConfig, "monthly_report"))
    if not _TIME_RE.match(monthly.time):
        raise ConfigError(f"monthly_report.time must be HH:MM, got {monthly.time!r}")
    if not 1 <= monthly.day <= 28:
        raise ConfigError("monthly_report.day must be between 1 and 28")
    monthly.channels = [str(c).strip().lower() for c in _as_list(monthly.channels)]
    if any(c not in ("email", "telegram", "whatsapp", "console") for c in monthly.channels):
        raise ConfigError("monthly_report.channels takes channel names (email, telegram, whatsapp, console)")

    dashboard = DashboardConfig(**_pick(_section(raw, "dashboard"), DashboardConfig, "dashboard"))
    dashboard.password = _env("DASHBOARD_PASSWORD")
    if dashboard.enabled and not dashboard.password and dashboard.host not in ("127.0.0.1", "localhost"):
        warnings.append(f"Dashboard has no DASHBOARD_PASSWORD: serving without login on 127.0.0.1 only "
                        f"(not {dashboard.host})")
        dashboard.host = "127.0.0.1"

    # --- sites
    defaults = _section(raw, "defaults")
    defaults.setdefault("slow_threshold_ms", 3000)
    sites = [_build_site(s, defaults, i) for i, s in enumerate(raw.get("sites") or [])]
    if not sites and not vps:
        raise ConfigError("Nothing to monitor: add at least one entry under 'sites' or enable 'vps'")
    names = [s.name for s in sites]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ConfigError(f"Duplicate site names: {', '.join(sorted(dupes))}")

    # --- security (early warning of "malicious activity")
    sec_raw = _section(raw, "security")
    if "safe_browsing_key" in sec_raw:
        raise ConfigError("Put the Safe Browsing key in .env as GOOGLE_SAFE_BROWSING_KEY, not in config.yaml")
    security = SecurityConfig(**_pick(sec_raw, SecurityConfig, "security"))
    for name in ("blacklists", "extra_ips", "known_processes", "web_roots", "php_watch_ignore"):
        setattr(security, name, [str(v).strip() for v in _as_list(getattr(security, name)) if str(v).strip()])
    if security.enabled and security.safe_browsing:
        security.safe_browsing_key = _env("GOOGLE_SAFE_BROWSING_KEY")
        if not security.safe_browsing_key:
            warnings.append("Google Safe Browsing off: missing GOOGLE_SAFE_BROWSING_KEY in .env")

    # --- watchdog heartbeat
    heartbeat = HeartbeatConfig(**_pick(_section(raw, "heartbeat"), HeartbeatConfig, "heartbeat"))
    if heartbeat.url:
        raise ConfigError("Put the heartbeat URL in .env as HEARTBEAT_URL, not in config.yaml")
    if heartbeat.enabled:
        heartbeat.url = _env("HEARTBEAT_URL")
        if not heartbeat.url:
            warnings.append("Watchdog heartbeat off: missing HEARTBEAT_URL in .env")
            heartbeat.enabled = False
        elif not heartbeat.url.startswith(("https://", "http://")):
            raise ConfigError("HEARTBEAT_URL must start with https://")

    # --- public status page
    status_page = StatusPageConfig(**_pick(_section(raw, "status_page"), StatusPageConfig, "status_page"))
    status_page.sites = [str(n) for n in _as_list(status_page.sites)]
    unknown = [n for n in status_page.sites if n not in names]
    if unknown:
        raise ConfigError(f"status_page.sites: unknown site name(s): {', '.join(unknown)}")
    if status_page.enabled and dashboard.host == "127.0.0.1" and not dashboard.password:
        warnings.append("Status page is only reachable on this machine until DASHBOARD_PASSWORD is set "
                        "(the web server then listens on dashboard.host)")

    # --- backups (over SSH)
    backups = BackupsConfig(**_pick(_section(raw, "backups"), BackupsConfig, "backups"))
    backups.paths = [str(p).strip() for p in _as_list(backups.paths) if str(p).strip()]
    for pattern in backups.paths:
        if not _BACKUP_GLOB_RE.match(pattern):
            raise ConfigError(f"backups.paths: {pattern!r} must be an absolute path using only letters, digits, "
                              "and . _ - / * ? (no spaces or quotes)")
    if backups.enabled and not backups.paths:
        warnings.append("Backup check off: add at least one pattern under backups.paths")
        backups.enabled = False
    if backups.enabled and not (vps and vps.ssh):
        warnings.append("Backup check off: it needs vps.ssh")
        backups.enabled = False

    return Config(general=general, thresholds=thresholds, alerts=alerts, daily_report=daily,
                  dashboard=dashboard, sites=sites, vps=vps, security=security, heartbeat=heartbeat,
                  monthly_report=monthly, status_page=status_page, backups=backups, base_dir=base,
                  warnings=warnings)

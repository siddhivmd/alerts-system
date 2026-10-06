"""External checks: DNS, HTTP, content keywords, SSL expiry, WHOIS domain expiry, VPS TCP ports.

Every network call is wrapped so that a failure is *recorded* in the result
object instead of raising: one broken site must never abort a check cycle.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import requests

from .config import SiteConfig, VpsConfig
from .pagetext import defacement_match, page_words

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 2 * 1024 * 1024  # enough for keyword checks; avoids pulling huge downloads
WHOIS_TTL = 24 * 3600
WHOIS_ERROR_TTL = 6 * 3600

# Public suffixes with two labels that are common for our customers. Anything
# unusual can be set explicitly per site with ``domain:``.
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in",
    "com.au", "net.au", "org.au", "co.nz", "org.nz", "com.br", "com.mx", "co.jp", "co.za",
    "com.sg", "com.my", "co.id", "com.tr", "com.cn", "com.hk", "com.pk", "com.bd", "com.ng",
    "co.ke", "com.ar", "com.co", "com.ph", "com.vn", "co.th", "co.kr", "com.sa", "com.eg",
}


@dataclass
class SiteCheckResult:
    """Raw facts collected about one site in one cycle (no interpretation)."""

    site: str
    url: str
    ts: float = field(default_factory=time.time)
    on_vps: bool = True
    verify_ssl: bool = True

    dns_ok: bool | None = None
    dns_error: str | None = None
    ip_addresses: list[str] = field(default_factory=list)

    http_status: int | None = None
    status_ok: bool | None = None
    expected_status: list[int] | None = None
    response_ms: int | None = None
    slow_threshold_ms: int | None = None
    final_url: str | None = None
    redirects: list[str] = field(default_factory=list)
    error_kind: str | None = None  # timeout | connection | ssl | too_many_redirects | request | internal
    error_message: str | None = None

    keyword: str | None = None
    keyword_found: bool | None = None
    forbidden_found: list[str] = field(default_factory=list)
    page_words: list[str] | None = None  # for defacement detection (not stored in history)
    defacement_text: str | None = None

    ssl_checked: bool = False
    ssl_days_left: int | None = None
    ssl_expires_at: str | None = None
    ssl_issuer: str | None = None
    ssl_error: str | None = None

    domain: str | None = None
    domain_days_left: int | None = None
    domain_expires_at: str | None = None
    domain_error: str | None = None

    @property
    def responded(self) -> bool:
        return self.http_status is not None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("page_words", None)  # large; only needed in memory
        return d


@dataclass
class VpsReachability:
    """TCP reachability of the VPS on each configured port."""

    host: str
    ports: dict[int, bool] = field(default_factory=dict)
    errors: dict[int, str] = field(default_factory=dict)

    @property
    def reachable(self) -> bool:
        return any(self.ports.values())

    @property
    def all_down(self) -> bool:
        return bool(self.ports) and not any(self.ports.values())

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "ports": self.ports, "errors": self.errors,
                "reachable": self.reachable}


# --------------------------------------------------------------------------- DNS

def resolve_dns(host: str) -> tuple[list[str], str | None]:
    """Return (ip addresses, error)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = sorted({info[4][0] for info in infos})
        return ips, None if ips else "no addresses returned"
    except socket.gaierror as exc:
        return [], f"{exc.strerror or exc}"
    except (OSError, UnicodeError) as exc:
        return [], str(exc)


# --------------------------------------------------------------------------- SSL

def _cert_not_after(der: bytes) -> datetime | None:
    """Parse the expiry date out of a DER certificate (works even for invalid certs)."""
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001 - best effort
        return None


def check_ssl(host: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    """Handshake with full verification; on failure, still try to read the expiry date.

    Returns keys: days_left, expires_at (ISO), issuer, error.
    """
    out: dict[str, Any] = {"days_left": None, "expires_at": None, "issuer": None, "error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        out["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    except ssl.SSLCertVerificationError as exc:
        out["error"] = exc.verify_message or str(exc)
        expires = _fetch_unverified_expiry(host, port, timeout)
    except ssl.SSLError as exc:
        out["error"] = f"TLS handshake failed: {exc.reason or exc}"
        return out
    except (OSError, KeyError, ValueError) as exc:
        # Port closed / timeout: not an SSL problem as such, HTTP check will report it.
        out["error"] = None
        out["unreachable"] = str(exc)
        return out

    if expires is not None:
        out["expires_at"] = expires.isoformat()
        out["days_left"] = int((expires.timestamp() - time.time()) // 86400)
    return out


def _fetch_unverified_expiry(host: str, port: int, timeout: float) -> datetime | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        return _cert_not_after(der) if der else None
    except (OSError, ssl.SSLError):
        return None


# --------------------------------------------------------------------------- WHOIS

def registered_domain(host: str) -> str | None:
    """Best-effort registrable domain: portal.example.co.in -> example.co.in. None for IPs."""
    host = host.strip(".").lower()
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, (list, tuple)):
        dates = [d for d in (_to_datetime(v) for v in value) if d]
        return min(dates) if dates else None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
            try:
                return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


class WhoisLookup:
    """WHOIS expiry lookups cached in SQLite (registrars rate-limit aggressively)."""

    def __init__(self, storage: Any | None = None, timeout: int = 10) -> None:
        self.storage = storage
        self.timeout = timeout
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock_for(self, domain: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(domain, threading.Lock())

    def expiry(self, domain: str) -> tuple[datetime | None, str | None]:
        """Return (expiry datetime, error). Uses the cache when fresh."""
        with self._lock_for(domain):  # several sites often share one domain
            cached = self.storage.get_whois(domain) if self.storage else None
            if cached:
                ttl = WHOIS_ERROR_TTL if cached["error"] else WHOIS_TTL
                if time.time() - cached["checked_at"] < ttl:
                    exp = cached["expires_at"]
                    return (datetime.fromtimestamp(exp, tz=timezone.utc) if exp else None), cached["error"]
            expires, error = self._query(domain)
            if self.storage:
                try:
                    self.storage.set_whois(domain, expires.timestamp() if expires else None, error)
                except Exception:  # noqa: BLE001
                    log.exception("Could not cache WHOIS result for %s", domain)
            return expires, error

    def _query(self, domain: str) -> tuple[datetime | None, str | None]:
        try:
            import whois  # python-whois
            data = whois.whois(domain, quiet=True, timeout=self.timeout)
            expires = _to_datetime(data.get("expiration_date") if hasattr(data, "get") else None)
            if expires is None:
                return None, "WHOIS returned no expiry date (some TLDs hide it)"
            return expires, None
        except Exception as exc:  # noqa: BLE001 - library raises many types
            log.info("WHOIS lookup failed for %s: %s", domain, exc)
            return None, f"WHOIS lookup failed: {str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__}"


# --------------------------------------------------------------------------- HTTP

def _http_check(site: SiteConfig, result: SiteCheckResult, user_agent: str) -> None:
    headers = {"User-Agent": user_agent, **site.headers}
    session = requests.Session()
    session.max_redirects = site.max_redirects
    start = time.perf_counter()
    try:
        with session.get(site.url, headers=headers, timeout=site.timeout,
                         allow_redirects=site.follow_redirects, verify=site.verify_ssl, stream=True) as resp:
            body = bytearray()
            for chunk in resp.iter_content(64 * 1024):
                body += chunk
                if len(body) >= MAX_BODY_BYTES:
                    break
            result.response_ms = int((time.perf_counter() - start) * 1000)
            result.http_status = resp.status_code
            result.final_url = resp.url
            result.redirects = [f"{h.status_code} {h.headers.get('Location', '')}" for h in resp.history]
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            text = bytes(body).decode(encoding, errors="replace")
    except requests.exceptions.SSLError as exc:
        result.error_kind, result.error_message = "ssl", _short(exc)
        return
    except requests.exceptions.TooManyRedirects as exc:
        result.error_kind, result.error_message = "too_many_redirects", _short(exc)
        return
    except requests.exceptions.Timeout as exc:
        result.error_kind, result.error_message = "timeout", f"No response within {site.timeout}s ({_short(exc)})"
        return
    except requests.exceptions.ConnectionError as exc:
        result.error_kind, result.error_message = "connection", _short(exc)
        return
    except requests.exceptions.RequestException as exc:
        result.error_kind, result.error_message = "request", _short(exc)
        return
    finally:
        session.close()

    if site.expected_status:
        result.status_ok = result.http_status in site.expected_status
    else:
        result.status_ok = result.http_status < 400
    if site.keyword:
        result.keyword_found = site.keyword in text
    result.forbidden_found = [k for k in site.forbidden_keywords if k in text]
    result.defacement_text = defacement_match(text)
    if site.content_change_alert > 0 and result.status_ok:
        result.page_words = page_words(text)


def _short(exc: BaseException, limit: int = 300) -> str:
    msg = str(exc) or type(exc).__name__
    return msg if len(msg) <= limit else msg[:limit] + "..."


def check_site(site: SiteConfig, whois_lookup: WhoisLookup | None = None,
               user_agent: str = "SiteMonitor/1.0") -> SiteCheckResult:
    """Run every configured check for one site. Never raises."""
    result = SiteCheckResult(site=site.name, url=site.url, on_vps=site.on_vps, verify_ssl=site.verify_ssl,
                             keyword=site.keyword or None, expected_status=site.expected_status,
                             slow_threshold_ms=site.slow_threshold_ms)
    try:
        host = site.hostname
        result.ip_addresses, result.dns_error = resolve_dns(host)
        result.dns_ok = result.dns_error is None

        # Domain expiry is still useful when DNS fails: it tells us *why* DNS fails.
        if site.check_domain and whois_lookup is not None:
            domain = site.domain or registered_domain(host)
            if domain:
                result.domain = domain
                expires, error = whois_lookup.expiry(domain)
                result.domain_error = error
                if expires:
                    result.domain_expires_at = expires.isoformat()
                    result.domain_days_left = int((expires.timestamp() - time.time()) // 86400)

        if not result.dns_ok:
            return result

        if site.is_https and site.check_ssl:
            info = check_ssl(host, 443, timeout=min(site.timeout, 10))
            result.ssl_checked = "unreachable" not in info
            result.ssl_days_left = info["days_left"]
            result.ssl_expires_at = info["expires_at"]
            result.ssl_issuer = info["issuer"]
            result.ssl_error = info["error"]

        _http_check(site, result, user_agent)
    except Exception as exc:  # noqa: BLE001 - last line of defence
        log.exception("Unexpected error while checking %s", site.name)
        result.error_kind = result.error_kind or "internal"
        result.error_message = f"Monitor internal error: {exc}"
    return result


# --------------------------------------------------------------------------- VPS

def check_vps_ports(vps: VpsConfig, connect: Callable[..., socket.socket] = socket.create_connection
                    ) -> VpsReachability:
    """TCP-connect to each configured port. All closed => VPS down or suspended."""
    out = VpsReachability(host=vps.host)
    for port in vps.ports:
        try:
            connect((vps.host, port), timeout=vps.port_timeout).close()
            out.ports[port] = True
        except OSError as exc:
            out.ports[port] = False
            out.errors[port] = str(exc) or type(exc).__name__
    return out

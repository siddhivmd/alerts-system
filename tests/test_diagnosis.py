"""Diagnosis engine tests: every rule, and the priority between rules."""
from conftest import healthy_stats, ok_result, reach

from sitemonitor.diagnosis import DOWN, UP, WARNING, diagnose, vps_warnings
from sitemonitor.ssh_stats import VpsStats

ALL_UP = dict(p22=True, p80=True, p443=True)
ALL_DOWN = dict(p22=False, p80=False, p443=False)


def test_healthy_site_is_up(thresholds):
    d = diagnose(ok_result(), reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.status == UP and d.cause_code is None and d.summary == "OK"


# ---- priority 1: DNS
def test_dns_failure(thresholds):
    r = ok_result(dns_ok=False, dns_error="Name or service not known", http_status=None, status_ok=None)
    d = diagnose(r, reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.status == DOWN and d.cause_code == "dns_failure"
    assert "domain expired or DNS misconfigured" in d.cause


def test_dns_failure_with_expired_domain_says_so(thresholds):
    r = ok_result(dns_ok=False, dns_error="NXDOMAIN", http_status=None, status_ok=None,
                  domain_days_left=-3, domain_expires_at="2026-09-25T00:00:00+00:00")
    d = diagnose(r, reach(**ALL_DOWN), None, thresholds)
    assert d.cause_code == "domain_expired" and "2026-09-25" in d.cause


def test_dns_failure_unregistered_domain(thresholds):
    r = ok_result(dns_ok=False, dns_error="getaddrinfo failed", http_status=None, status_ok=None,
                  domain_days_left=None, domain_error='WHOIS lookup failed: No match for "EXAMPLE.COM".')
    d = diagnose(r, None, None, thresholds)
    assert d.cause_code == "domain_not_registered" and "NOT REGISTERED" in d.cause


def test_dns_beats_vps_down(thresholds):
    r = ok_result(dns_ok=False, dns_error="x", http_status=None, status_ok=None)
    assert diagnose(r, reach(**ALL_DOWN), None, thresholds).cause_code == "dns_failure"


# ---- priority 2: VPS unreachable / suspended
def test_all_ports_closed_means_vps_down_or_suspended(thresholds):
    r = ok_result(http_status=None, status_ok=None, response_ms=None, error_kind="timeout", error_message="timed out")
    d = diagnose(r, reach(**ALL_DOWN), None, thresholds)
    assert d.cause_code == "vps_unreachable"
    assert "SUSPENDED" in d.cause
    assert any("Hostinger" in f for f in d.fixes) and any("SPAM" in f for f in d.fixes)


def test_vps_down_beats_ssl_error(thresholds):
    r = ok_result(http_status=None, status_ok=None, error_kind="ssl", ssl_error="certificate has expired")
    assert diagnose(r, reach(**ALL_DOWN), None, thresholds).cause_code == "vps_unreachable"


def test_site_not_on_vps_ignores_vps_state(thresholds):
    r = ok_result(on_vps=False, http_status=None, status_ok=None, error_kind="connection", error_message="refused")
    d = diagnose(r, reach(**ALL_DOWN), None, thresholds)
    assert d.cause_code == "site_connection"


# ---- priority 3: SSL
def test_expired_certificate(thresholds):
    r = ok_result(http_status=None, status_ok=None, error_kind="ssl", ssl_error="certificate has expired",
                  ssl_days_left=-2, ssl_expires_at="2026-09-26T00:00:00+00:00")
    d = diagnose(r, reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.cause_code == "ssl_expired" and "EXPIRED" in d.cause
    assert any("certbot renew" in f for f in d.fixes)


def test_hostname_mismatch(thresholds):
    r = ok_result(http_status=None, status_ok=None, error_kind="ssl",
                  ssl_error="Hostname mismatch, certificate is not valid for 'shop.example.com'.")
    d = diagnose(r, reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.cause_code == "ssl_hostname_mismatch"
    assert any("certbot --nginx -d shop.example.com" in f for f in d.fixes)


def test_ssl_error_ignored_when_verification_disabled(thresholds):
    r = ok_result(ssl_error="self-signed certificate", verify_ssl=False)
    d = diagnose(r, reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.status == WARNING and d.warnings[0].code == "ssl_invalid_ignored"


def test_ssl_beats_server_findings(thresholds):
    r = ok_result(http_status=None, status_ok=None, error_kind="ssl", ssl_error="certificate has expired")
    stats = healthy_stats(ram_percent=99.0)
    assert diagnose(r, reach(**ALL_UP), stats, thresholds).cause_code == "ssl_expired"


# ---- priority 4: VPS up but site down
def _down_timeout(**kw):
    return ok_result(http_status=None, status_ok=None, response_ms=None, error_kind="timeout",
                     error_message="No response within 15s", **kw)


def test_failed_nginx_is_root_cause_with_restart_fix(thresholds):
    stats = healthy_stats(services={"nginx": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    d = diagnose(_down_timeout(), reach(p22=True, p80=False, p443=False), stats, thresholds)
    assert d.cause_code == "service_down:nginx"
    assert d.fixes[0].startswith("Restart nginx: sudo systemctl restart nginx")
    # ports-closed finding is secondary evidence
    assert any("80/443 are closed" in e for e in d.evidence)


def test_disabled_inactive_service_is_not_blamed(thresholds):
    stats = healthy_stats(services={"apache2": {"active": "inactive", "sub": "dead", "enabled": "disabled"}})
    d = diagnose(_down_timeout(), reach(**ALL_UP), stats, thresholds)
    assert d.cause_code == "vps_up_site_down"


def test_disk_full_ranks_above_crashed_mysql(thresholds):
    stats = healthy_stats(disk_percent=99.0,
                          services={"mysql": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    r = ok_result(http_status=500, status_ok=False)
    d = diagnose(r, reach(**ALL_UP), stats, thresholds)
    assert d.cause_code == "disk_full" and "99%" in d.cause
    assert any("mysql" in e for e in d.evidence)
    assert any("systemctl restart mysql" in f for f in d.fixes)


def test_high_ram(thresholds):
    d = diagnose(_down_timeout(), reach(**ALL_UP), healthy_stats(ram_percent=96.0), thresholds)
    assert d.cause_code == "ram_high" and "96%" in d.cause


def test_ram_threshold_is_strictly_configurable(thresholds):
    d = diagnose(_down_timeout(), reach(**ALL_UP), healthy_stats(ram_percent=89.0), thresholds)
    assert d.cause_code == "vps_up_site_down"


def test_oom_kills_reported(thresholds):
    stats = healthy_stats(oom_kills=2, oom_last="Out of memory: Killed process 812 (mysqld)")
    d = diagnose(_down_timeout(), reach(**ALL_UP), stats, thresholds)
    assert d.cause_code == "oom_kills" and "mysqld" in d.cause


def test_error_log_lines_are_attached_and_scanned(thresholds):
    log = ["2026/09/28 10:00:01 [crit] connect() to unix:/run/php/php8.2-fpm.sock failed (2: No such file)"]
    d = diagnose(ok_result(http_status=502, status_ok=False), reach(**ALL_UP), healthy_stats(), thresholds,
                 error_log=log)
    assert d.cause_code == "log_php_fpm"
    assert d.error_log == log


def test_vps_up_no_findings_generic(thresholds):
    d = diagnose(_down_timeout(), reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.cause_code == "vps_up_site_down"
    assert "web server/app crashed or overloaded" in d.cause


def test_ssh_unavailable_still_diagnoses(thresholds):
    stats = VpsStats(ok=False, error="SSH authentication failed")
    d = diagnose(ok_result(http_status=502, status_ok=False), reach(**ALL_UP), stats, thresholds)
    assert d.cause_code == "http_502"
    assert any("SSH authentication failed" in e for e in d.evidence)


def test_no_vps_configured(thresholds):
    d = diagnose(_down_timeout(), None, None, thresholds)
    assert d.cause_code == "site_timeout"


# ---- priority 5: HTTP codes, content, slow
def test_http_codes(thresholds):
    for code, expected in [(500, "http_500"), (502, "http_502"), (503, "http_503"), (504, "http_504"),
                           (404, "http_404"), (403, "http_403"), (418, "http_418")]:
        d = diagnose(ok_result(http_status=code, status_ok=False), reach(**ALL_UP), healthy_stats(), thresholds)
        assert d.cause_code == expected, code
        assert d.fixes


def test_4xx_is_not_blamed_on_ram(thresholds):
    d = diagnose(ok_result(http_status=404, status_ok=False), reach(**ALL_UP),
                 healthy_stats(ram_percent=97.0), thresholds)
    assert d.cause_code == "http_404"
    assert any("RAM" in e for e in d.evidence)


def test_unexpected_status(thresholds):
    r = ok_result(http_status=301, status_ok=False, expected_status=[200])
    assert diagnose(r, reach(**ALL_UP), healthy_stats(), thresholds).cause_code == "unexpected_status"


def test_keyword_missing(thresholds):
    r = ok_result(keyword="Login", keyword_found=False)
    d = diagnose(r, reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.cause_code == "keyword_missing" and "'Login'" in d.cause


def test_forbidden_text_database_error(thresholds):
    r = ok_result(forbidden_found=["Error establishing a database connection"])
    d = diagnose(r, reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.cause_code == "log_db_connect"


def test_redirect_loop(thresholds):
    r = ok_result(http_status=None, status_ok=None, error_kind="too_many_redirects", error_message="Exceeded 10")
    assert diagnose(r, reach(**ALL_UP), healthy_stats(), thresholds).cause_code == "redirect_loop"


def test_slow_response_is_warning_not_down(thresholds):
    d = diagnose(ok_result(response_ms=4500), reach(**ALL_UP), healthy_stats(), thresholds)
    assert d.status == WARNING and d.warnings[0].code == "slow"


# ---- warnings
def test_ssl_expiry_warning_levels(thresholds):
    d14 = diagnose(ok_result(ssl_days_left=10), None, None, thresholds)
    d3 = diagnose(ok_result(ssl_days_left=2), None, None, thresholds)
    assert [w.code for w in d14.warnings] == ["ssl_expiring"]
    assert [w.code for w in d3.warnings] == ["ssl_expiring_critical"]
    assert d3.warnings[0].severity == "critical"


def test_domain_expiry_warning(thresholds):
    d = diagnose(ok_result(domain_days_left=20), None, None, thresholds)
    assert d.status == WARNING and d.warnings[0].code == "domain_expiring"


def test_vps_warnings(thresholds):
    stats = healthy_stats(disk_percent=88.0, oom_kills=1,
                          services={"mariadb": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    codes = {w.code for w in vps_warnings(stats, reach(**ALL_UP), thresholds)}
    assert codes == {"disk_high", "oom_kills", "service_down:mariadb"}
    assert vps_warnings(stats, reach(**ALL_DOWN), thresholds) == []  # reported per site instead


def test_monitor_internal_error_is_not_blamed_on_vps(thresholds):
    r = ok_result(http_status=None, status_ok=None, error_kind="internal", error_message="Monitor internal error: x")
    stats = healthy_stats(services={"nginx": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    d = diagnose(r, reach(**ALL_UP), stats, thresholds)
    assert d.cause_code == "monitor_error"

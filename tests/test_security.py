"""Security early-warning checks: blacklists, Safe Browsing, and SSH-based signals. All offline."""
import socket

from conftest import healthy_stats

from sitemonitor.config import (AlertsConfig, Config, DailyReportConfig, DashboardConfig, GeneralConfig,
                                SecurityConfig, SiteConfig, Thresholds, VpsConfig)
from sitemonitor.security import (SecurityChecker, blacklist_warnings, check_blacklists, check_safe_browsing,
                                  dnsbl_query_name, server_security_warnings)
from sitemonitor.ssh_stats import parse_stats

ZONES = ["zen.spamhaus.org", "bl.spamcop.net", "psbl.surriel.com"]


def fake_resolver(answers):
    """answers: {query name: ip}; anything else is NXDOMAIN (= not listed)."""
    calls = []

    def resolve(name):
        calls.append(name)
        if name in answers:
            return answers[name]
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    resolve.calls = calls
    return resolve


# ---------------------------------------------------------------- blacklists
def test_query_name_reverses_octets():
    assert dnsbl_query_name("1.2.3.4", "zen.spamhaus.org") == "4.3.2.1.zen.spamhaus.org"


def test_clean_ip():
    r = check_blacklists("1.2.3.4", ZONES, fake_resolver({}))
    assert r.listed == {} and sorted(r.clean) == sorted(ZONES) and r.errors == {}
    assert "not listed" in r.summary()
    assert blacklist_warnings(r) == []


def test_listed_ip_gives_critical_warning_with_delist_link():
    r = check_blacklists("1.2.3.4", ZONES, fake_resolver({"4.3.2.1.bl.spamcop.net": "127.0.0.2"}))
    assert r.listed == {"bl.spamcop.net": "127.0.0.2"}
    [w] = blacklist_warnings(r)
    assert w.severity == "critical" and "SpamCop" in w.message and "spamcop.net/bl.shtml" in w.fix
    assert "LISTED on 1 of 3" in r.summary()


def test_spamhaus_refusing_public_resolver_is_an_error_not_a_listing():
    r = check_blacklists("1.2.3.4", ZONES, fake_resolver({"4.3.2.1.zen.spamhaus.org": "127.255.255.254"}))
    assert r.listed == {} and "public" in r.errors["zen.spamhaus.org"]


def test_isp_dns_hijack_is_not_a_listing():
    r = check_blacklists("1.2.3.4", ZONES, fake_resolver({"4.3.2.1.psbl.surriel.com": "92.242.132.24"}))
    assert r.listed == {} and "unexpected" in r.errors["psbl.surriel.com"]


def test_non_ipv4_is_reported_not_crashed():
    assert check_blacklists("2001:db8::1", ZONES, fake_resolver({})).errors
    assert check_blacklists("not-an-ip", ZONES, fake_resolver({})).errors


# ---------------------------------------------------------------- Safe Browsing
class FakeResponse:
    def __init__(self, status, payload):
        self.status_code, self._payload, self.text = status, payload, str(payload)

    def json(self):
        return self._payload


def test_safe_browsing_flags_only_matching_site():
    sent = {}

    def post(url, params, json, timeout):
        sent.update(params=params, body=json)
        return FakeResponse(200, {"matches": [{"threatType": "MALWARE", "threat": {"url": "https://bad.test/"}}]})

    flags, err = check_safe_browsing(["https://bad.test/", "https://good.test/"], "KEY", post)
    assert err is None and flags == {"https://bad.test/": ["MALWARE"]}
    assert sent["params"] == {"key": "KEY"}
    assert len(sent["body"]["threatInfo"]["threatEntries"]) == 2   # one request for all sites


def test_safe_browsing_matches_normalised_url_by_hostname():
    post = lambda *a, **k: FakeResponse(200, {"matches": [  # noqa: E731
        {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "http://bad.test/login"}}]})
    flags, _ = check_safe_browsing(["https://bad.test/"], "KEY", post)
    assert flags == {"https://bad.test/": ["SOCIAL_ENGINEERING"]}


def test_safe_browsing_errors_hide_the_key():
    def post(*a, **k):
        raise RuntimeError("connection failed for https://x/?key=SECRETKEY")
    flags, err = check_safe_browsing(["https://a.test/"], "SECRETKEY", post)
    assert flags == {} and "SECRETKEY" not in err and "***" in err
    flags, err = check_safe_browsing(["https://a.test/"], "K", lambda *a, **k: FakeResponse(403, "denied"))
    assert flags == {} and "403" in err


# ---------------------------------------------------------------- SSH-based signals
SEC = SecurityConfig()


def proc(comm, cpu=1.0, args=None, user="www-data", pid=4242):
    return {"pid": pid, "user": user, "cpu": cpu, "comm": comm, "args": args or f"/usr/bin/{comm}"}


def codes(stats):
    return [w.code for w in server_security_warnings(stats, SEC)]


def test_crypto_miner_by_name_and_by_pool_protocol():
    stats = healthy_stats(top_processes=[
        proc("xmrig", 99.0),
        proc("kworkerds", 95.0, "./kworkerds -o stratum+tcp://pool.example:3333"),
    ])
    ws = server_security_warnings(stats, SEC)
    assert [w.code for w in ws] == ["miner:xmrig", "miner:kworkerds"]
    assert all(w.severity == "critical" for w in ws) and "kill -9 4242" in ws[0].fix


def test_program_running_from_tmp():
    assert codes(healthy_stats(top_processes=[proc("x", 0.5, "/tmp/.x/x -daemon")])) == ["tmp_process:x"]


def test_busy_known_process_is_fine_but_unknown_is_flagged():
    stats = healthy_stats(top_processes=[proc("mysqld", 180.0), proc("php-fpm8.2", 90.0), proc("zzqq", 85.0)])
    assert codes(stats) == ["unknown_cpu:zzqq"]
    assert codes(healthy_stats(top_processes=[proc("zzqq", 50.0)])) == []   # below cpu_process_percent


def test_new_php_files_uploads_are_critical_and_cache_is_ignored():
    stats = healthy_stats(new_php_files=[
        "/var/www/site/wp-content/uploads/2026/09/x.php",
        "/var/www/site/wp-content/cache/page.php",
        "/var/www/site/index.php",
    ])
    ws = server_security_warnings(stats, SEC)
    assert [w.code for w in ws] == ["new_php:/var/www/site/wp-content/uploads/2026/09/x.php",
                                    "new_php:/var/www/site/index.php"]
    assert [w.severity for w in ws] == ["critical", "warning"]


def test_many_new_php_files_become_one_warning():
    stats = healthy_stats(new_php_files=[f"/var/www/app/f{i}.php" for i in range(40)])
    assert codes(stats) == ["new_php_bulk"]


def test_ssh_bruteforce_threshold():
    ok = healthy_stats(failed_ssh_logins=SEC.failed_ssh_logins_per_hour - 1)
    bad = healthy_stats(failed_ssh_logins=500, failed_ssh_top_ips=[("203.0.113.9", 400)])
    assert codes(ok) == []
    [w] = server_security_warnings(bad, SEC)
    assert w.code == "ssh_bruteforce" and "203.0.113.9 (400)" in w.message and "fail2ban" in w.fix


def test_outbound_spam_connections():
    assert codes(healthy_stats(outbound_smtp=3)) == []
    [w] = server_security_warnings(healthy_stats(outbound_smtp=45), SEC)
    assert w.code == "outbound_smtp" and w.severity == "critical"


def test_disabled_or_unavailable_ssh_gives_nothing():
    stats = healthy_stats(outbound_smtp=99)
    assert server_security_warnings(stats, SecurityConfig(enabled=False)) == []
    assert server_security_warnings(None, SEC) == []


def test_parse_security_sections():
    output = """##PROCS
 4242 www-data 97.5 xmrig /tmp/.cache/xmrig -o stratum+tcp://pool:3333
  812 mysql     4.1 mysqld /usr/sbin/mysqld
##NEWPHP
/var/www/site/wp-content/uploads/shell.php
##SSHFAIL
window=last hour
Sep 29 10:00:01 vps sshd[1]: Invalid user admin from 203.0.113.9 port 5000
Sep 29 10:00:02 vps sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 5000 ssh2
Sep 29 10:00:03 vps sshd[2]: Failed password for root from 198.51.100.7 port 6000 ssh2
##SMTPOUT
37
##END
"""
    st = parse_stats(output, [])
    assert st.top_processes[0] == {"pid": 4242, "user": "www-data", "cpu": 97.5, "comm": "xmrig",
                                   "args": "/tmp/.cache/xmrig -o stratum+tcp://pool:3333"}
    assert st.new_php_files == ["/var/www/site/wp-content/uploads/shell.php"]
    assert st.failed_ssh_logins == 2          # the "invalid user" pair counts once
    assert st.failed_ssh_top_ips == [("203.0.113.9", 1), ("198.51.100.7", 1)]
    assert st.outbound_smtp == 37


def test_parse_without_security_sections_leaves_defaults():
    st = parse_stats("##MEM\n##END\n", [])
    assert st.failed_ssh_logins is None and st.outbound_smtp is None and st.top_processes == []


# ---------------------------------------------------------------- scheduling / caching
def make_config(**security):
    return Config(general=GeneralConfig(), thresholds=Thresholds(), alerts=AlertsConfig(),
                  daily_report=DailyReportConfig(), dashboard=DashboardConfig(),
                  sites=[SiteConfig(name="Shop", url="https://shop.test/")],
                  vps=VpsConfig(host="1.2.3.4"), security=SecurityConfig(**security))


def test_checker_caches_blacklist_between_intervals():
    resolve = fake_resolver({"4.3.2.1.zen.spamhaus.org": "127.0.0.4"})
    checker = SecurityChecker(make_config(blacklists=["zen.spamhaus.org"], blacklist_interval_minutes=60), resolve)
    checker.refresh(now=1000.0)
    checker.refresh(now=1000.0 + 30 * 60)       # within the hour: cached
    assert len(resolve.calls) == 1
    assert [w.code for w in checker.server_warnings(None)] == ["blacklisted:1.2.3.4:zen.spamhaus.org"]
    checker.refresh(now=1000.0 + 61 * 60)       # interval elapsed: looked up again
    assert len(resolve.calls) == 2


def test_checker_extra_ips_and_safe_browsing_site_warnings():
    resolve = fake_resolver({"2.0.0.127.zen.spamhaus.org": "127.0.0.2"})
    post = lambda *a, **k: FakeResponse(200, {"matches": [  # noqa: E731
        {"threatType": "MALWARE", "threat": {"url": "https://shop.test/"}}]})
    cfg = make_config(blacklists=["zen.spamhaus.org"], extra_ips=["127.0.0.2"], safe_browsing=True,
                      safe_browsing_key="K")
    checker = SecurityChecker(cfg, resolve, post)
    checker.refresh(now=1.0)
    assert [r.ip for r in checker.blacklist_results] == ["1.2.3.4", "127.0.0.2"]
    assert [w.code for w in checker.server_warnings(None)] == ["blacklisted:127.0.0.2:zen.spamhaus.org"]
    [w] = checker.site_warnings()["Shop"]
    assert w.code == "safe_browsing" and "malware" in w.message
    assert checker.summary()["safe_browsing"] == "1 site(s) flagged"


def test_safe_browsing_api_error_keeps_previous_flags():
    calls = {"n": 0}

    def post(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return FakeResponse(200, {"matches": [{"threatType": "MALWARE", "threat": {"url": "https://shop.test/"}}]})
        return FakeResponse(500, "oops")
    checker = SecurityChecker(make_config(blacklist_check=False, safe_browsing=True, safe_browsing_key="K",
                                          safe_browsing_interval_minutes=1), fake_resolver({}), post)
    checker.refresh(now=0.0)
    checker.refresh(now=120.0)
    assert "Shop" in checker.site_warnings() and "500" in checker.summary()["safe_browsing"]


def test_checker_does_nothing_when_disabled():
    resolve = fake_resolver({})
    checker = SecurityChecker(make_config(enabled=False), resolve)
    checker.refresh(now=1.0)
    assert resolve.calls == [] and checker.server_warnings(healthy_stats(outbound_smtp=99)) == []

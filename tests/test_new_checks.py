"""Multiple servers, inodes, disk trend, DNS hijack, RDAP, flapping and login checks. All offline."""
import textwrap
import threading
from datetime import datetime, timezone

import pytest
from conftest import healthy_stats, ok_result, reach

from sitemonitor import runner as runner_mod
from sitemonitor.alerts import AlertManager, Formatter
from sitemonitor.checks import WhoisLookup, extract_token, login_check, unexpected_ips
from sitemonitor.config import AlertsConfig, ConfigError, LoginConfig, SiteConfig, Thresholds, load_config
from sitemonitor.diagnosis import DOWN, UP, Diagnosis, diagnose, vps_warnings
from sitemonitor.runner import Monitor
from sitemonitor.ssh_stats import parse_stats
from sitemonitor.storage import Storage
from sitemonitor.trends import disk_forecast_warning, forecast_full

DAY = 86400.0


def load(tmp_path, text, env=None, monkeypatch=None):
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    (tmp_path / "c.yaml").write_text(textwrap.dedent(text))
    return load_config(tmp_path / "c.yaml", env_file=str(tmp_path / "none.env"))


# ================================================================ 1. multiple servers
SERVERS = """
general: {database: data/t.db, log_file: logs/t.log, connectivity_check: false}
security: {blacklist_check: false}
servers:
  - {name: web1, host: 10.0.0.1, ssh: {user: m, key_file: key}}
  - {name: web2, host: 10.0.0.2, ssh: {user: m, key_file: key}}
sites:
  - {name: Shop, url: "https://shop.test", server: web1}
  - {name: Blog, url: "https://blog.test", server: web2}
  - {name: Docs, url: "https://docs.test"}
  - {name: Saas, url: "https://saas.test", on_vps: false}
"""


def test_servers_config_and_site_assignment(tmp_path):
    (tmp_path / "key").write_text("k")
    cfg = load(tmp_path, SERVERS)
    assert list(cfg.servers) == ["web1", "web2"] and cfg.vps.name == "web1"
    assert {s.name: s.server for s in cfg.sites} == {"Shop": "web1", "Blog": "web2", "Docs": "web1", "Saas": None}
    for bad, msg in [("servers: [{name: a, host: x}]\nvps: {host: y}\nsites: [{name: A, url: 'https://a'}]", "not both"),
                     ("servers: [{name: a, host: x}]\nsites: [{name: A, url: 'https://a', server: zz}]", "unknown server"),
                     ("servers: [{host: x}]\nsites: [{name: A, url: 'https://a'}]", "needs a name")]:
        with pytest.raises(ConfigError, match=msg):
            load(tmp_path, bad)


def test_classic_vps_block_still_works(tmp_path):
    cfg = load(tmp_path, "vps: {name: Hostinger, host: 1.2.3.4}\nsites: [{name: A, url: 'https://a'}]")
    assert list(cfg.servers) == ["Hostinger"] and cfg.sites[0].server == "Hostinger"


def test_each_site_is_diagnosed_with_its_own_server(tmp_path, monkeypatch):
    (tmp_path / "key").write_text("k")
    cfg = load(tmp_path, SERVERS)
    broken = healthy_stats(services={"nginx": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    monkeypatch.setattr(runner_mod, "check_site", lambda site, w, ua: ok_result(
        site=site.name, url=site.url, on_vps=site.on_vps, http_status=None, status_ok=None, response_ms=None,
        error_kind="timeout", error_message="timed out"))
    monkeypatch.setattr(runner_mod, "check_vps_ports", lambda sv: reach(p22=True, p80=True, p443=True))
    monkeypatch.setattr(runner_mod, "collect_stats",
                        lambda host, ssh, sec=None, bk=None: broken if host == "10.0.0.1" else healthy_stats())
    monkeypatch.setattr(runner_mod, "fetch_error_logs", lambda host, ssh, paths: {})
    cycle = Monitor(cfg, Storage(cfg.general.database)).run_cycle(alert=False)
    causes = {d.site: d.cause_code for d in cycle.diagnoses}
    assert causes["Shop"] == "service_down:nginx"       # web1's nginx is down
    assert causes["Blog"] == "vps_up_site_down"         # web2 is healthy: not blamed on web1's nginx
    assert causes["Saas"] == "site_timeout"             # not on a monitored server
    assert set(cycle.servers) == {"web1", "web2"}
    assert [w.code for w in cycle.servers["web1"].warnings] == ["service_down:nginx"]
    assert cycle.servers["web2"].warnings == []
    rows = cycle and Storage(cfg.general.database).vps_history(0)
    assert {r["server"] for r in rows} == {"web1", "web2"}   # history kept per server


# ================================================================ 2. inodes
def test_parse_inodes():
    st = parse_stats("##INODES\nFilesystem Inodes IUsed IFree IUse% Mounted on\n"
                     "/dev/sda1 655360 642252 13108 98% /\nbtrfs - - - - /data\n##END\n", [])
    assert st.inode_percent == 98.0 and "/data" not in st.inodes


def test_inode_exhaustion_is_the_cause_even_with_free_space():
    stats = healthy_stats(disk_percent=40.0, inode_percent=99.0,
                          services={"php8.2-fpm": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    r = ok_result(http_status=500, status_ok=False)
    d = diagnose(r, reach(p22=True, p80=True, p443=True), stats, Thresholds())
    assert d.cause_code == "inodes_full" and "free space" in d.cause
    assert any("/var/lib/php/sessions" in f for f in d.fixes)
    codes = [w.code for w in vps_warnings(healthy_stats(inode_percent=88.0), reach(p22=True), Thresholds())]
    assert codes == ["inodes_high"]


# ================================================================ 3. disk trend
def test_forecast_needs_enough_history_and_growth():
    now = 1_800_000_000.0
    growing = [(now - DAY * 2 + i * 3600, 60 + i * (3 / 24)) for i in range(49)]   # +3 %/day for 2 days
    fc = forecast_full(growing, now)
    assert fc["rate_per_day"] == pytest.approx(3.0) and fc["seconds_to_full"] / DAY == pytest.approx(34 / 3, rel=0.01)
    assert forecast_full(growing[-10:], now) is None                           # < 12 samples / < 24 h
    assert forecast_full([(t, 60.0) for t, _ in growing], now) is None         # flat
    assert forecast_full([(t, 90 - (v - 60)) for t, v in growing], now) is None  # shrinking


def test_disk_forecast_warning_uses_server_history(tmp_path):
    store = Storage(str(tmp_path / "d.db"))
    now = 1_800_000_000.0
    for i in range(48):  # 2 days, growing 8 %/day from 60 % -> about 3 days left
        store.record_vps(now - DAY * 2 + i * 3600, True, {}, {"disk_percent": 60 + i * (8 / 24)}, None, server="web1")
    store.record_vps(now - 3600, True, {}, {"disk_percent": 20.0}, None, server="web2")  # other server ignored
    w = disk_forecast_warning(store, "web1", healthy_stats(disk_percent=76.0), now, warn_days=7)
    assert w.code == "disk_forecast" and "about 3d" in w.message and "8.0%/day" in w.message
    assert disk_forecast_warning(store, "web1", healthy_stats(disk_percent=76.0), now, warn_days=2) is None
    assert disk_forecast_warning(store, "web2", healthy_stats(disk_percent=20.0), now, warn_days=7) is None


# ================================================================ 4. DNS hijack
def test_unexpected_ips_with_ranges():
    assert unexpected_ips(["1.2.3.4"], ["1.2.3.4"]) == []
    assert unexpected_ips(["104.16.5.5", "6.6.6.6"], ["104.16.0.0/13"]) == ["6.6.6.6"]
    assert unexpected_ips(["2606:4700::1"], ["1.2.3.4", "2606:4700::/32"]) == []


def test_dns_pointing_elsewhere_is_down_with_hijack_cause():
    r = ok_result(ip_addresses=["6.6.6.6"], expected_ip=["1.2.3.4"], unexpected_ips=["6.6.6.6"])
    d = diagnose(r, reach(p22=True, p80=True, p443=True), healthy_stats(), Thresholds())
    assert d.status == DOWN and d.cause_code == "dns_unexpected_ip" and "6.6.6.6" in d.cause
    assert any("2FA" in f for f in d.fixes)


def test_expected_ip_validation(tmp_path):
    with pytest.raises(ConfigError, match="expected_ip"):
        load(tmp_path, "sites: [{name: A, url: 'https://a', expected_ip: [not-an-ip]}]")


# ================================================================ 5. RDAP first, WHOIS fallback
class Resp:
    def __init__(self, status, payload=None):
        self.status_code, self._p = status, payload or {}

    def json(self):
        return self._p


def test_rdap_is_used_first():
    calls = []
    payload = {"events": [{"eventAction": "registration"}, {"eventAction": "expiration",
                                                            "eventDate": "2027-08-13T04:00:00Z"}]}
    lookup = WhoisLookup(None, http_get=lambda url, **k: calls.append(url) or Resp(200, payload),
                         whois_query=lambda d: pytest.fail("WHOIS must not be needed"))
    expires, error = lookup.expiry("example.com")
    assert error is None and expires == datetime(2027, 8, 13, 4, tzinfo=timezone.utc)
    assert calls == ["https://rdap.org/domain/example.com"]


def test_rdap_not_found_falls_back_to_whois():
    lookup = WhoisLookup(None, http_get=lambda url, **k: Resp(404),
                         whois_query=lambda d: {"expiration_date": datetime(2028, 1, 1)})
    assert lookup.expiry("example.co.in")[0].year == 2028
    def no_match(d):
        raise RuntimeError('No match for "GHOST.COM".')
    _, error = WhoisLookup(None, http_get=lambda url, **k: Resp(404), whois_query=no_match).expiry("ghost.com")
    assert error.startswith("WHOIS lookup failed: No match") and "RDAP" in error   # still "not registered"


# ================================================================ 6. flapping / recovery confirmation
T0 = 1_800_000_000.0
MIN = 60.0


@pytest.fixture
def site(tmp_path):
    store = Storage(str(tmp_path / "f.db"))
    return store, store.sync_sites([("Shop", "https://shop.test")])["Shop"]


DOWN_D = Diagnosis(site="Shop", url="u", status=DOWN, cause_code="http_502", cause="HTTP 502")
UP_D = Diagnosis(site="Shop", url="u", status=UP)


def run(mgr, sid, d, t):
    events = mgr.evaluate_site(sid, d, t)
    mgr.mark_sent(events)
    return [e.kind for e in events]


def test_recovery_needs_two_good_checks_but_downtime_ends_at_the_first(site):
    store, sid = site
    mgr = AlertManager(store, AlertsConfig(consecutive_failures=1, recovery_successes=2, flap_threshold=0))
    assert run(mgr, sid, DOWN_D, T0) == ["down"]
    assert run(mgr, sid, UP_D, T0 + 5 * MIN) == []                 # one good check is not a recovery
    assert run(mgr, sid, DOWN_D, T0 + 10 * MIN) == []              # it fell over again: same incident
    assert run(mgr, sid, UP_D, T0 + 15 * MIN) == []
    events = mgr.evaluate_site(sid, UP_D, T0 + 20 * MIN)
    assert [e.kind for e in events] == ["recovered"] and events[0].duration == 15 * MIN
    assert len(store.incidents()) == 1


def test_flapping_sends_one_alert_instead_of_a_storm(site):
    store, sid = site
    mgr = AlertManager(store, AlertsConfig(consecutive_failures=1, flap_threshold=3, flap_window_minutes=60))
    kinds = []
    for i in range(5):                                             # down/up every 5 minutes
        kinds += run(mgr, sid, DOWN_D, T0 + i * 10 * MIN)
        kinds += run(mgr, sid, UP_D, T0 + i * 10 * MIN + 5 * MIN)
    # outages 1-2 alert normally; the 3rd triggers ONE flapping alert; 4-5 are silent
    assert kinds == ["down", "recovered", "down", "recovered", "flapping"]
    assert len(store.incidents()) == 5                             # still all recorded for the reports
    assert run(mgr, sid, UP_D, T0 + 99 * MIN) == []                 # last outage began at +40m: < 60 min ago
    assert run(mgr, sid, UP_D, T0 + 100 * MIN) == ["stable"]        # quiet for a full window
    assert run(mgr, sid, UP_D, T0 + 105 * MIN) == []                # said once


def test_flapping_site_that_stays_down_alerts_normally(site):
    store, sid = site
    mgr = AlertManager(store, AlertsConfig(consecutive_failures=1, flap_threshold=3, flap_window_minutes=30))
    for i in range(3):
        run(mgr, sid, DOWN_D, T0 + i * 4 * MIN)
        if i < 2:
            run(mgr, sid, UP_D, T0 + i * 4 * MIN + 2 * MIN)
    assert run(mgr, sid, DOWN_D, T0 + 20 * MIN) == []                # flapping: muted
    assert run(mgr, sid, DOWN_D, T0 + 39 * MIN) == ["still_down"]    # down for a whole window: real outage


def test_flapping_message_text():
    from sitemonitor.alerts import AlertEvent
    ev = AlertEvent(kind="flapping", key="Shop", ts=T0, url="u", diagnosis=DOWN_D, count=4, duration=3600)
    f = Formatter("UTC")
    assert f.subject([ev]).startswith("[ALERT] FLAPPING: Shop") and "went down 4 times" in f.event(ev)


# ================================================================ 7. login checks
@pytest.fixture
def portal():
    """A real local web app: login form with CSRF token, session cookie, dashboard."""
    from flask import Flask, redirect, request, session
    from werkzeug.serving import make_server
    app = Flask("portal")
    app.secret_key = "test"
    state = {"db_down": False}

    @app.get("/login")
    def form():
        session["csrf"] = "tok-123"
        return ('<form method=post><input type="hidden" name="_token" value="tok-123">'
                '<input name=email><input name=password type=password></form>')

    @app.post("/login")
    def submit():
        if state["db_down"]:
            return "SQLSTATE[HY000] [2002] Connection refused", 500
        if request.form.get("_token") != session.get("csrf"):
            return "Page expired (CSRF)", 419
        if request.form.get("password") != "s3cret":
            return "These credentials do not match our records.", 200
        session["user"] = request.form["email"]
        return redirect("/dashboard")

    @app.get("/dashboard")
    def dashboard():
        return f"Dashboard - welcome {session['user']} - Log out" if "user" in session else redirect("/login")

    server = make_server("127.0.0.1", 0, app)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}", state
    server.shutdown()


def portal_site(base, password="s3cret", **kw):
    kw.setdefault("csrf_field", "_token")
    return SiteConfig(name="Portal", url=f"{base}/login", login=LoginConfig(
        expect_keyword="Log out", fields={"email": "monitor@test", "password": password},
        failure_keywords=["do not match"], **kw))


def test_login_success_with_csrf_and_session(portal):
    base, _ = portal
    ok, error, ms = login_check(portal_site(base, after_url=f"{base}/dashboard"), "test")
    assert ok and error is None and ms >= 0


def test_login_failures_are_explained_without_leaking_the_password(portal):
    base, state = portal
    ok, error, _ = login_check(portal_site(base, password="wrong-pass"), "test")
    assert not ok and "do not match" in error and "wrong-pass" not in error
    state["db_down"] = True
    ok, error, _ = login_check(portal_site(base), "test")
    assert not ok and "HTTP 500" in error
    ok, error, _ = login_check(portal_site(base, csrf_field="csrf_missing"), "test")
    assert not ok and "csrf_missing" in error


def test_login_failure_diagnosis_prefers_a_server_cause():
    r = ok_result(login_ok=False, login_error="after logging in, 'Log out' is not on the page")
    d = diagnose(r, reach(p22=True, p80=True, p443=True), healthy_stats(), Thresholds())
    assert d.cause_code == "login_failed" and "logging in fails" in d.cause
    db_down = healthy_stats(services={"mysql": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    assert diagnose(r, reach(p22=True, p80=True, p443=True), db_down, Thresholds()).cause_code == "service_down:mysql"


def test_login_secrets_come_from_env(tmp_path, monkeypatch):
    text = """
    sites:
      - name: Portal
        url: https://portal.test
        login: {expect_keyword: Log out, fields: {email: monitor@test, password: "env:PORTAL_PASS"}}
    """
    monkeypatch.delenv("PORTAL_PASS", raising=False)
    cfg = load(tmp_path, text)
    assert cfg.sites[0].login is None and any("PORTAL_PASS" in w for w in cfg.warnings)
    cfg = load(tmp_path, text, {"PORTAL_PASS": "s3cret"}, monkeypatch)
    assert cfg.sites[0].login.fields["password"] == "s3cret"
    assert extract_token('<meta name="csrf-token" content="abc&amp;1">', "csrf-token") == "abc&1"

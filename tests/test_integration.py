"""Config loading, a full runner cycle with mocked network, and the dashboard API."""
import base64
import textwrap
from pathlib import Path

import pytest
from conftest import healthy_stats, ok_result, reach

from sitemonitor import runner as runner_mod
from sitemonitor.alerts import AlertEvent, Notifier
from sitemonitor.config import AlertsConfig, ConfigError, load_config
from sitemonitor.diagnosis import Warn
from sitemonitor.dashboard import create_app
from sitemonitor.runner import Monitor
from sitemonitor.storage import Storage

CONFIG = """
general: {database: data/t.db, log_file: logs/t.log}
defaults: {timeout: 7, slow_threshold_ms: 2000}
vps:
  host: 1.2.3.4
  ssh: {user: mon, key_file: key}
alerts: {consecutive_failures: 2}
dashboard: {username: admin}
sites:
  - {name: A, url: "https://a.example.com", keyword: Hello}
  - {name: B, url: "https://b.example.com", timeout: 3}
"""


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "s3cret")
    (tmp_path / "config.yaml").write_text(CONFIG)
    (tmp_path / "key").write_text("dummy")  # SSH is switched off when the key file is missing
    return load_config(tmp_path / "config.yaml", env_file=str(tmp_path / "missing.env"))


def test_config_defaults_and_secrets(cfg, tmp_path):
    a, b = cfg.sites
    assert (a.timeout, b.timeout, a.slow_threshold_ms) == (7, 3, 2000)
    assert cfg.dashboard.password == "s3cret"
    assert cfg.vps.ssh.key_file == str(tmp_path / "key")
    assert cfg.general.database == str(tmp_path / "data" / "t.db")


@pytest.mark.parametrize("bad, msg", [
    ("sites: []", "Nothing to monitor"),
    ("sites: [{name: A, url: ftp://x}]", "url must be"),
    ("sites: [{name: A, url: 'https://a'}, {name: A, url: 'https://b'}]", "Duplicate"),
    ("sites: [{name: A, url: 'https://a', keywrd: x}]", "Unknown key"),
    ("daily_report: {time: '25:00'}\nsites: [{name: A, url: 'https://a'}]", "HH:MM"),
    ("alerts: {email: {enabled: true, security: tls}}\nsites: [{name: A, url: 'https://a'}]", "security"),
    ("daily_report: {channels: [me@gmail.com]}\nsites: [{name: A, url: 'https://a'}]", "not a channel|channel names"),
])
def test_config_errors(tmp_path, monkeypatch, bad, msg):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    (tmp_path / "c.yaml").write_text(textwrap.dedent(bad))
    with pytest.raises(ConfigError, match=msg):
        load_config(tmp_path / "c.yaml", env_file=str(tmp_path / "none.env"))


def _load(tmp_path, text):
    (tmp_path / "c.yaml").write_text(textwrap.dedent(text))
    return load_config(tmp_path / "c.yaml", env_file=str(tmp_path / "none.env"))


SECRETS = ("TELEGRAM_BOT_TOKEN", "SMTP_PASSWORD", "SMTP_USERNAME", "DASHBOARD_PASSWORD")


def test_minimal_config_is_one_site(tmp_path, monkeypatch):
    for name in SECRETS:
        monkeypatch.delenv(name, raising=False)
    cfg = _load(tmp_path, "sites: [{name: A, url: 'https://a.example.com'}]")
    assert cfg.vps is None and cfg.alerts.email is None and cfg.alerts.telegram is None
    assert cfg.dashboard.host == "127.0.0.1"          # no password -> local only, no login
    assert any("Dashboard has no DASHBOARD_PASSWORD" in w for w in cfg.warnings)


def test_enabled_features_missing_secrets_are_switched_off_not_fatal(tmp_path, monkeypatch):
    for name in SECRETS:
        monkeypatch.delenv(name, raising=False)
    cfg = _load(tmp_path, """
        vps:
          host: 1.2.3.4
          ssh: {user: mon, key_file: does-not-exist}
        alerts:
          email: {enabled: true, host: smtp.test, username: me@test, to: [a@test]}
          telegram: {enabled: true, chat_ids: [1]}
        sites: [{name: A, url: 'https://a.example.com'}]
    """)
    assert cfg.vps is not None and cfg.vps.ssh is None
    assert cfg.alerts.email is None and cfg.alerts.telegram is None
    joined = " | ".join(cfg.warnings)
    assert "SSH stats off: key file not found" in joined
    assert "Email alerts off: missing SMTP_PASSWORD" in joined
    assert "Telegram alerts off: missing TELEGRAM_BOT_TOKEN" in joined


def test_email_defaults_port_and_sender(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    cfg = _load(tmp_path, """
        alerts: {email: {enabled: true, host: smtp.test, security: starttls, username: me@test, to: a@test}}
        sites: [{name: A, url: 'https://a.example.com'}]
    """)
    email = cfg.alerts.email
    assert (email.port, email.from_addr, email.to) == (587, "me@test", ["a@test"])


def test_vps_only_and_disabled_vps(tmp_path):
    assert _load(tmp_path, "vps: {host: 1.2.3.4}").sites == []
    with pytest.raises(ConfigError, match="Nothing to monitor"):
        _load(tmp_path, "vps: {enabled: false, host: 1.2.3.4}")


def test_shipped_configs_load():
    root = Path(__file__).resolve().parent.parent
    for name in ("config.example.yaml", "config.test.yaml"):
        assert load_config(root / name, env_file=str(root / "no-such.env")).sites


def test_console_channel_delivers(caplog):
    notifier = Notifier(AlertsConfig(console=True))
    with caplog.at_level("WARNING"):
        assert notifier.dispatch([AlertEvent(kind="warning", key="A", ts=0, warning=Warn("slow", "Slow: 4000 ms"))])
    assert "Slow: 4000 ms" in caplog.text


class Recorder:
    def __init__(self):
        self.batches = []

    def dispatch(self, events):
        self.batches.append(events)
        return True


@pytest.fixture
def monitor(cfg, monkeypatch):
    state = {"a_down": False, "online": True}  # online=False simulates the MONITOR losing its network

    def fake_check_site(site, whois, ua):
        if site.name == "B":
            raise RuntimeError("boom")  # a crashing check must not break the cycle
        if state["a_down"] or not state["online"]:  # without internet every site would time out
            return ok_result(site="A", url=site.url, http_status=None, status_ok=None, response_ms=None,
                             error_kind="timeout", error_message="timed out")
        return ok_result(site="A", url=site.url)

    monkeypatch.setattr(runner_mod, "check_site", fake_check_site)
    monkeypatch.setattr(runner_mod, "check_internet", lambda hosts, timeout=4.0: (
        (True, {"1.1.1.1:443": "ok"}) if state["online"] else
        (False, {h: "[WinError 10051] Network is unreachable" for h in hosts})))
    monkeypatch.setattr(runner_mod, "check_vps_ports", lambda vps: reach(p22=True, p80=True, p443=True))
    stats = healthy_stats(services={"nginx": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    monkeypatch.setattr(runner_mod, "collect_stats", lambda host, ssh, security=None, backups=None: stats)
    monkeypatch.setattr(runner_mod, "fetch_error_logs",
                        lambda host, ssh, paths: {"/var/log/nginx/error.log": ["[emerg] bind() failed"]})
    cfg.security.blacklist_check = False  # no real DNS lookups in tests (covered in test_security.py)
    m = Monitor(cfg, Storage(cfg.general.database), notifier=Recorder())
    m.test_state = state
    return m


def test_full_cycle_diagnoses_alerts_and_recovers(monitor):
    c1 = monitor.run_cycle()
    by_site = {d.site: d for d in c1.diagnoses}
    assert by_site["A"].status == "up"
    assert by_site["B"].cause_code == "monitor_error"          # crashed check recorded, not raised
    assert any(w.code == "service_down:nginx" for w in c1.vps_warnings)

    monitor.test_state["a_down"] = True
    monitor.run_cycle()                                         # 1st failure of A: no alert for A yet
    c3 = monitor.run_cycle()                                    # 2nd failure: DOWN alert
    a = next(d for d in c3.diagnoses if d.site == "A")
    assert a.cause_code == "service_down:nginx"
    assert a.error_log[0].startswith("==> /var/log/nginx/error.log")
    assert ("down", "A") in {(e.kind, e.key) for e in c3.events}

    monitor.test_state["a_down"] = False
    c4 = monitor.run_cycle()
    assert ("recovered", "A") in {(e.kind, e.key) for e in c4.events}
    incidents = monitor.storage.incidents()
    assert {i["site_name"] for i in incidents} == {"A", "B"}
    assert next(i for i in incidents if i["site_name"] == "A")["ended_at"] is not None


def test_recovery_alert_resent_after_all_channels_failed(monitor):
    """Regression: a RECOVERED alert lost to an email/Telegram outage used to be gone for good."""
    class Flaky(Recorder):
        working = True

        def dispatch(self, events):
            self.batches.append(events)
            return self.working

    monitor.notifier = Flaky()
    monitor.test_state["a_down"] = True
    monitor.run_cycle()
    monitor.run_cycle()                                         # DOWN alert delivered
    monitor.test_state["a_down"] = False
    monitor.notifier.working = False                            # every channel fails at recovery time
    assert ("recovered", "A") in {(e.kind, e.key) for e in monitor.run_cycle().events}
    monitor.notifier.working = True
    assert ("recovered", "A") in {(e.kind, e.key) for e in monitor.run_cycle().events}  # retried
    assert ("recovered", "A") not in {(e.kind, e.key) for e in monitor.run_cycle().events}  # and only once


def test_monitor_internet_outage_creates_no_fake_incidents(monitor):
    """Regression: losing the MONITOR's network for 2+ cycles used to mark every site DOWN, open
    incidents, send RECOVERED for an outage that never happened, and count it against uptime."""
    pings = []
    monitor.heartbeat.ping = lambda ok=True, message="": pings.append(ok)
    monitor.run_cycle()                                           # normal, online
    checks_before = len(monitor.storage.response_history(0))
    pings.clear()

    monitor.test_state["online"] = False
    for _ in range(3):                                            # 3 cycles without internet
        c = monitor.run_cycle()
        assert c.offline and c.results == [] and c.events == []
    assert monitor.storage.incidents() == [i for i in monitor.storage.incidents() if i["site_name"] == "B"]
    assert len(monitor.storage.response_history(0)) == checks_before   # nothing counted against uptime
    assert pings == []                                            # no "alive" ping while blind
    assert monitor.storage.get_kv("connectivity")["offline"] is True

    monitor.test_state["online"] = True
    c = monitor.run_cycle()
    assert not c.offline
    assert ("recovered", "A") not in {(e.kind, e.key) for e in c.events}     # no fake RECOVERED
    assert all(i["site_name"] != "A" for i in monitor.storage.incidents())   # no fake incident for A
    conn = monitor.storage.get_kv("connectivity")
    assert conn["offline"] is False and len(conn["periods"]) == 1             # the gap is recorded
    assert pings == [True]


def test_real_outage_while_online_still_alerts(monitor):
    """The canary must not hide real outages: online + site down -> DOWN alert as before."""
    monitor.test_state["a_down"] = True
    monitor.run_cycle()
    assert ("down", "A") in {(e.kind, e.key) for e in monitor.run_cycle().events}


def test_dashboard_and_report_show_monitor_offline(cfg, monitor):
    from sitemonitor.report import build_daily_report
    monitor.run_cycle()
    monitor.test_state["online"] = False
    monitor.run_cycle()
    client = create_app(cfg, monitor.storage).test_client()
    auth = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret").decode()}
    data = client.get("/api/status", headers=auth).get_json()
    assert data["monitor"]["offline"] is True and data["monitor"]["offline_since"]
    _, body = build_daily_report(cfg, monitor.storage)
    assert "Monitor offline" in body and "STILL OFFLINE" in body


def test_dashboard_requires_auth_and_serves_status(cfg, monitor):
    monitor.run_cycle()
    app = create_app(cfg, monitor.storage, lambda: monitor.last_cycle.ts)
    client = app.test_client()
    assert client.get("/api/status").status_code == 401
    bad = base64.b64encode(b"admin:wrong").decode()
    assert client.get("/api/status", headers={"Authorization": f"Basic {bad}"}).status_code == 401
    good = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret").decode()}
    data = client.get("/api/status", headers=good).get_json()
    assert data["counts"] == {"up": 1, "warning": 0, "down": 1, "total": 2}
    assert data["sites"][0]["name"] == "B"                     # down sites first
    assert data["vps"]["services"]["nginx"]["active"] == "failed"
    assert client.get("/", headers=good).status_code == 200
    assert "A" in client.get("/api/history", headers=good).get_json()["sites"]
    assert client.get("/healthz").get_json()["ok"] is True


def test_dashboard_without_password_needs_no_login(cfg, monitor):
    cfg.dashboard.password = None
    client = create_app(cfg, monitor.storage).test_client()
    assert client.get("/api/status").status_code == 200

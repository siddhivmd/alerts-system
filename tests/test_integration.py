"""Config loading, a full runner cycle with mocked network, and the dashboard API."""
import base64
import textwrap

import pytest
from conftest import healthy_stats, ok_result, reach

from sitemonitor import runner as runner_mod
from sitemonitor.config import ConfigError, load_config
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
    return load_config(tmp_path / "config.yaml", env_file=str(tmp_path / "missing.env"))


def test_config_defaults_and_secrets(cfg, tmp_path):
    a, b = cfg.sites
    assert (a.timeout, b.timeout, a.slow_threshold_ms) == (7, 3, 2000)
    assert cfg.dashboard.password == "s3cret"
    assert cfg.vps.ssh.key_file == str(tmp_path / "key")
    assert cfg.general.database == str(tmp_path / "data" / "t.db")


@pytest.mark.parametrize("bad, msg", [
    ("sites: []", "No sites"),
    ("sites: [{name: A, url: ftp://x}]", "url must be"),
    ("sites: [{name: A, url: 'https://a'}, {name: A, url: 'https://b'}]", "Duplicate"),
    ("sites: [{name: A, url: 'https://a', keywrd: x}]", "Unknown key"),
    ("daily_report: {time: '25:00'}\nsites: [{name: A, url: 'https://a'}]", "HH:MM"),
    ("alerts: {telegram: {enabled: true, chat_ids: [1]}}\nsites: [{name: A, url: 'https://a'}]", "TELEGRAM_BOT_TOKEN"),
])
def test_config_errors(tmp_path, monkeypatch, bad, msg):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    (tmp_path / "c.yaml").write_text(textwrap.dedent(bad))
    with pytest.raises(ConfigError, match=msg):
        load_config(tmp_path / "c.yaml", env_file=str(tmp_path / "none.env"))


class Recorder:
    def __init__(self):
        self.batches = []

    def dispatch(self, events):
        self.batches.append(events)
        return True


@pytest.fixture
def monitor(cfg, monkeypatch):
    state = {"a_down": False}

    def fake_check_site(site, whois, ua):
        if site.name == "B":
            raise RuntimeError("boom")  # a crashing check must not break the cycle
        if state["a_down"]:
            return ok_result(site="A", url=site.url, http_status=None, status_ok=None, response_ms=None,
                             error_kind="timeout", error_message="timed out")
        return ok_result(site="A", url=site.url)

    monkeypatch.setattr(runner_mod, "check_site", fake_check_site)
    monkeypatch.setattr(runner_mod, "check_vps_ports", lambda vps: reach(p22=True, p80=True, p443=True))
    stats = healthy_stats(services={"nginx": {"active": "failed", "sub": "failed", "enabled": "enabled"}})
    monkeypatch.setattr(runner_mod, "collect_stats", lambda host, ssh: stats)
    monkeypatch.setattr(runner_mod, "fetch_error_logs",
                        lambda host, ssh, paths: {"/var/log/nginx/error.log": ["[emerg] bind() failed"]})
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

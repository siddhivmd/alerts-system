"""Dashboard login lockout, bad query parameters, parallel port checks, plain-HTTP warning."""
import base64
import textwrap
import threading

import pytest

from sitemonitor.checks import check_vps_ports
from sitemonitor.config import VpsConfig, load_config
from sitemonitor.dashboard import LoginGuard, create_app
from sitemonitor.storage import Storage


def basic(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "s3cret")
    (tmp_path / "c.yaml").write_text(textwrap.dedent("""
        general: {database: data/t.db, log_file: logs/t.log}
        dashboard: {username: admin, max_login_failures: 3, lockout_minutes: 15}
        sites: [{name: A, url: "https://a.test"}]
    """))
    return load_config(tmp_path / "c.yaml", env_file=str(tmp_path / "none.env"))


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


def test_lockout_after_repeated_wrong_passwords(cfg):
    clock = Clock()
    client = create_app(cfg, Storage(cfg.general.database), guard=LoginGuard(3, 15 * 60, clock)).test_client()
    assert client.get("/api/status").status_code == 401                      # no credentials: not a failure
    for _ in range(3):
        assert client.get("/api/status", headers=basic("admin", "guess")).status_code == 401
    locked = client.get("/api/status", headers=basic("admin", "s3cret"))     # even the RIGHT password
    assert locked.status_code == 429 and int(locked.headers["Retry-After"]) > 0
    clock.t += 15 * 60 + 1                                                   # lockout expires
    assert client.get("/api/status", headers=basic("admin", "s3cret")).status_code == 200


def test_success_resets_the_failure_count(cfg):
    clock = Clock()
    client = create_app(cfg, Storage(cfg.general.database), guard=LoginGuard(3, 900, clock)).test_client()
    for _ in range(2):
        client.get("/api/status", headers=basic("admin", "x"))
    assert client.get("/api/status", headers=basic("admin", "s3cret")).status_code == 200
    for _ in range(2):
        client.get("/api/status", headers=basic("admin", "x"))
    assert client.get("/api/status", headers=basic("admin", "s3cret")).status_code == 200  # 2+2, never 3 in a row


def test_lockout_is_per_ip_and_forged_forwarded_for_does_not_help(cfg):
    cfg.dashboard.trust_proxy = True
    guard = LoginGuard(3, 900, Clock())
    client = create_app(cfg, Storage(cfg.general.database), guard=guard).test_client()
    for i in range(3):  # attacker rotates a forged left-most entry; the proxy appends the real IP
        client.get("/api/status", headers={**basic("admin", "x"), "X-Forwarded-For": f"10.9.9.{i}, 203.0.113.7"})
    assert guard.retry_after("203.0.113.7") > 0
    assert client.get("/api/status", headers={**basic("admin", "s3cret"),
                                              "X-Forwarded-For": "198.51.100.1"}).status_code == 200


@pytest.mark.parametrize("url", ["/api/history?hours=abc", "/api/incidents?limit=x", "/api/reliability?days=1e9"])
def test_bad_numbers_are_400_not_500(cfg, url):
    client = create_app(cfg, Storage(cfg.general.database)).test_client()
    resp = client.get(url, headers=basic("admin", "s3cret"))
    assert resp.status_code == 400 and "whole number" in resp.get_json()["error"]


def test_out_of_range_numbers_are_clamped(cfg):
    client = create_app(cfg, Storage(cfg.general.database)).test_client()
    assert client.get("/api/history?hours=999999", headers=basic("admin", "s3cret")).status_code == 200


def test_port_checks_run_in_parallel():
    # All three connects must be waiting AT THE SAME TIME to pass the barrier. Run one after another,
    # the first would wait alone and time out. Deterministic: no wall-clock thresholds.
    barrier = threading.Barrier(3, timeout=5)

    def connect(addr, timeout):
        barrier.wait()
        raise TimeoutError("timed out")

    r = check_vps_ports(VpsConfig(host="192.0.2.1", ports=[22, 80, 443]), connect=connect)
    assert not barrier.broken
    assert list(r.ports) == [22, 80, 443] and not r.reachable  # configured order kept
    assert r.errors[443] == "timed out"


def test_plain_http_dashboard_warning(tmp_path, monkeypatch):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "pw")
    (tmp_path / "c.yaml").write_text("dashboard: {host: 0.0.0.0}\nsites: [{name: A, url: 'https://a'}]")
    cfg = load_config(tmp_path / "c.yaml", env_file=str(tmp_path / "none.env"))
    assert any("plain HTTP" in w for w in cfg.warnings)
    (tmp_path / "c.yaml").write_text("dashboard: {host: 0.0.0.0, trust_proxy: true}\n"
                                     "sites: [{name: A, url: 'https://a'}]")
    assert not any("plain HTTP" in w for w in load_config(tmp_path / "c.yaml", env_file="none").warnings)


def test_login_guard_is_thread_safe():
    guard = LoginGuard(1000, 900, Clock())
    threads = [threading.Thread(target=lambda: [guard.failed("1.1.1.1") for _ in range(100)]) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len(guard._failures["1.1.1.1"]) == 800

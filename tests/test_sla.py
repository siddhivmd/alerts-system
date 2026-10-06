"""Monthly SLA reports, reliability metrics (MTTA/MTTR/top causes), status pages and acknowledgement."""
import base64
import textwrap
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

import monitor as cli
from sitemonitor import sla, status_page
from sitemonitor.alerts import AlertManager
from sitemonitor.config import AlertsConfig, EscalationConfig, load_config
from sitemonitor.dashboard import create_app
from sitemonitor.diagnosis import DOWN, Diagnosis
from sitemonitor.storage import Storage

TZ = "Asia/Kolkata"
CONFIG = """
general: {timezone: Asia/Kolkata, database: data/t.db, log_file: logs/t.log}
alerts:
  email: {enabled: true, host: smtp.test, username: me@test.com, to: [owner@test.com]}
monthly_report: {reports_dir: data/reports}
status_page: {enabled: true}
dashboard: {username: admin}
clients:
  acme:
    name: Acme Ltd
    report_to: [boss@acme.test]
    sla_target: 99.9
    status_page: true
    status_domain: status.acme.test
  beta:
    name: Beta Co
sites:
  - {name: Shop, url: "https://shop.acme.test", client: acme, public_name: Online shop}
  - {name: Portal, url: "https://portal.acme.test", client: acme}
  - {name: Blog, url: "https://blog.beta.test", client: beta}
  - {name: Internal, url: "https://intranet.test"}
"""


def ts(day, hour=0, minute=0, month=9, year=2026):
    return datetime(year, month, day, hour, minute, tzinfo=ZoneInfo(TZ)).timestamp()


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "s3cret")
    (tmp_path / "config.yaml").write_text(CONFIG)
    return load_config(tmp_path / "config.yaml", env_file=str(tmp_path / "none.env"))


@pytest.fixture
def store(cfg):
    s = Storage(cfg.general.database)
    ids = s.sync_sites([(x.name, x.url) for x in cfg.sites])
    # September 2026: Shop has 1000 checks, 4 of them down -> 99.6% (target 99.9 missed)
    s.record_checks([(ids["Shop"], ts(1) + i * 2000, "down" if i < 4 else "up", 200, 300, None, "", {})
                     for i in range(1000)] +
                    [(ids["Portal"], ts(1) + i * 2000, "up", 200, 100, None, "",
                      {"ssl_days_left": 50, "domain_days_left": 200}) for i in range(1000)])
    # Shop incidents: php-fpm twice (one acknowledged after 10 min), one started in August
    a = s.open_incident(ids["Shop"], ts(3, 10), "service_down:php8.2-fpm", "Site down: Service php8.2-fpm is failed", {})
    s.acknowledge_incident(a, "Siddhi", ts(3, 10, 10))
    s.close_incident(a, ts(3, 10, 30))                                   # 30 min, acked after 10
    b = s.open_incident(ids["Shop"], ts(9, 22), "service_down:php8.2-fpm", "Site down: Service php8.2-fpm is failed", {})
    s.close_incident(b, ts(9, 22, 20))                                   # 20 min, never acked
    c = s.open_incident(ids["Shop"], ts(31, 23, month=8), "http_502", "HTTP 502 Bad Gateway", {})
    s.close_incident(c, ts(1, 1))                                        # 2h, but only 1h in September
    return s


# ---------------------------------------------------------------- periods
def test_month_helpers():
    start, end, label = sla.month_range(2026, 12, TZ)
    assert label == "December 2026" and end == datetime(2027, 1, 1, tzinfo=ZoneInfo(TZ)).timestamp()
    assert sla.parse_month("2026-09") == (2026, 9)
    assert sla.previous_month(ts(1, 9, month=1, year=2027), TZ) == (2026, 12)
    with pytest.raises(ValueError):
        sla.parse_month("2026-13")


# ---------------------------------------------------------------- numbers
def test_uptime_downtime_mttr_mtta_and_causes(cfg, store):
    start, end, _ = sla.month_range(2026, 9, TZ)
    stats = {s.name: s for s in sla.compute(cfg, store, start, end, now=end)}
    shop = stats["Shop"]
    assert shop.uptime_pct == 99.6 and shop.sla_met is False and shop.sla_target == 99.9
    assert len(shop.incidents) == 3
    assert shop.downtime_s == (30 + 20 + 60) * 60                  # August part of the 502 is clipped off
    assert shop.mttr_s == pytest.approx((30 + 20 + 120) * 60 / 3)  # time to fix uses the full incident
    assert shop.mtta_s == 10 * 60 and shop.unacknowledged == 2
    assert stats["Portal"].sla_met is True and stats["Portal"].ssl_days_left == 50
    assert stats["Internal"].uptime_pct is None and stats["Internal"].sla_met is None   # no data != failed

    rel = sla.reliability(list(stats.values()))
    top = rel["sites"]["Shop"]["top_causes"][0]
    assert (top["code"], top["count"]) == ("service_down:php8.2-fpm", 2)
    assert top["label"] == "Service php8.2-fpm is failed"          # "Site down: " prefix removed
    assert rel["overall"]["incidents"] == 3 and rel["overall"]["unacknowledged"] == 2
    assert set(rel["servers"]) == {"VPS"} or "External hosting" in rel["servers"]


# ---------------------------------------------------------------- reports
def test_reports_go_to_owner_as_preview_by_default(cfg, store):
    reports = {r.client_id: r for r in sla.build_reports(cfg, store, 2026, 9)}
    assert set(reports) == {"acme", "beta", "internal"}             # beta has a site but no checks: still reported
    acme = reports["acme"]
    assert acme.preview and acme.recipients == ["owner@test.com"]
    assert acme.subject.startswith("[PREVIEW for Acme Ltd]") and "target missed" in acme.subject
    assert "Online shop" in acme.html and "99.60%" in acme.html and "Blog" not in acme.html
    assert "Time to ack" not in acme.html                           # internal metric hidden from clients
    internal = reports["internal"]
    assert "Reliability (internal)" in internal.html and "not acked" in internal.html


def test_reports_to_clients_when_enabled(cfg, store):
    cfg.monthly_report.send_to_clients = True
    reports = {r.client_id: r for r in sla.build_reports(cfg, store, 2026, 9)}
    assert reports["acme"].recipients == ["boss@acme.test"] and not reports["acme"].preview
    assert reports["beta"].preview                                  # beta has no report_to -> still preview


def test_send_monthly_saves_html_and_emails(cfg, store):
    sent = []

    class FakeEmail:
        name = "email"

        def send_rich(self, subject, text, html, to):
            sent.append((subject, to, "<html" in html))

    class FakeNotifier:
        channels = [FakeEmail()]

        def send(self, *a, **k):
            return {}

    reports = sla.send_monthly(cfg, store, FakeNotifier(), 2026, 9)
    assert len(sent) == 3 and all(has_html for _, _, has_html in sent)
    path = next(r.path for r in reports if r.client_id == "acme")
    assert path.endswith("2026-09\\acme.html") or path.endswith("2026-09/acme.html")
    assert "Online shop" in open(path, encoding="utf-8").read()


# ---------------------------------------------------------------- status page
def test_status_page_data_and_privacy(cfg, store):
    page = status_page.build(cfg, store, "acme", now=ts(30, 12))
    assert [s["name"] for s in page["services"]] == ["Online shop", "Portal"]
    assert len(page["services"][0]["bars"]) == 30
    assert all("url" not in s and "cause" not in str(s) for s in page["services"])
    assert all(set(i) == {"service", "started_at", "ended_at", "duration_s", "status"} for i in page["incidents"])


def test_status_routes_public_and_scoped(cfg, store):
    client = create_app(cfg, store).test_client()
    resp = client.get("/status/acme")                               # no login needed
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200 and "Online shop" in html and "Blog" not in html
    assert "shop.acme.test" not in html and "php8.2-fpm" not in html   # no URLs, no causes
    assert client.get("/status/beta").status_code == 404            # beta did not opt in
    assert client.get("/status/nope").status_code == 404
    j = client.get("/status/acme.json")
    assert j.get_json()["services"][0]["name"] == "Online shop" and j.headers["Access-Control-Allow-Origin"] == "*"
    custom = client.get("/", headers={"Host": "status.acme.test"})   # status.client.com -> client page
    assert custom.status_code == 200 and "Online shop" in custom.get_data(as_text=True)
    assert client.get("/").status_code == 401                       # the dashboard itself still needs login
    cfg.status_page.enabled = False
    assert create_app(cfg, store).test_client().get("/status/acme").status_code == 404


# ---------------------------------------------------------------- acknowledgement
AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret").decode()}


def test_ack_api(cfg, store):
    ids = store.sync_sites([(s.name, s.url) for s in cfg.sites])
    iid = store.open_incident(ids["Portal"], ts(30, 12), "http_500", "HTTP 500", {})
    client = create_app(cfg, store).test_client()
    url = f"/api/incidents/{iid}/ack"
    assert client.post(url, headers=AUTH, json={"by": "Siddhi"}).status_code == 403   # CSRF header missing
    hdr = {**AUTH, "X-Requested-With": "SiteMonitor"}
    assert client.post(url, json={"by": "Siddhi"}, headers={"X-Requested-With": "SiteMonitor"}).status_code == 401
    assert client.post(url, headers=hdr, json={"by": "Siddhi"}).get_json() == {"ok": True}
    assert client.post(url, headers=hdr, json={"by": "X"}).status_code == 409
    assert store.get_incident(iid)["acknowledged_by"] == "Siddhi"
    rows = client.get("/api/incidents", headers=AUTH).get_json()["incidents"]
    assert next(r for r in rows if r["id"] == iid)["acknowledged_by"] == "Siddhi"
    rel = client.get("/api/reliability?days=60", headers=AUTH).get_json()
    assert "Shop" in rel["sites"] and rel["overall"]["incidents"] >= 1


def test_acknowledged_incident_stops_reminders_and_escalation(tmp_path):
    store = Storage(str(tmp_path / "a.db"))
    sid = store.sync_sites([("Shop", "https://shop.test")])["Shop"]
    mgr = AlertManager(store, AlertsConfig(consecutive_failures=1, throttle_minutes=30,
                                           escalation=EscalationConfig(after_minutes=40, email_to=["b@x"])))
    down = Diagnosis(site="Shop", url="u", status=DOWN, cause_code="http_502", cause="HTTP 502")
    t0 = 1_800_000_000.0

    def run(t, d=down):
        events = mgr.evaluate_site(sid, d, t)
        mgr.mark_sent(events)
        return [e.kind for e in events]
    assert run(t0) == ["down"]
    store.acknowledge_incident(store.get_state(sid).incident_id, "Siddhi", t0 + 60)
    assert run(t0 + 35 * 60) == []                                  # no STILL DOWN reminder
    assert run(t0 + 45 * 60) == []                                  # no escalation
    changed = Diagnosis(site="Shop", url="u", status=DOWN, cause_code="disk_full", cause="Disk full")
    assert run(t0 + 50 * 60, changed) == ["cause_changed"]          # new information still goes out


# ---------------------------------------------------------------- CLI
def test_cli_ack_pause_resume_and_monthly(cfg, store, tmp_path, capsys):
    ids = store.sync_sites([(s.name, s.url) for s in cfg.sites])
    store.open_incident(ids["Blog"], ts(30, 12), "http_500", "HTTP 500", {})
    conf = ["-c", str(tmp_path / "config.yaml"), "--env-file", str(tmp_path / "none.env")]
    assert cli.main(conf + ["ack", "Blog", "--by", "Siddhi"]) == 0
    assert cli.main(conf + ["ack", "Blog"]) == 1                    # already acknowledged
    assert cli.main(conf + ["pause", "2h", "--site", "Shop", "--reason", "upgrade"]) == 0
    assert "alerts paused for Shop" in capsys.readouterr().out
    assert cli.main(conf + ["resume"]) == 0
    assert cli.main(conf + ["pause", "99d"]) == 2
    assert cli.main(conf + ["report", "--month", "2026-09", "--client", "acme"]) == 0
    out = capsys.readouterr().out
    assert "[PREVIEW for Acme Ltd]" in out and "Not sent" in out
    assert cli.main(conf + ["report", "--month", "2026-09", "--client", "nope"]) == 2


def test_client_config_validation(tmp_path):
    from sitemonitor.config import ConfigError
    bad = {"clients: {Acme: {name: A}}\nsites: [{name: A, url: 'https://a'}]": "lowercase",
           "sites: [{name: A, url: 'https://a', client: ghost}]": "undefined client",
           "clients: {a: {sla_target: 120}}\nsites: [{name: A, url: 'https://a'}]": "sla_target"}
    for text, msg in bad.items():
        (tmp_path / "c.yaml").write_text(textwrap.dedent(text))
        with pytest.raises(ConfigError, match=msg):
            load_config(tmp_path / "c.yaml", env_file=str(tmp_path / "none.env"))

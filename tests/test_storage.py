import time

import pytest

from sitemonitor.storage import SiteState, Storage


@pytest.fixture
def store(tmp_path):
    return Storage(str(tmp_path / "t.db"))


def test_sync_sites_is_idempotent_and_updates_url(store):
    ids = store.sync_sites([("A", "https://a.test"), ("B", "https://b.test")])
    again = store.sync_sites([("A", "https://a2.test")])
    assert ids["A"] == again["A"]
    assert {r["name"]: r["url"] for r in store.latest_checks()}["A"] == "https://a2.test"


def test_incident_lifecycle(store):
    sid = store.sync_sites([("A", "https://a.test")])["A"]
    iid = store.open_incident(sid, 1000.0, "dns_failure", "DNS broken", {"x": 1})
    store.update_incident_cause(iid, "vps_unreachable", "VPS down")
    store.close_incident(iid, 1600.0)
    inc = store.get_incident(iid)
    assert inc["ended_at"] == 1600.0 and inc["cause_code"] == "vps_unreachable"
    assert inc["details"] == {"x": 1}
    # Closing twice must not move the end time.
    store.close_incident(iid, 9999.0)
    assert store.get_incident(iid)["ended_at"] == 1600.0


def test_state_roundtrip(store):
    sid = store.sync_sites([("A", "https://a.test")])["A"]
    assert store.get_state(sid) == SiteState(site_id=sid)
    st = SiteState(site_id=sid, consecutive_failures=3, first_failure_at=5.0, incident_id=7,
                   last_alert_at=6.0, last_alert_cause="http_5xx")
    store.save_state(st)
    assert store.get_state(sid) == st


def test_summary_and_purge(store):
    sid = store.sync_sites([("A", "https://a.test")])["A"]
    now = time.time()
    store.record_check(sid, now - 100 * 86400, "up", 200, 100, None, "old", {})
    store.record_check(sid, now - 60, "up", 200, 100, None, "ok", {})
    store.record_check(sid, now - 30, "down", None, None, "timeout", "bad", {})
    store.record_check(sid, now - 10, "warning", 200, 300, "slow", "slow", {})
    summary = store.site_summary(now - 86400)[sid]
    assert summary["total"] == 3
    assert summary["uptime_pct"] == pytest.approx(66.67)
    assert summary["avg_ms"] == 200
    assert store.purge(90) == {"checks": 1, "vps_stats": 0}
    assert store.latest_checks()[0]["status"] == "warning"


def test_warning_tracking(store):
    assert store.touch_warning("A", "slow", 1.0) == (1, None)
    assert store.touch_warning("A", "slow", 2.0) == (2, None)
    store.mark_warning_sent("A", "slow", 2.0)
    store.touch_warning("A", "ssl_expiring", 2.0)
    store.clear_warnings("A", {"slow"})
    assert store.touch_warning("A", "slow", 3.0) == (3, 2.0)
    assert store.touch_warning("A", "ssl_expiring", 3.0) == (1, None)  # was cleared, starts over

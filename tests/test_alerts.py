"""Alert decisions: consecutive-failure threshold, throttling, recovery, delivery retry."""
import pytest

from sitemonitor.alerts import AlertEvent, AlertManager, Formatter, Notifier, format_duration
from sitemonitor.config import AlertsConfig
from sitemonitor.diagnosis import DOWN, UP, WARNING, Diagnosis, Warn
from sitemonitor.storage import Storage

T0 = 1_800_000_000.0
MIN = 60


def down(cause="http_502", text="HTTP 502 Bad Gateway"):
    return Diagnosis(site="Shop", url="https://shop.test", status=DOWN, cause_code=cause, cause=text,
                     fixes=["sudo systemctl restart php8.2-fpm"])


def up():
    return Diagnosis(site="Shop", url="https://shop.test", status=UP)


@pytest.fixture
def store(tmp_path):
    return Storage(str(tmp_path / "a.db"))


@pytest.fixture
def mgr(store):
    return AlertManager(store, AlertsConfig(consecutive_failures=2, throttle_minutes=30, warning_repeat_hours=24))


@pytest.fixture
def sid(store):
    return store.sync_sites([("Shop", "https://shop.test")])["Shop"]


def run(mgr, sid, diag, ts, delivered=True):
    events = mgr.evaluate_site(sid, diag, ts)
    if delivered:
        mgr.mark_sent(events)
    return [e.kind for e in events]


def test_single_failure_does_not_alert(mgr, sid, store):
    assert run(mgr, sid, down(), T0) == []
    assert run(mgr, sid, up(), T0 + 5 * MIN) == []  # blip recovered: no alert, no incident
    assert store.incidents() == []


def test_second_consecutive_failure_alerts(mgr, sid, store):
    assert run(mgr, sid, down(), T0) == []
    assert run(mgr, sid, down(), T0 + 5 * MIN) == ["down"]
    inc = store.incidents()[0]
    assert inc["started_at"] == T0 and inc["ended_at"] is None  # starts at the FIRST failure


def test_same_alert_throttled_for_30_minutes(mgr, sid):
    run(mgr, sid, down(), T0)
    assert run(mgr, sid, down(), T0 + 5 * MIN) == ["down"]
    kinds = [run(mgr, sid, down(), T0 + m * MIN) for m in (10, 15, 20, 25, 30)]
    assert kinds == [[], [], [], [], []]
    assert run(mgr, sid, down(), T0 + 35 * MIN) == ["still_down"]  # 30 min after the last alert
    assert run(mgr, sid, down(), T0 + 40 * MIN) == []


def test_throttle_window_is_configurable(store, sid):
    mgr = AlertManager(store, AlertsConfig(consecutive_failures=1, throttle_minutes=10))
    assert run(mgr, sid, down(), T0) == ["down"]
    assert run(mgr, sid, down(), T0 + 5 * MIN) == []
    assert run(mgr, sid, down(), T0 + 10 * MIN) == ["still_down"]


def test_cause_change_alerts_immediately(mgr, sid, store):
    run(mgr, sid, down(), T0)
    run(mgr, sid, down(), T0 + 5 * MIN)
    assert run(mgr, sid, down("disk_full", "Disk 99% full"), T0 + 10 * MIN) == ["cause_changed"]
    assert store.incidents()[0]["cause_code"] == "disk_full"


def test_recovery_alert_with_downtime(mgr, sid, store):
    run(mgr, sid, down(), T0)
    run(mgr, sid, down(), T0 + 5 * MIN)
    events = mgr.evaluate_site(sid, up(), T0 + 25 * MIN)
    assert [e.kind for e in events] == ["recovered"]
    assert events[0].duration == 25 * MIN
    assert events[0].cause == "HTTP 502 Bad Gateway"
    assert store.incidents()[0]["ended_at"] == T0 + 25 * MIN
    # A new outage afterwards needs 2 failures again and opens a new incident.
    assert run(mgr, sid, down(), T0 + 30 * MIN) == []
    assert run(mgr, sid, down(), T0 + 35 * MIN) == ["down"]
    assert len(store.incidents()) == 2


def test_failed_delivery_is_retried_next_cycle(mgr, sid):
    run(mgr, sid, down(), T0)
    assert run(mgr, sid, down(), T0 + 5 * MIN, delivered=False) == ["down"]
    assert run(mgr, sid, down(), T0 + 10 * MIN) == ["down"]  # retried, not throttled
    assert run(mgr, sid, down(), T0 + 15 * MIN) == []


def test_state_survives_restart(store, sid):
    cfg = AlertsConfig(consecutive_failures=2, throttle_minutes=30)
    run(AlertManager(store, cfg), sid, down(), T0)
    assert run(AlertManager(store, cfg), sid, down(), T0 + 5 * MIN) == ["down"]
    assert run(AlertManager(store, cfg), sid, down(), T0 + 10 * MIN) == []


def test_warnings_need_two_sightings_and_repeat_daily(mgr):
    w = [Warn("ssl_expiring", "SSL expires in 10 days")]
    kinds = lambda ts: [e.kind for e in _sent(mgr, mgr.evaluate_warnings("Shop", w, ts))]  # noqa: E731
    assert kinds(T0) == []
    assert kinds(T0 + 5 * MIN) == ["warning"]
    assert kinds(T0 + 60 * MIN) == []
    assert kinds(T0 + 24 * 3600 + 5 * MIN) == ["warning"]


def test_cleared_warning_starts_over(mgr):
    w = [Warn("slow", "Slow")]
    mgr.evaluate_warnings("Shop", w, T0)
    mgr.evaluate_warnings("Shop", [], T0 + 5 * MIN)  # went away
    assert mgr.evaluate_warnings("Shop", w, T0 + 10 * MIN) == []


def _sent(mgr, events):
    mgr.mark_sent(events)
    return events


# ---- delivery
class FakeChannel:
    def __init__(self, name, fail=False):
        self.name, self.fail, self.sent = name, fail, []

    def send(self, subject, text):
        if self.fail:
            raise RuntimeError("smtp down")
        self.sent.append((subject, text))


def test_batched_dispatch_and_partial_failure(mgr, sid):
    run(mgr, sid, down(), T0)
    events = mgr.evaluate_site(sid, down(), T0 + 5 * MIN)
    email, tg = FakeChannel("email", fail=True), FakeChannel("telegram")
    notifier = Notifier(AlertsConfig(), channels=[email, tg])
    assert notifier.dispatch(events) is True  # one channel succeeded
    subject, text = tg.sent[0]
    assert subject.startswith("[ALERT] DOWN: Shop")
    assert "HTTP 502" in text and "restart php8.2-fpm" in text


def test_dispatch_all_channels_fail():
    notifier = Notifier(AlertsConfig(), channels=[FakeChannel("email", fail=True)])
    assert notifier.dispatch([AlertEvent(kind="warning", key="VPS", ts=T0, warning=Warn("x", "y"))]) is False


def test_recovery_message_mentions_downtime():
    ev = AlertEvent(kind="recovered", key="Shop", ts=T0 + 3900, url="https://shop.test",
                    diagnosis=Diagnosis(site="Shop", url="https://shop.test", status=WARNING),
                    started_at=T0, duration=3900, cause="HTTP 502")
    text = Formatter("UTC").event(ev)
    assert "RECOVERED" in text and "1h 5m" in text and "HTTP 502" in text


def test_format_duration():
    assert [format_duration(s) for s in (5, 125, 3700, 90000)] == ["5s", "2m", "1h 1m", "1d 1h"]

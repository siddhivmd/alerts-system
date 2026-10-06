from sitemonitor.config import HeartbeatConfig
from sitemonitor.heartbeat import Heartbeat

URL = "https://hc-ping.com/1234-secret-uuid"


class Resp:
    def __init__(self, status=200):
        self.status_code = status


def recorder(status=200, raise_exc=None):
    calls = []

    def post(url, data, timeout):
        calls.append((url, data))
        if raise_exc:
            raise raise_exc
        return Resp(status)
    post.calls = calls
    return post


def test_success_and_failure_urls():
    post = recorder()
    hb = Heartbeat(HeartbeatConfig(enabled=True, url=URL), post)
    assert hb.ping(True, "2 up, 0 down") is True
    assert hb.ping(False, "crashed") is True
    assert post.calls == [(URL, b"2 up, 0 down"), (URL + "/fail", b"crashed")]


def test_disabled_sends_nothing():
    post = recorder()
    assert Heartbeat(HeartbeatConfig(enabled=False, url=URL), post).ping() is False
    assert Heartbeat(HeartbeatConfig(enabled=True, url=None), post).ping() is False
    assert post.calls == []


def test_no_fail_suffix_pings_normal_url():
    post = recorder()
    Heartbeat(HeartbeatConfig(enabled=True, url=URL, fail_suffix=""), post).ping(False)
    assert post.calls[0][0] == URL


def test_errors_never_raise_or_leak_the_url():
    hb = Heartbeat(HeartbeatConfig(enabled=True, url=URL), recorder(raise_exc=OSError(f"cannot reach {URL}")))
    assert hb.ping() is False and "secret" not in hb.last_error
    hb = Heartbeat(HeartbeatConfig(enabled=True, url=URL), recorder(status=404))
    assert hb.ping() is False and "404" in hb.last_error

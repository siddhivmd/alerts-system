"""WhatsApp, escalation, maintenance mode, defacement detection and backup checks. All offline."""
import pytest
from conftest import healthy_stats

from sitemonitor import content, maintenance
from sitemonitor.alerts import (AlertManager, Formatter, WhatsAppChannel, escalation_notifier,
                                flatten_for_template, whatsapp_text)
from sitemonitor.backups import backup_summary, backup_warnings
from sitemonitor.config import (AlertsConfig, BackupsConfig, EmailConfig, EscalationConfig, SiteConfig,
                                WhatsAppConfig)
from sitemonitor.diagnosis import DOWN, UP, Diagnosis
from sitemonitor.pagetext import change_percent, defacement_match, page_words
from sitemonitor.ssh_stats import parse_stats
from sitemonitor.storage import Storage

T0 = 1_800_000_000.0
MIN = 60


@pytest.fixture
def store(tmp_path):
    return Storage(str(tmp_path / "f.db"))


# ---------------------------------------------------------------- WhatsApp
class Resp:
    def __init__(self, status=201, payload=None):
        self.status_code, self._payload, self.text = status, payload or {}, str(payload)

    def json(self):
        return self._payload


def recorder(status=201, payload=None):
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return Resp(status, payload)
    post.calls = calls
    return post


def test_twilio_sends_to_each_number():
    post = recorder()
    cfg = WhatsAppConfig(provider="twilio", to=["+919800000001", "+919800000002"], from_number="+14155238886",
                         account_sid="AC123", auth_token="TOKEN")
    WhatsAppChannel(cfg, post).send("[ALERT] DOWN: Shop", "Cause: HTTP 502")
    assert len(post.calls) == 2
    url, kw = post.calls[0]
    assert url.endswith("/Accounts/AC123/Messages.json")
    assert kw["data"]["From"] == "whatsapp:+14155238886" and kw["data"]["To"] == "whatsapp:+919800000001"
    assert "HTTP 502" in kw["data"]["Body"] and kw["auth"] == ("AC123", "TOKEN")


def test_meta_template_flattens_text_and_strips_plus():
    post = recorder(200, {"messages": [{"id": "x"}]})
    cfg = WhatsAppConfig(provider="meta", to=["+919800000001"], phone_number_id="555", template="site_alert",
                         access_token="SECRET")
    WhatsAppChannel(cfg, post).send("[ALERT] DOWN: Shop", "Cause: HTTP 502\n\nFix:    restart")
    url, kw = post.calls[0]
    assert url.endswith("/555/messages") and kw["json"]["to"] == "919800000001"
    param = kw["json"]["template"]["components"][0]["parameters"][0]["text"]
    assert "\n" not in param and "    " not in param and "HTTP 502" in param
    assert kw["headers"]["Authorization"] == "Bearer SECRET"


def test_whatsapp_errors_are_reported_without_secrets():
    post = recorder(401, {"error": {"message": "Invalid OAuth token SECRET"}})
    cfg = WhatsAppConfig(provider="meta", to=["+919800000001"], phone_number_id="555", access_token="SECRET")
    with pytest.raises(RuntimeError) as err:
        WhatsAppChannel(cfg, post).send("s", "t")
    assert "401" in str(err.value) and "SECRET" not in str(err.value)


def test_whatsapp_length_limits():
    assert len(whatsapp_text("S", "x" * 5000)) <= 1500
    assert len(flatten_for_template("line\n" * 1000)) <= 1000


# ---------------------------------------------------------------- escalation
def diag(status=DOWN):
    return Diagnosis(site="Shop", url="https://shop.test", status=status, cause_code="http_502" if status == DOWN
                     else None, cause="HTTP 502 Bad Gateway" if status == DOWN else "")


def run(mgr, sid, d, ts):
    events = mgr.evaluate_site(sid, d, ts)
    mgr.mark_sent(events)
    return [e.kind for e in events]


def test_escalation_once_after_threshold_and_recovery_flag(store):
    sid = store.sync_sites([("Shop", "https://shop.test")])["Shop"]
    mgr = AlertManager(store, AlertsConfig(escalation=EscalationConfig(after_minutes=30, email_to=["boss@x"])))
    assert run(mgr, sid, diag(), T0) == []
    assert run(mgr, sid, diag(), T0 + 5 * MIN) == ["down"]
    assert "escalation" not in run(mgr, sid, diag(), T0 + 25 * MIN)
    assert run(mgr, sid, diag(), T0 + 30 * MIN) == ["escalation"]   # 30 min after the first failure
    assert run(mgr, sid, diag(), T0 + 35 * MIN) == ["still_down"]   # normal 30-min repeat still works
    assert "escalation" not in run(mgr, sid, diag(), T0 + 65 * MIN)   # only once per incident
    [rec] = mgr.evaluate_site(sid, diag(UP), T0 + 70 * MIN)
    assert rec.kind == "recovered" and rec.escalated is True
    assert store.get_state(sid).escalated_at is None                     # reset for the next incident


def test_escalation_retried_if_not_delivered(store):
    sid = store.sync_sites([("Shop", "https://shop.test")])["Shop"]
    mgr = AlertManager(store, AlertsConfig(consecutive_failures=1, escalation=EscalationConfig(after_minutes=10)))
    mgr.evaluate_site(sid, diag(), T0)
    assert "escalation" in [e.kind for e in mgr.evaluate_site(sid, diag(), T0 + 10 * MIN)]  # not marked sent
    assert "escalation" in [e.kind for e in mgr.evaluate_site(sid, diag(), T0 + 15 * MIN)]


def test_escalation_notifier_uses_escalation_recipients():
    cfg = AlertsConfig(email=EmailConfig(host="smtp.test", to=["team@x"], from_addr="m@x"),
                       escalation=EscalationConfig(email_to=["boss@x"], whatsapp_to=["+919800000009"]))
    n = escalation_notifier(cfg)
    [email] = n.channels                       # WhatsApp not configured -> skipped with a warning
    assert email.cfg.to == ["boss@x"] and cfg.email.to == ["team@x"]  # original config untouched


def test_escalation_subject_and_text():
    from sitemonitor.alerts import AlertEvent
    ev = AlertEvent(kind="escalation", key="Shop", ts=T0 + 2400, url="https://shop.test", diagnosis=diag(),
                    started_at=T0, duration=2400)
    f = Formatter("UTC")
    assert f.subject([ev]) == "[ESCALATION] Still down after 40m: Shop"
    assert "ESCALATED" in f.event(ev) and "HTTP 502" in f.event(ev)


# ---------------------------------------------------------------- maintenance
def test_parse_duration():
    assert [maintenance.parse_duration(x) for x in ("30m", "2h", "1d", "45", " 1.5h ")] == [30, 120, 1440, 45, 90]
    for bad in ("", "abc", "0m", "8d"):
        with pytest.raises(ValueError):
            maintenance.parse_duration(bad)


def test_maintenance_window_lifecycle(store):
    maintenance.start(store, 30, ["Shop"], "deploy", now=T0)
    w = maintenance.active(store, now=T0 + 10 * MIN)
    assert w["reason"] == "deploy" and maintenance.mutes(w, "Shop") and not maintenance.mutes(w, "Blog")
    assert not maintenance.mutes(w, None)                  # server warnings not muted by a per-site window
    assert maintenance.active(store, now=T0 + 31 * MIN) is None   # expires on its own
    maintenance.start(store, 30, [], now=T0)
    assert maintenance.mutes(maintenance.active(store, now=T0), None)  # all-sites window mutes everything
    assert maintenance.end(store) is True and maintenance.active(store) is None


# ---------------------------------------------------------------- defacement
PAGE = "<html><head><style>.x{}</style><script>var a=1</script></head><body>" + \
       " ".join(f"word{i} lorem ipsum dolor amet consectetur" for i in range(5)) + \
       " " + " ".join(f"alpha{chr(97 + i)}beta" for i in range(25)) + "</body></html>"


def test_page_words_ignores_scripts_and_markup():
    words = page_words(PAGE)
    assert "lorem" in words and "var" not in words and "html" not in words
    assert defacement_match("<p>Hacked by Evil Team</p>") == "Hacked by"
    assert defacement_match(PAGE) is None
    assert change_percent({"a", "b"}, {"a", "b"}) == 0 and change_percent({"a"}, {"b"}) == 100


def test_content_baseline_drift_and_defacement(store):
    site = SiteConfig(name="Shop", url="https://shop.test", content_change_alert=70)
    base = page_words(PAGE)
    assert content.check_content(store, site, base, None, now=T0) == []        # first sight: baseline saved
    small = base[:-2] + ["newword", "otherword"]
    assert content.check_content(store, site, small, None, now=T0 + 60) == []   # small edit: baseline follows
    assert set(store.get_kv("content:Shop")["words"]) == set(small)
    defaced = [f"hackerword{chr(97 + i)}" for i in range(26)]
    [w] = content.check_content(store, site, defaced, None, now=T0 + 120)
    assert w.code == "content_changed" and w.severity == "critical" and "accept-content" in w.fix
    assert set(store.get_kv("content:Shop")["words"]) == set(small)            # baseline kept as evidence
    content.accept(store, "Shop")
    assert content.check_content(store, site, defaced, None, now=T0 + 180) == []  # accepted: new baseline


def test_defacement_text_always_flagged_and_feature_can_be_off(store):
    off = SiteConfig(name="Blog", url="https://blog.test", content_change_alert=0)
    [w] = content.check_content(store, off, page_words(PAGE), "hacked by")
    assert w.code == "defacement_text" and store.get_kv("content:Blog") is None


def test_dry_run_does_not_save_baseline(store):
    site = SiteConfig(name="Shop", url="https://shop.test")
    content.check_content(store, site, page_words(PAGE), None, save=False)
    assert store.get_kv("content:Shop") is None


# ---------------------------------------------------------------- backups
DAY = 86400


def test_parse_backup_section():
    st = parse_stats("##BACKUPS\n@@ /var/backups/db-*.gz\n1790000000 52428800 /var/backups/db-1.gz\n"
                     "1790086400 60000000 /var/backups/db-2.gz\n@@ /srv/files-*.tar\n##END\n", [])
    assert [f["path"] for f in st.backups["/var/backups/db-*.gz"]] == ["/var/backups/db-1.gz", "/var/backups/db-2.gz"]
    assert st.backups["/srv/files-*.tar"] == []


def test_backup_warnings():
    now = 1_790_100_000.0
    cfg = BackupsConfig(enabled=True, paths=["/b/db-*", "/b/files-*", "/b/none-*"], max_age_hours=26, min_size_mb=1)
    stats = healthy_stats(backups={
        "/b/db-*": [{"mtime": now - 3600, "size": 50 * 1024 * 1024, "path": "/b/db-today"}],     # fine
        "/b/files-*": [{"mtime": now - 3 * DAY, "size": 1000, "path": "/b/files-old"}],           # old + tiny
        "/b/none-*": [],                                                                           # missing
    })
    codes = [w.code for w in backup_warnings(stats, cfg, now)]
    assert codes == ["backup_old:/b/files-*", "backup_small:/b/files-*", "backup_missing:/b/none-*"]
    summary = backup_summary(stats, cfg, now)
    assert summary[0].startswith("/b/db-*: newest db-today, 1.0 h old, 50.0 MB") and "none found" in summary[2]
    assert backup_warnings(stats, BackupsConfig(enabled=False, paths=["/b/x"]), now) == []

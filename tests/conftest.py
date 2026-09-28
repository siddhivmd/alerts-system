import pytest

from sitemonitor.checks import SiteCheckResult, VpsReachability
from sitemonitor.config import Thresholds
from sitemonitor.ssh_stats import VpsStats


@pytest.fixture
def thresholds() -> Thresholds:
    return Thresholds()


def ok_result(**overrides) -> SiteCheckResult:
    """A healthy site result; tests override the fields they care about."""
    base = dict(site="Shop", url="https://shop.example.com", dns_ok=True, ip_addresses=["1.2.3.4"],
                http_status=200, status_ok=True, response_ms=250, slow_threshold_ms=3000,
                ssl_checked=True, ssl_days_left=60, domain="example.com", domain_days_left=200)
    base.update(overrides)
    return SiteCheckResult(**base)


def reach(**ports: bool) -> VpsReachability:
    """reach(p22=True, p80=False, p443=False)"""
    return VpsReachability(host="1.2.3.4", ports={int(k[1:]): v for k, v in ports.items()})


def healthy_stats(**overrides) -> VpsStats:
    base = dict(ok=True, ram_percent=40.0, cpu_load=0.5, cpu_cores=2, disk_percent=50.0, oom_kills=0,
                services={"nginx": {"active": "active", "sub": "running", "enabled": "enabled"},
                          "mysql": {"active": "active", "sub": "running", "enabled": "enabled"}})
    base.update(overrides)
    return VpsStats(**base)

"""Watchdog heartbeat: tell an external service "the monitor is alive" after every cycle.

The monitor cannot alert anyone about its own death. So after every scheduled
check cycle it pings a URL at a free service such as healthchecks.io or
Better Stack. If the pings stop (server down, process crashed, network gone),
*that* service emails/texts you. A cycle that crashes pings ``<url>/fail`` so
you hear about it immediately instead of after the grace period.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import requests

from .config import HeartbeatConfig

log = logging.getLogger(__name__)


class Heartbeat:
    def __init__(self, cfg: HeartbeatConfig, post: Callable[..., Any] = requests.post) -> None:
        self.cfg = cfg
        self._post = post
        self.last_error: str | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.enabled and self.cfg.url)

    def ping(self, ok: bool = True, message: str = "") -> bool:
        """Send one ping. Returns True if the service accepted it. Never raises."""
        if not self.enabled:
            return False
        url = self.cfg.url if ok or not self.cfg.fail_suffix else self.cfg.url.rstrip("/") + self.cfg.fail_suffix
        try:
            resp = self._post(url, data=message.encode("utf-8")[:10_000], timeout=self.cfg.timeout)
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}")
            self.last_error = None
            log.debug("Heartbeat sent (%s)", "ok" if ok else "fail")
            return True
        except Exception as exc:  # noqa: BLE001
            # The ping URL is a secret (anyone with it can fake "alive"): never log it.
            self.last_error = f"{type(exc).__name__}: {str(exc).replace(self.cfg.url or '', '<heartbeat url>')}"
            log.warning("Heartbeat ping failed: %s", self.last_error)
            return False

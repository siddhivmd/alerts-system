"""Maintenance mode: pause alerts while you work on a site or the server on purpose.

Checks keep running and are recorded (so the dashboard and history stay
accurate); only notifications are muted. The pause is stored in the database,
so it survives restarts, and it ends by itself at ``until``.
"""
from __future__ import annotations

import re
import time
from typing import Any

from .storage import Storage

KEY = "maintenance"
_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([mhd]?)\s*$", re.I)
MAX_MINUTES = 7 * 24 * 60


def parse_duration(text: str) -> float:
    """'30m' / '2h' / '1d' / '45' (minutes) -> minutes."""
    m = _DURATION_RE.match(str(text))
    if not m:
        raise ValueError(f"Invalid duration {text!r}: use e.g. 30m, 2h or 1d")
    value, unit = float(m.group(1)), (m.group(2) or "m").lower()
    minutes = value * {"m": 1, "h": 60, "d": 1440}[unit]
    if not 1 <= minutes <= MAX_MINUTES:
        raise ValueError("Duration must be between 1 minute and 7 days")
    return minutes


def start(storage: Storage, minutes: float, sites: list[str] | None = None, reason: str = "",
          source: str = "cli", now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    record = {"started_at": now, "until": now + minutes * 60, "sites": sorted(set(sites or [])),
              "reason": reason.strip()[:200], "source": source}
    storage.set_kv(KEY, record)
    return record


def end(storage: Storage) -> bool:
    """Resume alerts. Returns True if a maintenance window was active."""
    was_active = active(storage) is not None
    storage.delete_kv(KEY)
    return was_active


def active(storage: Storage, now: float | None = None) -> dict[str, Any] | None:
    """The current maintenance window, or None (an expired window counts as none)."""
    record = storage.get_kv(KEY)
    now = time.time() if now is None else now
    if not record or record.get("until", 0) <= now:
        return None
    return record


def mutes(record: dict[str, Any] | None, site: str | None) -> bool:
    """Does this window mute alerts for ``site``? (site=None means server-level warnings.)"""
    if record is None:
        return False
    sites = record.get("sites") or []
    return not sites or (site is not None and site in sites)

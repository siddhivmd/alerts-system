"""Disk trend prediction: warn "disk full in about 4 days" long before a fixed threshold trips.

A least-squares line through the last 7 days of disk-usage samples gives a
growth rate (% per day). If usage keeps growing at that rate and would reach
100% within ``disk_full_warn_days``, raise a warning. Guards against noise:
at least 24 h of history, at least 12 samples, and a meaningful growth rate.
"""
from __future__ import annotations

from typing import Any

from .alerts import format_duration
from .diagnosis import Warn
from .ssh_stats import VpsStats

WINDOW_DAYS = 7
MIN_SPAN_HOURS = 24
MIN_SAMPLES = 12
MIN_RATE_PER_DAY = 0.2  # % per day; slower growth is not worth a warning


def linear_fit(points: list[tuple[float, float]]) -> tuple[float, float] | None:
    """Least squares y = a + b*x. Returns (a, b) or None if x has no spread."""
    n = len(points)
    if n < 2:
        return None
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    sxx = sum((x - mx) ** 2 for x, _ in points)
    if sxx == 0:
        return None
    b = sum((x - mx) * (y - my) for x, y in points) / sxx
    return my - b * mx, b


def forecast_full(points: list[tuple[float, float]], now: float) -> dict[str, Any] | None:
    """{'rate_per_day', 'seconds_to_full', 'current'} if usage is growing, else None."""
    if len(points) < MIN_SAMPLES or (points[-1][0] - points[0][0]) < MIN_SPAN_HOURS * 3600:
        return None
    fit = linear_fit(points)
    if fit is None:
        return None
    a, b = fit
    rate_per_day = b * 86400
    if rate_per_day < MIN_RATE_PER_DAY:
        return None
    current = points[-1][1]
    return {"rate_per_day": rate_per_day, "seconds_to_full": max(0.0, (100 - current) / b), "current": current}


def disk_forecast_warning(storage: Any, server: str, stats: VpsStats | None, now: float,
                          warn_days: float) -> Warn | None:
    if warn_days <= 0 or stats is None or not stats.ok or stats.disk_percent is None:
        return None
    history = storage.vps_history(now - WINDOW_DAYS * 86400, server)
    points = [(r["ts"], r["disk_percent"]) for r in history if r.get("disk_percent") is not None]
    points.append((now, stats.disk_percent))  # this cycle is saved only after the warnings are computed
    fc = forecast_full(points, now)
    if fc is None or fc["seconds_to_full"] > warn_days * 86400:
        return None
    eta = format_duration(fc["seconds_to_full"])
    return Warn("disk_forecast", f"Disk {fc['current']:.0f}% full and growing ~{fc['rate_per_day']:.1f}%/day: "
                f"full in about {eta} at this rate", "critical" if fc["seconds_to_full"] < 2 * 86400 else "warning",
                "Find what is growing: sudo du -xh / --max-depth=3 | sort -rh | head -20 (logs, backups, cache, "
                "sessions); add log rotation or a cleanup job, or grow the disk")

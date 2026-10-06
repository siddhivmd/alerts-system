"""Backup check: make sure backups on the VPS are still being made.

Most people discover that backups stopped only on the day they need one. Over
SSH we list the files matching each ``backups.paths`` pattern and look at the
newest one: missing -> critical, older than ``max_age_hours`` -> critical,
smaller than ``min_size_mb`` -> warning (an empty or failed dump).
"""
from __future__ import annotations

import time
from typing import Any

from .config import BackupsConfig
from .diagnosis import Warn
from .ssh_stats import VpsStats


def _size(n_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n_bytes < 1024 or unit == "GB":
            return f"{n_bytes:.0f} {unit}" if unit == "B" else f"{n_bytes:.1f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.1f} GB"


def _age(hours: float) -> str:
    return f"{hours:.1f} h" if hours < 48 else f"{hours / 24:.1f} days"


def newest(stats: VpsStats, pattern: str) -> dict[str, Any] | None:
    files = stats.backups.get(pattern) or []
    return max(files, key=lambda f: f["mtime"]) if files else None


def backup_warnings(stats: VpsStats | None, cfg: BackupsConfig, now: float | None = None) -> list[Warn]:
    if not cfg.enabled or stats is None or not stats.ok:
        return []
    now = time.time() if now is None else now
    out = []
    for pattern in cfg.paths:
        latest = newest(stats, pattern)
        if latest is None:
            out.append(Warn(f"backup_missing:{pattern}", f"No backup files found matching {pattern}", "critical",
                            "Check the backup job (crontab -l, or your backup plugin) and that it writes to this path"))
            continue
        age_h = (now - latest["mtime"]) / 3600
        if age_h > cfg.max_age_hours:
            out.append(Warn(f"backup_old:{pattern}", f"Newest backup is {_age(age_h)} old: {latest['path']}",
                            "critical", "The backup job has stopped: check its schedule, disk space and logs"))
        if latest["size"] < cfg.min_size_mb * 1024 * 1024:
            out.append(Warn(f"backup_small:{pattern}", f"Newest backup is only {_size(latest['size'])}: "
                            f"{latest['path']} - it may be empty or failed", "warning",
                            "Open the backup and check it contains data; check the backup job's error output"))
    return out


def backup_summary(stats: VpsStats | None, cfg: BackupsConfig, now: float | None = None) -> list[str]:
    """One human-readable line per pattern, for the dashboard/report."""
    if not cfg.enabled:
        return []
    if stats is None or not stats.ok:
        return ["unavailable (no SSH data)"]
    now = time.time() if now is None else now
    lines = []
    for pattern in cfg.paths:
        latest = newest(stats, pattern)
        if latest is None:
            lines.append(f"{pattern}: none found")
        else:
            lines.append(f"{pattern}: newest {latest['path'].rsplit('/', 1)[-1]}, "
                         f"{_age((now - latest['mtime']) / 3600)} old, {_size(latest['size'])}")
    return lines

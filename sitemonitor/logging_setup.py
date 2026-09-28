"""Logging to console plus a size-rotated log file."""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s [%(threadName)s] %(message)s"


def setup_logging(log_file: str | None, level: str = "INFO", max_bytes: int = 5 * 1024 * 1024,
                  backups: int = 5) -> None:
    """Configure the root logger. Safe to call more than once."""
    root = logging.getLogger()
    root.setLevel(level.upper())
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = logging.Formatter(_FORMAT)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    # Third-party libraries are noisy at INFO.
    for noisy in ("paramiko", "urllib3", "apscheduler", "waitress", "whois"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

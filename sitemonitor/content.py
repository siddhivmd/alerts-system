"""Defacement detection: notice when a page's text suddenly changes (hacked/defaced page).

The keyword check only catches pages that lose one word. Defacement usually
replaces the whole page. So we keep a baseline of each page's words:

* On a healthy check, compare the page's words with the baseline (Jaccard
  similarity of the word sets).
* If >= ``content_change_alert`` % of the words changed at once -> warning, and
  the old baseline is kept (so the warning persists until you accept it).
* Small changes (<= half the threshold) quietly move the baseline forward, so
  normal gradual edits never add up to a false alarm.
* Classic defacement phrases ("hacked by ...") are always a critical warning.

Accept an intentional redesign with:  python monitor.py accept-content --site NAME
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from .config import SiteConfig
from .diagnosis import Warn
from .pagetext import change_percent
from .storage import Storage

KEY_PREFIX = "content:"


def key(site: str) -> str:
    return KEY_PREFIX + site


def check_content(storage: Storage, site: SiteConfig, words: list[str] | None, deface: str | None,
                  save: bool = True, now: float | None = None) -> list[Warn]:
    """Warnings for one healthy page load. ``save=False`` compares without touching the baseline."""
    out: list[Warn] = []
    if deface:
        out.append(Warn("defacement_text", f"Page contains defacement text '{deface}': the site looks hacked",
                        "critical", "Take the site offline or restore it from a clean backup, then find the "
                        "entry point (outdated plugin, stolen password)"))
    if site.content_change_alert <= 0 or words is None or len(words) < 20:
        return out  # disabled, or too little text to compare meaningfully
    now = time.time() if now is None else now
    baseline: dict[str, Any] | None = storage.get_kv(key(site.name))
    if not baseline:
        if save:
            storage.set_kv(key(site.name), {"words": words, "ts": now})
        return out
    changed = change_percent(set(baseline["words"]), set(words))
    if changed >= site.content_change_alert:
        since = datetime.fromtimestamp(baseline["ts"], tz=timezone.utc).strftime("%Y-%m-%d")
        out.append(Warn("content_changed", f"{changed:.0f}% of the page text changed suddenly (compared with "
                        f"{since}): possible defacement/hack - or a redesign", "critical",
                        f"Open the page and check it. If the change is intended, run: "
                        f"python monitor.py accept-content --site \"{site.name}\""))
    elif changed <= site.content_change_alert / 2 and save:
        storage.set_kv(key(site.name), {"words": words, "ts": now})  # follow gradual, normal edits
    return out


def accept(storage: Storage, site: str | None = None) -> int:
    """Forget the baseline (one site or all); the next healthy check records a new one."""
    if site:
        storage.delete_kv(key(site))
        return 1
    return storage.delete_kv_prefix(KEY_PREFIX)

"""Pure text helpers for page content (no project imports, so checks.py can use them)."""
from __future__ import annotations

import html as html_lib
import re

MAX_WORDS = 5000
_STRIP_RE = re.compile(r"<(script|style|noscript|svg|template)\b.*?</\1\s*>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_WORD_RE = re.compile(r"[^\W\d_]{3,}", re.UNICODE)
DEFACEMENT_RE = re.compile(r"hacked\s+by|defaced\s+by|h[a4]ck[e3]d\s+by|was\s+here\s*[:!]|greetz\s+to", re.I)


def visible_text(page_html: str) -> str:
    return html_lib.unescape(_TAG_RE.sub(" ", _STRIP_RE.sub(" ", page_html)))


def page_words(page_html: str) -> list[str]:
    """Distinct visible words (3+ letters, lowercase) of a page, sorted."""
    return sorted({w.lower() for w in _WORD_RE.findall(visible_text(page_html))})[:MAX_WORDS]


def defacement_match(page_html: str) -> str | None:
    m = DEFACEMENT_RE.search(visible_text(page_html))
    return m.group(0) if m else None


def change_percent(old: set[str], new: set[str]) -> float:
    """Share of words that differ (0 = identical, 100 = nothing in common)."""
    if not old and not new:
        return 0.0
    return round(100.0 * (1 - len(old & new) / len(old | new)), 1)

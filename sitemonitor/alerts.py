"""Alerting: decide *when* to alert (AlertManager) and *how* to deliver (Notifier + channels).

Rules
-----
* A site must fail ``consecutive_failures`` checks in a row before an incident
  opens and a DOWN alert is sent (filters one-off network blips).
* While it stays down, the same cause is re-alerted at most once per
  ``throttle_minutes``. A *different* cause alerts immediately.
* The first successful check closes the incident and sends RECOVERED with the
  downtime (measured from the first failed check).
* Warnings (SSL/domain expiry, slow, VPS health) also need ``consecutive_failures``
  sightings and then repeat at most every ``warning_repeat_hours``.
* All events from one cycle go out as ONE message per channel, so a VPS outage
  with 20 sites produces one email, not twenty.
* "Last alerted" is only recorded after at least one channel delivered the
  message; if every channel fails, the next cycle retries.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Protocol
from zoneinfo import ZoneInfo

import requests

from .config import AlertsConfig, EmailConfig, TelegramConfig
from .diagnosis import DOWN, Diagnosis, Warn
from .storage import Storage

log = logging.getLogger(__name__)

DOWN_KINDS = ("down", "cause_changed", "still_down")
TELEGRAM_LIMIT = 4000


@dataclass
class AlertEvent:
    kind: str                     # down | cause_changed | still_down | recovered | warning
    key: str                      # site name, or the VPS name for server warnings
    ts: float
    site_id: int | None = None
    url: str | None = None
    diagnosis: Diagnosis | None = None
    warning: Warn | None = None
    started_at: float | None = None
    duration: float | None = None  # seconds down (recovered) or down so far (still_down)
    cause: str | None = None       # for recovered: what the cause was


# --------------------------------------------------------------------------- decision logic

class AlertManager:
    """Stateful alert decisions, persisted in SQLite so restarts do not re-alert."""

    def __init__(self, storage: Storage, cfg: AlertsConfig) -> None:
        self.storage = storage
        self.cfg = cfg

    def evaluate_site(self, site_id: int, diag: Diagnosis, ts: float) -> list[AlertEvent]:
        """Update state for one site's result and return the events to send."""
        state = self.storage.get_state(site_id)
        events: list[AlertEvent] = []

        if diag.status == DOWN:
            state.consecutive_failures += 1
            if state.first_failure_at is None:
                state.first_failure_at = ts
            if state.consecutive_failures >= self.cfg.consecutive_failures:
                kind = None
                if state.incident_id is None:
                    state.incident_id = self.storage.open_incident(
                        site_id, state.first_failure_at, diag.cause_code or "unknown", diag.cause, diag.to_dict())
                    kind = "down"
                elif state.last_alert_cause is None:
                    kind = "down"  # the first DOWN alert was never delivered: retry
                elif state.last_alert_cause != diag.cause_code:
                    self.storage.update_incident_cause(state.incident_id, diag.cause_code or "unknown", diag.cause)
                    kind = "cause_changed"
                elif ts - (state.last_alert_at or 0) >= self.cfg.throttle_minutes * 60:
                    kind = "still_down"
                if kind:
                    events.append(AlertEvent(kind=kind, key=diag.site, ts=ts, site_id=site_id, url=diag.url,
                                             diagnosis=diag, started_at=state.first_failure_at,
                                             duration=ts - state.first_failure_at))
        else:
            if state.incident_id is not None:
                incident = self.storage.get_incident(state.incident_id)
                self.storage.close_incident(state.incident_id, ts)
                started = incident["started_at"] if incident else state.first_failure_at or ts
                events.append(AlertEvent(kind="recovered", key=diag.site, ts=ts, site_id=site_id, url=diag.url,
                                         diagnosis=diag, started_at=started, duration=ts - started,
                                         cause=incident["cause"] if incident else None))
            state.consecutive_failures = 0
            state.first_failure_at = None
            state.incident_id = None
            state.last_alert_at = None
            state.last_alert_cause = None

        self.storage.save_state(state)
        return events

    def evaluate_warnings(self, key: str, warnings: list[Warn], ts: float) -> list[AlertEvent]:
        """Warnings for a site (or the VPS). Warnings no longer present are forgotten."""
        events: list[AlertEvent] = []
        for w in warnings:
            seen, last_sent = self.storage.touch_warning(key, w.code, ts)
            if seen < self.cfg.consecutive_failures:
                continue
            if last_sent is None or ts - last_sent >= self.cfg.warning_repeat_hours * 3600:
                events.append(AlertEvent(kind="warning", key=key, ts=ts, warning=w))
        self.storage.clear_warnings(key, {w.code for w in warnings})
        return events

    def mark_sent(self, events: list[AlertEvent]) -> None:
        """Record successful delivery (drives throttling)."""
        for ev in events:
            if ev.kind in DOWN_KINDS and ev.site_id is not None and ev.diagnosis is not None:
                state = self.storage.get_state(ev.site_id)
                state.last_alert_at = ev.ts
                state.last_alert_cause = ev.diagnosis.cause_code
                self.storage.save_state(state)
            elif ev.kind == "warning" and ev.warning is not None:
                self.storage.mark_warning_sent(ev.key, ev.warning.code, ev.ts)


# --------------------------------------------------------------------------- formatting

def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return f"{secs}s"


class Formatter:
    def __init__(self, tz_name: str = "UTC") -> None:
        try:
            self.tz = ZoneInfo(tz_name)
        except Exception:  # noqa: BLE001
            log.warning("Unknown timezone %r, using UTC", tz_name)
            self.tz = timezone.utc

    def when(self, ts: float | None) -> str:
        if ts is None:
            return "unknown"
        return datetime.fromtimestamp(ts, tz=self.tz).strftime("%Y-%m-%d %H:%M %Z")

    def subject(self, events: list[AlertEvent]) -> str:
        down = [e.key for e in events if e.kind in DOWN_KINDS]
        rec = [e.key for e in events if e.kind == "recovered"]
        warn = sorted({e.key for e in events if e.kind == "warning"})
        parts = []
        if down:
            parts.append(f"DOWN: {', '.join(down)}")
        if rec:
            parts.append(f"RECOVERED: {', '.join(rec)}")
        if warn and not parts:
            parts.append(f"Warning: {', '.join(warn)}")
        elif warn:
            parts.append(f"+{sum(1 for e in events if e.kind == 'warning')} warning(s)")
        prefix = "[ALERT]" if down else "[OK]" if rec and not warn else "[WARN]"
        return f"{prefix} " + " | ".join(parts)

    def event(self, ev: AlertEvent, full: bool = True) -> str:
        d = ev.diagnosis
        lines: list[str] = []
        if ev.kind in DOWN_KINDS and d is not None:
            label = {"down": "DOWN", "cause_changed": "STILL DOWN - cause changed",
                     "still_down": f"STILL DOWN for {format_duration(ev.duration)}"}[ev.kind]
            lines.append(f"🔴 {label}: {ev.key}  {ev.url}")
            lines.append(f"Cause: {d.cause}")
            lines.append(f"Down since: {self.when(ev.started_at)} ({format_duration(ev.duration)})")
            if d.fixes:
                lines.append("Suggested fix:")
                lines += [f"  - {f}" for f in (d.fixes if full else d.fixes[:3])]
            if d.evidence:
                lines.append("Details:")
                lines += [f"  - {e}" for e in (d.evidence if full else d.evidence[:3])]
            if d.error_log and full:
                lines.append("Last web server error log lines:")
                lines += [f"    {line}" for line in d.error_log]
        elif ev.kind == "recovered":
            lines.append(f"✅ RECOVERED: {ev.key}  {ev.url}")
            lines.append(f"Downtime: {format_duration(ev.duration)} "
                         f"({self.when(ev.started_at)} -> {self.when(ev.ts)})")
            if ev.cause:
                lines.append(f"Cause was: {ev.cause}")
            if d is not None and d.warnings:
                lines += [f"  ⚠ {w.message}" for w in d.warnings]
        elif ev.kind == "warning" and ev.warning is not None:
            w = ev.warning
            icon = "❗" if w.severity == "critical" else "⚠️"
            lines.append(f"{icon} {w.severity.upper()}: {ev.key} - {w.message}")
            if w.fix:
                lines.append(f"  Fix: {w.fix}")
        return "\n".join(lines)

    def body(self, events: list[AlertEvent], full: bool = True) -> str:
        order = {"down": 0, "cause_changed": 0, "still_down": 1, "recovered": 2, "warning": 3}
        events = sorted(events, key=lambda e: (order.get(e.kind, 9), e.key))
        header = f"Site monitor report - {self.when(time.time())}"
        return header + "\n\n" + "\n\n".join(self.event(e, full) for e in events)


# --------------------------------------------------------------------------- channels

class Channel(Protocol):
    name: str

    def send(self, subject: str, text: str) -> None: ...


class EmailChannel:
    name = "email"

    def __init__(self, cfg: EmailConfig) -> None:
        self.cfg = cfg

    def send(self, subject: str, text: str) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.cfg.from_addr
        msg["To"] = ", ".join(self.cfg.to)
        msg.set_content(text)
        ctx = ssl.create_default_context()
        if self.cfg.security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(self.cfg.host, self.cfg.port, timeout=self.cfg.timeout, context=ctx)
        else:
            server = smtplib.SMTP(self.cfg.host, self.cfg.port, timeout=self.cfg.timeout)
        with server:
            if self.cfg.security == "starttls":
                server.starttls(context=ctx)
            if self.cfg.username and self.cfg.password:
                server.login(self.cfg.username, self.cfg.password)
            server.send_message(msg)


class TelegramChannel:
    name = "telegram"

    def __init__(self, cfg: TelegramConfig) -> None:
        self.cfg = cfg

    def send(self, subject: str, text: str) -> None:
        message = f"{subject}\n\n{text}"
        chunks = [message[i:i + TELEGRAM_LIMIT] for i in range(0, len(message), TELEGRAM_LIMIT)] or [""]
        url = f"https://api.telegram.org/bot{self.cfg.bot_token}/sendMessage"
        errors = []
        for chat_id in self.cfg.chat_ids:
            for chunk in chunks:
                try:
                    resp = requests.post(url, json={"chat_id": chat_id, "text": chunk,
                                                    "disable_web_page_preview": True}, timeout=self.cfg.timeout)
                    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                    if not data.get("ok"):
                        raise RuntimeError(f"Telegram API error {resp.status_code}: {data.get('description', resp.text[:200])}")
                except Exception as exc:  # noqa: BLE001
                    # Never leak the bot token (it is part of the URL) into logs.
                    errors.append(f"chat {chat_id}: {str(exc).replace(self.cfg.bot_token, '***')}")
                    break
        if errors:
            raise RuntimeError("; ".join(errors))


class ConsoleChannel:
    """Writes alerts to the log (and console). Lets you see real alert text without SMTP/Telegram."""

    name = "console"

    def send(self, subject: str, text: str) -> None:
        log.warning("ALERT MESSAGE: %s\n%s", subject, text)


class Notifier:
    """Deliver batched events over all configured channels."""

    def __init__(self, cfg: AlertsConfig, tz_name: str = "UTC", channels: list[Channel] | None = None) -> None:
        if channels is None:
            channels = [ConsoleChannel()] if cfg.console else []
            if cfg.email:
                channels.append(EmailChannel(cfg.email))
            if cfg.telegram:
                channels.append(TelegramChannel(cfg.telegram))
        self.channels = channels
        self.fmt = Formatter(tz_name)

    def send(self, subject: str, full_text: str, short_text: str | None = None,
             only: list[str] | None = None) -> dict[str, str | None]:
        """Send to each channel; returns {channel: error or None}. Never raises."""
        results: dict[str, str | None] = {}
        for ch in self.channels:
            if only is not None and ch.name not in only:
                continue
            text = full_text if ch.name == "email" or short_text is None else short_text
            try:
                ch.send(subject, text)
                results[ch.name] = None
                log.info("Alert sent via %s: %s", ch.name, subject)
            except Exception as exc:  # noqa: BLE001
                results[ch.name] = str(exc) or type(exc).__name__
                log.error("Sending via %s failed: %s", ch.name, results[ch.name])
        return results

    def dispatch(self, events: list[AlertEvent]) -> bool:
        """Send one combined message. True if at least one channel delivered it."""
        if not events:
            return True
        if not self.channels:
            log.warning("%d alert(s) not sent: no alert channels configured", len(events))
            return False
        subject = self.fmt.subject(events)
        results = self.send(subject, self.fmt.body(events, full=True), self.fmt.body(events, full=False))
        return any(err is None for err in results.values())

    def test(self) -> dict[str, str | None]:
        text = ("This is a test message from the site monitor.\n"
                "If you received it, this alert channel is configured correctly.")
        if not self.channels:
            return {}
        return self.send("[TEST] Site monitor alert test", text)

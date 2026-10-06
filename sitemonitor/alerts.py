"""Alerting: decide *when* to alert (AlertManager) and *how* to deliver (Notifier + channels).

Rules
-----
* A site must fail ``consecutive_failures`` checks in a row before an incident
  opens and a DOWN alert is sent (filters one-off network blips).
* While it stays down, the same cause is re-alerted at most once per
  ``throttle_minutes``. A *different* cause alerts immediately.
* The first successful check closes the incident and sends RECOVERED with the
  downtime (measured from the first failed check). If that message cannot be
  delivered, it stays pending and is retried every cycle (for up to
  ``RECOVERY_RETRY_HOURS``) until a channel accepts it.
* Warnings (SSL/domain expiry, slow, VPS health) also need ``consecutive_failures``
  sightings and then repeat at most every ``warning_repeat_hours``.
* All events from one cycle go out as ONE message per channel, so a VPS outage
  with 20 sites produces one email, not twenty.
* "Last alerted" is only recorded after at least one channel delivered the
  message; if every channel fails, the next cycle retries.
* Escalation (optional): if an incident is still open after ``after_minutes``,
  a separate list of people gets ONE "escalation" alert, and (optionally) a
  recovery message later. It is recorded per incident, so it never repeats.
"""
from __future__ import annotations

import logging
import re
import smtplib
import ssl
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Protocol
from zoneinfo import ZoneInfo

import requests

from .config import AlertsConfig, EmailConfig, TelegramConfig, WhatsAppConfig
from .diagnosis import DOWN, Diagnosis, Warn
from .storage import Storage

log = logging.getLogger(__name__)

DOWN_KINDS = ("down", "cause_changed", "still_down")
TELEGRAM_LIMIT = 4000
WHATSAPP_LIMIT = 1500  # Twilio allows 1600 characters per WhatsApp message
RECOVERY_RETRY_HOURS = 24  # after this, an undeliverable RECOVERED message is dropped (and logged)


@dataclass
class AlertEvent:
    kind: str                     # down | cause_changed | still_down | recovered | warning | escalation
    key: str                      # site name, or the VPS name for server warnings
    ts: float
    site_id: int | None = None
    url: str | None = None
    diagnosis: Diagnosis | None = None
    warning: Warn | None = None
    started_at: float | None = None
    duration: float | None = None  # seconds down (recovered) or down so far (still_down)
    cause: str | None = None       # for recovered: what the cause was
    incident_id: int | None = None  # for recovered: which incident it closes (clears the pending flag)
    notify_normal: bool = True     # for recovered: still owed to the normal alert recipients
    escalated: bool = False        # for recovered: still owed to the escalation contacts


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
                    # A RECOVERED message still owed for the previous outage is now wrong: drop it.
                    state.recovery_pending = state.recovery_pending_escalation = None
                elif state.last_alert_cause is None:
                    kind = "down"  # the first DOWN alert was never delivered: retry
                elif state.last_alert_cause != diag.cause_code:
                    self.storage.update_incident_cause(state.incident_id, diag.cause_code or "unknown", diag.cause)
                    kind = "cause_changed"
                elif ts - (state.last_alert_at or 0) >= self.cfg.throttle_minutes * 60:
                    kind = "still_down"
                # Someone acknowledged the incident ("I'm on it"): stop the reminders and the
                # escalation. A *new* cause and the final RECOVERED message are still sent.
                acked = kind != "down" and self._acknowledged(state.incident_id)
                if kind == "still_down" and acked:
                    kind = None
                if kind:
                    events.append(AlertEvent(kind=kind, key=diag.site, ts=ts, site_id=site_id, url=diag.url,
                                             diagnosis=diag, started_at=state.first_failure_at,
                                             duration=ts - state.first_failure_at))
                esc = self.cfg.escalation
                if esc and not acked and state.escalated_at is None \
                        and ts - state.first_failure_at >= esc.after_minutes * 60:
                    events.append(AlertEvent(kind="escalation", key=diag.site, ts=ts, site_id=site_id, url=diag.url,
                                             diagnosis=diag, started_at=state.first_failure_at,
                                             duration=ts - state.first_failure_at))
        else:
            if state.incident_id is not None:
                # Close the incident now (the site IS back), but only mark the RECOVERED message as
                # owed. mark_sent() clears it once a channel accepts it; until then it is re-sent.
                self.storage.close_incident(state.incident_id, ts)
                state.recovery_pending = state.incident_id
                esc = self.cfg.escalation
                if esc and esc.notify_recovery and state.escalated_at is not None:
                    state.recovery_pending_escalation = state.incident_id
            events += self._pending_recovery(site_id, diag, state, ts)
            state.consecutive_failures = 0
            state.escalated_at = None
            state.first_failure_at = None
            state.incident_id = None
            state.last_alert_at = None
            state.last_alert_cause = None

        self.storage.save_state(state)
        return events

    def _acknowledged(self, incident_id: int | None) -> bool:
        if incident_id is None:
            return False
        incident = self.storage.get_incident(incident_id)
        return bool(incident and incident.get("acknowledged_at"))

    def _pending_recovery(self, site_id: int, diag: Diagnosis, state: Any, ts: float) -> list[AlertEvent]:
        """RECOVERED message for a closed incident that has not been delivered yet (first try or retry)."""
        incident_id = state.recovery_pending or state.recovery_pending_escalation
        if incident_id is None:
            return []
        incident = self.storage.get_incident(incident_id)
        ended = (incident or {}).get("ended_at")
        if incident is None or ended is None or ts - ended > RECOVERY_RETRY_HOURS * 3600:
            log.warning("Dropping undeliverable RECOVERED alert for %s (incident %s): no channel accepted it "
                        "within %d h", diag.site, incident_id, RECOVERY_RETRY_HOURS)
            state.recovery_pending = state.recovery_pending_escalation = None
            return []
        started = incident["started_at"]
        return [AlertEvent(kind="recovered", key=diag.site, ts=ended, site_id=site_id, url=diag.url,
                           diagnosis=diag, started_at=started, duration=ended - started, cause=incident["cause"],
                           incident_id=incident_id, notify_normal=state.recovery_pending == incident_id,
                           escalated=state.recovery_pending_escalation == incident_id)]

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

    def mark_sent(self, events: list[AlertEvent], escalation: bool = False) -> None:
        """Record successful delivery (drives throttling and retries).

        ``escalation=True`` means the events went to the escalation contacts.
        """
        for ev in events:
            if ev.kind == "recovered" and ev.site_id is not None:
                state = self.storage.get_state(ev.site_id)
                if escalation and state.recovery_pending_escalation == ev.incident_id:
                    state.recovery_pending_escalation = None
                elif not escalation and state.recovery_pending == ev.incident_id:
                    state.recovery_pending = None
                self.storage.save_state(state)
                continue
            if ev.kind in DOWN_KINDS and ev.site_id is not None and ev.diagnosis is not None:
                state = self.storage.get_state(ev.site_id)
                state.last_alert_at = ev.ts
                state.last_alert_cause = ev.diagnosis.cause_code
                self.storage.save_state(state)
            elif ev.kind == "escalation" and ev.site_id is not None:
                state = self.storage.get_state(ev.site_id)
                state.escalated_at = ev.ts
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
        esc = [e for e in events if e.kind == "escalation"]
        if esc:
            longest = max(e.duration or 0 for e in esc)
            return f"[ESCALATION] Still down after {format_duration(longest)}: {', '.join(e.key for e in esc)}"
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
        elif ev.kind == "escalation" and d is not None:
            lines.append(f"🚨 ESCALATED: {ev.key} has been down for {format_duration(ev.duration)} "
                         f"and is not fixed yet  {ev.url}")
            lines.append(f"Cause: {d.cause}")
            lines.append(f"Down since: {self.when(ev.started_at)}")
            if d.fixes:
                lines.append("Suggested fix:")
                lines += [f"  - {f}" for f in (d.fixes if full else d.fixes[:2])]
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
        order = {"escalation": 0, "down": 0, "cause_changed": 0, "still_down": 1, "recovered": 2, "warning": 3}
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
        self.send_rich(subject, text)

    def send_rich(self, subject: str, text: str, html: str | None = None, to: list[str] | None = None) -> None:
        """Plain-text email, optionally with an HTML version and other recipients (monthly reports)."""
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.cfg.from_addr
        msg["To"] = ", ".join(to or self.cfg.to)
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
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


def whatsapp_text(subject: str, text: str, limit: int = WHATSAPP_LIMIT) -> str:
    """Short WhatsApp message: subject + body, trimmed to the provider limit."""
    message = f"{subject}\n\n{text}".strip()
    return message if len(message) <= limit else message[:limit - 20].rstrip() + "\n...(truncated)"


def flatten_for_template(text: str, limit: int = 1000) -> str:
    """Meta template parameters may not contain newlines, tabs or 4+ spaces in a row."""
    flat = re.sub(r"\s*\n\s*", " | ", text.strip())
    flat = re.sub(r"[\t ]{2,}", " ", flat)
    return flat if len(flat) <= limit else flat[:limit - 3] + "..."


class WhatsAppChannel:
    """WhatsApp alerts via Twilio or Meta's WhatsApp Cloud API.

    Note: WhatsApp only allows free-form messages to someone who messaged you in
    the last 24 hours. For alerts at any time, Meta needs an approved *template*
    (set alerts.whatsapp.template); Twilio's sandbox allows free-form text to
    numbers that joined the sandbox.
    """

    name = "whatsapp"

    def __init__(self, cfg: WhatsAppConfig, post=None) -> None:
        self.cfg = cfg
        self._post = post or requests.post

    def _secrets(self) -> list[str]:
        return [s for s in (self.cfg.auth_token, self.cfg.access_token, self.cfg.account_sid) if s]

    def _mask(self, text: str) -> str:
        for secret in self._secrets():
            text = text.replace(secret, "***")
        return text

    def _send_twilio(self, number: str, message: str) -> None:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{self.cfg.account_sid}/Messages.json"
        resp = self._post(url, data={"From": f"whatsapp:{self.cfg.from_number}", "To": f"whatsapp:{number}",
                                     "Body": message},
                          auth=(self.cfg.account_sid, self.cfg.auth_token), timeout=self.cfg.timeout)
        if resp.status_code >= 300:
            try:
                detail = resp.json().get("message", resp.text[:200])
            except ValueError:
                detail = resp.text[:200]
            raise RuntimeError(f"Twilio error {resp.status_code}: {detail}")

    def _send_meta(self, number: str, message: str) -> None:
        url = f"https://graph.facebook.com/v20.0/{self.cfg.phone_number_id}/messages"
        to = number.lstrip("+")
        if self.cfg.template:
            payload = {"messaging_product": "whatsapp", "to": to, "type": "template",
                       "template": {"name": self.cfg.template, "language": {"code": self.cfg.template_language},
                                    "components": [{"type": "body", "parameters": [
                                        {"type": "text", "text": flatten_for_template(message)}]}]}}
        else:
            payload = {"messaging_product": "whatsapp", "to": to, "type": "text",
                       "text": {"body": message, "preview_url": False}}
        resp = self._post(url, json=payload, headers={"Authorization": f"Bearer {self.cfg.access_token}"},
                          timeout=self.cfg.timeout)
        if resp.status_code >= 300:
            try:
                detail = (resp.json().get("error") or {}).get("message", resp.text[:200])
            except ValueError:
                detail = resp.text[:200]
            raise RuntimeError(f"WhatsApp Cloud API error {resp.status_code}: {detail}")

    def send(self, subject: str, text: str) -> None:
        message = whatsapp_text(subject, text)
        sender = self._send_twilio if self.cfg.provider == "twilio" else self._send_meta
        errors = []
        for number in self.cfg.to:
            try:
                sender(number, message)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{number}: {self._mask(str(exc) or type(exc).__name__)}")
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
            if cfg.whatsapp:
                channels.append(WhatsAppChannel(cfg.whatsapp))
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


def escalation_notifier(cfg: AlertsConfig, tz_name: str = "UTC") -> Notifier | None:
    """A Notifier that reuses the configured channels but sends to the escalation contacts."""
    esc = cfg.escalation
    if esc is None:
        return None
    channels: list[Channel] = [ConsoleChannel()] if cfg.console else []
    if esc.email_to:
        if cfg.email:
            channels.append(EmailChannel(replace(cfg.email, to=esc.email_to)))
        else:
            log.warning("Escalation email_to is set but email alerts are not configured")
    if esc.telegram_chat_ids:
        if cfg.telegram:
            channels.append(TelegramChannel(replace(cfg.telegram, chat_ids=esc.telegram_chat_ids)))
        else:
            log.warning("Escalation telegram_chat_ids is set but Telegram alerts are not configured")
    if esc.whatsapp_to:
        if cfg.whatsapp:
            channels.append(WhatsAppChannel(replace(cfg.whatsapp, to=esc.whatsapp_to)))
        else:
            log.warning("Escalation whatsapp_to is set but WhatsApp alerts are not configured")
    return Notifier(cfg, tz_name, channels)

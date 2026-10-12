"""Email alerting. Sends one message per flush containing every un-notified alert at or
above the configured severity. Critical alerts bypass the normal cool-down; failed sends
are retried and never mark alerts as notified."""
from dataclasses import dataclass, field
from email.message import EmailMessage
import html
import json
import smtplib
import socket
import ssl
import time
from . import config
from .database import SEVERITY_RANK, pending_notifications, mark_notified

COLORS = {"Critical": "#b71c1c", "High": "#e65100", "Medium": "#f9a825", "Low": "#546e7a"}
RETRY_AFTER = 30  # seconds to wait after a failed send


@dataclass
class EmailSettings:
    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    security: str = "starttls"      # starttls | ssl | none
    sender: str = ""
    recipients: list = field(default_factory=list)
    min_severity: str = "High"
    min_interval: int = 60

    @classmethod
    def from_env(cls):
        return cls(config.SMTP_HOST, config.SMTP_PORT, config.SMTP_USER, config.SMTP_PASSWORD,
                   config.SMTP_SECURITY, config.MAIL_FROM or "sentinelpy@localhost", list(config.MAIL_TO),
                   config.NOTIFY_MIN_SEVERITY, config.NOTIFY_MIN_INTERVAL)

    @property
    def configured(self):
        return bool(self.host and self.recipients)


def default_smtp_factory(s):
    if s.security == "ssl":
        client = smtplib.SMTP_SSL(s.host, s.port, timeout=20, context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(s.host, s.port, timeout=20)
        client.ehlo()
        if s.security == "starttls":
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
    if s.user:
        client.login(s.user, s.password)
    return client


def _evidence_lines(row, limit=3):
    try:
        items = json.loads(row["evidence"])
    except (TypeError, ValueError):
        return []
    out = []
    for item in items[:limit]:
        text = item.get("raw") or json.dumps(item, ensure_ascii=False)
        out.append(text[:300])
    return out


def build_message(rows, settings, siem_host=None):
    siem_host = siem_host or socket.gethostname()
    top = max(rows, key=lambda r: SEVERITY_RANK.get(r["severity"], 0))["severity"]
    if len(rows) == 1:
        r = rows[0]
        subject = f'[SentinelPy][{top.upper()}] {r["title"]}' + (f' from {r["src_ip"]}' if r["src_ip"] else "")
    else:
        subject = f"[SentinelPy][{top.upper()}] {len(rows)} new alerts on {siem_host}"
    msg = EmailMessage()
    msg["Subject"] = subject.replace("\r", " ").replace("\n", " ")[:200]
    msg["From"] = settings.sender
    msg["To"] = ", ".join(settings.recipients)

    text = [f"SentinelPy detected {len(rows)} alert(s) on {siem_host}.", ""]
    cards = []
    for r in rows:
        text += [f'[{r["severity"].upper()}] {r["title"]}  ({r["rule_id"]})',
                 f'  Time:       {r["created_at"]}',
                 f'  Source IP:  {r["src_ip"] or "n/a"}',
                 f'  Events:     {r["event_count"]}',
                 f'  Detail:     {r["description"]}']
        ev = _evidence_lines(r)
        for line in ev:
            text.append(f"  Evidence:   {line}")
        text.append("")
        color = COLORS.get(r["severity"], "#546e7a")
        cards.append(
            f'<div style="border-left:6px solid {color};padding:8px 12px;margin:12px 0;background:#fafafa">'
            f'<b style="color:{color}">{html.escape(r["severity"].upper())}</b> &mdash; {html.escape(r["title"])}'
            f' <small>({html.escape(r["rule_id"])})</small><br>'
            f'Time: {html.escape(str(r["created_at"]))} &middot; Source IP: {html.escape(str(r["src_ip"] or "n/a"))}'
            f' &middot; Events: {r["event_count"]}<br>{html.escape(r["description"])}'
            + "".join(f'<pre style="margin:6px 0;white-space:pre-wrap;font-size:12px">{html.escape(l)}</pre>' for l in ev)
            + "</div>")
    text.append("Alerts are leads for investigation, not proof of compromise.")
    msg.set_content("\n".join(text))
    msg.add_alternative(
        f'<html><body style="font-family:system-ui,sans-serif"><h2>SentinelPy alert &mdash; {html.escape(siem_host)}</h2>'
        + "".join(cards) + "<p><small>Alerts are leads for investigation, not proof of compromise.</small></p></body></html>",
        subtype="html")
    return msg


class Notifier:
    def __init__(self, settings=None, smtp_factory=None, clock=time.monotonic, log=print):
        self.settings = settings or EmailSettings.from_env()
        self.factory = smtp_factory or default_smtp_factory
        self.clock = clock
        self.log = log
        self.next_ok = 0.0      # earliest time for the next non-critical email
        self.next_retry = 0.0   # earliest time to retry after a failure

    @property
    def enabled(self):
        return self.settings.configured

    def send_rows(self, rows):
        msg = build_message(rows, self.settings)
        with self.factory(self.settings) as smtp:
            smtp.send_message(msg)

    def flush(self, db):
        """Email pending alerts if allowed. Returns the number of alerts sent."""
        if not self.enabled:
            return 0
        now = self.clock()
        if now < self.next_retry:
            return 0
        rows = pending_notifications(db, self.settings.min_severity)
        if not rows:
            return 0
        critical = any(r["severity"] == "Critical" for r in rows)
        if now < self.next_ok and not critical:
            return 0
        try:
            self.send_rows(rows)
        except Exception as exc:  # network/SMTP errors must never stop monitoring
            self.next_retry = now + RETRY_AFTER
            self.log(f"[WARN] Email send failed ({type(exc).__name__}: {exc}); will retry in {RETRY_AFTER}s")
            return 0
        mark_notified(db, [r["id"] for r in rows])
        db.commit()
        self.next_ok = now + self.settings.min_interval
        self.log(f"[INFO] Email sent for {len(rows)} alert(s) to {', '.join(self.settings.recipients)}")
        return len(rows)

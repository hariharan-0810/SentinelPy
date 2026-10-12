"""Live monitor: tails local logs, receives syslog from the LAN, runs detections
continuously and emails alerts. One thread owns the database; receivers only enqueue."""
import hashlib
import signal
import sys
import time
from .config import AUTH_LOG, DB_PATH, NGINX_ACCESS_LOG, NGINX_ERROR_LOG
from .database import (alerts_after, connect, init_db, insert_event, max_alert_id, set_tail_state)
from .detections import run_detections
from .notify import Notifier
from .parsers import parse_access, parse_auth, parse_error, parse_syslog
from .syslog_server import SyslogReceiver
from .tailer import FileTailer

ANSI = {"Critical": "\033[1;97;41m", "High": "\033[1;31m", "Medium": "\033[33m", "Low": "\033[36m"}


def _paint(sev, text):
    return f"{ANSI.get(sev, '')}{text}\033[0m" if sys.stdout.isatty() else text


class Monitor:
    def __init__(self, files=None, syslog_port=0, syslog_bind="0.0.0.0", allow=None, from_start=False,
                 poll=1.0, notifier=None, log=print, db_path=None):
        self.files = files if files is not None else [
            (AUTH_LOG, parse_auth), (NGINX_ACCESS_LOG, parse_access), (NGINX_ERROR_LOG, parse_error)]
        self.syslog_port, self.syslog_bind, self.allow = syslog_port, syslog_bind, allow
        self.from_start, self.poll, self.log = from_start, poll, log
        self.notifier = notifier if notifier is not None else Notifier(log=log)
        self.db_path = db_path or DB_PATH
        self.stop_flag = False
        self.receiver = None
        self.events_total = self.alerts_total = 0

    def request_stop(self, *_):
        self.stop_flag = True

    def _ingest_file_lines(self, db, tailer, parser):
        n = 0
        for key, text in tailer.poll():
            event = parser(text)
            if event:
                event["event_key"] = hashlib.sha256(key.encode()).hexdigest()
                n += insert_event(db, event)
        return n

    def _ingest_syslog(self, db):
        n = 0
        if self.receiver:
            for peer, line in self.receiver.drain():
                event = parse_syslog(line, peer)
                if event:
                    n += insert_event(db, event)
        return n

    def _print_alerts(self, db, last_id):
        for a in alerts_after(db, last_id):
            self.alerts_total += 1
            last_id = a["id"]
            self.log(_paint(a["severity"],
                f'[ALERT][{a["severity"].upper()}] {a["created_at"]} {a["rule_id"]} src={a["src_ip"]} - {a["description"]}'))
        return last_id

    def run(self, max_seconds=None):
        init_db(self.db_path)
        db = connect(self.db_path)
        tailers = [(FileTailer(p, db, self.from_start, self.log), parser) for p, parser in self.files]
        if self.syslog_port:
            self.receiver = SyslogReceiver(self.syslog_port, self.syslog_bind, self.allow, log=self.log)
            self.receiver.start()
        email = "email alerts ON -> " + ", ".join(self.notifier.settings.recipients) if self.notifier.enabled \
            else "email alerts OFF (set SENTINELPY_SMTP_* in .env)"
        self.log(f"[INFO] SentinelPy live monitor started: {len(tailers)} log file(s)"
                 f"{', syslog port ' + str(self.syslog_port) if self.syslog_port else ''}; {email}. Ctrl+C to stop.")
        last_alert_id = max_alert_id(db)
        last_detect = 0.0
        started = time.monotonic()
        try:
            while not self.stop_flag:
                new = sum(self._ingest_file_lines(db, t, p) for t, p in tailers) + self._ingest_syslog(db)
                self.events_total += new
                for t, _ in tailers:
                    if t.dirty:
                        set_tail_state(db, t.path, t.inode, t.offset)
                        t.dirty = False
                db.commit()
                if new or time.monotonic() - last_detect > 30:
                    run_detections(db)
                    db.commit()
                    last_detect = time.monotonic()
                    last_alert_id = self._print_alerts(db, last_alert_id)
                self.notifier.flush(db)        # also retries earlier failures
                if max_seconds is not None and time.monotonic() - started >= max_seconds:
                    break
                time.sleep(self.poll)
        finally:
            if self.receiver:
                if self.receiver.dropped:
                    self.log(f"[WARN] {self.receiver.dropped} syslog lines dropped (queue full)")
                self.receiver.stop()
            db.close()
            self.log(f"[INFO] Stopped. Events stored: {self.events_total}; alerts raised: {self.alerts_total}")


def install_signal_handlers(monitor):
    signal.signal(signal.SIGINT, monitor.request_stop)
    signal.signal(signal.SIGTERM, monitor.request_stop)

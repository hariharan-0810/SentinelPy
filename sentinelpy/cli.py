import argparse
from pathlib import Path
from . import config
from .config import AUTH_LOG, NGINX_ACCESS_LOG, NGINX_ERROR_LOG
from .database import init_db
from .collector import collect
from .reports import export


def _test_email():
    from .notify import Notifier, EmailSettings
    n = Notifier(EmailSettings.from_env())
    if not n.enabled:
        print("Email is not configured. Set SENTINELPY_SMTP_HOST and SENTINELPY_MAIL_TO (see .env.example).")
        return 1
    row = dict(id=0, severity="Critical", title="SentinelPy test alert", rule_id="TEST", src_ip="192.0.2.1",
               event_count=1, created_at="now", description="This is a test message from SentinelPy.",
               evidence="[]")
    try:
        n.send_rows([row])
    except Exception as e:
        print(f"Send failed: {type(e).__name__}: {e}")
        return 1
    print("Test email sent to " + ", ".join(n.settings.recipients))
    return 0


def main():
    p = argparse.ArgumentParser(description="SentinelPy Mini SIEM (detection and alerting only)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    sub.add_parser("test-email", help="send a test alert email using your SMTP settings")

    def add_files(c):
        c.add_argument("--auth", type=Path, default=AUTH_LOG)
        c.add_argument("--nginx-access", type=Path, default=NGINX_ACCESS_LOG)
        c.add_argument("--nginx-error", type=Path, default=NGINX_ERROR_LOG)

    c = sub.add_parser("collect", help="one-shot scan of log files")
    add_files(c)
    m = sub.add_parser("monitor", help="LIVE monitoring: tail logs, receive syslog, alert, email")
    add_files(m)
    m.add_argument("--syslog-port", type=int, default=0, help=f"listen for LAN syslog (UDP+TCP); suggested {config.SYSLOG_PORT}")
    m.add_argument("--syslog-bind", default="0.0.0.0")
    m.add_argument("--allow", action="append", metavar="CIDR", help="only accept syslog from this network (repeatable), e.g. 192.168.1.0/24")
    m.add_argument("--from-start", action="store_true", help="also process existing log content on first run")
    m.add_argument("--poll", type=float, default=1.0)
    r = sub.add_parser("report")
    r.add_argument("--format", choices=["csv", "json", "html"], default="json")
    r.add_argument("--output", type=Path)
    a = p.parse_args()

    if a.cmd == "init-db":
        init_db(); print("Database initialized.")
    elif a.cmd == "test-email":
        raise SystemExit(_test_email())
    elif a.cmd == "collect":
        n, k = collect(a.auth, a.nginx_access, a.nginx_error); print(f"Done. New events: {n}; new alerts: {k}")
    elif a.cmd == "monitor":
        from .live import Monitor, install_signal_handlers
        from .parsers import parse_access, parse_auth, parse_error
        mon = Monitor(files=[(a.auth, parse_auth), (a.nginx_access, parse_access), (a.nginx_error, parse_error)],
                      syslog_port=a.syslog_port, syslog_bind=a.syslog_bind, allow=a.allow,
                      from_start=a.from_start, poll=a.poll)
        install_signal_handlers(mon)
        mon.run()
    else:
        path, n = export(a.format, a.output); print(f"Exported {n} alerts to {path}")


if __name__ == "__main__":
    main()

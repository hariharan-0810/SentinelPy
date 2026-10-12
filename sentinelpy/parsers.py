from datetime import datetime, timezone
from hashlib import sha256
import re
import uuid

AUTH_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+")
AUTH_TIME_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})")
ACCEPT_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+")
PRI_RE = re.compile(r"^<\d{1,3}>(?:\d{1,2} )?")
ISO_SYSLOG_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+) (?P<host>\S+) (?P<rest>.*)$")
BSD_SYSLOG_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} (?P<host>\S+) (?P<rest>.*)$")
ACCESS_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>[^"]+)" (?P<status>\d{3}) \S+')

def key(source, line):
    return sha256((source + "\0" + line.strip()).encode("utf-8", errors="replace")).hexdigest()

def _auth_time(line, now):
    tm = AUTH_TIME_RE.search(line)
    if tm:
        try:
            return datetime.strptime(f'{now.year} {tm["mon"]} {tm["day"]} {tm["time"]}', "%Y %b %d %H:%M:%S").astimezone().astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    return now.astimezone(timezone.utc).isoformat()


def parse_auth(line):
    """Failed and accepted SSH logins from auth.log / syslog-style lines."""
    failed = AUTH_RE.search(line)
    accepted = None if failed else ACCEPT_RE.search(line)
    m = failed or accepted
    if not m: return None
    event_time = _auth_time(line, datetime.now())
    if failed:
        etype, msg = "ssh_failed_password", "Failed SSH password authentication"
    else:
        etype, msg = "ssh_accepted_login", f'Accepted SSH login ({m["method"]})'
    return dict(event_key=key("auth",line), source="auth", event_time=event_time, src_ip=m["ip"],
        event_type=etype, username=m["user"], status_code=None, request_path=None,
        message=msg, raw=line.rstrip())


def parse_access(line):
    m = ACCESS_RE.match(line.strip())
    if not m: return None
    try:
        dt = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
        status = int(m["status"])
    except ValueError: return None
    path = m["path"].split("?",1)[0]
    return dict(event_key=key("nginx_access",line), source="nginx_access", event_time=dt,
        src_ip=m["ip"], event_type="nginx_http", username=None, status_code=status,
        request_path=path, message=f'{m["method"]} {path} returned HTTP {status}', raw=line.rstrip())

def parse_error(line):
    if not line.strip(): return None
    tm = re.search(r"\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\]", line)
    ip = re.search(r"\bclient:\s*(\d{1,3}(?:\.\d{1,3}){3})", line)
    dt = datetime.now(timezone.utc).isoformat()
    if tm:
        try: dt = datetime.strptime(tm[1], "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
        except ValueError: pass
    return dict(event_key=key("nginx_error",line), source="nginx_error", event_time=dt,
        src_ip=ip[1] if ip else None, event_type="nginx_error", username=None, status_code=None,
        request_path=None, message=line.strip()[:500], raw=line.rstrip())


def parse_syslog(line, peer_ip=None):
    """Parse one syslog message received over the network (RFC3164 or rsyslog's
    ISO-timestamp forward format) into an event, or None if it is not interesting.

    Remote BSD-style timestamps carry no year/timezone, so the receive time is used
    for them; ISO timestamps (with offset) are trusted."""
    line = line.strip()
    if not line: return None
    pri = PRI_RE.match(line)
    body = line[pri.end():] if pri else line
    host, ts, rest = peer_ip, None, body
    m = ISO_SYSLOG_RE.match(body)
    if m:
        host, ts, rest = m["host"], m["ts"], m["rest"]
    else:
        m = BSD_SYSLOG_RE.match(body)
        if m: host, rest = m["host"], m["rest"]
    msg = rest.split(": ", 1)[1] if ": " in rest else rest

    event = parse_auth(body) or parse_access(msg)
    if event is None and rest.lower().startswith("nginx") and "[error]" in msg:
        event = parse_error(msg)
    if event is None: return None

    event["host"] = host
    event["event_key"] = uuid.uuid4().hex          # network events are never de-duplicated
    event["raw"] = line
    if event["source"] == "auth":
        event["event_time"] = datetime.now(timezone.utc).isoformat()
        if ts:
            try:
                d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if d.tzinfo is not None:
                    event["event_time"] = d.astimezone(timezone.utc).isoformat()
            except ValueError:
                pass
    return event

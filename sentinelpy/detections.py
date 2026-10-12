from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus
import json
import re
from .database import insert_alert

SENSITIVE = ("/.env","/.git","/wp-admin","/wp-login.php","/phpmyadmin","/etc/passwd","/server-status")

# Only recent events matter for rolling-window rules, so live mode never rescans history.
WINDOW = timedelta(minutes=15)

SIGNATURES = (
    ("SQL injection", re.compile(r"(union(\s|/\*.*?\*/)+(all\s+)?select|information_schema|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d+\)|benchmark\()", re.I)),
    ("Path traversal", re.compile(r"(\.\./|\.\.\\)")),
    ("Cross-site scripting probe", re.compile(r"(<script|javascript:|onerror\s*=)", re.I)),
    ("Command injection / Shellshock", re.compile(r"(\(\)\s*\{\s*:;\s*\}|/bin/(ba)?sh\b|;\s*(wget|curl)\s+http)", re.I)),
)


def parse_time(s):
    try:
        d = datetime.fromisoformat(s.replace("Z","+00:00"))
        return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d.astimezone(timezone.utc)
    except (ValueError, AttributeError): return None


def run_detections(db, now=None, window=WINDOW):
    now = now or datetime.now(timezone.utc)
    cutoff = (now - window).strftime("%Y-%m-%dT%H:%M:%S")
    rows = db.execute("SELECT * FROM events WHERE src_ip IS NOT NULL AND event_time >= ? ORDER BY event_time",
                      (cutoff,)).fetchall()
    ev = [(r,parse_time(r["event_time"])) for r in rows]
    ev = [(r,t) for r,t in ev if t and t <= now + timedelta(minutes=2)]
    created = 0

    def alert(rule, severity, title, ip, count, desc, evidence, bucket):
        nonlocal created
        a = dict(alert_key=f"{rule}|{ip}|{bucket}", rule_id=rule, severity=severity, title=title,
                 src_ip=ip, event_count=count, description=desc,
                 evidence=json.dumps(evidence, ensure_ascii=False))
        if insert_alert(db,a): created += 1

    # ---- SSH: failures, heavy brute force, and success after failures -------------
    failures = defaultdict(list)
    for r,t in ev:
        if r["event_type"] == "ssh_failed_password" and now-t <= timedelta(minutes=10):
            failures[r["src_ip"]].append((r,t))
    ten = now.strftime("%Y%m%d%H") + f"{now.minute//10:02d}"
    for ip, rs in failures.items():
        evid = [dict(id=r["id"],time=r["event_time"],username=r["username"],host=r["host"],raw=r["raw"]) for r,t in rs[-10:]]
        users = {r["username"] for r,t in rs}
        if len(rs) >= 5:
            alert("AUTH_SSH_FAILED_BURST","High","Repeated failed SSH logins",ip,len(rs),
                  f"{len(rs)} failed password events ({len(users)} usernames) within 10 minutes.",evid,ten)
        if len(rs) >= 20:
            alert("AUTH_SSH_BRUTE_FORCE_HEAVY","Critical","Sustained SSH brute-force attack",ip,len(rs),
                  f"{len(rs)} failed password events within 10 minutes - automated brute force is likely.",evid,ten)

    for r,t in ev:
        if r["event_type"] != "ssh_accepted_login": continue
        prior = [(f,ft) for f,ft in (failures.get(r["src_ip"]) or []) if f["id"] < r["id"] and t-ft <= timedelta(minutes=10)]  # ingestion order; log timestamps only have 1s resolution
        if len(prior) >= 5:
            alert("AUTH_SSH_LOGIN_AFTER_FAILURES","Critical","Successful SSH login after repeated failures",
                  r["src_ip"],len(prior)+1,
                  f'{r["username"]} logged in from {r["src_ip"]} after {len(prior)} failed attempts - possible compromised account.',
                  [dict(id=r["id"],time=r["event_time"],username=r["username"],host=r["host"],raw=r["raw"])]
                  +[dict(id=f["id"],time=f["event_time"],username=f["username"]) for f,ft in prior[-5:]],
                  f'{r["id"]}')

    # ---- Nginx ------------------------------------------------------------------------
    access = [(r,t) for r,t in ev if r["source"] == "nginx_access"]
    five = now.strftime("%Y%m%d%H") + f"{now.minute//5:02d}"
    for ip in {r["src_ip"] for r,t in access}:
        mine = [(r,t) for r,t in access if r["src_ip"] == ip]
        misses = [(r,t) for r,t in mine if r["status_code"] == 404 and now-t <= timedelta(minutes=5)]
        if len(misses) >= 10:
            alert("NGINX_404_BURST","Medium","High volume of HTTP 404 responses",ip,len(misses),
                  f"{len(misses)} HTTP 404 responses within 5 minutes.",
                  [dict(id=r["id"],time=r["event_time"],path=r["request_path"],status=r["status_code"]) for r,t in misses[-10:]],five)
        requests = [(r,t) for r,t in mine if now-t <= timedelta(minutes=1)]
        if len(requests) >= 60:
            alert("NGINX_REQUEST_BURST","Medium","High request rate from one IP",ip,len(requests),
                  f"{len(requests)} requests within one minute.",
                  [dict(id=r["id"],time=r["event_time"],path=r["request_path"],status=r["status_code"]) for r,t in requests[-10:]],
                  now.strftime("%Y%m%d%H%M"))

    hits = defaultdict(list)
    for r,t in access:
        path = (r["request_path"] or "").lower()
        if any(path == p or path.startswith(p+"/") for p in SENSITIVE):
            alert("NGINX_SUSPICIOUS_PATH","Medium","Request for a sensitive path",r["src_ip"],1,
                  f"Request matched a sensitive-path heuristic: {path}",
                  [dict(id=r["id"],time=r["event_time"],path=path,status=r["status_code"],raw=r["raw"])],
                  t.strftime("%Y%m%d%H")+"|"+path)
        text = unquote_plus((r["raw"] or "")[:2000])
        for name, rx in SIGNATURES:
            if rx.search(text):
                hits[(r["src_ip"], name)].append((r,t))
    for (ip, name), rs in hits.items():
        alert("NGINX_ATTACK_SIGNATURE","High",f"Web attack pattern: {name}",ip,len(rs),
              f"{len(rs)} request(s) matched a {name.lower()} signature.",
              [dict(id=r["id"],time=r["event_time"],status=r["status_code"],raw=r["raw"][:300]) for r,t in rs[-5:]],
              now.strftime("%Y%m%d%H")+"|"+name)
    return created

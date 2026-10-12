from pathlib import Path
from .config import AUTH_LOG, NGINX_ACCESS_LOG, NGINX_ERROR_LOG
from .database import connect, init_db, insert_event
from .parsers import parse_auth, parse_access, parse_error
from .detections import run_detections

def lines(path):
    try:
        with Path(path).open(encoding="utf-8",errors="replace") as f:
            yield from f
    except FileNotFoundError: print(f"[INFO] Not found; skipped: {path}")
    except PermissionError: print(f"[WARN] Permission denied; skipped: {path}")
    except OSError as e: print(f"[WARN] Could not read {path}: {e}")

def collect(auth=AUTH_LOG, access=NGINX_ACCESS_LOG, error=NGINX_ERROR_LOG):
    init_db()
    db=connect(); added=0
    try:
        for path, parser in ((auth,parse_auth),(access,parse_access),(error,parse_error)):
            for line in lines(path):
                event=parser(line)
                if event and insert_event(db,event): added += 1
        db.commit()
        alerts=run_detections(db)
        db.commit()
        return added,alerts
    finally: db.close()

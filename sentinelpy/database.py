import sqlite3
from .config import DB_PATH

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL, source TEXT NOT NULL,
 event_time TEXT NOT NULL, src_ip TEXT, event_type TEXT NOT NULL, username TEXT,
 status_code INTEGER, request_path TEXT, message TEXT, raw TEXT NOT NULL, host TEXT
);
CREATE INDEX IF NOT EXISTS events_time_idx ON events(event_time);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY, alert_key TEXT UNIQUE NOT NULL,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 rule_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
 src_ip TEXT, event_count INTEGER NOT NULL, description TEXT NOT NULL,
 evidence TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'New',
 notified INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tail_state (
 path TEXT PRIMARY KEY, inode INTEGER NOT NULL, offset INTEGER NOT NULL
);
'''

# Columns added after the first release: (table, column, definition)
MIGRATIONS = (
    ("events", "host", "TEXT"),
    ("alerts", "notified", "INTEGER NOT NULL DEFAULT 0"),
)


def connect(path=DB_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_db(path=DB_PATH):
    db = connect(path)
    try:
        db.executescript(SCHEMA)
        for table, column, definition in MIGRATIONS:
            cols = {r["name"] for r in db.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        db.commit()
    finally:
        db.close()


def insert_event(db, e):
    cur = db.execute('''INSERT OR IGNORE INTO events
    (event_key,source,event_time,src_ip,event_type,username,status_code,request_path,message,raw,host)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
    (e["event_key"],e["source"],e["event_time"],e.get("src_ip"),e["event_type"],
     e.get("username"),e.get("status_code"),e.get("request_path"),e.get("message"),e["raw"],e.get("host")))
    return cur.rowcount == 1


def insert_alert(db, a):
    cur = db.execute('''INSERT OR IGNORE INTO alerts
    (alert_key,rule_id,severity,title,src_ip,event_count,description,evidence)
    VALUES (?,?,?,?,?,?,?,?)''',
    (a["alert_key"],a["rule_id"],a["severity"],a["title"],a.get("src_ip"),
     a["event_count"],a["description"],a["evidence"]))
    return cur.rowcount == 1


def pending_notifications(db, min_severity="High"):
    """Alerts at or above min_severity that have not been emailed yet (oldest first)."""
    floor = SEVERITY_RANK.get(min_severity, SEVERITY_RANK["High"])
    rows = db.execute("SELECT * FROM alerts WHERE notified=0 ORDER BY id").fetchall()
    return [r for r in rows if SEVERITY_RANK.get(r["severity"], 0) >= floor]


def mark_notified(db, ids):
    db.executemany("UPDATE alerts SET notified=1 WHERE id=?", [(i,) for i in ids])


def alerts_after(db, last_id):
    return db.execute("SELECT * FROM alerts WHERE id>? ORDER BY id", (last_id,)).fetchall()


def max_alert_id(db):
    return db.execute("SELECT COALESCE(MAX(id),0) FROM alerts").fetchone()[0]


def set_alert_status(db, alert_id, status):
    db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
    db.commit()


def get_tail_state(db, path):
    r = db.execute("SELECT inode,offset FROM tail_state WHERE path=?", (str(path),)).fetchone()
    return (r["inode"], r["offset"]) if r else None


def set_tail_state(db, path, inode, offset):
    db.execute("INSERT OR REPLACE INTO tail_state(path,inode,offset) VALUES (?,?,?)",
               (str(path), inode, offset))

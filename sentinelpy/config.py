from pathlib import Path
import os

ROOT = Path(__file__).resolve().parent.parent


def _load_env_file(path):
    """Tiny .env loader (no dependency). Real environment variables win."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env_file(ROOT / ".env")


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


DATA_DIR = Path(os.environ.get("SENTINELPY_DATA_DIR", ROOT / "data"))
DB_PATH = Path(os.environ.get("SENTINELPY_DB_PATH", DATA_DIR / "sentinelpy.sqlite3"))
REPORTS_DIR = ROOT / "reports"
AUTH_LOG = Path(os.environ.get("SENTINELPY_AUTH_LOG", "/var/log/auth.log"))
NGINX_ACCESS_LOG = Path(os.environ.get("SENTINELPY_NGINX_ACCESS_LOG", "/var/log/nginx/access.log"))
NGINX_ERROR_LOG = Path(os.environ.get("SENTINELPY_NGINX_ERROR_LOG", "/var/log/nginx/error.log"))

# Live monitoring
SYSLOG_PORT = env_int("SENTINELPY_SYSLOG_PORT", 5514)

# Email alerting (see README). Leave SMTP_HOST empty to disable email.
SMTP_HOST = os.environ.get("SENTINELPY_SMTP_HOST", "")
SMTP_PORT = env_int("SENTINELPY_SMTP_PORT", 587)
SMTP_USER = os.environ.get("SENTINELPY_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SENTINELPY_SMTP_PASSWORD", "")
SMTP_SECURITY = os.environ.get("SENTINELPY_SMTP_SECURITY", "starttls").lower()  # starttls | ssl | none
MAIL_FROM = os.environ.get("SENTINELPY_MAIL_FROM", "") or SMTP_USER
MAIL_TO = [a.strip() for a in os.environ.get("SENTINELPY_MAIL_TO", "").split(",") if a.strip()]
NOTIFY_MIN_SEVERITY = os.environ.get("SENTINELPY_NOTIFY_MIN_SEVERITY", "High")
NOTIFY_MIN_INTERVAL = env_int("SENTINELPY_NOTIFY_MIN_INTERVAL", 60)  # seconds between non-critical emails

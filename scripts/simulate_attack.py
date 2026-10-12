"""Generate SYNTHETIC attack log lines to demo the live monitor against YOUR OWN SentinelPy.
No attack traffic is produced - it only writes log text.

  python scripts/simulate_attack.py --file sample_logs/live_auth.log --scenario ssh-takeover
  python scripts/simulate_attack.py --syslog 127.0.0.1:5514 --scenario ssh-brute
Scenarios: ssh-brute (High), ssh-heavy (Critical), ssh-takeover (Critical), web-attack (High)"""
import argparse
import socket
import time
from datetime import datetime, timezone

IP = "192.0.2.77"          # TEST-NET address, never routable
HOST = "demo-server"


def auth_fail(i):
    return f"{datetime.now().strftime('%b %d %H:%M:%S')} {HOST} sshd[{4000+i}]: Failed password for invalid user admin{i % 3} from {IP} port {40000+i} ssh2"


def auth_ok():
    return f"{datetime.now().strftime('%b %d %H:%M:%S')} {HOST} sshd[4999]: Accepted password for root from {IP} port 49999 ssh2"


def web(path):
    t = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{IP} - - [{t}] "GET {path} HTTP/1.1" 404 153 "-" "sim/1.0"'


def scenario(name):
    if name == "ssh-brute": return [auth_fail(i) for i in range(6)]
    if name == "ssh-heavy": return [auth_fail(i) for i in range(22)]
    if name == "ssh-takeover": return [auth_fail(i) for i in range(6)] + [auth_ok()]
    if name == "web-attack": return [web("/index.php?id=1'%20OR%20'1'='1"), web("/download?f=../../etc/passwd"), web("/.env")]
    raise SystemExit("unknown scenario")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", default="ssh-takeover", choices=["ssh-brute", "ssh-heavy", "ssh-takeover", "web-attack"])
    p.add_argument("--file", help="append lines to this log file")
    p.add_argument("--syslog", metavar="HOST:PORT", help="send lines as UDP syslog to a SentinelPy receiver")
    p.add_argument("--delay", type=float, default=0.3)
    a = p.parse_args()
    if not a.file and not a.syslog:
        raise SystemExit("choose --file or --syslog")
    sock = host = port = None
    if a.syslog:
        host, port = a.syslog.rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for line in scenario(a.scenario):
        if a.file:
            with open(a.file, "a", encoding="utf-8") as f: f.write(line + "\n")
        if sock:
            sock.sendto(f"<38>{line}".encode(), (host, int(port)))
        print("sent:", line[:100])
        time.sleep(a.delay)


if __name__ == "__main__":
    main()

import json, socket, tempfile, threading, time, unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from sentinelpy.database import init_db, connect, insert_event, pending_notifications
from sentinelpy.detections import run_detections
from sentinelpy.live import Monitor
from sentinelpy.notify import EmailSettings, Notifier, build_message
from sentinelpy.parsers import parse_access, parse_auth, parse_error, parse_syslog
from sentinelpy.syslog_server import SyslogReceiver
from sentinelpy.tailer import FileTailer


def auth_line(kind, ip="192.0.2.10", user="demo", i=0):
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    if kind == "fail":
        return f"{ts} kali sshd[1{i}]: Failed password for {user} from {ip} port {5000+i} ssh2"
    return f"{ts} kali sshd[99]: Accepted password for {user} from {ip} port 6000 ssh2"


class DbCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.dir = Path(self.tmp.name)
        self.path = self.dir / "t.db"; init_db(self.path); self.db = connect(self.path)
        self.now = datetime.now(timezone.utc)
    def tearDown(self): self.db.close(); self.tmp.cleanup()
    def add(self, event, ago=0):
        event["event_time"] = (self.now - timedelta(seconds=ago)).isoformat(); insert_event(self.db, event)
    def rules(self):
        return {r[0]: r[1] for r in self.db.execute("SELECT rule_id,severity FROM alerts")}


class NewRuleTests(DbCase):
    def test_login_after_failures_is_critical(self):
        for i in range(6): self.add(parse_auth(auth_line("fail", i=i)), ago=60 - i)
        self.add(parse_auth(auth_line("ok")), ago=5)
        run_detections(self.db, self.now); self.db.commit()
        self.assertEqual(self.rules()["AUTH_SSH_LOGIN_AFTER_FAILURES"], "Critical")
    def test_login_without_failures_is_quiet(self):
        self.add(parse_auth(auth_line("ok")))
        run_detections(self.db, self.now)
        self.assertEqual(self.rules(), {})
    def test_heavy_bruteforce_is_critical(self):
        for i in range(21): self.add(parse_auth(auth_line("fail", i=i)), ago=100 - i)
        run_detections(self.db, self.now)
        r = self.rules(); self.assertEqual(r["AUTH_SSH_BRUTE_FORCE_HEAVY"], "Critical"); self.assertEqual(r["AUTH_SSH_FAILED_BURST"], "High")
    def test_web_signatures(self):
        for path in ("/a.php?id=1'%20OR%20'1'='1", "/dl?f=../../etc/hosts", "/s?q=<script>alert(1)</script>"):
            t = self.now.strftime("%d/%b/%Y:%H:%M:%S +0000")
            self.add(parse_access(f'192.0.2.9 - - [{t}] "GET {path} HTTP/1.1" 200 5 "-" "x"'))
        run_detections(self.db, self.now)
        n = self.db.execute("SELECT COUNT(*) FROM alerts WHERE rule_id='NGINX_ATTACK_SIGNATURE'").fetchone()[0]
        self.assertEqual(n, 3)
    def test_normal_web_traffic_is_quiet(self):
        t = self.now.strftime("%d/%b/%Y:%H:%M:%S +0000")
        self.add(parse_access(f'192.0.2.9 - - [{t}] "GET /index.html?page=2 HTTP/1.1" 200 5 "-" "Mozilla/5.0 (X11; Linux x86_64)"'))
        run_detections(self.db, self.now)
        self.assertEqual(self.rules(), {})
    def test_old_events_ignored_and_alerts_deduplicated(self):
        for i in range(6): self.add(parse_auth(auth_line("fail", i=i)), ago=3600)
        run_detections(self.db, self.now); self.assertEqual(self.rules(), {})
        for i in range(6): self.add(parse_auth(auth_line("fail", ip="192.0.2.11", i=i)), ago=30)
        run_detections(self.db, self.now); run_detections(self.db, self.now)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)


class SyslogParseTests(unittest.TestCase):
    def test_formats(self):
        e = parse_syslog("<38>Oct 10 10:00:01 web1 sshd[9]: Failed password for root from 10.0.0.5 port 22 ssh2", "9.9.9.9")
        self.assertEqual((e["host"], e["src_ip"], e["event_type"]), ("web1", "10.0.0.5", "ssh_failed_password"))
        e = parse_syslog("<38>2026-10-10T10:00:01.123456+05:30 web1 sshd[9]: Failed password for a from 10.0.0.5 port 22 ssh2")
        self.assertTrue(e["event_time"].startswith("2026-10-10T04:30:01"))
        e = parse_syslog('<134>Oct 10 10:00:01 web1 nginx: 10.0.0.6 - - [10/Oct/2026:10:00:00 +0000] "GET /x HTTP/1.1" 404 1 "-" "u"')
        self.assertEqual((e["source"], e["status_code"]), ("nginx_access", 404))
        self.assertIsNone(parse_syslog("<13>Oct 10 10:00:01 web1 cron[1]: nothing to see"))
    def test_events_not_deduplicated(self):
        l = "<38>Oct 10 10:00:01 w sshd[9]: Failed password for a from 10.0.0.5 port 22 ssh2"
        self.assertNotEqual(parse_syslog(l)["event_key"], parse_syslog(l)["event_key"])


class TailerTests(DbCase):
    def test_tail_rotation_partial_and_resume(self):
        log = self.dir / "a.log"; log.write_text("old1\nold2\n")
        t = FileTailer(log, self.db)
        self.assertEqual(t.poll(), [])                                  # starts at end
        with log.open("a") as f: f.write("new1\npart")
        self.assertEqual([l for _, l in t.poll()], ["new1\n"])          # partial line held back
        with log.open("a") as f: f.write("ial\n")
        self.assertEqual([l for _, l in t.poll()], ["partial\n"])
        log.rename(self.dir / "a.log.1"); log.write_text("after-rotate\n")
        self.assertEqual([l for _, l in t.poll()], ["after-rotate\n"])  # rotation
        from sentinelpy.database import set_tail_state
        set_tail_state(self.db, t.path, t.inode, t.offset)
        with log.open("a") as f: f.write("while-down\n")
        t2 = FileTailer(log, self.db)                                  # restart resumes
        self.assertEqual([l for _, l in t2.poll()], ["while-down\n"])
    def test_missing_file_then_created_is_read_from_start(self):
        log = self.dir / "later.log"; t = FileTailer(log, self.db, log=lambda *_: None)
        self.assertEqual(t.poll(), []); log.write_text("hello\n")
        self.assertEqual([l for _, l in t.poll()], ["hello\n"])


class NotifierTests(DbCase):
    class FakeSMTP:
        sent = []
        def __init__(self, fail=False): self.fail = fail
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def send_message(self, m):
            if self.fail: raise OSError("smtp down")
            self.sent.append(m)
    def mk(self, fail=False, clock=None):
        self.FakeSMTP.sent = []
        s = EmailSettings(host="smtp.test", sender="s@test", recipients=["a@test"], min_interval=60)
        return Notifier(s, smtp_factory=lambda _s: self.FakeSMTP(fail), clock=clock or (lambda: 1000.0), log=lambda *_: None)
    def alert(self, key, sev):
        self.db.execute("INSERT INTO alerts(alert_key,rule_id,severity,title,src_ip,event_count,description,evidence) VALUES (?,?,?,?,?,?,?,?)",
                        (key, "R", sev, "Title <b>", "192.0.2.1", 3, "desc", json.dumps([{"raw": "x<script>"}]))); self.db.commit()
    def test_only_high_and_above_emailed_and_marked(self):
        self.alert("a", "Medium"); self.alert("b", "High"); n = self.mk()
        self.assertEqual(n.flush(self.db), 1); self.assertEqual(len(self.FakeSMTP.sent), 1)
        self.assertEqual(pending_notifications(self.db), [])
        self.assertEqual(n.flush(self.db), 0)                               # nothing new -> no duplicate email
    def test_failure_keeps_alert_pending_then_retries(self):
        self.alert("a", "Critical"); t = [1000.0]; n = self.mk(fail=True, clock=lambda: t[0])
        self.assertEqual(n.flush(self.db), 0); self.assertEqual(len(pending_notifications(self.db)), 1)
        n.factory = lambda _s: self.FakeSMTP(False); self.assertEqual(n.flush(self.db), 0)   # still backing off
        t[0] += 31; self.assertEqual(n.flush(self.db), 1)
    def test_critical_bypasses_cooldown_high_does_not(self):
        t = [1000.0]; n = self.mk(clock=lambda: t[0]); self.alert("a", "High"); n.flush(self.db)
        self.alert("b", "High"); t[0] += 5; self.assertEqual(n.flush(self.db), 0)
        self.alert("c", "Critical"); self.assertEqual(n.flush(self.db), 2)
    def test_message_is_escaped_and_subject_safe(self):
        self.alert("a", "Critical"); rows = pending_notifications(self.db)
        m = build_message(rows, EmailSettings(sender="s@t", recipients=["a@t"]), "host")
        html_part = m.get_body(("html",)).get_content()
        self.assertNotIn("<script>", html_part); self.assertIn("CRITICAL", m["Subject"])
    def test_disabled_without_config(self):
        self.alert("a", "Critical"); n = Notifier(EmailSettings(), log=lambda *_: None)
        self.assertEqual(n.flush(self.db), 0)


class EndToEnd(unittest.TestCase):
    def test_live_monitor_detects_and_emails_over_real_smtp_and_syslog(self):
        import importlib.util, sys
        spec = importlib.util.spec_from_file_location("fake_smtp", Path(__file__).parents[1] / "scripts" / "fake_smtp.py")
        fake = importlib.util.module_from_spec(spec); spec.loader.exec_module(fake)
        inbox = []
        class H(fake.Handler):
            def handle(self):
                import io, contextlib
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf): super().handle()
                inbox.append(buf.getvalue())
        srv = fake.Server(("127.0.0.1", 0), H); smtp_port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        with socket.socket() as s: s.bind(("127.0.0.1", 0)); syslog_port = s.getsockname()[1]
        tmp = tempfile.TemporaryDirectory(); d = Path(tmp.name); log = d / "auth.log"; log.write_text("")
        settings = EmailSettings(host="127.0.0.1", port=smtp_port, security="none", sender="siem@test",
                                 recipients=["soc@test"], min_interval=0)
        logs = []
        mon = Monitor(files=[(log, parse_auth)], syslog_port=syslog_port, syslog_bind="127.0.0.1", allow=["127.0.0.0/8"],
                      poll=0.1, notifier=Notifier(settings, log=logs.append), log=logs.append, db_path=d / "e2e.db")
        def attack():
            time.sleep(0.6)
            with log.open("a") as f:
                for i in range(6): f.write(auth_line("fail", ip="192.0.2.50", i=i) + "\n")
                f.write(auth_line("ok", ip="192.0.2.50") + "\n")
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for i in range(6):
                u.sendto(f"<38>Oct 10 10:00:0{i} remote1 sshd[9]: Failed password for root from 192.0.2.60 port {i+20} ssh2".encode(), ("127.0.0.1", syslog_port))
            u.close()
        threading.Thread(target=attack).start()
        mon.run(max_seconds=4)
        srv.shutdown(); srv.server_close()
        db = connect(d / "e2e.db")
        rules = {r["rule_id"] for r in db.execute("SELECT rule_id FROM alerts")}
        hosts = {r["host"] for r in db.execute("SELECT host FROM events")}
        pending = pending_notifications(db, "High"); db.close(); tmp.cleanup()
        self.assertIn("AUTH_SSH_LOGIN_AFTER_FAILURES", rules)
        self.assertIn("remote1", hosts)                                 # LAN syslog events captured
        self.assertEqual(pending, [])                                   # everything high+ was emailed
        joined = "\n".join(inbox)
        self.assertIn("CRITICAL", joined); self.assertIn("192.0.2.50", joined)

if __name__ == "__main__": unittest.main()

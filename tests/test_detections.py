import tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone,timedelta
from sentinelpy.database import init_db,connect,insert_event
from sentinelpy.parsers import parse_auth,parse_access
from sentinelpy.detections import run_detections

class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/"test.db"
        init_db(self.path); self.db=connect(self.path); self.now=datetime.now(timezone.utc).replace(microsecond=0)
    def tearDown(self): self.db.close(); self.tmp.cleanup()
    def test_ssh_burst(self):
        for i in range(5):
            t=self.now-timedelta(minutes=2)+timedelta(seconds=i)
            line=t.astimezone().strftime("%b %d %H:%M:%S")+f" kali sshd[12{i}]: Failed password for demo from 192.0.2.10 port {5000+i} ssh2"
            e=parse_auth(line); e["event_time"]=t.isoformat(); insert_event(self.db,e)
        self.db.commit(); run_detections(self.db,self.now); self.db.commit()
        n=self.db.execute("SELECT COUNT(*) FROM alerts WHERE rule_id='AUTH_SSH_FAILED_BURST'").fetchone()[0]
        self.assertEqual(n,1)
    def test_sensitive_path(self):
        t=self.now.strftime("%d/%b/%Y:%H:%M:%S +0000")
        e=parse_access(f'192.0.2.30 - - [{t}] "GET /.env HTTP/1.1" 404 123 "-" "test"')
        e["event_time"]=self.now.isoformat(); insert_event(self.db,e); self.db.commit()
        run_detections(self.db,self.now); self.db.commit()
        n=self.db.execute("SELECT COUNT(*) FROM alerts WHERE rule_id='NGINX_SUSPICIOUS_PATH'").fetchone()[0]
        self.assertEqual(n,1)
if __name__=="__main__": unittest.main()

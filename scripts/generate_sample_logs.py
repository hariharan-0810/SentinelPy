from pathlib import Path
from datetime import datetime,timedelta
root=Path(__file__).resolve().parents[1]
out=root/"sample_logs"; out.mkdir(exist_ok=True)
now=datetime.now().astimezone()
auth=[]
for i in range(6):
    t=now-timedelta(minutes=4)+timedelta(seconds=i*15)
    auth.append(t.strftime("%b %d %H:%M:%S")+f" kali sshd[120{i}]: Failed password for invalid user demo from 192.0.2.10 port {50000+i} ssh2")
access=[]
for i in range(10):
    t=now-timedelta(minutes=2)+timedelta(seconds=i*5)
    access.append(f'192.0.2.20 - - [{t.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET /missing-{i} HTTP/1.1" 404 153 "-" "SentinelPy-Test/1.0"')
t=now
access.append(f'192.0.2.30 - - [{t.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET /.env HTTP/1.1" 404 153 "-" "SentinelPy-Test/1.0"')
(out/"auth.log").write_text("\n".join(auth)+"\n",encoding="utf-8")
(out/"nginx_access.log").write_text("\n".join(access)+"\n",encoding="utf-8")
(out/"nginx_error.log").write_text(t.strftime("%Y/%m/%d %H:%M:%S")+' [error] 1234#1234: client: 192.0.2.20, request failed\n',encoding="utf-8")
print("Synthetic test logs created. No network traffic was sent.")

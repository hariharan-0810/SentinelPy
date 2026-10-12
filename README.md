# SentinelPy - Live Mini SIEM / SOC

Detection and alerting Mini SIEM. It **tails logs in real time**, **receives logs from other machines on your LAN (syslog)**, runs correlation rules continuously, shows a **live Streamlit dashboard**, and **emails you automatically** when an alert is High or Critical. It never blocks, remediates or changes firewall rules.

```
 other servers --syslog UDP/TCP--> [ SyslogReceiver ]--+
 /var/log/auth.log, nginx logs --> [ FileTailer     ]--+--> parsers --> SQLite --> detections --> alerts
                                                                                        |            |
                                                              console + Streamlit <-----+            +--> Email (SMTP)
```

## Quick start (Kali / Debian)
```bash
cd SentinelPy
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v          # 22 tests should pass
cp .env.example .env && nano .env                # SMTP settings (see Email below)
python -m sentinelpy.cli test-email              # confirm email works
python -m sentinelpy.cli monitor --syslog-port 5514 --allow 192.168.1.0/24
```
In a second terminal: `streamlit run dashboard.py --server.address 127.0.0.1`

`/var/log/auth.log` is usually root-readable only. Don't run the whole tool as root; either add your user to the `adm` group (`sudo usermod -aG adm $USER`, then log in again) or use the syslog receiver instead.

## Try it without attacking anything
```bash
python scripts/fake_smtp.py &                      # local email sink, prints messages
export SENTINELPY_SMTP_HOST=127.0.0.1 SENTINELPY_SMTP_PORT=1025 SENTINELPY_SMTP_SECURITY=none SENTINELPY_MAIL_TO=me@example.test
python -m sentinelpy.cli monitor --auth sample_logs/live_auth.log --syslog-port 5514 &
python scripts/simulate_attack.py --file sample_logs/live_auth.log --scenario ssh-takeover
python scripts/simulate_attack.py --syslog 127.0.0.1:5514 --scenario web-attack
```
The simulator only writes synthetic log text (documentation IP `192.0.2.77`); it sends no attack traffic.

## Monitoring the whole LAN
Run `monitor --syslog-port 5514 --allow <your-subnet>` on the SIEM machine (open UDP/TCP 5514 in its firewall to that subnet only). On every other Linux machine, forward auth logs with rsyslog, e.g. `/etc/rsyslog.d/90-sentinelpy.conf`:
```
auth,authpriv.*  @@SIEM_IP:5514
```
then `sudo systemctl restart rsyslog`. To forward Nginx access logs:
```
module(load="imfile")
input(type="imfile" File="/var/log/nginx/access.log" Tag="nginx:")
if $programname == 'nginx' then @@SIEM_IP:5514
```
Each event is stored with the sender's hostname, so the dashboard can filter by host.

## Email alerts
Configured in `.env` (git-ignored). For Gmail use an **App password**, never your real password.
- Emails go out for alerts at or above `SENTINELPY_NOTIFY_MIN_SEVERITY` (default `High`).
- **Critical** alerts send immediately; others are batched with at least `SENTINELPY_NOTIFY_MIN_INTERVAL` seconds (default 60) between emails, so an attack cannot flood your inbox.
- An alert is marked as sent only after SMTP succeeds; failures retry every 30 s and monitoring continues.

## Detection rules
| Rule | Severity | Trigger |
|---|---|---|
| AUTH_SSH_LOGIN_AFTER_FAILURES | **Critical** | Successful SSH login from an IP with 5+ failures in the previous 10 min |
| AUTH_SSH_BRUTE_FORCE_HEAVY | **Critical** | 20+ failed SSH logins from one IP in 10 min |
| AUTH_SSH_FAILED_BURST | High | 5+ failed SSH logins from one IP in 10 min |
| NGINX_ATTACK_SIGNATURE | High | SQL injection, path traversal, XSS or command-injection patterns in a request |
| NGINX_SUSPICIOUS_PATH | Medium | `/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `/etc/passwd`, ... |
| NGINX_404_BURST | Medium | 10+ HTTP 404s from one IP in 5 min |
| NGINX_REQUEST_BURST | Medium | 60+ requests from one IP in 1 min |

These are starter heuristics; expect false positives. Alerts are leads for investigation, not proof of compromise. Alerts are de-duplicated per rule/IP/time bucket.

## Security notes
- The Streamlit dashboard has **no login**. Keep it on `127.0.0.1` and reach it via an SSH tunnel; don't bind it to the LAN.
- Syslog over UDP is unauthenticated: anyone who can reach the port can inject fake events. Always use `--allow` and a firewall rule.
- Remote events using classic syslog timestamps are timestamped on arrival (no year/timezone in the format).

## Limitations / next steps
Single-host SQLite, no TLS syslog, no authentication on the receiver, SSH/Nginx parsers only. Good next steps: network sensor (port-scan detection with scapy), sudo/su and Windows event parsing, GeoIP enrichment, Slack/Telegram notifications.

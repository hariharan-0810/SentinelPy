import unittest
from sentinelpy.parsers import parse_auth,parse_access,parse_error

class ParserTests(unittest.TestCase):
    def test_auth(self):
        e=parse_auth("Oct 10 10:00:01 kali sshd[123]: Failed password for demo from 192.0.2.10 port 50100 ssh2")
        self.assertEqual(e["src_ip"],"192.0.2.10")
    def test_access(self):
        e=parse_access('192.0.2.20 - - [10/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "test"')
        self.assertEqual(e["status_code"],404); self.assertEqual(e["request_path"],"/.env")
    def test_error(self):
        e=parse_error("2026/10/10 10:00:00 [error] 123: client: 192.0.2.20, request failed")
        self.assertEqual(e["src_ip"],"192.0.2.20")
    def test_ignore_successful_auth(self):
        self.assertIsNone(parse_auth("Oct 10 10:00:01 kali sshd[123]: Accepted publickey for demo"))
if __name__=="__main__": unittest.main()

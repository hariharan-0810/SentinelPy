"""Tiny local SMTP sink for testing email alerts without real credentials.
Run:  python scripts/fake_smtp.py          (listens on 127.0.0.1:1025, prints every message)
Then: SENTINELPY_SMTP_HOST=127.0.0.1 SENTINELPY_SMTP_PORT=1025 SENTINELPY_SMTP_SECURITY=none
      SENTINELPY_MAIL_TO=me@example.test python -m sentinelpy.cli test-email"""
import socketserver
import sys


class Handler(socketserver.StreamRequestHandler):
    def reply(self, text):
        self.wfile.write((text + "\r\n").encode())

    def handle(self):
        self.reply("220 fake-smtp ready")
        data_mode, lines = False, []
        for raw in self.rfile:
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if data_mode:
                if line == ".":
                    data_mode = False
                    print("=" * 70 + "\n" + "\n".join(lines) + "\n" + "=" * 70, flush=True)
                    lines = []
                    self.reply("250 queued")
                else:
                    lines.append(line[1:] if line.startswith("..") else line)
                continue
            cmd = line.upper()
            if cmd.startswith(("EHLO", "HELO")):
                self.reply("250 fake-smtp")
            elif cmd.startswith(("MAIL", "RCPT", "RSET", "NOOP")):
                self.reply("250 OK")
            elif cmd.startswith("DATA"):
                data_mode = True
                self.reply("354 end with <CRLF>.<CRLF>")
            elif cmd.startswith("QUIT"):
                self.reply("221 bye")
                break
            else:
                self.reply("502 not supported")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1025
    print(f"Fake SMTP sink on 127.0.0.1:{port} (Ctrl+C to stop)")
    with Server(("127.0.0.1", port), Handler) as s:
        try:
            s.serve_forever()
        except KeyboardInterrupt:
            pass

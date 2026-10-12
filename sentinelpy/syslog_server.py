"""Receive syslog over the LAN (UDP and TCP) so other machines can ship logs to SentinelPy."""
import ipaddress
import queue
import socketserver
import threading


def _allowed(ip, networks):
    if not networks:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in networks)


class SyslogReceiver:
    def __init__(self, port, bind="0.0.0.0", allow=None, maxsize=100_000, log=print):
        self.port, self.bind, self.log = port, bind, log
        self.networks = [ipaddress.ip_network(a, strict=False) for a in (allow or [])]
        self.q = queue.Queue(maxsize=maxsize)
        self.dropped = 0
        self.rejected = 0
        self._servers = []

    def _push(self, peer, data):
        if not _allowed(peer, self.networks):
            self.rejected += 1
            return
        for line in data.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    self.q.put_nowait((peer, line))
                except queue.Full:
                    self.dropped += 1

    def start(self):
        outer = self

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                outer._push(self.client_address[0], self.request[0])

        class TCP(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(300)
                peer = self.client_address[0]
                if not _allowed(peer, outer.networks):
                    outer.rejected += 1
                    return
                try:
                    while True:
                        line = self.rfile.readline(8192)
                        if not line:
                            break
                        outer._push(peer, line)
                except OSError:
                    pass

        class UDPServer(socketserver.ThreadingUDPServer):
            daemon_threads = True
            allow_reuse_address = True

        class TCPServer(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        for cls, handler in ((UDPServer, UDP), (TCPServer, TCP)):
            server = cls((self.bind, self.port), handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self._servers.append(server)
        scope = ", ".join(map(str, self.networks)) or "ANY source"
        self.log(f"[INFO] Syslog receiver listening on {self.bind}:{self.port} (UDP+TCP); accepting: {scope}")

    def drain(self, limit=5000):
        items = []
        while len(items) < limit:
            try:
                items.append(self.q.get_nowait())
            except queue.Empty:
                break
        return items

    def stop(self):
        for s in self._servers:
            s.shutdown()
            s.server_close()

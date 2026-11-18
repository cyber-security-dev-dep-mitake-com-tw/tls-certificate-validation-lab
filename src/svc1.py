"""SVC1: isolated TLS protocol/certificate scenario endpoints."""
from __future__ import annotations

import os
import signal
import socketserver
import ssl
import threading
import warnings
from pathlib import Path

from config import CASES, TLS_VERSIONS, port
from fixtures import generate

warnings.filterwarnings("ignore", category=DeprecationWarning, message="ssl.TLSVersion.TLSv1_1")
VERSIONS = {"1.1": ssl.TLSVersion.TLSv1_1,
            "1.2": ssl.TLSVersion.TLSv1_2,
            "1.3": ssl.TLSVersion.TLSv1_3}


class TLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.tls_context.wrap_socket(self.request, server_side=True) as tls_conn:
                tls_conn.settimeout(3)
                try:
                    tls_conn.recv(1024)
                except (TimeoutError, OSError):
                    pass
                body = b"TLS validation lab. No user data.\n"
                resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        + b"Content-Length: " + str(len(body)).encode()
                        + b"\r\nConnection: close\r\n\r\n" + body)
                try:
                    tls_conn.sendall(resp)
                except OSError:
                    pass
        except (ssl.SSLError, OSError):
            # Invalid clients and aborted TLS handshakes are expected in this lab.
            return


class TLSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, bind_addr, context):
        self.tls_context = context
        super().__init__(bind_addr, TLSHandler)


def tls_context(case: str, version: str, state_dir: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if version == "1.1":
        # For legacy compatibility tests ONLY; NEVER use in production.
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.minimum_version = VERSIONS[version]
    ctx.maximum_version = VERSIONS[version]
    ctx.load_cert_chain(str(state_dir / f"{case}.pem"), str(state_dir / f"{case}.key"))
    return ctx


def main():
    domain = os.getenv("LAB_DOMAIN", "tls-lab.example.test")
    if not domain or "/" in domain or ":" in domain or " " in domain:
        raise ValueError("LAB_DOMAIN must be a bare DNS name")
    state_dir = Path(os.getenv("LAB_STATE", "/state"))
    trust_dir = Path(os.getenv("LAB_TRUST", "/trust"))
    bind = os.getenv("LAB_BIND", "0.0.0.0")
    generate(domain, state_dir, trust_dir)
    servers = []
    for case in CASES:
        for version in TLS_VERSIONS:
            p = port(case, version)
            srv = TLSServer((bind, p), tls_context(case, version, state_dir))
            servers.append(srv)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            print(f"LISTEN {bind}:{p} tls={version} fixture={case}", flush=True)
    stopped = threading.Event()
    def stop(_sig, _frame):
        stopped.set()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    stopped.wait()
    for srv in servers:
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    main()

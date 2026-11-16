#!/usr/bin/env python3
"""Fake DoH upstream (HTTP/1.1, no TLS) for testing doh_forward.c.

Paths:
  /dns-query   valid response (QR=1, RCODE=NXDOMAIN), echoes question
  /slow        same, after 3 s
  /redirect    301 to /dns-query
  /notfound    404
  /garbage     200 with a non-DNS body
  /wrongq      200, response with a different question
Every request is logged to stderr with its DNS ID and headers.
"""
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_response(q, rename=False):
    hdr = bytearray(q[:12])
    hdr[2] = 0x80 | (q[2] & 0x79)  # QR=1, keep opcode/RD
    hdr[3] = 0x83                  # RA=1, RCODE=NXDOMAIN
    hdr[6:12] = b"\x00\x00\x00\x00\x00\x00"
    body = bytearray(q[12:])
    if rename:
        body[1] ^= 0x01
    return bytes(hdr) + bytes(body)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        q = self.rfile.read(n)
        sys.stderr.write(
            f"upstream: {self.path} id={q[0]:02x}{q[1]:02x} "
            f"ct={self.headers.get('Content-Type')} acc={self.headers.get('Accept')}\n")
        sys.stderr.flush()
        if self.path == "/slow":
            time.sleep(3)
        if self.path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "/dns-query")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/notfound":
            body, code = b"no", 404
        elif self.path == "/garbage":
            body, code = b"hello", 200
        elif self.path == "/big":
            r = bytearray(make_response(q))
            r[3] = 0x80  # NOERROR
            n = 40
            r[6:8] = n.to_bytes(2, "big")
            for i in range(n):
                r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04" + bytes([10, 0, 0, i])
            body, code = bytes(r), 200
        else:
            body, code = make_response(q, rename=self.path == "/wrongq"), 200
        self.send_response(code)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


ThreadingHTTPServer.request_queue_size = 256
srv = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H)
if len(sys.argv) > 3:  # TLS: cert, key
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[2], sys.argv[3])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()

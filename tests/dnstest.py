"""
Shared helpers for the runtime tests of isa-dnsproxy.

  * DNS message building and parsing (stdlib only, no dnspython)
  * Upstream    - an in-process fake DoH server (HTTP/1.1, optional TLS) that
                  records every request and can be told how to misbehave
  * Proxy       - starts isa-dnsproxy, waits for the "listening on" lines,
                  collects the query log, sends UDP/TCP queries, stops it

  * ProxyTestCase, params, slow - small unittest helpers (per-test temporary
                  directory, parametrised cases as subtests, skipping slow tests)

Only the Python standard library is used (unittest), so the tests run in the
unmodified dev-envs devShell. Run from the project root:

    make test                                   (all tests)
    make test-fast                              (without the slow TCP idle test)
    ISA_BIN=./isa-dnsproxy python3 -m unittest discover -s tests -v
    ISA_BIN=./isa-dnsproxy python3 -m unittest discover -s tests -p test_runtime.py -v

AI usage: the test suite was written with the help of an AI assistant
(Claude, Anthropic), see "Use of AI" in README.md.
"""

import os
import random
import re
import signal
import socket
import ssl
import struct
import subprocess
import threading
import tempfile
import time
import unittest
from functools import wraps
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BIN = os.environ.get("ISA_BIN", "./isa-dnsproxy")

EX_USAGE = 64
EX_UNAVAILABLE = 69
EX_CONFIG = 78

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
         "SRV": 33, "OPT": 41, "HTTPS": 65, "IXFR": 251, "AXFR": 252, "ANY": 255, "CAA": 257}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5,
          "YXDOMAIN": 6, "YXRRSET": 7, "NXRRSET": 8, "NOTAUTH": 9, "NOTZONE": 10}

# regular expression from the assignment
LOG_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) '
    r'((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]):\d{1,5} '
    r'(-|\.|(?:(?:[^\sA-Z\\.;()@$"]|\\[0-9]{3}|\\[.;()@$"\\])+\.)+) '
    r'(-|[A-Z][A-Z0-9-]*|TYPE\d+) '
    r'(local|blocked|forwarded|invalid|dropped) '
    r'(-|[A-Z]+|RCODE\d+)$')


def free_port():
    """A port free for both UDP and TCP on 127.0.0.1."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.bind(("127.0.0.1", 0))
            port = u.getsockname()[1]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
                    t.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue


def ipv6_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


# =========================================================================== DNS

def encode_name(name):
    """'www.example.com' / 'www.example.com.' / '.' -> wire form.
    Labels may also be given as a list of bytes (to test odd bytes)."""
    if isinstance(name, list):
        labels = name
    else:
        name = name.rstrip(".")
        labels = [l.encode() for l in name.split(".")] if name else []
    return b"".join(bytes([len(l)]) + l for l in labels) + b"\0"


def opt_record(udp_size=1232, version=0, owner=b"\0", rdata=b""):
    return owner + struct.pack(">HHBBHH", TYPES["OPT"], udp_size, 0, version, 0, len(rdata)) + rdata


def build_query(name, qtype="A", qid=0x1234, rd=True, cd=False, opcode=0, qclass=1,
                opt=None, qdcount=1, flags_or=0, answer=b"", authority=b"", additional=b"",
                ancount=0, nscount=0, arcount=None):
    """opt=None -> no OPT; opt=<int> -> OPT with that UDP payload size in additional."""
    qtype = TYPES.get(qtype, qtype)
    flags = (opcode & 0xF) << 11 | (0x0100 if rd else 0) | (0x0010 if cd else 0) | flags_or
    add = additional
    if opt is not None:
        add += opt_record(opt)
    if arcount is None:
        arcount = (1 if opt is not None else 0) + (1 if additional else 0)
    question = encode_name(name) + struct.pack(">HH", qtype, qclass) if qdcount else b""
    return (struct.pack(">HHHHHH", qid, flags, qdcount, ancount, nscount, arcount)
            + question + answer + authority + add)


def read_name(data, off):
    """Name at offset (follows compression pointers). Returns (lowercase text, next offset)."""
    labels, jumped, end = [], False, None
    for _ in range(128):
        length = data[off]
        if length == 0:
            off += 1
            break
        if length >= 0xC0:
            if not jumped:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            jumped = True
            continue
        labels.append(data[off + 1:off + 1 + length].decode("latin-1").lower())
        off += 1 + length
    return (".".join(labels) + ".") if labels else ".", (end if jumped else off)


def parse(data):
    """Parse a DNS message into a dict (raises on garbage)."""
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    m = {
        "id": qid, "qr": bool(flags & 0x8000), "opcode": (flags >> 11) & 0xF,
        "aa": bool(flags & 0x0400), "tc": bool(flags & 0x0200), "rd": bool(flags & 0x0100),
        "ra": bool(flags & 0x0080), "z": bool(flags & 0x0040), "ad": bool(flags & 0x0020),
        "cd": bool(flags & 0x0010), "rcode": flags & 0xF,
        "qdcount": qd, "ancount": an, "nscount": ns, "arcount": ar,
        "question": None, "answer": [], "authority": [], "additional": [], "raw": data,
    }
    off = 12
    if qd:
        start = off
        qname, off = read_name(data, off)
        qtype, qclass = struct.unpack(">HH", data[off:off + 4])
        off += 4
        m["question"] = {"name": qname, "type": qtype, "class": qclass, "raw": data[start:off]}
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            owner, off = read_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            m[section].append({"name": owner, "type": rtype, "class": rclass, "ttl": ttl,
                               "rdata": rdata, "rdata_off": off})
            off += rdlen
    m["opt"] = next((r for r in m["additional"] if r["type"] == TYPES["OPT"]), None)
    return m


def rr_text(m, rr):
    """Readable rdata for the record types used in tests."""
    t, d = rr["type"], rr["rdata"]
    if t == TYPES["A"]:
        return socket.inet_ntop(socket.AF_INET, d)
    if t == TYPES["AAAA"]:
        return socket.inet_ntop(socket.AF_INET6, d)
    if t in (TYPES["CNAME"], TYPES["NS"]):
        return read_name(m["raw"], rr["rdata_off"])[0]
    if t == TYPES["MX"]:
        return "%d %s" % (struct.unpack(">H", d[:2])[0], read_name(m["raw"], rr["rdata_off"] + 2)[0])
    return d.hex()


# =========================================================================== fake upstream

def make_answer(query, rcode=0, n_a=1, ad=False, opt=None):
    """A valid DoH response to `query`: same question, RA, n_a random A records for
    A queries, optional AD flag and optional OPT (bytes of the whole OPT record)."""
    q = parse(query)
    flags = 0x8000 | (query[2] & 0x79) << 8 | 0x0080 | (0x0020 if ad else 0) | (rcode & 0xF)
    flags |= query[3] & 0x10        # CD
    answers = b""
    count = 0
    if q["question"] and q["question"]["type"] == TYPES["A"]:
        for _ in range(n_a):
            ip = bytes([10, random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)])
            answers += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, random.randint(60, 9000), 4) + ip
            count += 1
    add = opt if opt is not None else b""
    return (struct.pack(">HHHHHH", 0, flags, 1, count, 0, 1 if add else 0)
            + q["question"]["raw"] + answers + add)


class Upstream:
    """In-process fake DoH server.

    Behaviour knobs (change them any time, also inside a test):
      delay      seconds to wait before answering
      status     HTTP status code
      location   Location header (for 3xx)
      respond    function(query_bytes) -> body bytes (default: make_answer)
    Every request is appended to `requests` as a dict with
    method, path, headers, body, response, time.
    """

    def __init__(self, tls_cert=None, tls_key=None):
        self.delay = 0.0
        self.status = 200
        self.location = None
        self.respond = lambda q: make_answer(q)
        self.requests = []
        self.lock = threading.Lock()
        up = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def handle_one_request(self):
                try:
                    super().handle_one_request()
                except (ConnectionError, ssl.SSLError):
                    self.close_connection = True

            def do_GET(self):
                self._serve(b"")

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self._serve(body)

            def _serve(self, body):
                rec = {"method": self.command, "path": self.path, "headers": dict(self.headers),
                       "body": body, "time": time.time(), "response": None}
                with up.lock:
                    up.requests.append(rec)
                if up.delay:
                    time.sleep(up.delay)
                if 300 <= up.status < 400:
                    self.send_response(up.status)
                    self.send_header("Location", up.location or "/followed")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if up.status != 200:
                    payload = b"error"
                else:
                    payload = up.respond(body)
                    rec["response"] = payload
                self.send_response(up.status)
                self.send_header("Content-Type", "application/dns-message")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except ConnectionError:
                    pass

        ThreadingHTTPServer.request_queue_size = 256
        ThreadingHTTPServer.daemon_threads = True
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.tls = tls_cert is not None
        if self.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls_cert, tls_key)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, host="127.0.0.1", path="/dns-query"):
        return "%s://%s:%d%s" % ("https" if self.tls else "http", host, self.port, path)

    def dns_requests(self):
        with self.lock:
            return [r for r in self.requests if r["method"] == "POST"]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# =========================================================================== proxy

class Proxy:
    def __init__(self, upstream_url, *args, addr="127.0.0.1", port=None, env=None,
                 wait_listening=True, timeout=None):
        self.port = port or free_port()
        self.addr = addr
        cmd = [BIN, "-u", upstream_url, "-p", str(self.port)]
        if addr:
            cmd += ["-a", addr]
        if timeout is not None:
            cmd += ["-w", str(timeout)]
        cmd += [str(a) for a in args]
        self.cmd = cmd
        self.stdout_lines, self.stderr_lines = [], []
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env=env if env is not None else os.environ.copy())
        threading.Thread(target=self._reader, args=(self.proc.stdout, self.stdout_lines), daemon=True).start()
        threading.Thread(target=self._reader, args=(self.proc.stderr, self.stderr_lines), daemon=True).start()
        if wait_listening:
            self.wait_listening()

    @staticmethod
    def _reader(stream, sink):
        for line in iter(stream.readline, b""):
            sink.append(line.decode("utf-8", "replace").rstrip("\n"))

    # --- start / stop ------------------------------------------------------
    def listening_lines(self):
        return [l for l in self.stderr_lines if l.startswith("listening on ")]

    def wait_listening(self, timeout=5.0):
        expected = 2 if self.addr else 4
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise AssertionError("proxy exited with %s: %s" % (self.proc.returncode, self.stderr_lines))
            n = len(self.listening_lines())
            if n >= expected:
                return
            if n >= 2 and not self.addr and time.time() > end - timeout + 1.0:
                return          # dual-stack sockets print two lines only
            time.sleep(0.02)
        raise AssertionError("no 'listening on' lines within %ss: %s" % (timeout, self.stderr_lines))

    def cap(self):
        """Outstanding-request cap printed on stderr, or None."""
        for l in self.stderr_lines:
            if "listening on" in l:
                continue
            m = re.search(r"\b(\d{2,})\b", l)
            if m and int(m.group(1)) >= 64 and "cap" in l.lower():
                return int(m.group(1))
        return None

    def stop(self, sig=signal.SIGTERM, timeout=3.0):
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            raise AssertionError("proxy did not exit within %ss after signal" % timeout)

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()

    # --- queries -----------------------------------------------------------
    def target(self, family=socket.AF_INET):
        host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        return host, self.port

    def udp_raw(self, msg, timeout=3.0, family=socket.AF_INET):
        """Send one datagram; return (response bytes or None, source address)."""
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(msg, self.target(family))
            try:
                data, src = s.recvfrom(65535)
                return data, src
            except socket.timeout:
                return None, None

    def udp(self, msg, timeout=3.0, family=socket.AF_INET):
        return self.udp_raw(msg, timeout, family)[0]

    def tcp(self, msgs, timeout=5.0, family=socket.AF_INET, expect=None):
        """Send messages on one connection (pipelined); return the list of responses."""
        expect = len(msgs) if expect is None else expect
        with socket.create_connection(self.target(family), timeout=timeout) as c:
            c.sendall(b"".join(struct.pack(">H", len(m)) + m for m in msgs))
            return read_tcp(c, expect, timeout)

    def query(self, name, qtype="A", tcp=False, **kw):
        timeout = kw.pop("timeout", 3.0)
        msg = build_query(name, qtype, **kw)
        data = self.tcp([msg], timeout=timeout)[0] if tcp else self.udp(msg, timeout=timeout)
        assert data is not None, "no response for %s %s" % (name, qtype)
        return parse(data)

    # --- log ---------------------------------------------------------------
    def log(self, wait=0.3):
        time.sleep(wait)
        return list(self.stdout_lines)

    def wait_log(self, count, timeout=3.0):
        end = time.time() + timeout
        while time.time() < end and len(self.stdout_lines) < count:
            time.sleep(0.02)
        return list(self.stdout_lines)

    def log_entries(self, wait=0.3):
        """Log lines split into dicts."""
        out = []
        for line in self.log(wait):
            parts = line.split(" ")
            if len(parts) == 6:
                out.append(dict(zip(("time", "client", "qname", "qtype", "verdict", "rcode"), parts)))
        return out

    def find_log(self, qname, qtype=None, verdict=None, timeout=2.0):
        end = time.time() + timeout
        while time.time() < end:
            for e in reversed(self.log_entries(wait=0)):       # newest first
                if e["qname"] == qname and (qtype is None or e["qtype"] == qtype) \
                        and (verdict is None or e["verdict"] == verdict):
                    return e
            time.sleep(0.05)
        return None


def read_tcp(sock, expect, timeout=5.0):
    """Read `expect` length-prefixed messages from a TCP socket."""
    sock.settimeout(timeout)
    buf, out = b"", []
    end = time.time() + timeout
    while len(out) < expect and time.time() < end:
        try:
            chunk = sock.recv(65535)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 2 and len(buf) - 2 >= struct.unpack(">H", buf[:2])[0]:
            n = struct.unpack(">H", buf[:2])[0]
            out.append(buf[2:2 + n])
            buf = buf[2 + n:]
    return out


def write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return p


HOME_LAN = """$ORIGIN home.lan.
$TTL 3600
@       IN SOA   ns1.home.lan. admin.home.lan. 2026091401 7200 3600 1209600 300
@       IN NS    ns1
@       IN MX    10 mail
ns1     IN A     192.168.1.1
router  IN A     192.168.1.1
router  IN AAAA  fd00:cafe::1
nas     IN A     192.168.1.20
mail    IN A     192.168.1.25
media   IN CNAME nas
ext     IN CNAME www.fit.vut.cz.
loop1   IN CNAME loop2
loop2   IN CNAME loop1
dangle  IN CNAME nothing
tolab   IN CNAME srv.lab.home.lan.
deep.a.b IN A    10.9.9.9
txtonly IN TXT   "hello"
both    IN A     10.0.0.66
"""

LAB_ZONE = """lab.home.lan. 600 IN SOA ns.lab.home.lan. root.lab.home.lan. 1 2 3 4 5
srv 600 IN A 10.1.1.1
"""

BLOCKLIST = """# advertising
ads.example.com
0.0.0.0 tracker.example.net telemetry.example.net\r
:: ipv6.example.org
both.home.lan
lan
"""


# --------------------------------------------------------------------------- unittest helpers

# ISA_FAST=1 (make test-fast) skips tests that wait for long timeouts
slow = unittest.skipIf(os.environ.get("ISA_FAST") == "1", "slow test, skipped by ISA_FAST=1")


def params(names, values):
    """Run one test method for every value, each value as its own subtest.

    `names` is a comma separated list of argument names; with one name every
    value is the argument itself, with more names a tuple of arguments.
    Decorators can be stacked; the cases are then all combinations.
    Every case gets fresh per-test resources (setUp is run again and the
    cleanups of the previous case are done), so cases do not share state."""
    names = [n.strip() for n in names.split(",")]

    def decorator(test):
        innermost = not getattr(test, "is_params_wrapper", False)

        @wraps(test)
        def run_all(self, **outer):
            for value in values:
                args = dict(zip(names, (value,) if len(names) == 1 else value))
                with self.subTest(**args):
                    if innermost:
                        self.doCleanups()
                        self.setUp()
                    test(self, **outer, **args)
        run_all.is_params_wrapper = True
        return run_all
    return decorator


class ProxyTestCase(unittest.TestCase):
    """Base class: temporary directories and proxies that are cleaned up after each test."""

    def tmp_dir(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        return Path(d.name)

    def proxy_for(self, url, *args, **kw):
        """Start a Proxy that is stopped at the end of the test."""
        p = Proxy(url, *args, **kw)
        self.addCleanup(p.kill)
        return p

    @classmethod
    def class_tmp_dir(cls):
        d = tempfile.TemporaryDirectory()
        cls.addClassCleanup(d.cleanup)
        return Path(d.name)

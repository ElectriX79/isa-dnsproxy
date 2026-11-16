"""
Runtime tests of forwarding to the DoH upstream (about one half of the points).

Every case follows the "Forwarding" section of the assignment and the
"Scenarios a literal reading may miss" list. The upstream is a fake DoH server
in this process (see dnstest.Upstream), so the tests need no Internet access.
Cases that depend on an interpretation of the assignment are marked
# INTERPRETATION.

Run:  pytest -v tests/test_forwarding.py
"""

import shutil
import signal
import socket
import struct
import subprocess
import threading
import time

import pytest

from dnstest import (Proxy, Upstream, build_query, make_answer, opt_record, parse, read_tcp,
                     write, free_port, RCODES, TYPES, BLOCKLIST, HOME_LAN)


@pytest.fixture
def upstream():
    up = Upstream()
    yield up
    up.close()


@pytest.fixture
def proxy_for():
    """proxy_for(upstream_url, *args, **kw) -> started Proxy; all stopped at the end."""
    started = []

    def start(url, *args, **kw):
        p = Proxy(url, *args, **kw)
        started.append(p)
        return p
    yield start
    for p in started:
        p.kill()


def same_except_id(resp, upstream_body, client_id):
    return resp[:2] == struct.pack(">H", client_id) and resp[2:] == upstream_body[2:]


# --------------------------------------------------------------------------- the request

def test_request_is_rfc8484_post(upstream, proxy_for):
    p = proxy_for(upstream.url())
    q = build_query("www.example.org", "A", qid=0xBEEF, opt=1232)
    assert p.udp(q) is not None
    req = upstream.dns_requests()[0]
    assert req["method"] == "POST"
    assert req["path"] == "/dns-query"
    assert req["headers"].get("Content-Type") == "application/dns-message"
    assert req["headers"].get("Accept") == "application/dns-message"


def test_query_relayed_unchanged_except_id_zero(upstream, proxy_for):
    p = proxy_for(upstream.url())
    q = build_query("Mixed.Case.Example.ORG", "AAAA", qid=0x7777, opt=4096, cd=True)
    p.udp(q)
    body = upstream.dns_requests()[0]["body"]
    assert body[:2] == b"\x00\x00"                     # SHOULD: ID 0 (RFC 8484 4.1)
    assert body[2:] == q[2:]                            # everything else byte for byte


def test_url_path_and_query_string_kept(upstream, proxy_for):
    p = proxy_for(upstream.url(path="/custom/path?x=1"))
    p.udp(build_query("a.example.org"))
    assert upstream.dns_requests()[0]["path"] == "/custom/path?x=1"


def test_one_upstream_request_per_forwarded_query(upstream, proxy_for):
    p = proxy_for(upstream.url())
    q = build_query("same.example.org")
    for _ in range(3):
        assert p.udp(q) is not None
    assert len(upstream.dns_requests()) == 3          # no cache by default


# --------------------------------------------------------------------------- the response

def test_response_relayed_unchanged_with_client_id(upstream, proxy_for):
    p = proxy_for(upstream.url())
    q = build_query("www.example.org", qid=0x4321)
    resp = p.udp(q)
    assert same_except_id(resp, upstream.dns_requests()[0]["response"], 0x4321)


def test_response_over_tcp_unchanged(upstream, proxy_for):
    p = proxy_for(upstream.url())
    q = build_query("www.example.org", qid=0x1111)
    resp = p.tcp([q])[0]
    assert same_except_id(resp, upstream.dns_requests()[0]["response"], 0x1111)


@pytest.mark.parametrize("rcode", ["NXDOMAIN", "REFUSED", "SERVFAIL", "FORMERR", "YXDOMAIN", "NOTAUTH"])
def test_non_noerror_rcode_relayed_and_logged(upstream, proxy_for, rcode):
    upstream.respond = lambda q: make_answer(q, rcode=RCODES[rcode], n_a=0)
    p = proxy_for(upstream.url())
    resp = p.udp(build_query("r.example.org", qid=5))
    assert same_except_id(resp, upstream.dns_requests()[0]["response"], 5)
    e = p.find_log("r.example.org.", "A")
    assert e and e["verdict"] == "forwarded" and e["rcode"] == rcode


def test_unassigned_rcode_logged_as_rcodeN(upstream, proxy_for):
    upstream.respond = lambda q: make_answer(q, rcode=13, n_a=0)
    p = proxy_for(upstream.url())
    p.udp(build_query("r13.example.org"))
    assert p.find_log("r13.example.org.")["rcode"] == "RCODE13"


def test_response_with_upstream_opt_and_ad_relayed(upstream, proxy_for):
    padding = struct.pack(">HH", 12, 8) + b"\0" * 8          # EDNS padding option
    upstream.respond = lambda q: make_answer(q, ad=True, opt=opt_record(1232, rdata=padding))
    p = proxy_for(upstream.url())
    q = build_query("ad.example.org", qid=9, opt=1232)
    resp = p.udp(q)
    assert same_except_id(resp, upstream.dns_requests()[0]["response"], 9)
    m = parse(resp)
    assert m["ad"] and m["opt"]["rdata"] == padding


def test_qname_case_differs_is_still_valid(upstream, proxy_for):
    def respond(q):
        a = bytearray(make_answer(q))
        a[13:16] = bytes(a[13:16]).upper()          # first label upper case
        return bytes(a)
    upstream.respond = respond
    p = proxy_for(upstream.url())
    m = parse(p.udp(build_query("www.example.org")))
    assert m["rcode"] == 0 and m["question"]["raw"][1:4] == b"WWW"


def test_two_clients_same_id_get_own_answers(upstream, proxy_for):
    upstream.delay = 0.5
    p = proxy_for(upstream.url())
    names = ["first.example.org", "second.example.org", "third.example.org"]
    results = {}

    def ask(name):
        results[name] = parse(p.udp(build_query(name, qid=0x2222), timeout=5))
    threads = [threading.Thread(target=ask, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for n in names:
        assert results[n]["id"] == 0x2222
        assert results[n]["question"]["name"] == n + "."


def test_two_clients_same_id_over_tcp(upstream, proxy_for):
    upstream.delay = 0.3
    p = proxy_for(upstream.url())
    c1 = socket.create_connection(p.target())
    c2 = socket.create_connection(p.target())
    for c, n in ((c1, "one.example.org"), (c2, "two.example.org")):
        m = build_query(n, qid=0x3333)
        c.sendall(struct.pack(">H", len(m)) + m)
    r1, r2 = read_tcp(c1, 1)[0], read_tcp(c2, 1)[0]
    c1.close(), c2.close()
    assert parse(r1)["question"]["name"] == "one.example.org."
    assert parse(r2)["question"]["name"] == "two.example.org."


# --------------------------------------------------------------------------- SERVFAIL cases

def assert_servfail(p, name, qid=0x55, opt=None, qtype="A"):
    q = build_query(name, qtype, qid=qid, opt=opt, cd=True)
    m = parse(p.udp(q, timeout=8))
    assert m["rcode"] == RCODES["SERVFAIL"]
    assert m["id"] == qid and m["qr"] and m["ra"] and not m["aa"] and not m["ad"]
    assert m["rd"] and m["cd"]
    assert m["question"]["raw"] == q[12:12 + len(m["question"]["raw"])]
    assert m["ancount"] == 0 and m["nscount"] == 0
    assert (m["opt"] is not None) == (opt is not None)
    e = p.find_log(name + ".", qtype)
    assert e and e["verdict"] == "forwarded" and e["rcode"] == "SERVFAIL"
    return m


@pytest.mark.parametrize("status", [400, 404, 415, 500, 503])
def test_non_2xx_is_servfail(upstream, proxy_for, status):
    upstream.status = status
    assert_servfail(proxy_for(upstream.url()), "err%d.example.org" % status)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_not_followed(upstream, proxy_for, status):
    upstream.status = status
    upstream.location = "/followed"
    assert_servfail(proxy_for(upstream.url()), "redir.example.org")
    assert [r["path"] for r in upstream.requests] == ["/dns-query"]


INVALID_BODIES = {
    "empty":           lambda q: b"",
    "11_octets":       lambda q: make_answer(q)[:11],
    "qr_zero":         lambda q: (lambda a: a[:2] + bytes([a[2] & 0x7F]) + a[3:])(make_answer(q)),
    "opcode_status":   lambda q: (lambda a: a[:2] + bytes([a[2] | 0x10]) + a[3:])(make_answer(q)),
    "qdcount_0":       lambda q: (lambda a: a[:4] + b"\x00\x00" + a[6:])(make_answer(q)),
    "qdcount_2":       lambda q: (lambda a: a[:4] + b"\x00\x02" + a[6:])(make_answer(q)),
    "other_name":      lambda q: make_answer(build_query("other.example.org")),
    "other_qtype":     lambda q: make_answer(build_query("bad.example.org", "AAAA")),
    "other_qclass":    lambda q: make_answer(build_query("bad.example.org", qclass=3)),
    "truncated_question": lambda q: make_answer(q)[:14],
    "too_large":       lambda q: make_answer(q) + b"\0" * 65536,
}


@pytest.mark.parametrize("case", INVALID_BODIES.keys())
def test_invalid_body_is_servfail(upstream, proxy_for, case):
    upstream.respond = INVALID_BODIES[case]
    assert_servfail(proxy_for(upstream.url()), "bad.example.org")


def test_servfail_keeps_opt_of_query(upstream, proxy_for):
    upstream.status = 500
    m = assert_servfail(proxy_for(upstream.url()), "opt.example.org", opt=4096)
    assert m["opt"]["class"] >= 1232 and m["opt"]["rdata"] == b""


def test_connection_refused_is_servfail(proxy_for):
    port = free_port()
    assert_servfail(proxy_for("http://127.0.0.1:%d/dns-query" % port), "refused.example.org")


def test_unresolvable_host_is_servfail(proxy_for):
    assert_servfail(proxy_for("https://nonexistent.invalid/dns-query"), "nohost.example.org")


def test_timeout_is_servfail_not_before(upstream, proxy_for):
    upstream.delay = 3
    p = proxy_for(upstream.url(), timeout=1)
    t = time.time()
    assert_servfail(p, "slow.example.org")
    elapsed = time.time() - t
    assert 0.8 <= elapsed <= 2.0, elapsed


def test_answer_within_timeout_is_not_servfail(upstream, proxy_for):
    upstream.delay = 1
    p = proxy_for(upstream.url(), timeout=3)
    assert parse(p.udp(build_query("ok.example.org"), timeout=5))["rcode"] == 0


def test_timeout_covers_connect(proxy_for):
    # TCP listener that never accepts nor answers: a slow handshake / request
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(0)
    port = srv.getsockname()[1]
    try:
        p = proxy_for("https://127.0.0.1:%d/dns-query" % port, timeout=1)
        t = time.time()
        assert_servfail(p, "hang.example.org")
        assert time.time() - t <= 2.0
    finally:
        srv.close()


# --------------------------------------------------------------------------- concurrency and cap

def test_slow_upstream_does_not_delay_local_or_blocked(upstream, proxy_for, tmp_path):
    upstream.delay = 3
    z = write(tmp_path, "home.lan.zone", HOME_LAN)
    b = write(tmp_path, "ads.txt", BLOCKLIST)
    p = proxy_for(upstream.url(), "-z", z, "-b", b, timeout=5)
    p.udp(build_query("router.home.lan"))                       # warm-up
    results = {}

    def ask(i):
        t = time.time()
        r = p.udp(build_query("f%d.example.org" % i, qid=i), timeout=8)
        results[i] = (time.time() - t, r)
    threads = [threading.Thread(target=ask, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    time.sleep(0.3)
    for name in ("router.home.lan", "x.ads.example.com"):
        t = time.time()
        assert p.udp(build_query(name), timeout=1) is not None
        assert time.time() - t < 0.2, name
    t = time.time()
    assert p.tcp([build_query("router.home.lan")], timeout=1)
    assert time.time() - t < 0.2
    for t in threads:
        t.join()
    for i, (elapsed, r) in results.items():
        assert r is not None and parse(r)["id"] == i and parse(r)["rcode"] == 0
        assert elapsed < 5, elapsed                              # TIMEOUT + 1 s
    assert len(upstream.dns_requests()) == 10                    # HTTP/1.1, all in parallel


def test_outstanding_cap(upstream, proxy_for):
    upstream.delay = 2
    p = proxy_for(upstream.url(), timeout=5)
    cap = p.cap()
    n = (cap or 64) + 10
    socks, sent = [], {}
    for i in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(6)
        s.sendto(build_query("c%d.example.org" % i, qid=i), p.target())
        socks.append(s)
        sent[i] = time.time()
    # collect answers as they arrive, so that the arrival time is real
    import selectors
    sel = selectors.DefaultSelector()
    for i, s in enumerate(socks):
        sel.register(s, selectors.EVENT_READ, i)
    fast_servfail, got, end = 0, 0, time.time() + 8
    while got < n and time.time() < end:
        for key, _ in sel.select(timeout=0.5):
            i = key.data
            m = parse(key.fileobj.recv(4096))
            if m["rcode"] == RCODES["SERVFAIL"] and time.time() - sent[i] < 1.5:
                fast_servfail += 1
            sel.unregister(key.fileobj)
            key.fileobj.close()
            got += 1
    assert got == n
    reqs = len(upstream.dns_requests())
    log = p.log_entries(wait=0.5)
    assert len(log) == n and all(e["verdict"] == "forwarded" for e in log)
    if cap is None:                                              # INTERPRETATION: no cap at all
        assert reqs == n and fast_servfail == 0
    else:
        assert reqs <= cap
        assert reqs + fast_servfail == n                         # every forwarded has a request, except capped


def test_upstream_tcp_connections_reused_or_parallel(upstream, proxy_for):
    p = proxy_for(upstream.url())
    for i in range(20):
        assert p.udp(build_query("seq%d.example.org" % i)) is not None
    assert len(upstream.dns_requests()) == 20


# --------------------------------------------------------------------------- truncation of forwarded answers

def test_forwarded_truncated_without_opt(upstream, proxy_for):
    upstream.respond = lambda q: make_answer(q, n_a=60)
    p = proxy_for(upstream.url())
    q = build_query("big.example.org", qid=0x99)
    resp = p.udp(q)
    m = parse(resp)
    assert len(resp) <= 512
    assert m["tc"] and m["ancount"] == 0 and m["nscount"] == 0 and m["arcount"] == 0
    assert m["id"] == 0x99 and m["question"]["raw"] == q[12:]
    upstream_flags = upstream.dns_requests()[0]["response"][2:4]
    assert resp[2] & ~0x02 == upstream_flags[0] & ~0x02 and resp[3] == upstream_flags[1]


def test_forwarded_truncated_with_opt_512(upstream, proxy_for):
    upstream.respond = lambda q: make_answer(q, n_a=60, opt=opt_record(1232))
    p = proxy_for(upstream.url())
    resp = p.udp(build_query("big.example.org", opt=512))
    m = parse(resp)
    assert len(resp) <= 512 and m["tc"] and m["ancount"] == 0 and m["arcount"] == 1 and m["opt"]


def test_forwarded_not_truncated_within_client_size(upstream, proxy_for):
    upstream.respond = lambda q: make_answer(q, n_a=40)       # ~700 B
    p = proxy_for(upstream.url())
    m = parse(p.udp(build_query("mid.example.org", opt=1232)))
    assert not m["tc"] and m["ancount"] == 40


def test_client_size_clamped_to_1232(upstream, proxy_for):
    upstream.respond = lambda q: make_answer(q, n_a=90)       # ~1500 B
    p = proxy_for(upstream.url())
    m = parse(p.udp(build_query("huge.example.org", opt=4096)))
    assert m["tc"] and m["ancount"] == 0


def test_forwarded_over_tcp_never_truncated(upstream, proxy_for):
    upstream.respond = lambda q: make_answer(q, n_a=200)
    p = proxy_for(upstream.url())
    q = build_query("big.example.org", qid=0x77)
    resp = p.tcp([q])[0]
    assert same_except_id(resp, upstream.dns_requests()[0]["response"], 0x77)


# --------------------------------------------------------------------------- blocked and local never forwarded

def test_blocked_and_local_never_reach_upstream(upstream, proxy_for, tmp_path):
    z = write(tmp_path, "home.lan.zone", HOME_LAN)
    b = write(tmp_path, "ads.txt", BLOCKLIST)
    p = proxy_for(upstream.url(), "-z", z, "-b", b)
    names = ["router.home.lan", "printer.home.lan", "both.home.lan", "x.ads.example.com",
             "ADS.example.COM", "tracker.example.net", "ext.home.lan", "something.lan"]
    for n in names:
        for qt in ("A", "AAAA", "MX", "ANY", "HTTPS"):
            assert p.udp(build_query(n, qt)) is not None
            assert p.tcp([build_query(n, qt)])
    assert upstream.dns_requests() == []


def test_invalid_never_reaches_upstream(upstream, proxy_for):
    p = proxy_for(upstream.url())
    p.udp(build_query("x.example.org", qclass=3))
    p.udp(build_query("x.example.org", "AXFR"))
    p.udp(build_query("x.example.org", opcode=2))
    p.udp(b"\x00" * 5)
    time.sleep(0.3)
    assert upstream.dns_requests() == []


# --------------------------------------------------------------------------- shutdown

def test_sigterm_answers_inflight_servfail(upstream, proxy_for):
    upstream.delay = 5
    p = proxy_for(upstream.url(), timeout=10)
    results = {}

    def ask():
        results["udp"] = p.udp(build_query("inflight.example.org", qid=0x5151), timeout=5)
    t = threading.Thread(target=ask)
    t.start()
    c = socket.create_connection(p.target())
    m = build_query("inflight-tcp.example.org", qid=0x5252)
    c.sendall(struct.pack(">H", len(m)) + m)
    time.sleep(0.5)
    start = time.time()
    rc = p.stop(signal.SIGTERM)
    assert rc == 0 and time.time() - start < 2.0
    t.join()
    tcp_resp = read_tcp(c, 1, timeout=2)
    c.close()
    assert parse(results["udp"])["rcode"] == RCODES["SERVFAIL"]
    assert tcp_resp and parse(tcp_resp[0])["rcode"] == RCODES["SERVFAIL"]
    log = p.log_entries(wait=0.1)
    for n in ("inflight.example.org.", "inflight-tcp.example.org."):
        assert any(e["qname"] == n and e["verdict"] == "forwarded" and e["rcode"] == "SERVFAIL" for e in log)


def test_sigint_also_stops(upstream, proxy_for):
    p = proxy_for(upstream.url())
    assert p.stop(signal.SIGINT) == 0


def test_client_gone_before_answer_still_logged(upstream, proxy_for):
    upstream.delay = 0.5
    p = proxy_for(upstream.url())
    c = socket.create_connection(p.target())
    m = build_query("gone.example.org")
    c.sendall(struct.pack(">H", len(m)) + m)
    c.close()                                                  # client leaves
    e = p.find_log("gone.example.org.", timeout=3)
    assert e and e["verdict"] == "forwarded"
    assert p.udp(build_query("alive.example.org")) is not None  # proxy survived


# --------------------------------------------------------------------------- TLS

@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("certs")

    def make(name, cn, san):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", d / (name + ".key"), "-out", d / (name + ".pem"),
                        "-subj", "/CN=" + cn, "-addext", "subjectAltName=" + san],
                       check=True, capture_output=True)
        return d / (name + ".pem"), d / (name + ".key")
    return {"server": make("server", "localhost", "DNS:localhost"),
            "other": make("other", "other", "DNS:other")}


@pytest.fixture
def tls_upstream(certs):
    up = Upstream(*certs["server"])
    yield up
    up.close()


def env_with(cafile):
    import os
    env = os.environ.copy()
    env["SSL_CERT_FILE"] = str(cafile)
    return env


def test_tls_trusted_via_ssl_cert_file(tls_upstream, proxy_for, certs):
    p = proxy_for(tls_upstream.url("localhost"), env=env_with(certs["server"][0]))
    assert parse(p.udp(build_query("tls.example.org")))["rcode"] == 0


def test_tls_untrusted_certificate_is_servfail(tls_upstream, proxy_for, certs):
    p = proxy_for(tls_upstream.url("localhost"), env=env_with(certs["other"][0]))
    assert_servfail(p, "untrusted.example.org")
    assert tls_upstream.dns_requests() == []


def test_tls_hostname_mismatch_is_servfail(tls_upstream, proxy_for, certs):
    p = proxy_for(tls_upstream.url("127.0.0.1"), env=env_with(certs["server"][0]))
    assert_servfail(p, "mismatch.example.org")


def test_tls_insecure_accepts_anything(tls_upstream, proxy_for, certs):
    p = proxy_for(tls_upstream.url("127.0.0.1"), "--insecure", env=env_with(certs["other"][0]))
    assert parse(p.udp(build_query("insecure.example.org")))["rcode"] == 0

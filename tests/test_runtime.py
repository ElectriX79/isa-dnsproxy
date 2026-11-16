"""
Runtime tests of local zones, blocking, message processing (steps 1-9),
response format, UDP/TCP transport and the query log.

Every case follows the "Required functionality" and "Query log" sections of the
assignment. Upstream is a fake DoH server that answers everything; tests that
must not reach it check its request log. Cases depending on an interpretation of
the assignment are marked # INTERPRETATION.

Run:  ISA_BIN=./isa-dnsproxy python3 -m unittest discover -s tests -p test_runtime.py -v
"""

import re
import socket
import struct
import time

import unittest

from dnstest import ProxyTestCase, params, slow

from dnstest import (Proxy, Upstream, build_query, encode_name, opt_record, parse, read_tcp,
                     rr_text, write, ipv6_available, LOG_RE, RCODES, TYPES,
                     HOME_LAN, LAB_ZONE, BLOCKLIST)


def answers(m):
    return sorted((r["name"], r["type"], rr_text(m, r)) for r in m["answer"])


# =========================================================================== zones


# =========================================================================== blocking


# =========================================================================== message processing (steps 1-8)

def raw(p, msg, tcp=False):
    if tcp:
        r = p.tcp([msg], timeout=2)
        return parse(r[0]) if r else None
    r = p.udp(msg, timeout=1)
    return parse(r) if r else None


BAD_QUESTIONS = {
    "label_64":      [b"a" * 64, b"com"],
    "label_byte_100": None,
    "pointer":       None,
    "name_256":      [b"a" * 63] * 4 + [b"b"],        # 4*64 + 2 + 1 > 255
    "cut_name":      None,
    "cut_type":      None,
}


def bad_question_msg(case):
    hdr = struct.pack(">HHHHHH", 0xAB, 0x0100, 1, 0, 0, 0)
    if case == "label_byte_100":
        return hdr + b"\x64" + b"a" * 100 + b"\0\0\1\0\1"
    if case == "pointer":
        return hdr + b"\x03www\xc0\x0c\0\1\0\1"
    if case == "cut_name":
        return hdr + b"\x07exam"
    if case == "cut_type":
        return hdr + encode_name("x.example.org") + b"\x00"
    return hdr + encode_name(BAD_QUESTIONS[case]) + b"\0\1\0\1"


# =========================================================================== response format

def check_built_response(m, q, aa):
    assert m["qr"] and m["ra"] and not m["ad"] and not m["z"]
    assert m["aa"] == aa
    assert m["opcode"] == 0 and m["rd"] == bool(q[2] & 1) and m["cd"] == bool(q[3] & 0x10)
    assert m["id"] == struct.unpack(">H", q[:2])[0]
    assert m["question"]["raw"] == q[12:12 + len(m["question"]["raw"])]   # byte for byte


# =========================================================================== transport


# =========================================================================== query log


class TestRuntime(ProxyTestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = Upstream()
        cls.addClassCleanup(cls.upstream.close)
        d = cls.class_tmp_dir()
        z1 = write(d, "home.lan.zone", HOME_LAN)
        z2 = write(d, "lab.zone", LAB_ZONE)
        big = write(d, "big.zone", "$ORIGIN big.lan.\n$TTL 60\n@ IN SOA ns r 1 2 3 4 5\n"
                    + "".join("many IN A 10.2.0.%d\n" % i for i in range(60)))
        chain = write(d, "chain.zone", "$ORIGIN chain.lan.\n$TTL 60\n@ IN SOA ns r 1 2 3 4 5\n"
                      + "".join("c%d IN CNAME c%d\n" % (i, i + 1) for i in range(10)) + "c10 IN A 10.10.10.10\n")
        b = write(d, "ads.txt", BLOCKLIST)
        cls.p = Proxy(cls.upstream.url(), "-z", z1, "-z", z2, "-z", big, "-z", chain, "-b", b)
        cls.addClassCleanup(cls.p.kill)
        cls.p.udp(build_query("router.home.lan"))           # warm-up

    def test_local_a(self):
        p = self.p
        m = p.query("router.home.lan", "A")
        assert m["rcode"] == 0 and m["aa"]
        assert answers(m) == [("router.home.lan.", 1, "192.168.1.1")]
        assert m["answer"][0]["ttl"] == 3600

    def test_local_aaaa_case_insensitive(self):
        p = self.p
        m = p.query("ROUTER.Home.LAN", "AAAA")
        assert m["aa"] and answers(m) == [("router.home.lan.", 28, "fd00:cafe::1")]

    def test_local_mx_ns_at_apex(self):
        p = self.p
        assert answers(p.query("home.lan", "MX")) == [("home.lan.", 15, "10 mail.home.lan.")]
        assert answers(p.query("home.lan", "NS")) == [("home.lan.", 2, "ns1.home.lan.")]

    def test_local_soa_query(self):
        p = self.p
        m = p.query("home.lan", "SOA")
        assert len(m["answer"]) == 1 and m["answer"][0]["type"] == TYPES["SOA"]
        assert m["answer"][0]["ttl"] == 3600                 # zone TTL unchanged in the answer

    def test_any_returns_every_rrset(self):
        p = self.p
        m = p.query("home.lan", "ANY")
        assert m["aa"] and sorted(r["type"] for r in m["answer"]) == [2, 6, 15]

    def test_any_at_cname_owner_returns_cname_only(self):
        p = self.p
        m = p.query("media.home.lan", "ANY")
        assert answers(m) == [("media.home.lan.", 5, "nas.home.lan.")]

    def test_cname_chain_followed(self):
        p = self.p
        m = p.query("media.home.lan", "A")
        assert m["rcode"] == 0 and m["aa"]
        assert m["answer"][0]["type"] == TYPES["CNAME"]               # CNAME first
        assert answers(m) == [("media.home.lan.", 5, "nas.home.lan."), ("nas.home.lan.", 1, "192.168.1.20")]

    def test_cname_query_returns_only_cname(self):
        p = self.p
        assert answers(p.query("media.home.lan", "CNAME")) == [("media.home.lan.", 5, "nas.home.lan.")]

    def test_cname_target_without_type_is_nodata_with_soa(self):
        p = self.p
        m = p.query("media.home.lan", "AAAA")
        assert m["rcode"] == 0 and [r["type"] for r in m["answer"]] == [5]
        assert [r["type"] for r in m["authority"]] == [6]

    def test_cname_to_missing_name_is_nxdomain(self):
        p = self.p
        m = p.query("dangle.home.lan", "A")
        assert m["rcode"] == RCODES["NXDOMAIN"] and [r["type"] for r in m["answer"]] == [5]
        assert m["authority"][0]["name"] == "home.lan."

    def test_cname_outside_zones_noerror_no_soa(self):
        p = self.p
        upstream = self.upstream
        before = len(upstream.dns_requests())
        m = p.query("ext.home.lan", "A")
        assert m["rcode"] == 0 and answers(m) == [("ext.home.lan.", 5, "www.fit.vut.cz.")]
        assert m["authority"] == []
        assert len(upstream.dns_requests()) == before                  # target is not resolved upstream

    def test_cname_loop_each_once_no_soa(self):
        p = self.p
        m = p.query("loop1.home.lan", "A")
        assert m["rcode"] == 0 and m["authority"] == []
        assert answers(m) == [("loop1.home.lan.", 5, "loop2.home.lan."), ("loop2.home.lan.", 5, "loop1.home.lan.")]

    def test_cname_into_nested_zone(self):
        p = self.p
        m = p.query("tolab.home.lan", "A")
        assert answers(m) == [("srv.lab.home.lan.", 1, "10.1.1.1"), ("tolab.home.lan.", 5, "srv.lab.home.lan.")]

    def test_cname_chain_limit_8_hops(self):
        p = self.p
        m = p.query("c0.chain.lan", "A")
        cnames = [r for r in m["answer"] if r["type"] == TYPES["CNAME"]]
        assert len(cnames) <= 9                                       # INTERPRETATION: at most 8 followed
        assert not any(r["type"] == TYPES["A"] for r in m["answer"])  # c10 is 10 hops away

    def test_nxdomain_with_soa_negative_ttl(self):
        p = self.p
        m = p.query("printer.home.lan", "A")
        assert m["rcode"] == RCODES["NXDOMAIN"] and m["aa"] and m["answer"] == []
        soa = m["authority"]
        assert len(soa) == 1 and soa[0]["type"] == 6 and soa[0]["name"] == "home.lan."
        assert soa[0]["ttl"] == 300                                   # min(3600, MINIMUM 300)

    def test_nodata_with_soa(self):
        p = self.p
        m = p.query("router.home.lan", "MX")
        assert m["rcode"] == 0 and m["aa"] and m["answer"] == []
        assert [r["type"] for r in m["authority"]] == [6] and m["authority"][0]["ttl"] == 300

    def test_empty_non_terminal_exists(self):
        p = self.p
        for name in ("a.b.home.lan", "b.home.lan"):
            m = p.query(name, "A")
            assert m["rcode"] == 0 and m["answer"] == [] and len(m["authority"]) == 1, name

    def test_name_below_existing_leaf_is_nxdomain(self):
        p = self.p
        assert p.query("x.router.home.lan", "A")["rcode"] == RCODES["NXDOMAIN"]

    def test_skipped_type_owner_exists(self):
        p = self.p
        m = p.query("txtonly.home.lan", "A")
        assert m["rcode"] == 0 and m["answer"] == [] and len(m["authority"]) == 1

    def test_longest_apex_wins(self):
        p = self.p
        m = p.query("nothing.lab.home.lan", "A")
        assert m["rcode"] == RCODES["NXDOMAIN"] and m["authority"][0]["name"] == "lab.home.lan."
        assert m["authority"][0]["ttl"] == 5

    def test_zone_name_beats_blocklist(self):
        p = self.p
        upstream = self.upstream
        before = len(upstream.dns_requests())
        m = p.query("both.home.lan", "A")                             # both.home.lan is blocked too
        assert m["aa"] and answers(m) == [("both.home.lan.", 1, "10.0.0.66")]
        assert p.find_log("both.home.lan.", "A", "local")
        assert len(upstream.dns_requests()) == before

    def test_blocklist_entry_above_apex(self):
        p = self.p
        assert p.query("router.home.lan")["aa"]
        assert p.query("printer.home.lan")["rcode"] == RCODES["NXDOMAIN"]
        assert p.find_log("printer.home.lan.", "A", "local")
        m = p.query("other.lan", "A")                                  # outside the zones -> blocked
        assert m["rcode"] == RCODES["NXDOMAIN"] and not m["aa"]

    def test_local_ttl_unchanged(self):
        p = self.p
        m = p.query("srv.lab.home.lan", "A")
        assert m["answer"][0]["ttl"] == 600

    def test_local_over_tcp(self):
        p = self.p
        m = p.query("media.home.lan", "A", tcp=True)
        assert m["aa"] and len(m["answer"]) == 2

    def test_local_response_over_512_truncated_without_opt(self):
        p = self.p
        resp = p.udp(build_query("many.big.lan", qid=77))
        m = parse(resp)
        assert len(resp) <= 512 and m["tc"] and m["aa"] and m["id"] == 77
        assert m["ancount"] == 0 and m["nscount"] == 0 and m["arcount"] == 0
        assert m["question"]["name"] == "many.big.lan."

    def test_local_truncated_bufsize_512_keeps_opt(self):
        p = self.p
        resp = p.udp(build_query("many.big.lan", opt=512))
        m = parse(resp)
        assert len(resp) <= 512 and m["tc"] and m["arcount"] == 1 and m["opt"]

    def test_local_bufsize_below_512_treated_as_512(self):
        p = self.p
        resp = p.udp(build_query("many.big.lan", opt=100))
        assert parse(resp)["tc"] and len(resp) <= 512

    def test_local_bufsize_above_1232_clamped(self):
        p = self.p
        resp = p.udp(build_query("many.big.lan", opt=65000))          # 60 A records = ~1700 B
        assert parse(resp)["tc"] and len(resp) <= 1232

    def test_local_small_answer_not_truncated(self):
        p = self.p
        m = parse(p.udp(build_query("media.home.lan", opt=512)))
        assert not m["tc"] and m["ancount"] == 2

    def test_local_over_tcp_never_truncated(self):
        p = self.p
        m = p.query("many.big.lan", "A", tcp=True)
        assert not m["tc"] and m["ancount"] == 60

    @params("name", ["ads.example.com", "x.ads.example.com", "a.b.ads.example.com",
                                      "ADS.Example.COM", "tracker.example.net", "telemetry.example.net",
                                      "ipv6.example.org"])
    def test_blocked_names(self, name):
        p = self.p
        m = p.query(name, "A", opt=1232)
        assert m["rcode"] == RCODES["NXDOMAIN"] and not m["aa"]
        assert m["answer"] == [] and m["authority"] == [] and m["opt"]
        assert p.find_log(name.lower() + ".", "A", "blocked")["rcode"] == "NXDOMAIN"

    @params("qtype", ["A", "AAAA", "MX", "TXT", "ANY", "HTTPS", "SOA", 999])
    def test_blocked_any_qtype(self, qtype):
        p = self.p
        m = p.query("q.ads.example.com", qtype)
        assert m["rcode"] == RCODES["NXDOMAIN"] and m["answer"] == [] and m["authority"] == []

    @params("name", ["bads.example.com", "example.com", "ads.example.co",
                                      "localhost"])
    def test_not_blocked(self, name):
        p = self.p
        m = p.query(name, "A")
        e = p.find_log(name + ".", "A")
        assert e and e["verdict"] == "forwarded", (name, e)

    def test_blocked_trailing_dot_query(self):
        p = self.p
        assert p.query("ads.example.com.", "A")["rcode"] == RCODES["NXDOMAIN"]

    def test_blocked_over_tcp(self):
        p = self.p
        assert p.query("x.ads.example.com", "A", tcp=True)["rcode"] == RCODES["NXDOMAIN"]

    def test_step1_short_message_dropped(self):
        p = self.p
        for msg in (b"", b"\x12", b"\x00" * 11):
            assert raw(p, msg) is None
        entries = [e for e in p.log_entries() if e["verdict"] == "dropped"]
        assert entries and all(e["qname"] == "-" and e["qtype"] == "-" and e["rcode"] == "-" for e in entries)

    def test_step2_response_dropped(self):
        p = self.p
        assert raw(p, build_query("qr.example.org", flags_or=0x8000)) is None

    def test_step3_opcode_notimp(self):
        p = self.p
        for opcode in (1, 2, 4, 5, 15):
            m = raw(p, build_query("op.example.org", opcode=opcode, qid=opcode))
            assert m["rcode"] == RCODES["NOTIMP"] and m["opcode"] == opcode
            assert m["qdcount"] == 0                                    # question not parsed yet

    def test_step3_before_step4(self):
        p = self.p
        m = raw(p, build_query("x.example.org", opcode=2, qdcount=0))
        assert m["rcode"] == RCODES["NOTIMP"]

    @params("qd", [0, 2])
    def test_step4_qdcount_formerr(self, qd):
        p = self.p
        msg = build_query("qd.example.org", qdcount=qd)
        if qd == 2:
            msg = msg[:4] + b"\x00\x02" + msg[6:] + encode_name("b.example.org") + b"\x00\x01\x00\x01"
        m = raw(p, msg)
        assert m["rcode"] == RCODES["FORMERR"] and m["qdcount"] == 0 and m["opt"] is None

    @params("case", BAD_QUESTIONS.keys())
    def test_step5_unparsable_question_formerr(self, case):
        p = self.p
        m = raw(p, bad_question_msg(case))
        assert m["rcode"] == RCODES["FORMERR"] and m["qdcount"] == 0 and m["opt"] is None
        assert m["id"] == 0xAB

    def test_step6_two_opts_formerr(self):
        p = self.p
        msg = build_query("o.example.org", opt=1232, additional=opt_record(1232), arcount=2)
        m = raw(p, msg)
        assert m["rcode"] == RCODES["FORMERR"] and m["qdcount"] == 1 and m["opt"] is None

    def test_step6_opt_in_answer_formerr(self):
        p = self.p
        msg = build_query("o.example.org", answer=opt_record(1232), ancount=1)
        assert raw(p, msg)["rcode"] == RCODES["FORMERR"]

    def test_step6_opt_non_root_owner_formerr(self):
        p = self.p
        msg = build_query("o.example.org", additional=opt_record(1232, owner=encode_name("x")), arcount=1)
        assert raw(p, msg)["rcode"] == RCODES["FORMERR"]

    def test_step6_counts_beyond_message_formerr(self):
        p = self.p
        msg = build_query("o.example.org", ancount=3)
        assert raw(p, msg)["rcode"] == RCODES["FORMERR"]

    @params("qclass", [3, 4, 254, 255])
    def test_step7_qclass_notimp(self, qclass):
        p = self.p
        m = raw(p, build_query("c.example.org", qclass=qclass, opt=1232))
        assert m["rcode"] == RCODES["NOTIMP"] and m["qdcount"] == 1 and m["opt"]

    @params("qtype", ["AXFR", "IXFR"])
    def test_step8_zone_transfer_refused(self, qtype):
        p = self.p
        m = raw(p, build_query("home.lan", qtype))
        assert m["rcode"] == RCODES["REFUSED"]
        m = raw(p, build_query("home.lan", qtype), tcp=True)
        assert m["rcode"] == RCODES["REFUSED"]

    def test_step7_before_step8(self):
        p = self.p
        assert raw(p, build_query("x.example.org", "AXFR", qclass=3))["rcode"] == RCODES["NOTIMP"]

    def test_flags_and_records_not_errors(self):
        p = self.p
        flags = 0x0200 | 0x0400 | 0x0080 | 0x0020 | 0x0040
        extra = encode_name("x") + struct.pack(">HHIH", 1, 1, 60, 4) + b"\1\2\3\4"
        msg = build_query("router.home.lan", flags_or=flags, additional=extra
                          + struct.pack(">BHHBBHH", 0, 41, 1232, 0, 1, 0, 0), arcount=2)
        m = raw(p, msg)
        assert m["rcode"] == 0 and m["aa"] and len(m["answer"]) == 1

    def test_invalid_logged_with_question_when_parsed(self):
        p = self.p
        raw(p, build_query("logged.example.org", "AXFR"))
        e = p.find_log("logged.example.org.", "AXFR")
        assert e and e["verdict"] == "invalid" and e["rcode"] == "REFUSED"

    @params("name,aa", [("RoUtEr.HoMe.LaN", True), ("X.Ads.Example.COM", False),
                                         ("PRINTER.home.lan", True)])
    @params("rd,cd", [(True, False), (False, True)])
    def test_built_response_header_and_question(self, name, aa, rd, cd):
        p = self.p
        q = build_query(name, qid=0x6543, rd=rd, cd=cd)
        check_built_response(parse(p.udp(q)), q, aa)

    def test_opt_echoed_only_when_query_had_one(self):
        p = self.p
        m = p.query("router.home.lan", opt=4096)
        assert m["opt"] and m["opt"]["class"] >= 1232 and m["opt"]["rdata"] == b""
        assert (m["opt"]["ttl"] >> 16) & 0xFF == 0                     # version 0
        assert p.query("router.home.lan")["opt"] is None
        assert p.query("x.ads.example.com", opt=512)["opt"]
        assert p.query("x.ads.example.com")["opt"] is None

    def test_udp_answer_from_queried_address(self):
        p = self.p
        data, src = p.udp_raw(build_query("router.home.lan"))
        assert data and src == ("127.0.0.1", p.port)

    def test_tcp_several_queries_one_connection(self):
        p = self.p
        msgs = [build_query(n, qid=i) for i, n in enumerate(["router.home.lan", "x.ads.example.com",
                                                              "printer.home.lan", "home.lan"])]
        resps = p.tcp(msgs)
        assert sorted(parse(r)["id"] for r in resps) == [0, 1, 2, 3]

    def test_tcp_sequential_queries_one_connection(self):
        p = self.p
        with socket.create_connection(p.target(), timeout=3) as c:
            for i in range(5):
                m = build_query("router.home.lan", qid=i)
                c.sendall(struct.pack(">H", len(m)) + m)
                assert parse(read_tcp(c, 1)[0])["id"] == i

    def test_tcp_message_split_across_segments(self):
        p = self.p
        m = build_query("router.home.lan", qid=0x0A0A)
        frame = struct.pack(">H", len(m)) + m
        with socket.create_connection(p.target(), timeout=3) as c:
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for b in frame:
                c.send(bytes([b]))
                time.sleep(0.003)
            assert parse(read_tcp(c, 1)[0])["id"] == 0x0A0A

    def test_tcp_two_messages_in_one_segment_and_split_third(self):
        p = self.p
        a, b, c3 = (build_query("router.home.lan", qid=i) for i in (1, 2, 3))
        data = b"".join(struct.pack(">H", len(m)) + m for m in (a, b, c3))
        with socket.create_connection(p.target(), timeout=3) as c:
            c.sendall(data[:-5])
            time.sleep(0.2)
            c.sendall(data[-5:])
            assert sorted(parse(r)["id"] for r in read_tcp(c, 3)) == [1, 2, 3]

    def test_tcp_dropped_message_closes_connection(self):
        p = self.p
        m = build_query("x.example.org", flags_or=0x8000)
        with socket.create_connection(p.target(), timeout=3) as c:
            c.sendall(struct.pack(">H", len(m)) + m)
            assert c.recv(10) == b""

    def test_tcp_zero_length_frame_dropped_and_closed(self):
        p = self.p
        with socket.create_connection(p.target(), timeout=3) as c:
            c.sendall(b"\x00\x00")
            assert c.recv(10) == b""

    def test_tcp_close_mid_message_no_log(self):
        p = self.p
        before = len(p.log(wait=0.2))
        with socket.create_connection(p.target(), timeout=3) as c:
            c.sendall(b"\x00\x30\x12\x34\x01")
        assert len(p.log(wait=0.5)) == before
        assert p.udp(build_query("router.home.lan")) is not None      # still alive

    def test_tcp_reset_does_not_kill_proxy(self):
        p = self.p
        m = build_query("router.home.lan")
        for _ in range(5):
            c = socket.create_connection(p.target(), timeout=3)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            c.sendall(struct.pack(">H", len(m)) + m)
            c.close()                                                  # RST, maybe before the answer
        assert p.udp(build_query("router.home.lan")) is not None

    def test_many_parallel_tcp_connections(self):
        p = self.p
        conns = [socket.create_connection(p.target(), timeout=3) for _ in range(30)]
        for i, c in enumerate(conns):
            m = build_query("router.home.lan", qid=i)
            c.sendall(struct.pack(">H", len(m)) + m)
        for i, c in enumerate(conns):
            assert parse(read_tcp(c, 1)[0])["id"] == i
            c.close()

    def test_idle_tcp_does_not_block_udp(self):
        p = self.p
        idle = socket.create_connection(p.target(), timeout=3)
        idle.sendall(b"\x00")                                          # half a length prefix
        t = time.time()
        assert p.udp(build_query("router.home.lan")) is not None
        assert time.time() - t < 0.2
        idle.close()

    @slow
    def test_tcp_idle_timeout_10s(self):
        p = self.p
        with socket.create_connection(p.target(), timeout=20) as c:
            t = time.time()
            assert c.recv(10) == b""
            assert 9.5 <= time.time() - t <= 15.5

    @unittest.skipIf(not ipv6_available(), reason="IPv6 loopback not available")
    def test_default_listens_ipv4_and_ipv6(self):
        upstream = self.upstream
        tmp_path = self.tmp_dir()
        z = write(tmp_path, "home.lan.zone", HOME_LAN)
        proxy = Proxy(upstream.url(), "-z", z, addr=None)
        try:
            lines = proxy.listening_lines()
            assert any("[" in l for l in lines) and any("[" not in l for l in lines)
            for fam in (socket.AF_INET, socket.AF_INET6):
                assert parse(proxy.udp(build_query("router.home.lan"), family=fam))["aa"]
                assert parse(proxy.tcp([build_query("router.home.lan")], family=fam)[0])["aa"]
            proxy.udp(build_query("v6log.home.lan"), family=socket.AF_INET6)
            e = proxy.find_log("v6log.home.lan.")
            assert e and e["client"].startswith("[::1]:")
            proxy.udp(build_query("v4log.home.lan"), family=socket.AF_INET)
            assert proxy.find_log("v4log.home.lan.")["client"].startswith("127.0.0.1:")
        finally:
            proxy.kill()

    @unittest.skipIf(not ipv6_available(), reason="IPv6 loopback not available")
    def test_specific_ipv6_address_only(self):
        upstream = self.upstream
        tmp_path = self.tmp_dir()
        z = write(tmp_path, "home.lan.zone", HOME_LAN)
        proxy = Proxy(upstream.url(), "-z", z, addr="::1")
        try:
            assert all("[::1]" in l for l in proxy.listening_lines())
            assert proxy.udp(build_query("router.home.lan"), family=socket.AF_INET6)
            assert proxy.udp(build_query("router.home.lan"), timeout=0.5) is None
        finally:
            proxy.kill()

    def test_specific_ipv4_address_only(self):
        upstream = self.upstream
        tmp_path = self.tmp_dir()
        z = write(tmp_path, "home.lan.zone", HOME_LAN)
        proxy = Proxy(upstream.url(), "-z", z, addr="127.0.0.1")
        try:
            assert proxy.listening_lines() and all("127.0.0.1:" in l for l in proxy.listening_lines())
            if ipv6_available():
                assert proxy.udp(build_query("router.home.lan"), timeout=0.5, family=socket.AF_INET6) is None
        finally:
            proxy.kill()

    def test_every_log_line_matches_regex(self):
        p = self.p
        lines = p.log()
        assert lines
        bad = [l for l in lines if not LOG_RE.match(l)]
        assert bad == []

    def test_log_one_line_per_message(self):
        upstream = self.upstream
        tmp_path = self.tmp_dir()
        z = write(tmp_path, "home.lan.zone", HOME_LAN)
        b = write(tmp_path, "ads.txt", BLOCKLIST)
        proxy = Proxy(upstream.url(), "-z", z, "-b", b)
        try:
            msgs = [build_query("router.home.lan"), build_query("x.ads.example.com"),
                    build_query("fwd.example.org"), build_query("x.example.org", qclass=3), b""]
            for m in msgs:
                proxy.udp(m, timeout=1)
            proxy.tcp([build_query("router.home.lan"), build_query("x.ads.example.com")])
            lines = proxy.wait_log(7, timeout=3)
            time.sleep(0.3)
            assert len(proxy.stdout_lines) == 7
            verdicts = sorted(l.split(" ")[4] for l in lines)
            assert verdicts == sorted(["local", "blocked", "forwarded", "invalid", "dropped", "local", "blocked"])
        finally:
            proxy.kill()

    def test_log_fields(self):
        p = self.p
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
            s.settimeout(2)
            s.sendto(build_query("Router.HOME.lan", "AAAA"), p.target())
            s.recv(4096)
        e = p.find_log("router.home.lan.", "AAAA")
        assert e["client"] == "127.0.0.1:%d" % port
        assert e["verdict"] == "local" and e["rcode"] == "NOERROR"
        assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(Z|[+-]\d\d:\d\d)$", e["time"])

    @params("labels,expected", [
        ([b"a.b", b"example"], r"a\.b.example."),
        ([b"x y", b"example"], r"x\032y.example."),
        ([b"semi;colon", b"example"], r"semi\;colon.example."),
        ([b'q"\\', b"example"], r'q\"\\.example.'),
        ([b"\x80\x00z", b"example"], r"\128\000z.example."),
        ([b"(@$)", b"example"], r"\(\@\$\).example."),
        ([b"UPPER", b"Example"], "upper.example."),
        ([], "."),
    ])
    def test_log_qname_escaping(self, labels, expected):
        p = self.p
        p.udp(build_query(labels, "A"))
        assert p.find_log(expected), (expected, p.log()[-3:])

    @params("qtype,text", [(1, "A"), (28, "AAAA"), (65, "HTTPS"), (255, "ANY"),
                                            (16, "TXT"), (99, "SPF"), (999, "TYPE999"), (65280, "TYPE65280")])
    def test_log_qtype_mnemonic(self, qtype, text):
        p = self.p
        name = "t%d.ads.example.com" % qtype
        p.udp(build_query(name, qtype))
        assert p.find_log(name + ".", text), (text, p.log()[-2:])

    def test_log_invalid_without_question(self):
        p = self.p
        raw(p, build_query("x.example.org", qdcount=0))
        assert any(e["verdict"] == "invalid" and e["qname"] == "-" and e["qtype"] == "-"
                   and e["rcode"] == "FORMERR" for e in p.log_entries())


if __name__ == "__main__":
    unittest.main()

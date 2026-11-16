"""
Runtime tests of the command line, start-up and shutdown.

Follows the "Command-line interface" and "Start-up, shutdown, and time limits"
sections of the assignment. Zone file and blocklist syntax is covered by
test_zonefile.py and test_blocklist.py; here only the process behaviour is tested.
Cases depending on an interpretation are marked # INTERPRETATION.

Run:  pytest -v tests/test_lifecycle.py
"""

import signal
import socket
import subprocess
import time

import pytest

from dnstest import (BIN, Proxy, Upstream, build_query, free_port, ipv6_available, parse, write,
                     EX_CONFIG, EX_UNAVAILABLE, EX_USAGE, HOME_LAN)

URL = "https://cloudflare-dns.com/dns-query"


def run(*args, timeout=3.0):
    """Run the binary, expect it to exit by itself. Returns (rc, stdout, stderr);
    rc is None if it was still running after `timeout` (it is killed then)."""
    try:
        p = subprocess.run([BIN, *map(str, args)], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return None, e.stdout or "", e.stderr or ""


@pytest.fixture(scope="module")
def upstream():
    up = Upstream()
    yield up
    up.close()


# =========================================================================== help

@pytest.mark.parametrize("args", [["-h"], ["--help"], ["-u", URL, "-h"], ["-h", "-p", "0"],
                                  ["-p", "99999", "--help"], ["-p", "1", "-p", "2", "-h"],
                                  ["-u", "ftp://x", "-h"], ["-z", "/nonexistent", "-h"]])
def test_help_wins_over_validation(args):
    rc, out, err = run(*args)
    assert rc == 0
    assert "-u" in out and "DOH_URL" in out                    # usage text on stdout
    assert out.endswith("\n")


# =========================================================================== usage errors

USAGE_ERRORS = {
    "missing_u":          ["-p", "5300"],
    "nothing":            [],
    "u_without_value":    ["-u"],
    "u_not_url":          ["-u", "cloudflare-dns.com"],
    "u_ftp":              ["-u", "ftp://example.com/dns-query"],
    "u_scheme_only":      ["-u", "https://"],
    "u_twice":            ["-u", URL, "-u", URL],
    "p_zero":             ["-u", URL, "-p", "0"],
    "p_65536":            ["-u", URL, "-p", "65536"],
    "p_negative":         ["-u", URL, "-p", "-1"],
    "p_text":             ["-u", URL, "-p", "abc"],
    "p_suffix":           ["-u", URL, "-p", "53x"],
    "p_empty":            ["-u", URL, "-p", ""],
    "p_twice":            ["-u", URL, "-p", "5300", "-p", "5301"],
    "p_twice_same":       ["-u", URL, "-p", "5300", "-p", "5300"],
    "p_without_value":    ["-u", URL, "-p"],
    "w_zero":             ["-u", URL, "-w", "0"],
    "w_3601":             ["-u", URL, "-w", "3601"],
    "w_fraction":         ["-u", URL, "-w", "1.5"],
    "w_twice":            ["-u", URL, "-w", "3", "-w", "3"],
    "a_hostname":         ["-u", URL, "-a", "localhost"],
    "a_brackets":         ["-u", URL, "-a", "[::1]"],
    "a_zone_index":       ["-u", URL, "-a", "fe80::1%lo"],
    "a_bad_ipv4":         ["-u", URL, "-a", "256.1.1.1"],
    "a_twice":            ["-u", URL, "-a", "127.0.0.1", "-a", "127.0.0.1"],
    "unknown_option":     ["-u", URL, "-x"],                     # INTERPRETATION
    "positional":         ["-u", URL, "extra"],                  # INTERPRETATION
}


@pytest.mark.parametrize("case", USAGE_ERRORS.keys())
def test_usage_error(case):
    rc, out, err = run(*USAGE_ERRORS[case])
    assert rc == EX_USAGE, (rc, err)
    assert err.strip() != ""
    assert out == ""                                             # stdout only for the log and -h


@pytest.mark.parametrize("value", ["1", "65535"])
def test_port_bounds_accepted(upstream, value):
    if value == "1":
        pytest.skip("port 1 needs privileges")
    p = Proxy(upstream.url(), port=int(value))
    p.kill()


@pytest.mark.parametrize("value", ["1", "3600"])
def test_timeout_bounds_accepted(upstream, value):
    p = Proxy(upstream.url(), timeout=value)
    p.kill()


def test_http_url_accepted(upstream):
    p = Proxy(upstream.url())                                    # http:// for local testing
    assert parse(p.udp(build_query("a.example.org")))["rcode"] == 0
    p.kill()


def test_uppercase_scheme_accepted(upstream):                  # INTERPRETATION (RFC 3986: case-insensitive)
    p = Proxy(upstream.url().replace("http://", "HTTP://"))
    p.kill()


def test_repeatable_z_and_b(upstream, tmp_path):
    z1 = write(tmp_path, "a.zone", HOME_LAN)
    z2 = write(tmp_path, "b.zone", "$ORIGIN other.lan.\n$TTL 60\n@ IN SOA ns r 1 2 3 4 5\nx IN A 1.2.3.4\n")
    b1 = write(tmp_path, "a.txt", "one.example\n")
    b2 = write(tmp_path, "b.txt", "two.example\n")
    p = Proxy(upstream.url(), "-z", z1, "-z", z2, "-b", b1, "-b", b2)
    try:
        assert parse(p.udp(build_query("x.other.lan")))["aa"]
        assert parse(p.udp(build_query("router.home.lan")))["aa"]
        assert parse(p.udp(build_query("one.example")))["rcode"] == 3
        assert parse(p.udp(build_query("two.example")))["rcode"] == 3
    finally:
        p.kill()


def test_insecure_flag_accepted(upstream):
    p = Proxy(upstream.url(), "--insecure")
    p.kill()


# =========================================================================== config errors

def test_missing_zone_file_is_config_error(tmp_path):
    rc, out, err = run("-u", URL, "-p", free_port(), "-z", tmp_path / "nope.zone", "-a", "127.0.0.1")
    assert rc == EX_CONFIG and "nope.zone:" in err


def test_missing_blocklist_is_config_error(tmp_path):
    rc, out, err = run("-u", URL, "-p", free_port(), "-b", tmp_path / "nope.txt", "-a", "127.0.0.1")
    assert rc == EX_CONFIG and "nope.txt:" in err


def test_config_error_before_serving(tmp_path):
    bad = write(tmp_path, "bad.zone", "this is not a zone\n")
    rc, out, err = run("-u", URL, "-p", free_port(), "-z", bad, "-a", "127.0.0.1")
    assert rc == EX_CONFIG and "listening on" not in err


def test_two_zones_same_apex(tmp_path):
    z = "$ORIGIN home.lan.\n$TTL 60\n@ IN SOA ns r 1 2 3 4 5\n"
    a = write(tmp_path, "a.zone", z)
    b = write(tmp_path, "b.zone", z)
    rc, out, err = run("-u", URL, "-p", free_port(), "-z", a, "-z", b, "-a", "127.0.0.1")
    assert rc == EX_CONFIG


# =========================================================================== bind errors

@pytest.mark.parametrize("proto", [socket.SOCK_DGRAM, socket.SOCK_STREAM])
def test_port_in_use_ipv4(proto):
    port = free_port()
    s = socket.socket(socket.AF_INET, proto)
    s.bind(("127.0.0.1", port))
    if proto == socket.SOCK_STREAM:
        s.listen(1)
    try:
        rc, out, err = run("-u", URL, "-p", port, "-a", "127.0.0.1")
        assert rc == EX_UNAVAILABLE and err.strip()
    finally:
        s.close()


@pytest.mark.skipif(not ipv6_available(), reason="IPv6 loopback not available")
@pytest.mark.parametrize("proto", [socket.SOCK_DGRAM, socket.SOCK_STREAM])
def test_port_in_use_ipv6_without_a(proto):
    port = free_port()
    s = socket.socket(socket.AF_INET6, proto)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(("::", port))
    if proto == socket.SOCK_STREAM:
        s.listen(1)
    try:
        rc, out, err = run("-u", URL, "-p", port)
        assert rc == EX_UNAVAILABLE
    finally:
        s.close()


def test_address_not_local():
    rc, out, err = run("-u", URL, "-p", free_port(), "-a", "192.0.2.1")
    assert rc == EX_UNAVAILABLE


# =========================================================================== start-up

def test_listening_lines_format(upstream):
    p = Proxy(upstream.url())
    try:
        assert p.listening_lines() == ["listening on 127.0.0.1:%d" % p.port] * 2
        assert p.stdout_lines == []                               # stdout empty until a message
    finally:
        p.kill()


def test_startup_within_5s_with_big_inputs(upstream, tmp_path):
    zones = []
    for i in range(10):
        body = "$ORIGIN z%d.lan.\n$TTL 60\n@ IN SOA ns r 1 2 3 4 5\n" % i
        body += "".join("h%d IN A 10.0.%d.%d\n" % (j, j // 250, j % 250) for j in range(1000))
        zones += ["-z", write(tmp_path, "z%d.zone" % i, body)]
    bl = write(tmp_path, "big.txt", "".join("host%d.ads%d.example.com\n" % (i, i % 97) for i in range(200000)))
    t = time.time()
    p = Proxy(upstream.url(), *zones, "-b", bl)
    try:
        assert time.time() - t < 5.0
        assert parse(p.udp(build_query("host5.ads5.example.com")))["rcode"] == 3
        assert parse(p.udp(build_query("h999.z9.lan")))["aa"]
    finally:
        p.kill()


def test_signal_before_listening_exits_nonzero(tmp_path):
    bl = write(tmp_path, "big.txt", "".join("host%d.example.com\n" % i for i in range(200000)))
    proc = subprocess.Popen([BIN, "-u", URL, "-p", str(free_port()), "-a", "127.0.0.1", "-b", str(bl)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.005)
    proc.send_signal(signal.SIGTERM)
    rc = proc.wait(timeout=5)
    out, err = proc.communicate()
    if b"listening on" in err:
        pytest.skip("start-up finished before the signal arrived")
    assert rc != 0


# =========================================================================== shutdown

@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_signal_exits_zero_within_2s(upstream, sig):
    p = Proxy(upstream.url())
    p.udp(build_query("a.example.org"))
    t = time.time()
    assert p.stop(sig) == 0
    assert time.time() - t < 2.0


def test_shutdown_with_open_idle_tcp(upstream):
    p = Proxy(upstream.url())
    c = socket.create_connection(p.target())
    try:
        t = time.time()
        assert p.stop() == 0 and time.time() - t < 2.0
    finally:
        c.close()


def test_survives_sigpipe(upstream):
    p = Proxy(upstream.url())
    try:
        p.proc.send_signal(signal.SIGPIPE)
        time.sleep(0.2)
        assert p.proc.poll() is None
        assert p.udp(build_query("a.example.org")) is not None
    finally:
        p.kill()

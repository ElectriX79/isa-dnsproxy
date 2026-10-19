"""
Black-box tests for zone file loading in isa-dnsproxy.

They only exercise start-up, exactly like test_blocklist.py:
  * a broken zone file must make the program exit with EX_CONFIG (78) and
    print `<file>:<line>: <message>` on stderr,
  * a valid one must NOT fail that way.
Answers from the zones (dig) are not tested here - add those once the proxy
answers queries.

Every case is derived from the "Zone file format" section of the assignment.
Cases whose expected result is an interpretation of the assignment, not an
explicit sentence in it, are marked with  # INTERPRETATION.

Run:  pytest -v tests/test_zonefile.py
      ISA_BIN=./isa-dnsproxy pytest -v tests/test_zonefile.py
"""

import os
import re
import socket
import subprocess
from pathlib import Path

import pytest

BIN = os.environ.get("ISA_BIN", "./isa-dnsproxy")
UPSTREAM = "https://cloudflare-dns.com/dns-query"
EX_CONFIG = 78
STARTUP_WAIT = 1.0
ANY_LINE = None          # file-level error: any line number accepted (0 recommended)

# A minimal valid header used by most cases.
HDR = "$ORIGIN home.lan.\n$TTL 3600\n@ IN SOA ns1 admin 1 7200 3600 1209600 3600\n"
HDR_LINES = 3            # number of lines in HDR


# --------------------------------------------------------------------------- helpers

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_proxy(*zonefiles, wait=STARTUP_WAIT):
    """Start the proxy with the given zone files.

    Returns (returncode or None if still running, stdout, stderr).
    A still-running process is terminated.
    """
    args = [BIN, "-u", UPSTREAM, "-p", str(free_port())]
    for z in zonefiles:
        args += ["-z", str(z)]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, errors="replace")
    try:
        rc = proc.wait(timeout=wait)
    except subprocess.TimeoutExpired:
        rc = None
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    out, err = proc.communicate()
    return rc, out, err


def write(tmp_path: Path, name: str, content, binary=False) -> Path:
    p = tmp_path / name
    if binary:
        p.write_bytes(content)
    else:
        p.write_text(content)
    return p


def assert_valid(rc, out, err, path=None):
    assert rc != EX_CONFIG, f"valid zone rejected (exit 78), stderr:\n{err}"
    assert rc is None or rc >= 0, f"crashed with signal {-rc}, stderr:\n{err}"
    assert out == "", f"stdout must stay empty at start-up, got:\n{out}"


def assert_config_error(rc, err, path, line):
    assert rc == EX_CONFIG, f"expected exit 78, got {rc}, stderr:\n{err}"
    num = r"\d+" if line is ANY_LINE else str(line)
    pattern = rf"^{re.escape(str(path))}:{num}: \S"
    assert re.search(pattern, err, re.M), (
        f"expected a line '{path}:{'<n>' if line is ANY_LINE else line}: <message>' "
        f"on stderr, got:\n{err}"
    )


# =========================================================================== VALID

SPEC_EXAMPLE = """\
$ORIGIN home.lan.
$TTL 3600
@       IN SOA   ns1.home.lan. admin.home.lan. 2026091401 7200 3600 1209600 3600
@       IN NS    ns1
@       IN MX    10 mail
ns1     IN A     192.168.1.1
router  IN A     192.168.1.1
router  IN AAAA  fd00:cafe::1
nas     IN A     192.168.1.20
mail    IN A     192.168.1.25
media   IN CNAME nas
"""

VALID_CASES = {
    # ---- the example from the assignment
    "spec_example": SPEC_EXAMPLE,

    # ---- origin
    "no_origin_soa_first_absolute": (
        "home.lan. 3600 IN SOA ns1 admin 1 2 3 4 5\n"
        "www 3600 IN A 10.0.0.1\n"              # relative to the SOA owner
    ),
    "no_origin_soa_first_mixed_case": (
        "Home.LAN. 3600 IN SOA ns1 admin 1 2 3 4 5\n"
        "WWW.home.lan. 3600 A 10.0.0.1\n"
    ),
    "origin_soa_not_first": (                    # with $ORIGIN the SOA may come later
        "$ORIGIN home.lan.\n$TTL 60\n"
        "www A 10.0.0.1\n"
        "@ SOA ns1 admin 1 2 3 4 5\n"
    ),
    "origin_mixed_case": "$ORIGIN Home.Lan.\n$TTL 60\n@ SOA ns1 admin 1 2 3 4 5\n",
    "soa_owner_explicit_absolute": (
        "$ORIGIN home.lan.\n$TTL 60\nhome.lan. SOA ns1 admin 1 2 3 4 5\n"
    ),
    "single_label_origin": "$ORIGIN lan.\n$TTL 60\n@ SOA ns1 admin 1 2 3 4 5\nx A 1.2.3.4\n",

    # ---- $TTL and record TTLs
    "ttl_zero": "$ORIGIN home.lan.\n$TTL 0\n@ SOA ns1 admin 1 2 3 4 5\n",
    "ttl_max": "$ORIGIN home.lan.\n$TTL 2147483647\n@ SOA ns1 admin 1 2 3 4 5\n",
    "record_ttl_without_default": (
        "$ORIGIN home.lan.\n@ 60 SOA ns1 admin 1 2 3 4 5\nwww 0 A 1.2.3.4\n"
    ),
    "record_ttl_overrides_default": HDR + "www 60 IN A 1.2.3.4\n",
    "ttl_directive_repeated": (
        "$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 1 2 3 4 5\n"
        "$TTL 120\na A 1.1.1.1\n$TTL 300\nb A 2.2.2.2\n"
    ),
    "same_type_same_ttl_explicit_and_default": HDR + "www A 1.1.1.1\nwww 3600 A 2.2.2.2\n",
    "different_types_different_ttl": HDR + "www 60 A 1.1.1.1\nwww 120 AAAA ::1\n",
    "same_name_rrsets_after_ttl_change": (   # different owners, TTL change is irrelevant
        HDR + "a A 1.1.1.1\n$TTL 60\nb A 2.2.2.2\n"
    ),

    # ---- class and mnemonics
    "class_omitted": HDR + "www A 1.2.3.4\n",
    "class_lowercase": HDR + "www in A 1.2.3.4\n",
    "class_mixed_case": HDR + "www In A 1.2.3.4\n",
    "type_lowercase": HDR + "www a 1.2.3.4\nwww aaaa ::1\nm mx 10 mail\nn ns ns1\nc cname www\n",
    "type_mixed_case": HDR + "www Aaaa ::1\n",
    "soa_lowercase": "$ORIGIN home.lan.\n$TTL 60\n@ in soa ns1 admin 1 2 3 4 5\n",

    # ---- owner handling
    "owner_at": HDR + "@ A 1.2.3.4\n",
    "owner_absolute_inside": HDR + "www.home.lan. A 1.2.3.4\n",
    "owner_uppercase": HDR + "WWW A 1.2.3.4\nwww AAAA ::1\n",
    "owner_inherited_space": HDR + "www A 1.2.3.4\n AAAA ::1\n",
    "owner_inherited_tab": HDR + "www A 1.2.3.4\n\tAAAA ::1\n",
    "owner_inherited_with_ttl": HDR + "www 60 A 1.2.3.4\n    60 A 5.6.7.8\n",
    "owner_inherited_after_comment_line": HDR + "www A 1.2.3.4\n; comment\n AAAA ::1\n",
    "owner_inherited_after_blank_line": HDR + "www A 1.2.3.4\n\n AAAA ::1\n",
    "owner_deep_ancestors": HDR + "a.b.c.d A 1.2.3.4\nb.c.d AAAA ::1\n",
    "owner_label_63": HDR + "a" * 63 + " A 1.2.3.4\n",
    "owner_name_253": (
        "$ORIGIN " + "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + ".lan.\n$TTL 60\n"
        "@ SOA ns1 admin 1 2 3 4 5\n" + "d" * 57 + " A 1.2.3.4\n"   # 57+1+63*3+3+3 = 253
    ),
    "owner_underscore_and_hyphen": HDR + "_dmarc A 1.2.3.4\n-x- A 1.2.3.4\n",

    # ---- names in rdata
    "rdata_at": HDR + "c CNAME @\n",
    "rdata_absolute_outside_zone": HDR + "@ NS ns.provider.example.\nc CNAME www.example.com.\n",
    "rdata_relative": HDR + "@ MX 10 mail\nmail A 1.2.3.4\n",
    "soa_names_absolute": (
        "$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1.home.lan. admin.home.lan. 1 2 3 4 5\n"
    ),

    # ---- record sets
    "multiple_ns": HDR + "@ NS ns1\n@ NS ns2\n@ NS ns.other.example.\n",
    "multiple_mx_same_pref": HDR + "@ MX 10 mail1\n@ MX 10 mail2\n",
    "multiple_a": HDR + "www A 1.1.1.1\nwww A 2.2.2.2\nwww A 3.3.3.3\n",
    "cname_to_name_in_zone": HDR + "nas A 1.2.3.4\nmedia CNAME nas\n",
    "cname_to_nonexistent": HDR + "media CNAME nothing\n",
    "cname_chain": HDR + "a CNAME b\nb CNAME c\nc A 1.2.3.4\n",
    "cname_below_apex_with_children": HDR + "x CNAME y\na.x A 1.2.3.4\n",   # child is a different owner
    "ns_below_apex_is_ordinary": HDR + "sub NS ns1\nsub A 1.2.3.4\n",
    # Duplicate identical records are not in the list of errors, and RFC 2181
    # says duplicates are simply suppressed.                         # INTERPRETATION
    "duplicate_identical_record": HDR + "www A 1.2.3.4\nwww A 1.2.3.4\n",

    # ---- rdata ranges
    "a_zero_and_broadcast": HDR + "a A 0.0.0.0\nb A 255.255.255.255\n",
    "aaaa_forms": HDR + (
        "a AAAA ::\nb AAAA ::1\nc AAAA 2001:db8::1\n"
        "d AAAA 2001:0db8:0000:0000:0000:0000:0000:0001\n"
        "e AAAA ::ffff:192.0.2.1\nf AAAA FD00:CAFE::1\n"
    ),
    "mx_pref_zero": HDR + "@ MX 0 mail\n",
    "mx_pref_max": HDR + "@ MX 65535 mail\n",
    "soa_counters_max": (
        "$ORIGIN home.lan.\n$TTL 60\n"
        "@ SOA ns1 admin 4294967295 4294967295 4294967295 4294967295 2147483647\n"
    ),
    "soa_counters_zero": "$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 0 0 0 0 0\n",

    # ---- comments, whitespace, line endings
    "comment_full_line": "; header\n" + HDR + "; trailing\n",
    "comment_inline": HDR + "www A 1.2.3.4 ; the web\n",
    "comment_no_space": HDR + "www A 1.2.3.4;comment\n",
    "comment_after_directive": "$ORIGIN home.lan. ; origin\n$TTL 60 ; ttl\n@ SOA ns1 admin 1 2 3 4 5\n",
    "comment_hides_garbage": HDR + "www A 1.2.3.4 ; *** not rdata ***\n",
    "blank_and_whitespace_lines": HDR + "\n   \n\t\n" + "www A 1.2.3.4\n\n",
    "tabs_and_multiple_spaces": HDR + "www\t\t3600   IN\tA \t 1.2.3.4\n",
    "no_trailing_newline": HDR + "www A 1.2.3.4",
    "trailing_whitespace": HDR + "www A 1.2.3.4   \t\n",

    # ---- registered but unsupported types: warning, not an error
    "unsupported_txt": HDR + 'www TXT "hello world"\n',
    "unsupported_srv": HDR + "_sip._tcp SRV 10 60 5060 sip\n",
    "unsupported_ptr": HDR + "1 PTR host\n",
    "unsupported_caa": HDR + 'www CAA 0 issue "letsencrypt.org"\n',
    "unsupported_type_lowercase": HDR + 'www txt "x"\n',
}


@pytest.mark.parametrize("name", VALID_CASES.keys())
def test_valid_zone(tmp_path, name):
    path = write(tmp_path, f"{name}.zone", VALID_CASES[name])
    assert_valid(*run_proxy(path), path)


def test_crlf_line_endings(tmp_path):
    content = SPEC_EXAMPLE.replace("\n", "\r\n").encode()
    path = write(tmp_path, "crlf.zone", content, binary=True)
    assert_valid(*run_proxy(path))


def test_crlf_with_comment(tmp_path):
    content = (HDR + "www A 1.2.3.4 ; x\n").replace("\n", "\r\n").encode()
    path = write(tmp_path, "crlf_comment.zone", content, binary=True)
    assert_valid(*run_proxy(path))


def test_unsupported_type_prints_warning(tmp_path):
    path = write(tmp_path, "txt.zone", HDR + 'www TXT "x"\n')
    rc, out, err = run_proxy(path)
    assert_valid(rc, out, err)
    assert err.strip() != "", "a skipped record MUST produce a warning on stderr"


def test_multiple_zone_files(tmp_path):
    a = write(tmp_path, "a.zone", SPEC_EXAMPLE)
    b = write(tmp_path, "b.zone", "$ORIGIN example.test.\n$TTL 60\n@ SOA ns admin 1 2 3 4 5\n")
    assert_valid(*run_proxy(a, b))


def test_nested_zones(tmp_path):
    parent = write(tmp_path, "parent.zone", SPEC_EXAMPLE)
    child = write(tmp_path, "child.zone",
                  "$ORIGIN sub.home.lan.\n$TTL 60\n@ SOA ns admin 1 2 3 4 5\nx A 1.2.3.4\n")
    assert_valid(*run_proxy(parent, child))


def test_large_zone_loads(tmp_path):
    body = "".join(f"host{i} A 10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}\n"
                   for i in range(50_000))
    path = write(tmp_path, "big.zone", HDR + body)
    assert_valid(*run_proxy(path, wait=5))


# =========================================================================== INVALID
# (content, line number of the error; ANY_LINE for file-level errors)

INVALID_CASES = {
    # ---- SOA
    "empty_file": ("", ANY_LINE),
    "only_comments": ("; nothing\n\n; here\n", ANY_LINE),
    "missing_soa": ("$ORIGIN home.lan.\n$TTL 60\nwww A 1.2.3.4\n", ANY_LINE),
    "two_soa": (HDR + "@ SOA ns1 admin 2 2 3 4 5\n", HDR_LINES + 1),
    "soa_owner_not_origin": ("$ORIGIN home.lan.\n$TTL 60\nwww SOA ns1 admin 1 2 3 4 5\n", 3),
    "soa_owner_absolute_other": ("$ORIGIN home.lan.\n$TTL 60\nother.lan. SOA ns1 admin 1 2 3 4 5\n", 3),
    "no_origin_first_not_soa": ("home.lan. 60 A 1.2.3.4\n", 1),
    "no_origin_first_soa_relative": ("home 60 SOA ns1 admin 1 2 3 4 5\n", 1),
    "no_origin_first_soa_at": ("@ 60 SOA ns1 admin 1 2 3 4 5\n", 1),
    "no_origin_relative_before_soa": ("www 60 A 1.2.3.4\nhome.lan. 60 SOA a b 1 2 3 4 5\n", 1),
    "soa_parentheses": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin ( 1 2 3 4 5 )\n", 3),
    "soa_multiline": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin (\n 1 2 3 4 5 )\n", 3),

    # ---- $ORIGIN
    "origin_twice": ("$ORIGIN home.lan.\n$ORIGIN home.lan.\n$TTL 60\n@ SOA a b 1 2 3 4 5\n", 2),
    "origin_after_record": (HDR + "$ORIGIN other.lan.\n", HDR_LINES + 1),
    "origin_relative": ("$ORIGIN home.lan\n$TTL 60\n@ SOA a b 1 2 3 4 5\n", 1),
    "origin_missing_name": ("$ORIGIN\n", 1),
    "origin_extra_token": ("$ORIGIN home.lan. extra\n", 1),
    "origin_empty_label": ("$ORIGIN home..lan.\n", 1),
    "origin_only_dot": ("$ORIGIN .\n", 1),
    "origin_label_64": ("$ORIGIN " + "a" * 64 + ".lan.\n", 1),

    # ---- $TTL
    "ttl_missing_value": ("$TTL\n", 1),
    "ttl_not_number": ("$TTL abc\n", 1),
    "ttl_negative": ("$TTL -1\n", 1),
    "ttl_plus_sign": ("$TTL +60\n", 1),
    "ttl_too_large": ("$TTL 2147483648\n", 1),
    "ttl_huge": ("$TTL 99999999999999999999999\n", 1),
    "ttl_unit_suffix": ("$TTL 1h\n", 1),
    "ttl_extra_token": ("$TTL 60 60\n", 1),

    # ---- other directives
    "include_directive": ("$INCLUDE other.zone\n", 1),
    "generate_directive": ("$GENERATE 1-10 host$ A 10.0.0.$\n", 1),
    "unknown_directive": ("$FOO bar\n", 1),

    # ---- owner
    "first_record_without_owner": ("$ORIGIN home.lan.\n$TTL 60\n @ SOA a b 1 2 3 4 5\n", 3),
    "first_record_without_owner_no_origin": (" home.lan. 60 SOA a b 1 2 3 4 5\n", 1),
    "owner_outside_zone": (HDR + "www.example.com. A 1.2.3.4\n", HDR_LINES + 1),
    "owner_parent_of_apex": (HDR + "lan. A 1.2.3.4\n", HDR_LINES + 1),
    "owner_suffix_not_label_boundary": (HDR + "xhome.lan. A 1.2.3.4\n", HDR_LINES + 1),
    "owner_empty_label": (HDR + "a..b A 1.2.3.4\n", HDR_LINES + 1),
    "owner_leading_dot": (HDR + ".www A 1.2.3.4\n", HDR_LINES + 1),
    "owner_label_64": (HDR + "a" * 64 + " A 1.2.3.4\n", HDR_LINES + 1),
    "owner_name_254": (
        "$ORIGIN " + "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + ".lan.\n$TTL 60\n"
        "@ SOA ns1 admin 1 2 3 4 5\n" + "d" * 58 + " A 1.2.3.4\n", 4
    ),

    # ---- record form
    "owner_only": (HDR + "www\n", HDR_LINES + 1),
    "owner_ttl_only": (HDR + "www 60\n", HDR_LINES + 1),
    "owner_ttl_class_only": (HDR + "www 60 IN\n", HDR_LINES + 1),
    "class_before_ttl": (HDR + "www IN 60 A 1.2.3.4\n", HDR_LINES + 1),
    "class_after_type": (HDR + "www A IN 1.2.3.4\n", HDR_LINES + 1),
    "class_ch": (HDR + "www CH A 1.2.3.4\n", HDR_LINES + 1),
    "class_any": (HDR + "www ANY A 1.2.3.4\n", HDR_LINES + 1),
    "two_ttls": (HDR + "www 60 60 A 1.2.3.4\n", HDR_LINES + 1),
    "record_ttl_negative": (HDR + "www -1 A 1.2.3.4\n", HDR_LINES + 1),
    "record_ttl_too_large": (HDR + "www 2147483648 A 1.2.3.4\n", HDR_LINES + 1),
    "record_ttl_unit": (HDR + "www 1h A 1.2.3.4\n", HDR_LINES + 1),
    "unregistered_type": (HDR + "www FOO 1.2.3.4\n", HDR_LINES + 1),
    "type_number_garbage": (HDR + "www A1 1.2.3.4\n", HDR_LINES + 1),
    "no_ttl_and_no_default": ("$ORIGIN home.lan.\n@ 60 SOA a b 1 2 3 4 5\nwww A 1.2.3.4\n", 3),
    "no_ttl_on_first_soa": ("$ORIGIN home.lan.\n@ SOA a b 1 2 3 4 5\n", 2),

    # ---- A
    "a_missing": (HDR + "www A\n", HDR_LINES + 1),
    "a_octet_256": (HDR + "www A 256.1.1.1\n", HDR_LINES + 1),
    "a_three_octets": (HDR + "www A 1.2.3\n", HDR_LINES + 1),
    "a_five_octets": (HDR + "www A 1.2.3.4.5\n", HDR_LINES + 1),
    "a_ipv6": (HDR + "www A ::1\n", HDR_LINES + 1),
    "a_text": (HDR + "www A localhost\n", HDR_LINES + 1),
    "a_extra_token": (HDR + "www A 1.2.3.4 5.6.7.8\n", HDR_LINES + 1),

    # ---- AAAA
    "aaaa_missing": (HDR + "www AAAA\n", HDR_LINES + 1),
    "aaaa_ipv4": (HDR + "www AAAA 1.2.3.4\n", HDR_LINES + 1),
    "aaaa_zone_index": (HDR + "www AAAA fe80::1%eth0\n", HDR_LINES + 1),
    "aaaa_brackets": (HDR + "www AAAA [::1]\n", HDR_LINES + 1),
    "aaaa_triple_colon": (HDR + "www AAAA :::1\n", HDR_LINES + 1),
    "aaaa_two_double_colons": (HDR + "www AAAA 1::2::3\n", HDR_LINES + 1),
    "aaaa_group_too_long": (HDR + "www AAAA 12345::1\n", HDR_LINES + 1),
    "aaaa_extra_token": (HDR + "www AAAA ::1 ::2\n", HDR_LINES + 1),

    # ---- NS / CNAME
    "ns_missing": (HDR + "@ NS\n", HDR_LINES + 1),
    "ns_extra_token": (HDR + "@ NS ns1 ns2\n", HDR_LINES + 1),
    "ns_empty_label": (HDR + "@ NS ns1..home.lan.\n", HDR_LINES + 1),
    "ns_label_64": (HDR + "@ NS " + "a" * 64 + "\n", HDR_LINES + 1),
    "cname_missing": (HDR + "c CNAME\n", HDR_LINES + 1),
    "cname_extra_token": (HDR + "c CNAME a b\n", HDR_LINES + 1),
    "cname_empty_label": (HDR + "c CNAME a..b\n", HDR_LINES + 1),

    # ---- MX
    "mx_missing_all": (HDR + "@ MX\n", HDR_LINES + 1),
    "mx_missing_exchange": (HDR + "@ MX 10\n", HDR_LINES + 1),
    "mx_pref_not_number": (HDR + "@ MX ten mail\n", HDR_LINES + 1),
    "mx_pref_negative": (HDR + "@ MX -1 mail\n", HDR_LINES + 1),
    "mx_pref_65536": (HDR + "@ MX 65536 mail\n", HDR_LINES + 1),
    "mx_swapped": (HDR + "@ MX mail 10\n", HDR_LINES + 1),
    "mx_extra_token": (HDR + "@ MX 10 mail extra\n", HDR_LINES + 1),
    "mx_bad_exchange": (HDR + "@ MX 10 a..b\n", HDR_LINES + 1),

    # ---- SOA rdata
    "soa_missing_rdata": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA\n", 3),
    "soa_missing_rname": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1\n", 3),
    "soa_missing_minimum": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 1 2 3 4\n", 3),
    "soa_extra_token": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 1 2 3 4 5 6\n", 3),
    "soa_serial_too_large": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 4294967296 2 3 4 5\n", 3),
    "soa_refresh_too_large": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 1 4294967296 3 4 5\n", 3),
    "soa_retry_negative": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 1 2 -3 4 5\n", 3),
    "soa_expire_text": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 1 2 3 x 5\n", 3),
    "soa_minimum_too_large": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 1 2 3 4 2147483648\n", 3),
    "soa_counter_unit": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA ns1 admin 1 2h 3 4 5\n", 3),
    "soa_bad_mname": ("$ORIGIN home.lan.\n$TTL 60\n@ SOA a..b admin 1 2 3 4 5\n", 3),

    # ---- RRset TTL rule (RFC 2181)
    "rrset_ttl_mismatch": (HDR + "www 60 A 1.1.1.1\nwww 120 A 2.2.2.2\n", HDR_LINES + 2),
    "rrset_ttl_mismatch_default": (HDR + "www A 1.1.1.1\nwww 60 A 2.2.2.2\n", HDR_LINES + 2),
    "rrset_ttl_mismatch_inherited_owner": (HDR + "www 60 A 1.1.1.1\n 120 A 2.2.2.2\n", HDR_LINES + 2),
    "rrset_ttl_mismatch_after_ttl_change": (HDR + "www A 1.1.1.1\n$TTL 60\nwww A 2.2.2.2\n", HDR_LINES + 3),

    # ---- CNAME rules
    "cname_then_a": (HDR + "c CNAME www\nc A 1.2.3.4\n", HDR_LINES + 2),
    "a_then_cname": (HDR + "c A 1.2.3.4\nc CNAME www\n", HDR_LINES + 2),
    "two_cnames_same_owner": (HDR + "c CNAME a\nc CNAME b\n", HDR_LINES + 2),
    "cname_at_apex": (HDR + "@ CNAME www\n", HDR_LINES + 1),
    "cname_then_mx": (HDR + "c CNAME www\nc MX 10 mail\n", HDR_LINES + 2),
    # A skipped record still makes its owner "own a record".       # INTERPRETATION
    "cname_then_unsupported_type": (HDR + 'c CNAME www\nc TXT "x"\n', HDR_LINES + 2),
    "unsupported_type_then_cname": (HDR + 'c TXT "x"\nc CNAME www\n', HDR_LINES + 2),

    # ---- error line numbers
    "error_after_comments_and_blanks": (HDR + "; c\n\n   \n; c\nbad..name A 1.2.3.4\n", HDR_LINES + 5),
    "error_in_last_line_without_newline": (HDR + "www A 1.2.3.999", HDR_LINES + 1),
}


@pytest.mark.parametrize("name", INVALID_CASES.keys())
def test_invalid_zone(tmp_path, name):
    content, line = INVALID_CASES[name]
    path = write(tmp_path, f"{name}.zone", content)
    rc, out, err = run_proxy(path)
    assert_config_error(rc, err, path, line)
    assert out == ""


def test_invalid_crlf_line_number(tmp_path):
    content = (HDR + "www A 1.2.3.4\nbad A 1.2.3\n").replace("\n", "\r\n").encode()
    path = write(tmp_path, "crlf_bad.zone", content, binary=True)
    rc, _, err = run_proxy(path)
    assert_config_error(rc, err, path, HDR_LINES + 2)


def test_error_in_second_file(tmp_path):
    good = write(tmp_path, "good.zone", SPEC_EXAMPLE)
    bad = write(tmp_path, "bad.zone", HDR + "www A 1.2.3\n")
    rc, _, err = run_proxy(good, bad)
    assert_config_error(rc, err, bad, HDR_LINES + 1)


def test_missing_file(tmp_path):
    path = tmp_path / "does_not_exist.zone"
    rc, _, err = run_proxy(path)
    assert rc == EX_CONFIG, err
    assert str(path) in err


def test_directory_is_rejected(tmp_path):
    d = tmp_path / "a_directory"
    d.mkdir()
    rc, _, err = run_proxy(d)
    assert rc == EX_CONFIG, err


def test_dev_null_is_not_regular(tmp_path):
    rc, _, err = run_proxy("/dev/null")
    assert rc == EX_CONFIG, err


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_file(tmp_path):
    path = write(tmp_path, "secret.zone", SPEC_EXAMPLE)
    path.chmod(0o000)
    try:
        rc, _, err = run_proxy(path)
        assert rc == EX_CONFIG, err
    finally:
        path.chmod(0o644)


def test_binary_garbage(tmp_path):
    path = write(tmp_path, "garbage.zone", bytes(range(256)) * 4, binary=True)
    rc, _, err = run_proxy(path)
    assert rc == EX_CONFIG, f"expected exit 78, got {rc}, stderr:\n{err}"


def test_very_long_line(tmp_path):
    path = write(tmp_path, "long.zone", HDR + "www A " + "1" * 100_000 + "\n")
    rc, _, err = run_proxy(path)
    assert_config_error(rc, err, path, HDR_LINES + 1)


# Two files with the same apex: the assignment does not say what happens.
# Rejecting it at start-up is the safest choice; change this test if you
# decide otherwise and document the decision in README.md.   # INTERPRETATION
def test_duplicate_apex_in_two_files(tmp_path):
    a = write(tmp_path, "a.zone", SPEC_EXAMPLE)
    b = write(tmp_path, "b.zone", SPEC_EXAMPLE)
    rc, _, err = run_proxy(a, b)
    assert rc == EX_CONFIG, f"expected exit 78, got {rc}, stderr:\n{err}"
"""
Black-box tests for blocklist loading in isa-dnsproxy.

They only exercise start-up: a broken blocklist must make the program exit
with EX_CONFIG (78) and print `<file>:<line>: <message>` on stderr; a valid
one must NOT fail that way. Blocking of actual queries is not tested here
(add dig-based tests once the proxy answers queries).

Run:  pytest -v tests/test_blocklist.py
      ISA_BIN=./isa-dnsproxy pytest -v tests/test_blocklist.py
"""

import os
import re
import socket
import subprocess
import time
from pathlib import Path

import pytest

BIN = os.environ.get("ISA_BIN", "./isa-dnsproxy")
UPSTREAM = "https://cloudflare-dns.com/dns-query"
EX_CONFIG = 78
STARTUP_WAIT = 1.0      # seconds to wait for a config error before assuming success


# --------------------------------------------------------------------------- helpers

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_proxy(*blocklists, wait=STARTUP_WAIT):
    """Start the proxy with the given blocklists.

    Returns (returncode or None if still running, stdout, stderr).
    A still-running process is terminated.
    """
    args = [BIN, "-u", UPSTREAM, "-p", str(free_port())]
    for b in blocklists:
        args += ["-b", str(b)]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
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


def assert_valid(rc, out, err):
    assert rc != EX_CONFIG, f"valid blocklist rejected (exit 78), stderr:\n{err}"
    assert not re.search(r"^\S+:\d+:", err, re.M), f"unexpected config error on stderr:\n{err}"
    assert out == "", f"stdout must stay empty at start-up, got:\n{out}"


def assert_config_error(rc, err, path, line):
    assert rc == EX_CONFIG, f"expected exit 78, got {rc}, stderr:\n{err}"
    pattern = rf"^{re.escape(str(path))}:{line}: \S"
    assert re.search(pattern, err, re.M), (
        f"expected a line '{path}:{line}: <message>' on stderr, got:\n{err}"
    )


# --------------------------------------------------------------------------- valid files

VALID_CASES = {
    "spec_example": (
        "# advertising\n"
        "ads.example.com\n"
        "0.0.0.0 tracker.example.net telemetry.example.net\n"
    ),
    "empty_file": "",
    "only_comments": "# one\n#two\n   # three\n",
    "blank_and_whitespace_lines": "\n   \n\t\n \t \n",
    "no_trailing_newline": "ads.example.com",
    "inline_comment": "ads.example.com # comment\n",
    "comment_without_space": "ads.example.com#comment\n",
    "comment_hides_garbage": "ads.example.com # *** not a name ***\n",
    "tabs_and_multiple_spaces": "0.0.0.0\t\tads.example.com   \t tracker.example.net\n",
    "leading_whitespace": "    ads.example.com\n",
    "trailing_dot": "ads.example.com.\n",
    "uppercase": "ADS.Example.COM\n",
    "underscore_and_hyphens": "_dmarc.example.com -lead.example.com trail-.example.com\n",
    "hosts_header_ipv4": (
        "127.0.0.1 localhost\n"
        "127.0.0.1 localhost.localdomain\n"
        "127.0.0.1 local\n"
        "255.255.255.255 broadcasthost\n"
    ),
    "hosts_header_ipv6": (
        "::1 localhost ip6-localhost ip6-loopback\n"
        "fe00::0 ip6-localnet\n"
        "ff00::0 ip6-mcastprefix\n"
        "ff02::1 ip6-allnodes\n"
        "ff02::2 ip6-allrouters\n"
        "ff02::3 ip6-allhosts\n"
    ),
    "hosts_header_case_and_dot": "127.0.0.1 LOCALHOST. Broadcasthost\n",
    "ipv6_first_token_unchecked": "fe80::1%eth0 ads.example.com\n",
    "garbage_with_colon_first_token": "abc:*/xyz ads.example.com\n",
    "ipv6_only_on_line": "::\n",
    "digits_and_dots_ignored": "999.999.999.999 1.2.3 12345 ads.example.com\n",
    "digits_and_dots_not_first": "ads.example.com 0.0.0.0 1.2.3.4\n",
    "digit_name_with_letter_is_entry": "1.2.3.4a\n",
    "label_63": "a" * 63 + ".com\n",
    "name_253": ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61]) + "\n",
    "name_253_with_trailing_dot": ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61]) + ".\n",
    "labels_127": ".".join(["a"] * 127) + "\n",
    "duplicates": "ads.example.com\nads.example.com\nADS.EXAMPLE.COM.\n",
}


@pytest.mark.parametrize("name", VALID_CASES.keys())
def test_valid_blocklist(tmp_path, name):
    path = write(tmp_path, f"{name}.txt", VALID_CASES[name])
    assert_valid(*run_proxy(path))


def test_crlf_line_endings(tmp_path):
    path = write(
        tmp_path, "crlf.txt",
        b"# header\r\n0.0.0.0 ads.example.com tracker.example.net\r\n\r\nlast.example.com\r\n",
        binary=True,
    )
    assert_valid(*run_proxy(path))


def test_crlf_with_comment(tmp_path):
    path = write(tmp_path, "crlf_comment.txt", b"ads.example.com # x\r\n", binary=True)
    assert_valid(*run_proxy(path))


def test_many_names_on_one_line(tmp_path):
    names = " ".join(f"n{i}.example.com" for i in range(30000))
    path = write(tmp_path, "one_long_line.txt", "0.0.0.0 " + names + "\n")
    assert_valid(*run_proxy(path, wait=3))


def test_multiple_blocklists(tmp_path):
    a = write(tmp_path, "a.txt", "ads.example.com\n")
    b = write(tmp_path, "b.txt", "0.0.0.0 tracker.example.net\n")
    c = write(tmp_path, "c.txt", "")
    assert_valid(*run_proxy(a, b, c))


def test_200k_entries_load_fast(tmp_path):
    lines = "".join(f"0.0.0.0 host{i}.ads{i % 97}.example.com\n" for i in range(200_000))
    path = write(tmp_path, "big.txt", lines)
    start = time.monotonic()
    rc, out, err = run_proxy(path, wait=5)
    elapsed = time.monotonic() - start
    assert_valid(rc, out, err)
    # If the program already prints "listening on", it must do so within 5 s.
    if "listening on" in err:
        assert elapsed < 5.5


# --------------------------------------------------------------------------- invalid files
# (content, line number of the error)

INVALID_CASES = {
    "empty_label_middle": ("ads..example.com\n", 1),
    "empty_label_start": (".ads.example.com\n", 1),
    "only_dot": (".\n", 1),
    "double_trailing_dot": ("ads.example.com..\n", 1),
    "digits_with_empty_label": ("1..2\n", 1),
    "label_64": ("a" * 64 + ".com\n", 1),
    "name_254": (".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62]) + "\n", 1),
    # 128 labels cannot fit into 253 characters, so this also checks the length
    "labels_128": (".".join(["a"] * 128) + "\n", 1),
    "asterisk": ("*.example.com\n", 1),
    "slash": ("ads.example.com/path\n", 1),
    "at_sign": ("user@example.com\n", 1),
    "non_ascii": ("reklamy.príklad.sk\n", 1),
    "colon_in_second_token": ("0.0.0.0 a:b\n", 1),
    "colon_after_ignored_token": ("0.0.0.0 ads.example.com x:y\n", 1),
    "error_on_third_line": ("# ok\nads.example.com\nbad..name\n", 3),
    "error_after_blank_lines": ("\n\n\n\nbad*name\n", 5),
    "error_in_last_line_without_newline": ("ok.example.com\nbad..name", 2),
}


@pytest.mark.parametrize("name", INVALID_CASES.keys())
def test_invalid_blocklist(tmp_path, name):
    content, line = INVALID_CASES[name]
    path = write(tmp_path, f"{name}.txt", content)
    rc, out, err = run_proxy(path)
    assert_config_error(rc, err, path, line)
    assert out == ""


def test_invalid_crlf_line_number(tmp_path):
    path = write(tmp_path, "crlf_bad.txt", b"ok.example.com\r\nbad..name\r\n", binary=True)
    rc, _, err = run_proxy(path)
    assert_config_error(rc, err, path, 2)


def test_error_in_second_file(tmp_path):
    good = write(tmp_path, "good.txt", "ads.example.com\n")
    bad = write(tmp_path, "bad.txt", "ok.example.com\nbad..name\n")
    rc, _, err = run_proxy(good, bad)
    assert_config_error(rc, err, bad, 2)


def test_missing_file(tmp_path):
    path = tmp_path / "does_not_exist.txt"
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
    path = write(tmp_path, "secret.txt", "ads.example.com\n")
    path.chmod(0o000)
    try:
        rc, _, err = run_proxy(path)
        assert rc == EX_CONFIG, err
    finally:
        path.chmod(0o644)
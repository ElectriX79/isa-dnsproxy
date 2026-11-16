# isa-dnsproxy – filtering DNS-to-DoH proxy

**Author:** Samuel Chovan (xchovas00)
**Course:** ISA – Network Applications and Network Administration, FIT BUT (VUT v Brne), 2026/2027
**Assignment:** [NESFIT/ISA-Project](https://git.fit.vutbr.cz/NESFIT/ISA-Project) · **Guidelines:** [NESFIT/Project-Guidelines](https://git.fit.vutbr.cz/NESFIT/Project-Guidelines)

---

## Contents

1. [Overview](#1-overview)
2. [Building and running](#2-building-and-running)
3. [Architecture and concurrency](#3-architecture-and-concurrency)
4. [Libraries used](#4-libraries-used)
5. [Parsing and building DNS messages](#5-parsing-and-building-dns-messages)
6. [Zones: storage and lookup](#6-zones-storage-and-lookup)
7. [Blocklists](#7-blocklists)
8. [Forwarding over DoH](#8-forwarding-over-doh)
9. [Query log](#9-query-log)
10. [Design decisions and interpretations](#10-design-decisions-and-interpretations)
11. [Testing](#11-testing)
12. [Known limitations](#12-known-limitations)
13. [Use of AI](#13-use-of-ai)
14. [References](#14-references)

---

## 1. Overview

`isa-dnsproxy` is a DNS proxy for a home network, in the spirit of Pi-hole. It accepts plain DNS
queries (Do53) over **UDP and TCP**, on **IPv4 and IPv6**, and assigns every query exactly one verdict:

| Verdict | When | Response |
|---|---|---|
| `local` | the name belongs to a loaded zone (`-z`) | authoritative answer from the zone (AA = 1), NOERROR or NXDOMAIN |
| `blocked` | the name or one of its parents is in a blocklist (`-b`) | NXDOMAIN, empty sections, nothing is sent upstream |
| `forwarded` | otherwise | the query is sent encrypted over **DNS-over-HTTPS** (RFC 8484, POST) to the upstream (`-u`); the answer is returned to the client unchanged except for the ID |
| `invalid` | the message is malformed (steps 3–8) | FORMERR, NOTIMP or REFUSED |
| `dropped` | the message is shorter than 12 B or is a response (QR = 1) | none |

Every received message produces exactly one query log line on stdout.

## 2. Building and running

The project is built and run in the reference environment [dev-envs](https://git.fit.vutbr.cz/NESFIT/dev-envs)
(devShell `isa` chained with `c`):

```bash
nix develop dev-envs#isa -c nix develop dev-envs#c -c make        # build -> ./isa-dnsproxy
nix develop dev-envs#isa -c nix develop dev-envs#c -c make test   # automated tests
```

| Target | Description |
|---|---|
| `make` | build (`-std=c17 -Wall -Wextra -Wpedantic`, links `-lcurl`) |
| `make test` / `make test-fast` | all tests / without the slow idle-timeout test |
| `make debug` | build with `-g -O0` and AddressSanitizer + UBSan |
| `make clean` | remove build artifacts and test caches |
| `make zip LOGIN=xchovas00` | submission archive `xchovas00.zip` |
| `make NixDevShellName` | prints `c` |

### Usage

```text
./isa-dnsproxy -u DOH_URL [-p PORT] [-a ADDRESS] [-z ZONEFILE]... [-b BLOCKLIST]... [-w TIMEOUT] [--insecure]
./isa-dnsproxy -h | --help
```

| Option | Meaning |
|---|---|
| `-u DOH_URL` | upstream URL (`https://`, also `http://` for local testing), mandatory |
| `-p PORT` | UDP and TCP port 1..65535, default 53 |
| `-a ADDRESS` | literal IPv4/IPv6 address, otherwise all local addresses (IPv4 and IPv6) |
| `-z ZONEFILE` | zone file, repeatable |
| `-b BLOCKLIST` | blocklist, repeatable |
| `-w TIMEOUT` | upstream timeout in seconds 1..3600, default 3 |
| `--insecure` | disable TLS certificate and hostname verification |

Example (the files in `examples/` are taken from the assignment):

```bash
./isa-dnsproxy -u https://cloudflare-dns.com/dns-query -p 5300 -z examples/home.lan.zone -b examples/ads.txt
dig @127.0.0.1 -p 5300 router.home.lan A
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | stopped by SIGINT/SIGTERM, or `-h` |
| 64 (`EX_USAGE`) | invalid arguments |
| 69 (`EX_UNAVAILABLE`) | a socket cannot be opened (port in use, address not local) |
| 78 (`EX_CONFIG`) | error in a zone file or blocklist, unreadable file, two zones with the same apex |

## 3. Architecture and concurrency

### Modules

| File | Responsibility |
|---|---|
| `main.c` | start-up order: arguments → blocklists → zones → sockets → event loop |
| `arg_parser.c`, `config.c` | argument parsing and configuration |
| `blocklist_parser.c`, `hash_table.c` | loading blocklists into a hash table (FNV-1a) |
| `zonefile_parser.c` | loading zone files and zone lookup (`zone_answer`) |
| `dns_parser.c` | validation and parsing of a received message (steps 1–8) |
| `dns_response.c` | building responses (header, question, OPT, records) |
| `socket_binding.c` | opening UDP/TCP sockets for IPv4/IPv6, printing `listening on` |
| `event_loop.c` | main loop, UDP/TCP transport, verdicts, truncation, signals |
| `doh_forward.c` | DoH client on top of libcurl multi |
| `query_log.c` | query log line format |

### Concurrency model: single thread, event-driven loop

The program runs in **a single thread**. The only place where it waits is `doh_poll()`
(a wrapper around `curl_multi_poll`), which waits at once for:

- listening sockets (UDP and TCP, IPv4 and IPv6),
- open TCP client connections,
- libcurl sockets towards the upstream,
- a timer (at most 1 s, plus libcurl's internal timers, e.g. for `-w`).

All sockets are **non-blocking**, so after waking up, ready events are handled without waiting:

```text
while (!stop_requested) {
    build pollfd (listeners + TCP connections)
    doh_poll()                 // wait; libcurl advances transfers and calls on_doh_done
    UDP socket   -> udp_read  -> handle_message
    TCP listener -> tcp_accept
    TCP conn     -> tcp_read  -> frames -> handle_message
    close TCP connections idle for 10 s
}
```

`local`, `blocked` and `invalid` responses are sent **immediately** in `handle_message`. For
`forwarded`, a context is stored (`client_ctx`: where to reply, the stored query) and the query is
passed to `doh_submit`. The answer arrives **later** through the `on_doh_done` callback. A slow
upstream therefore does not delay other clients: other queries are served while waiting.

Why an event loop and not threads: shared state (contexts, TCP connections, log) needs no locking,
log lines never interleave, and libcurl multi is designed for this model.

### Limits and timers

| Constant | Value | Reason |
|---|---|---|
| `DOH_MAX_PENDING` | 64 | cap on outstanding upstream requests (assignment: at least 64), printed on stderr |
| `MAX_TCP_CONN` | 64 | maximum concurrent TCP clients (64 KB buffer per connection) |
| `TCP_IDLE_MS` | 10 000 | closing an idle TCP connection (assignment: 10 s, +5 s) |
| `POLL_TIMEOUT_MS` | 1 000 | the loop wakes up at least once per second (idle check) |
| `UDP_BATCH` | 64 | maximum datagrams per wake-up (fairness under a flood) |

### TCP

Every connection has a buffer for received bytes. `tcp_read` takes **complete frames** from it
(2 B length + message), so a message split over several segments works, as do several pipelined
queries. Forwarded queries on one connection may be answered out of order (RFC 7766). A connection
is closed when the client closes it, after a dropped message, on a send error, or after 10 s of
inactivity (unless it waits for the upstream). If the client closes the connection while waiting for
the upstream, the query finishes and is logged, but the answer is not sent.

### Signals

`SIGINT` and `SIGTERM` only set the `stop_requested` flag (`volatile sig_atomic_t`). The loop
ends, `doh_shutdown()` answers all outstanding queries with SERVFAIL and logs them, the sockets are
closed and the program exits with 0. The signal handlers are installed only after the
`listening on` lines are printed, so a signal during start-up ends the program with a non-zero code.
`SIGPIPE` is ignored and TCP `send` uses `MSG_NOSIGNAL`.

## 4. Libraries used

| Library | Version | License | URL | Responsibility |
|---|---|---|---|---|
| **libcurl** | 8.21.0 | curl license (MIT/X derived) | <https://curl.se/libcurl/> | the whole DoH transfer: resolving the upstream name (threaded resolver), TCP, TLS, HTTP/1.1 and HTTP/2, POST, timeouts, connection cache, multi interface for non-blocking transfers |
| OpenSSL (via libcurl) | 3.6.3 | Apache 2.0 | <https://www.openssl.org/> | TLS handshake, certificate chain verification (`SSL_CERT_FILE`) and hostname verification |
| nghttp2 (via libcurl) | 1.69.0 | MIT | <https://nghttp2.org/> | HTTP/2, if the upstream offers it via ALPN |
| glibc / POSIX | from the devShell | LGPL 2.1 | <https://www.gnu.org/software/libc/> | sockets, `poll`, signals, `inet_ntop`, `clock_gettime` |

**Why libcurl:** it is part of the `c` devShell, its multi interface allows non-blocking HTTPS
transfers in one loop together with the other sockets, and it handles HTTP/1.1 and HTTP/2,
keep-alive, chunked encoding and TLS. An own HTTP implementation on top of OpenSSL would be large and
would bring nothing to the assignment.

Important options in `doh_submit`:

| Option | Reason |
|---|---|
| `CURLOPT_POSTFIELDSIZE` + `CURLOPT_COPYPOSTFIELDS` | the body is a binary DNS message (ID = 0); curl copies it |
| headers `Content-Type` / `Accept: application/dns-message`, empty `Expect:` | RFC 8484; no waiting for `100 Continue` |
| `CURLOPT_TIMEOUT_MS` | `-w` covers name resolution, connection, TLS, request and response |
| `CURLOPT_FOLLOWLOCATION = 0` | redirects are not followed, 3xx leads to SERVFAIL |
| `CURLOPT_SSL_VERIFYPEER/HOST`, `CURLOPT_CAINFO` | certificate verification; libcurl does not read `SSL_CERT_FILE` itself, so it is passed explicitly |
| `CURLOPT_NOSIGNAL` | libcurl does not use signals |
| `CURLOPT_PRIVATE` | matching a finished transfer to its client (not by DNS ID) |

## 5. Parsing and building DNS messages

### Validating a received message (`dns_parser.c`)

Checks in the exact order of the assignment; the first failing one decides:

| # | Condition | Result |
|---|---|---|
| 1 | shorter than 12 B | `dropped` |
| 2 | QR = 1 | `dropped` |
| 3 | OPCODE ≠ QUERY | `invalid`, NOTIMP |
| 4 | QDCOUNT ≠ 1 | `invalid`, FORMERR |
| 5 | the question cannot be parsed (label 64..191, compression, name > 255 B, overrun) | `invalid`, FORMERR |
| 6 | sections cannot be skipped, more than one OPT, OPT outside additional or with a non-root name | `invalid`, FORMERR |
| 7 | QCLASS ≠ IN | `invalid`, NOTIMP |
| 8 | QTYPE = AXFR / IXFR | `invalid`, REFUSED |

Reading goes through a `reader` structure (buffer, length, position) with a bounds check on every
read. Compression is not accepted in the question. In the other sections names are only skipped,
including compression pointers. From the OPT record, `has_opt` and the client's UDP buffer size are
stored.

### Building responses (`dns_response.c`)

Writing goes through a `writer` structure (buffer, capacity, position). Every response the proxy
builds itself (local, blocked, invalid, SERVFAIL) has QR = 1, copied OPCODE, RD, CD and ID, RA = 1,
AD = Z = 0, and AA = 1 only for `local`. The question is **copied byte for byte** (letter case is
preserved), or QDCOUNT = 0 if it was not parsed. If the query passed step 6 and carried an OPT, the
response carries a bare OPT (version 0, no options, payload 1232).

### Truncation (`udp_truncate` in `event_loop.c`)

The UDP limit is 512 B without OPT, otherwise the client's OPT size clamped to 512..1232
(RFC 6891 §6.2.3). A larger response is **replaced** (not cut): the original header with TC = 1 and
ANCOUNT = NSCOUNT = 0, the question, and an OPT if the query had one (ARCOUNT 1, else 0). For a
forwarded response the upstream's OPT is kept; for an own response a bare OPT is used. This applies
to local and forwarded responses alike. TCP responses are never truncated.

## 6. Zones: storage and lookup

### Storage

Every zone file is one `zone`: the apex, the SOA record and a hash table (FNV-1a) whose key is the
**owner name** (lowercase, without the trailing dot) and whose value is a linked list of records
(`record`: type, TTL, rdata in wire format). **Ancestors** of names inside the zone are inserted too
(without records), so a name also "exists" as an ancestor (empty non-terminal).

Supported types: **SOA, NS, A, AAAA, CNAME, MX**. Other IANA-registered types are skipped with a
warning on stderr. Only a marker (`skipped`) is stored for them, so the owner exists and the rule
"a CNAME must not coexist with other records" still applies. Unregistered types and meta types
(ANY, OPT, AXFR, IXFR, TSIG...) are errors.

Loading checks every error listed in the assignment (number and owner of the SOA, owner outside the
zone, TTL, different TTLs of one type, CNAME with other records, first record without owner...) and
two zones with the same apex. An identical record listed twice is stored once (RFC 2181).

### Lookup (`zone_answer`)

1. The zone with the **longest apex** containing the name is found (on label boundaries,
   case-insensitive). If there is none, the name is not `local`.
2. **CNAME chain:** if the name owns a CNAME and QTYPE is neither CNAME nor ANY, the CNAME is added
   to the answer and the lookup continues with its target, **at most 8 hops**, as long as the target
   is in one of the zones. A target outside the zones or a loop ends the chain (NOERROR, every CNAME
   once, no SOA).
3. Records of the queried type are added for the last name (all records for ANY).
4. **Negative answers** (RFC 2308): the name does not exist → **NXDOMAIN**; the name exists without
   the type → **NOERROR** with an empty answer. In both cases the SOA of the last name's zone is added
   to the authority section with TTL `min(SOA TTL, SOA MINIMUM)`.

TTLs from the zone are returned unchanged. Names in a zone are never blocked or forwarded.

## 7. Blocklists

A line is cut at `#`, CR and whitespace are stripped, and it is split into tokens. A token
containing `:` is an IPv6 address and is skipped. Names made only of digits and dots (IPv4
addresses) and hosts(5) header names (`localhost`, `broadcasthost`, `ip6-...`) are ignored. All
other tokens must be valid domain names (1..127 labels of 1..63 characters `a-z 0-9 - _`, at most
253 characters), otherwise it is a start-up error. Entries are stored lowercase without the trailing
dot in a hash table.

A name is blocked if it or **any of its parents** (on label boundaries) is in the table: for
`x.ads.example.com` the lookups are `x.ads.example.com`, `ads.example.com`, `example.com`, `com`.
`bads.example.com` is therefore not blocked by `ads.example.com`. A lookup is O(number of labels);
start-up with 200 000 entries takes a fraction of a second.

## 8. Forwarding over DoH

- The query is sent unchanged except for ID = 0 (RFC 8484 §4.1), using POST.
- A valid answer (2xx, 12..65535 B, QR = 1, OPCODE = QUERY, QDCOUNT = 1, the same question with
  a case-insensitive QNAME) is sent to the client **unchanged** except for the client's ID and
  possible truncation, with any RCODE.
- SERVFAIL is returned when: the upstream name cannot be resolved, the connection or TLS fails, the
  status is not 2xx (including redirects), the body is invalid, the cap is reached, the program is
  shutting down, or `-w` expires.
- Answers are matched to clients by the HTTP exchange, so two clients using the same ID each get
  their own answer.
- No cache: every forwarded query is exactly one upstream request.

### Verified public resolver

Tested against **Cloudflare** `https://cloudflare-dns.com/dns-query`. RFC 8484 POST compliance was
verified:

- by answers through the proxy to `dig` / `kdig` (UDP, TCP, IPv4, IPv6), see [11.4](#114-manual-tests-with-a-real-resolver),
- by comparison with a direct DoH query `kdig +https`, see [11.5](#115-comparison-with-a-similar-tool),
- by a direct query with `curl` (`-v`, relevant lines):

```bash
printf '\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x03fit\x03vut\x02cz\x00\x00\x01\x00\x01' |
  curl -sv -H 'Content-Type: application/dns-message' -H 'Accept: application/dns-message' \
       --data-binary @- https://cloudflare-dns.com/dns-query -o /dev/null
```

```text
> POST /dns-query HTTP/2
> Content-Type: application/dns-message
< HTTP/2 200
< content-type: application/dns-message
```

Cloudflare accepted the request in RFC 8484 format (POST with an `application/dns-message` body) and
replied 200 with the same content type. The proxy sends requests with the same headers (see
`doh_submit` and the test `test_request_is_rfc8484_post`).

### tcpdump capture

One client query to the proxy and the corresponding HTTPS exchange with the upstream. Captured in
WSL2 (proxy, `dig` and `tcpdump` in three terminals of the same distribution):

```bash
sudo tcpdump -i any -p -n -w dns.pcap 'port 5300 or port 443'   # terminal 3
dig @127.0.0.1 -p 5300 www.muni.cz A                              # terminal 2
tcpdump -n -r dns.pcap                                            # convert to text
```

```text
14:42:00.839508 lo    In  IP 127.0.0.1.40493 > 127.0.0.1.5300: UDP, length 52
14:42:00.839717 eth0  Out IP 172.31.254.151.51006 > 104.16.249.249.443: Flags [P.], seq 2078618379:2078618427, ack 3524855548, win 62, options [nop,nop,TS val 70736333 ecr 1269324869], length 48
14:42:00.840052 eth0  Out IP 172.31.254.151.51006 > 104.16.249.249.443: Flags [P.], seq 48:72, ack 1, win 62, options [nop,nop,TS val 70736333 ecr 1269324869], length 24
14:42:00.841358 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [S], seq 1943824080, win 64480, options [mss 1240,sackOK,TS val 2564482602 ecr 0,nop,wscale 10], length 0
14:42:00.844900 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.51006: Flags [.], ack 72, win 16, options [nop,nop,TS val 1269455335 ecr 70736333], length 0
14:42:00.845579 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [S.], seq 1177212253, ack 1943824081, win 65535, options [mss 1400,sackOK,TS val 1616761227 ecr 2564482602,nop,wscale 13], length 0
14:42:00.845632 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [.], ack 1, win 63, options [nop,nop,TS val 2564482606 ecr 1616761227], length 0
14:42:00.846255 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.51006: Flags [F.], seq 1, ack 72, win 16, options [nop,nop,TS val 1269455337 ecr 70736333], length 0
14:42:00.846535 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [P.], seq 1:1839, ack 1, win 63, options [nop,nop,TS val 2564482607 ecr 1616761227], length 1838
14:42:00.850945 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [.], ack 920, win 16, options [nop,nop,TS val 1616761232 ecr 2564482607], length 0
14:42:00.850946 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [.], ack 1839, win 16, options [nop,nop,TS val 1616761232 ecr 2564482607], length 0
14:42:00.851754 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [P.], seq 1:1317, ack 1839, win 16, options [nop,nop,TS val 1616761233 ecr 2564482607], length 1316
14:42:00.851785 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [.], ack 1317, win 62, options [nop,nop,TS val 2564482613 ecr 1616761233], length 0
14:42:00.851924 eth0  Out IP 172.31.254.151.51006 > 104.16.249.249.443: Flags [F.], seq 72, ack 2, win 62, options [nop,nop,TS val 70736345 ecr 1269455337], length 0
14:42:00.852185 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [P.], seq 1839:1919, ack 1317, win 62, options [nop,nop,TS val 2564482613 ecr 1616761233], length 80
14:42:00.852318 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [P.], seq 1919:2143, ack 1317, win 62, options [nop,nop,TS val 2564482613 ecr 1616761233], length 224
14:42:00.852550 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [P.], seq 2143:2191, ack 1317, win 62, options [nop,nop,TS val 2564482613 ecr 1616761233], length 48
14:42:00.856436 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [P.], seq 1317:1877, ack 1919, win 16, options [nop,nop,TS val 1616761238 ecr 2564482613], length 560
14:42:00.856583 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.51006: Flags [.], ack 73, win 16, options [nop,nop,TS val 1269455347 ecr 70736345], length 0
14:42:00.856614 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [P.], seq 2191:2222, ack 1877, win 62, options [nop,nop,TS val 2564482617 ecr 1616761238], length 31
14:42:00.856615 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [P.], seq 1877:1908, ack 2191, win 16, options [nop,nop,TS val 1616761238 ecr 2564482613], length 31
14:42:00.859163 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [P.], seq 1908:2069, ack 2191, win 16, options [nop,nop,TS val 1616761240 ecr 2564482613], length 161
14:42:00.859164 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [P.], seq 2069:2162, ack 2191, win 16, options [nop,nop,TS val 1616761240 ecr 2564482613], length 93
14:42:00.859243 eth0  Out IP 172.31.254.151.56252 > 104.16.249.249.443: Flags [.], ack 2162, win 62, options [nop,nop,TS val 2564482620 ecr 1616761238], length 0
14:42:00.859308 lo    In  IP 127.0.0.1.5300 > 127.0.0.1.40493: UDP, length 62
14:42:00.902695 eth0  In  IP 104.16.249.249.443 > 172.31.254.151.56252: Flags [.], ack 2222, win 16, options [nop,nop,TS val 1616761284 ecr 2564482617], length 0
```

Description of the capture (the whole query took ~20 ms):

1. `lo In 127.0.0.1.40493 > 127.0.0.1.5300: UDP, length 52`: the client's query to the proxy (Do53, unencrypted).
2. Lines with port 51006: libcurl does not reuse the old idle connection to the upstream
   (older than `CURLOPT_MAXAGE_CONN`, 118 s by default) and closes it
   (HTTP/2 GOAWAY and TLS `close_notify`, 48 B and 24 B, then FIN).
3. `[S]`, `[S.]`, `[.]` on port 56252: TCP three-way handshake with Cloudflare (104.16.249.249:443).
4. 1838 B out / 1316 B in: TLS 1.3 handshake (Client Hello with a post-quantum key exchange,
   Server Hello and certificate).
5. 80 B, 224 B, 48 B out: TLS finished, HTTP/2 preface and SETTINGS, `POST` request headers with
   `content-type: application/dns-message`, and the body with the DNS message (ID 0), all encrypted.
6. 560, 31, 161, 93 B in: the encrypted HTTP/2 response carrying the DNS answer.
7. `lo In 127.0.0.1.5300 > 127.0.0.1.40493: UDP, length 62`: the proxy sends the answer to the
   client with the client's original ID. On loopback, tcpdump shows both directions as `In`.

On the client side DNS is plain text (port 5300); towards the Internet only encrypted HTTPS goes out
(port 443). An observer on the network sees only a connection to Cloudflare, not the queried name.

## 9. Query log

On stdout, one line per received message, written with a single `write` after the response is sent:

```text
<RFC 3339 time> <client IP:port> <qname> <qtype> <verdict> <rcode>
2026-11-15T16:55:01+01:00 127.0.0.1:50417 router.home.lan. A local NOERROR
```

QNAME in lowercase with a trailing dot, special characters as `\c` and non-printable bytes as
`\DDD` (as `dig` prints them). QTYPE and RCODE as IANA mnemonics, otherwise `TYPE<n>` / `RCODE<n>`.
For `invalid`/`dropped` without a parsed question, name and type are `-`. IPv6 clients are in square
brackets. IPv6 sockets use `IPV6_V6ONLY`, so IPv4-mapped addresses never occur. Diagnostics
(warnings, upstream errors) go to stderr.

## 10. Design decisions and interpretations

Points the assignment does not specify unambiguously (guidelines: the decision MUST be documented):

| Situation | Decision |
|---|---|
| CNAME chain longer than 8 hops | after 8 added CNAMEs the ninth name is handled as the last name of the chain (without its CNAME → NOERROR + SOA) |
| identical record twice in a zone | stored once, not an error (RFC 2181 §5) |
| unsupported type (TXT, HINFO...) | data is not stored; a query for it, and ANY, returns NOERROR without it (+ SOA) |
| meta types in a zone (ANY, OPT, AXFR...) | error, they are not data types |
| two zones with the same apex | exit 78, compared case-insensitively |
| unknown option, positional argument | exit 64 |
| repeated `--insecure` | allowed (it is not an option with a value) |
| full TCP connection table (64) | a new connection is closed immediately |
| cap on outstanding forwards | 64; above it, immediate SERVFAIL with verdict `forwarded` |
| OPT when truncating a forwarded response | the upstream's OPT is kept |
| no `-a` on a host without IPv6 | exit 69 (the IPv6 socket cannot be opened) |

## 11. Testing

### 11.1 Environment and topology

| Item | Value |
|---|---|
| OS | Windows + WSL2, Ubuntu 26.04.1 LTS, kernel 6.18.58.1-microsoft-standard-WSL2 |
| dev-envs commit | `d3ec76c08946c0f2c50725c091f062a2dbdc27d3` (2026-11-14) |
| GCC | 15.2.0 |
| libcurl | 8.21.0 (OpenSSL 3.6.3, nghttp2 1.69.0) |
| Python | 3.13.15 (devShell); the tests use only the standard library (`unittest`) |
| dig / kdig | DiG 9.20.26 / Knot DNS 3.5.8 |

Topology of the automated tests (everything on loopback, no Internet):

```text
 test client (Python)              isa-dnsproxy                fake DoH upstream (Python)
 UDP/TCP, IPv4/IPv6  ──────────►  127.0.0.1 / ::1  ── HTTP/1.1 ──►  127.0.0.1:<free port>
                                   :<free port>       or HTTPS        (records every request,
                                                     (own cert)       configurable delay,
                                                                       HTTP status, body, TLS)
```

Manual tests: `dig`/`kdig` → proxy on `127.0.0.1:5300` / `[::1]:5300` → Cloudflare over the Internet.

### 11.2 Automated tests (`make test`)

The tests are **black-box**: they run the built binary and talk to it only through the network,
stdout, stderr and the exit code, just like the assignment's evaluation. Framework: **`unittest`**
from the Python standard library, so the tests run in the unmodified devShell without installing
extra packages (C has no native test framework; the finished program is tested from outside).
Parametrised cases (for example 109 broken zone files) run as `subTest`, each with its own fake
upstream and temporary directory (`params` in `dnstest.py`). `unittest` therefore reports 162 tests
(methods), which together cover 482 cases.

| File | Methods / cases | What it tests | Why |
|---|---|---|---|
| `test_zonefile.py` | 17 / 190 | zone file grammar and errors, exit 78 with `file:line:` | format rules of the assignment |
| `test_blocklist.py` | 13 / 55 | blocklist format (CRLF, hosts(5), several names per line), start-up with 200 000 entries | format rules and the start-up time limit |
| `test_forwarding.py` | 38 / 60 | POST shape, ID 0, answer unchanged, upstream RCODE and OPT, same ID from two clients, SERVFAIL on 4xx/5xx, redirects, 11 kinds of bad bodies, refused connection, unresolvable name, timeout (and not earlier), concurrency, cap, truncation, TLS (`SSL_CERT_FILE`, untrusted, other hostname, `--insecure`), SIGTERM | forwarding is ½ of the points |
| `test_runtime.py` | 73 / 118 | zones (CNAME, loops, 8 hops, NXDOMAIN/NODATA + SOA TTL, longest apex, zone before blocklist), blocking, steps 1–8 with malformed messages, response format, UDP/TCP (segments, pipelining, dropped, RST, 30 connections, 10 s idle), IPv6, log | zones and blocking ¼ of the points each, transport and log |
| `test_lifecycle.py` | 21 / 59 | `-h`, 27 invalid argument combinations → 64, boundary values, 78, 69 (port in use, UDP/TCP, IPv4/IPv6), start-up within 5 s, signals, SIGPIPE | CLI, start-up and shutdown |
| `dnstest.py` | – | helper module: building and parsing DNS messages, fake DoH server, running the proxy, `unittest` helpers | |

Checking that the tests really catch bugs: 6 bugs were deliberately inserted into a copy of the
program (client ID not restored, truncation disabled, blocking by exact match only, following
redirects, SOA TTL without the minimum, wrong handling of the rest of the TCP buffer). Each of them
was caught by 2 to 14 tests.

**Result** (WSL2, devShell, 2026-11-16):

```text
$ nix develop dev-envs#isa -c nix develop dev-envs#c -c make test
...
«FILL IN: the last two lines of make test, e.g. "Ran 162 tests in ...s" and "OK (skipped=1)"»
```

The skipped test is the port 1 test, which cannot bind without root privileges.

### 11.3 Representative cases: input, expected and actual output

| Input | Expected (assignment) | Actual |
|---|---|---|
| `router.home.lan A` | NOERROR, `qr aa rd ra`, 1× A 192.168.1.1, TTL 3600 | matches (`test_local_a`) |
| `media.home.lan A` | NOERROR, CNAME nas.home.lan. and A 192.168.1.20, CNAME first | matches (`test_cname_chain_followed`) |
| `printer.home.lan A` | NXDOMAIN, `aa`, SOA in authority with TTL min(TTL, MINIMUM) | matches (`test_nxdomain_with_soa_negative_ttl`) |
| `www.ads.example.com AAAA` | NXDOMAIN, no `aa`, empty answer and authority, nothing upstream | matches (`test_blocked_names`, `test_blocked_and_local_never_reach_upstream`) |
| name both in a zone and in a blocklist | `local` | matches (`test_zone_name_beats_blocklist`) |
| `+bufsize=512`, local answer with 60× A | TC = 1, ANCOUNT 0, ARCOUNT 1 (OPT), ≤ 512 B | matches (`test_local_truncated_bufsize_512_keeps_opt`) |
| no OPT, forwarded answer > 512 B | TC = 1, ANCOUNT = NSCOUNT = ARCOUNT = 0 | matches (`test_forwarded_truncated_without_opt`) |
| upstream delayed 3 s, 10 forwards + 1 local | local < 200 ms, forwards < 5 s | local ~0 ms, forwards 3.0 s (`test_slow_upstream_does_not_delay_local_or_blocked`) |
| two clients, same ID 0x2222, different names | each gets the answer with its own question | matches (`test_two_clients_same_id_get_own_answers`) |
| upstream 301 | SERVFAIL, exactly 1 request, redirect not followed | matches (`test_redirect_not_followed`) |
| `-w 1`, upstream 3 s | SERVFAIL after 1 s (not earlier) | ~1.0 s (`test_timeout_is_servfail_not_before`) |
| SIGTERM with an outstanding query | SERVFAIL to the client, log line, exit 0 < 2 s | exit 0 in ~3 ms (`test_sigterm_answers_inflight_servfail`) |
| empty UDP datagram | no answer, log `- - dropped -` | matches (`test_step1_short_message_dropped`) |
| QDCOUNT = 0 | FORMERR, QDCOUNT 0, no OPT | matches (`test_step4_qdcount_formerr`) |

### 11.4 Manual tests with a real resolver

```bash
./isa-dnsproxy -u https://cloudflare-dns.com/dns-query -p 5300 -z examples/home.lan.zone -b examples/ads.txt
```

The proxy ran in WSL2 (devShell) with the example files from the assignment; queries were sent from a
second terminal (`dig` 9.20.26, `kdig` 3.5.8). The outputs are copied unchanged except for shortening
one long TXT answer.

| Case | Expected (assignment) | Actual |
|---|---|---|
| `router.home.lan A` | NOERROR, `qr aa rd ra`, A 192.168.1.1, TTL 3600, OPT 1232 | matches |
| `media.home.lan A` | CNAME `nas.home.lan.` followed by A 192.168.1.20 | matches |
| `printer.home.lan A` | NXDOMAIN, `aa`, SOA in authority, TTL min(3600, 3600) | matches |
| `www.ads.example.com AAAA` | NXDOMAIN, no `aa`, empty sections, only OPT | matches |
| `www.fit.vut.cz` over UDP, TCP, IPv6 | upstream answer unchanged (including `ad` and EDE from Cloudflare) | matches |
| `google.com TXT +bufsize=512 +ignore` | answer > 512 B: `tc`, ANSWER 0, AUTHORITY 0, OPT kept | matches |
| the same query with `+tcp` | the full answer (17 TXT), no truncation | matches |
| QCLASS CH | NOTIMP, no `aa` | matches |
| AXFR | REFUSED (`dig` reports `Transfer failed.`) | matches |
| `kdig` | the same local answer as `dig`, 75 B, 0.5 ms | matches |

```text
$ dig @127.0.0.1 -p 5300 router.home.lan A +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25750
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
router.home.lan.        3600    IN      A       192.168.1.1


$ dig @127.0.0.1 -p 5300 media.home.lan A +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38040
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
media.home.lan.         3600    IN      CNAME   nas.home.lan.
nas.home.lan.           3600    IN      A       192.168.1.20


$ dig @127.0.0.1 -p 5300 printer.home.lan A +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 6440
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; AUTHORITY SECTION:
home.lan.               3600    IN      SOA     ns1.home.lan. admin.home.lan. 2026091401 7200 3600 1209600 3600


$ dig @127.0.0.1 -p 5300 router.home.lan AAAA +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30359
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
router.home.lan.        3600    IN      AAAA    fd00:cafe::1


$ dig @127.0.0.1 -p 5300 www.ads.example.com AAAA +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 47724
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232

$ dig @127.0.0.1 -p 5300 www.fit.vut.cz A +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35132
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; EDE: 18 (Prohibited)
;; ANSWER SECTION:
www.fit.vut.cz.         10142   IN      A       147.229.9.65


$ dig @127.0.0.1 -p 5300 www.fit.vut.cz A +tcp +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 18871
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; EDE: 18 (Prohibited)
;; ANSWER SECTION:
www.fit.vut.cz.         10142   IN      A       147.229.9.65


$ dig @::1 -p 5300 www.fit.vut.cz AAAA +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62190
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
www.fit.vut.cz.         168     IN      AAAA    2001:67c:1220:809::93e5:941


$ dig @127.0.0.1 -p 5300 google.com TXT +bufsize=512 +ignore +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54095
;; flags: qr tc rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232

$ dig @127.0.0.1 -p 5300 google.com TXT +tcp +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19981
;; flags: qr rd ra; QUERY: 1, ANSWER: 17, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
google.com.             59      IN      TXT     "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
google.com.             59      IN      TXT     "cisco-ci-domain-verification=47c38bc8c4b74b7233e9053220c1bbe76bcc1cd33c7acf7acd36cd6a5332004b"
google.com.             59      IN      TXT     "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
... (14 more TXT records omitted in this README)


$ dig @127.0.0.1 -p 5300 router.home.lan A -c CH +noall +comments +answer +authority
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOTIMP, id: 31273
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232

$ dig @127.0.0.1 -p 5300 home.lan AXFR

; <<>> DiG 9.20.26 <<>> @127.0.0.1 -p 5300 home.lan AXFR
; (1 server found)
;; global options: +cmd
; Transfer failed.

$ kdig @127.0.0.1 -p 5300 router.home.lan A
;; ->>HEADER<<- opcode: QUERY; status: NOERROR; id: 45559
;; Flags: qr aa rd ra; QUERY: 1; ANSWER: 1; AUTHORITY: 0; ADDITIONAL: 1

;; EDNS PSEUDOSECTION:
;; Version: 0; flags: ; UDP size: 1232 B; ext-rcode: NOERROR

;; QUESTION SECTION:
;; router.home.lan.             IN      A

;; ANSWER SECTION:
router.home.lan.        3600    IN      A       192.168.1.1

;; Received 75 B
;; Time 2026-11-16 14:21:20 CET
;; From 127.0.0.1@5300(UDP) in 0.5 ms
```

### 11.5 Comparison with a similar tool

The answer through `isa-dnsproxy` compared with a direct DoH query by `kdig` (Knot DNS 3.5.8) to
Cloudflare:

```bash
dig  @127.0.0.1 -p 5300 www.fit.vut.cz A +noall +answer        # via isa-dnsproxy
kdig @1.1.1.1 +https www.fit.vut.cz A +noall +answer             # direct DoH (kdig)
```

```text
$ dig via isa-dnsproxy
www.fit.vut.cz.         10131   IN      A       147.229.9.65
$ kdig directly over DoH
www.fit.vut.cz.         12777   IN      A       147.229.9.65
```

Both paths returned the same record (name, type, address). Only the TTL differs: the proxy queries
`cloudflare-dns.com` while `kdig` queries `1.1.1.1`, so the answers come from different Cloudflare
cache nodes holding records of different age. The proxy does not change TTLs (it has no cache).

Unlike Pi-hole, `isa-dnsproxy` blocks whole subtrees and answers NXDOMAIN (RFC 8020), not 0.0.0.0.

### 11.6 Memory check

Valgrind 3.26.0 from the devShell. The proxy ran with the example files, received a local, a blocked
and a forwarded query, and was stopped with SIGINT:

```bash
valgrind --leak-check=full ./isa-dnsproxy -u https://cloudflare-dns.com/dns-query -p 5300 \
    -a 127.0.0.1 -z examples/home.lan.zone -b examples/ads.txt
```

```text
==3336== HEAP SUMMARY:
==3336==     in use at exit: 5,347 bytes in 73 blocks
==3336==   total heap usage: 94,381 allocs, 94,308 frees, 8,283,675 bytes allocated
==3336==
==3336== 194 (16 direct, 178 indirect) bytes in 1 blocks are definitely lost in loss record 29 of 36
==3336==    at 0x4CC2549: calloc (...)
==3336==    by 0x4006358: hashtable_constructor (in /home/electrix/isa-dnsproxy/isa-dnsproxy)
==3336==    by 0x4003710: blocklist_parser (in /home/electrix/isa-dnsproxy/isa-dnsproxy)
==3336==    by 0x4002582: main (in /home/electrix/isa-dnsproxy/isa-dnsproxy)
==3336==
==3336== LEAK SUMMARY:
==3336==    definitely lost: 16 bytes in 1 blocks
==3336==    indirectly lost: 178 bytes in 7 blocks
```

No leak occurs while running: of 94 381 allocations, only the blocklist hash table (194 B) remained,
because it is not destroyed at exit. The rest of `in use at exit` is global state held by libcurl
and OpenSSL.

On a start-up failure (port in use, exit 69), valgrind also reported unfreed zones (1 717 B from
`zoneBuffer_allocation`), because `main` does not free the loaded data on that path.

## 12. Known limitations

- At most **64 concurrent TCP connections**. Further ones are closed immediately (UDP is unaffected).
- If a TCP client does not read and the kernel buffer is full, the connection is closed instead of
  waiting (otherwise it would delay the others).
- A UDP socket bound to `0.0.0.0`/`::` answers with the source address chosen by routing. On a host
  with several addresses, an answer to a query sent to a secondary address may come from another
  address (`IP_PKTINFO` would solve this; not implemented).
- Unsupported types in a zone are not stored, so they cannot be returned even for ANY.
- Without `-a`, IPv6 must be available in the kernel (otherwise exit 69).
- Not implemented: cache, DoH GET, wildcards, `$INCLUDE`, multi-line records, escapes in zone files
  (optional according to the assignment).
- The blocklist hash table (194 B) is not freed at exit, and the zones are not freed on an error exit
  after the files were loaded (see [11.6](#116-memory-check)). Memory does not grow while running.

## 13. Use of AI
s
According to [AI-USAGE.md](https://git.fit.vutbr.cz/NESFIT/Project-Guidelines/src/branch/main/AI-USAGE.md).

**Tool:** Claude (Anthropic), via claude.ai.


| Part | AI use |
| bug fixes in `main.c`, `socket_binding.c`, `blocklist_parser.c`, `arg_parser.c` (`print_help`) | proposed by AI |
| `tests/dnstest.py`, `test_forwarding.py`, `test_runtime.py`, `test_lifecycle.py`, `fake_upstream.py` | generated by AI, verified by mutation testing; conversion from pytest to `unittest` done by AI |
| `tests/test_zonefile.py`, `tests/test_blocklist.py` | written by the author; conversion from pytest to `unittest` done by AI |
| `Makefile` (targets `test`, `test-fast`, `zip`, `-std=c17`) | generated by AI |
| `CHANGELOG.md` | written by AI from the author's commit history |
| `README.md` | text generated by AI (in Slovak, then translated to English by AI); test results and measurements supplied by the author |
| study and explanations (libcurl multi, `poll`, signals, DNS) | consultations with AI |


## 14. References

Cited according to ČSN ISO 690.

1. MOCKAPETRIS, Paul. *Domain names – concepts and facilities* [online]. RFC 1034. IETF, 1987 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc1034>
2. MOCKAPETRIS, Paul. *Domain names – implementation and specification* [online]. RFC 1035. IETF, 1987 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc1035>
3. ELZ, Robert and BUSH, Randy. *Clarifications to the DNS Specification* [online]. RFC 2181. IETF, 1997 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc2181>
4. ANDREWS, Mark. *Negative Caching of DNS Queries (DNS NCACHE)* [online]. RFC 2308. IETF, 1998 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc2308>
5. THOMSON, Susan et al. *DNS Extensions to Support IP Version 6* [online]. RFC 3596. IETF, 2003 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc3596>
6. GUSTAFSSON, Andreas. *Handling of Unknown DNS Resource Record (RR) Types* [online]. RFC 3597. IETF, 2003 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc3597>
7. EASTLAKE, Donald. *Domain Name System (DNS) Case Insensitivity Clarification* [online]. RFC 4343. IETF, 2006 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc4343>
8. KAWAMURA, Seiichi and KAWASHIMA, Masanobu. *A Recommendation for IPv6 Address Text Representation* [online]. RFC 5952. IETF, 2010 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc5952>
9. DAMAS, Joao, GRAFF, Michael and VIXIE, Paul. *Extension Mechanisms for DNS (EDNS(0))* [online]. RFC 6891. IETF, 2013 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc6891>
10. DICKINSON, John et al. *DNS Transport over TCP – Implementation Requirements* [online]. RFC 7766. IETF, 2016 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc7766>
11. BORTZMEYER, Stéphane and HUQUE, Shumon. *NXDOMAIN: There Really Is Nothing Underneath* [online]. RFC 8020. IETF, 2016 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc8020>
12. ABLEY, Joe et al. *Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY* [online]. RFC 8482. IETF, 2019 [cit. 2026-11-16]. Available from: <https://www.rfc-editor.org/rfc/rfc8482>

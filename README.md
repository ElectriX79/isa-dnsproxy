ISA Project – Filtering DNS-to-DoH Proxy
General build, submission, and documentation rules are defined in the shared NES@FIT project guidelines. This document adds the requirements specific to the ISA project; MUST / SHOULD / MAY are used as defined in the guidelines' Interpretation Rules.

A Gemini Gem loaded with this assignment, the guidelines, AI-USAGE.md, and the dev-envs documentation is available for orientation and explanations. Open it in a browser window where you are signed in with your VUT account. It is an AI tool like any other: its answers are not an official interpretation of the assignment, it does not write the core of the solution, and its use MUST be marked in the Use of AI section of your README.md. Questions about the assignment belong in the issues of this repository.

Deadlines
See deadlines in IS VUT.

Global assignment rules
Students MUST follow the guidelines and AI-USAGE.md. This project deviates from them as follows:

Environment. Everything runs in the course devShell isa chained with your language devShell: nix develop dev-envs#isa -c nix develop dev-envs#<shell> -c make, where <shell> is what make NixDevShellName prints and dev-envs is the flake registry entry of the reference environment. The isa devShell adds dig, kdig, curl, openssl, tcpdump, and the CA bundle (SSL_CERT_FILE); the c devShell adds the libcurl and openssl libraries.
Libraries. Any library MAY be used, including DNS, HTTP, and TLS libraries. Libraries cover the protocol machinery (message parsing and building, zone loading and lookup, DoH transport); the decision logic, blocklist semantics, query log, error handling, and start-up behavior specified below are yours to write. At the defence you MUST be able to explain what every library you use does at the protocol level and why you chose it. The executable MUST be your program, not a wrapper around an existing DNS server.
Streams. -z and -b take regular files only; - has no special meaning and the proxy does not read stdin.
Privileges. Tests run the proxy unprivileged with -p. Binding port 53 is the operator's concern.
AI-USAGE.md. The core of this project is every line of code on the executable's runtime path that is not an unmodified third-party dependency; test helpers MUST NOT be imported by the program.
Assignment
Implement a DNS proxy that receives Do53 queries (plain DNS over UDP and TCP) and forwards them to a DNS-over-HTTPS (DoH) recursive resolver, the upstream.

Serve zones loaded from zone files, answering names in them locally and authoritatively.
Filter queries against domain blocklists, so that blocked names are never forwarded.
Cover the required functionality with automated tests.
The proxy models a home-network DNS forwarder such as Pi-hole: LAN devices keep using plain DNS while the proxy encrypts traffic to the Internet, serves local names, and blocks advertising domains. Unlike Pi-hole (NULL blocking, exact hosts matching), it answers blocked names with NXDOMAIN and blocks whole subtrees, consistent with RFC 8020.

The required executable name is isa-dnsproxy.

Specification
A message is one UDP datagram or one length-prefixed TCP frame; a query is a message that passes steps 1–5 of Message processing; a response is the DNS message sent to the client. The apex of a zone is the owner of its SOA record (the origin of the zone file).

Every message gets exactly one verdict:

Verdict	When	RCODE sent to the client
local	the name belongs to a loaded zone; answered from the zone	NOERROR or NXDOMAIN
blocked	otherwise, the name matches a blocklist entry	NXDOMAIN
forwarded	otherwise, the query was (or would have been) sent to the upstream	the upstream's RCODE, or SERVFAIL on failure
invalid	rejected in steps 3–8 of Message processing	FORMERR, NOTIMP, or REFUSED
dropped	no response sent (steps 1–2 of Message processing)	none
Required functionality
Listeners
The proxy MUST accept messages over UDP and TCP on the configured port. Without -a it MUST serve IPv4 and IPv6 (one dual-stack socket per transport or two sockets); with -a it MUST bind exactly that address and serve only its family (0.0.0.0 IPv4 only, :: IPv6 only). If a socket cannot be bound, it MUST exit non-zero (EX_UNAVAILABLE 69).
UDP responses MUST leave from the socket that received the query.
TCP messages carry the two-byte length prefix of RFC 1035. The proxy MUST handle several consecutive queries per connection and SHOULD answer pipelined queries in any order (RFC 7766). It MUST close a connection after 10 s of idleness (tolerance +5 s) or when the client closes it; after a dropped TCP message it closes the connection, and a client closing mid-message produces no log line.
A slow upstream or client MUST NOT delay other messages on any transport or from any address. The proxy MAY cap outstanding upstream requests at a value of at least 64, printed on stderr at start-up; queries above the cap are answered SERVFAIL and logged forwarded.
The proxy MUST survive SIGPIPE and clients disconnecting at any moment.
Message processing
The proxy MUST check every message in this order; the first failing check decides:

#	Condition	Result
1	shorter than 12 octets	dropped
2	QR = 1	dropped
3	OPCODE ≠ QUERY	invalid, NOTIMP
4	QDCOUNT ≠ 1	invalid, FORMERR (RFC 9619; QDCOUNT = 0 by this specification)
5	the question does not parse	invalid, FORMERR
6	the remaining sections cannot be skipped, more than one OPT record, or an OPT outside the additional section or with a non-root owner	invalid, FORMERR
7	QCLASS ≠ IN (including ANY)	invalid, NOTIMP
8	QTYPE = AXFR or IXFR	invalid, REFUSED
9	otherwise	local, blocked, or forwarded
A question does not parse if a label length octet is 64..191, a compression pointer occurs, the name exceeds 255 octets, or the name, QTYPE, or QCLASS runs past the message. The question is parsed only after steps 3 and 4 pass. Records in the other sections of a query (such as the OPT every dig sends) and the flags TC, AA, RA, AD, Z MUST NOT be treated as errors; the OPT version is not checked.

Zones
Zone files (-z, format) MUST be loaded at start-up. SOA, NS, A, AAAA, CNAME, and MX MUST be supported; other IANA-registered types MAY be. A record of a registered but unsupported type MUST be skipped with a warning on stderr, its owner still existing.
A name belongs to a zone if it is the apex or below it, case-insensitively; among nested zones the longest apex MUST win. A name exists if it owns a record (including skipped ones) or is an in-zone ancestor of one. NS records below the apex are ordinary records; delegations are not modeled.
Records of the queried type MUST be returned in the answer section; ANY MUST return every record set of the name.
If the name owns a CNAME and QTYPE is neither CNAME nor ANY, the CNAME MUST be returned and the chain followed for up to 8 hops while the target is in a loaded zone, adding the queried records of the last name reached. That name decides the RCODE: NXDOMAIN if it does not exist, NOERROR otherwise. A target outside all zones or a loop ends the chain with NOERROR, each CNAME once, and no SOA.
A name that exists without the queried type MUST get NOERROR with an empty answer; a name that does not exist MUST get NXDOMAIN. Both MUST carry the SOA of the zone containing the last name in the authority section, TTL min(SOA TTL, SOA MINIMUM) (RFC 2308).
Zone TTLs MUST be returned unchanged. Tests ignore glue in the additional section and compare owner names case-insensitively.
Names in a loaded zone MUST NOT be blocked or forwarded, even if a blocklist entry covers them.
Blocklists
Blocklists (-b, format) MUST be loaded at start-up.
A name matches an entry if it equals it or lies below it on a label boundary (ads.example.com blocks x.ads.example.com, not bads.example.com), case-insensitively and ignoring a trailing dot.
A blocked query MUST get NXDOMAIN regardless of QTYPE, with empty answer and authority sections.
Forwarding
Queries MUST be sent to the upstream given by -u per RFC 8484: POST, Content-Type and Accept application/dns-message. GET MAY be added.
The query MUST be relayed unchanged except for the ID, which SHOULD be 0 (RFC 8484 §4.1). The response MUST carry the client's ID; responses are matched to queries by the HTTP exchange, so two clients using the same ID at once each get their own response.
The DNS message in a 2xx response MUST be relayed unchanged except for the ID and truncation, whatever its RCODE. It is valid if it has 12..65535 octets, QR = 1, OPCODE = QUERY, QDCOUNT = 1, and a question equal to the forwarded one (QNAME case-insensitively).
The proxy MUST answer SERVFAIL as soon as one of these is known, and not before:
the upstream hostname does not resolve;
the connection or TLS handshake fails;
a final non-2xx HTTP response arrives (redirects MUST NOT be followed);
the body is invalid;
the outstanding-request cap is hit;
the proxy is shutting down;
the timeout -w (covering resolution, connection, handshake, request, and response) elapses.
The upstream certificate chain and hostname MUST be verified against SSL_CERT_FILE when set, otherwise the system trust store, unless --insecure is given.
The proxy MUST work with an upstream offering HTTP/1.1 only, and its connection handling MUST NOT limit parallelism below the outstanding-request cap.
The upstream hostname is resolved by the system resolver; the proxy need not resolve it through itself.
Caching is not required. If implemented it MUST be off by default, and with caching off every forwarded query MUST cause exactly one upstream request (a transparent resend on a connection closed by the upstream does not count).
Responses
Every response the proxy builds (local, blocked, invalid, forwarded SERVFAIL) MUST have QR = 1; OPCODE, RD, CD copied from the query; RA = 1; AD = Z = 0; AA = 1 only for local; the client's ID; and the question copied byte-for-byte if it was parsed, otherwise QDCOUNT = 0.
If a query that passed step 6 carries an OPT, every response the proxy builds MUST carry an OPT with version 0, no options, payload size ≥ 1232; otherwise it MUST NOT carry one. Responses to messages rejected in steps 1–6 carry no OPT.
Full EDNS(0) support is not required; the basic handling described here is sufficient. The proxy only has to recognise the OPT record, echo a bare OPT (version 0, no options) in its own responses, and honour the advertised UDP payload size. EDNS options (client subnet, cookies, padding, extended DNS errors, …), EXTENDED-RCODE, the DO bit, and any other EDNS mechanism are out of scope and are not tested.
The UDP response limit is 512 octets without OPT, or the client's advertised size clamped to 512..1232 with OPT (RFC 6891 §6.2.3). A larger response MUST be replaced by its own header with TC = 1 and ANCOUNT = NSCOUNT = 0, the question, and its own OPT if the query had one (ARCOUNT 1, else 0). Cutting at the limit is not acceptable. TCP responses MUST NOT be truncated.
Start-up, shutdown, and time limits
Zone files and blocklists MUST be fully parsed at start-up. On any error from their format sections, an unreadable file, or two zones with the same apex, the proxy MUST print <file>:<line>: <message> on stderr and exit non-zero (EX_CONFIG 78) before serving anything.
Start-up (files loaded, sockets bound) MUST finish within 5 s for 10 zone files and 200 000 blocklist entries, then the proxy MUST print listening on <address>:<port> per socket on stderr (IPv6 in brackets); tests wait for these lines.
After that, SIGINT or SIGTERM MUST stop accepting messages, answer in-flight queries SERVFAIL, log them, and exit 0 within 2 s. A signal before the listening on lines MUST exit non-zero.
local, blocked, and invalid responses MUST arrive within 200 ms (after one warm-up query), forwarded within TIMEOUT + 1 s.
Files are read once; reloading is not required.
What is not required
caching (see Forwarding if you add it); DNSSEC; DNS-over-TLS or other upstream transports; RFC 8484 GET;
optional record types, wildcards, $INCLUDE, multi-line records, and backslash escapes in zone files; delegations and zone transfers;
regular expressions, ABP-style entries (||example.com^), or allowlists in blocklists;
out-of-order answering of pipelined TCP queries; runtime reloading, statistics, a web interface.
Command-line interface
./isa-dnsproxy -u DOH_URL [-p PORT] [-a ADDRESS] [-z ZONEFILE]... [-b BLOCKLIST]... [-w TIMEOUT] [--insecure]
./isa-dnsproxy -h | --help
Option	Description
-u DOH_URL	https:// (or, for local testing, http://) URL of the upstream, e.g. https://cloudflare-dns.com/dns-query. Mandatory.
-p PORT	UDP and TCP port, 1..65535. Default 53.
-a ADDRESS	Literal IPv4 or IPv6 address (no brackets, zone index, or hostname). Default: all local addresses.
-z ZONEFILE, -b BLOCKLIST	Zone file or blocklist; repeatable.
-w TIMEOUT	Upstream timeout in whole seconds, 1..3600. Default 3.
--insecure	Disable TLS certificate and hostname verification.
A repeated single-valued option, a value out of range, or a -u that is not an http(s) URL MUST exit non-zero (EX_USAGE 64) with a message on stderr. -h / --help wins over all validation.

Zone file format
The master file format of RFC 1035 §5 with $TTL (RFC 2308) and AAAA (RFC 3596), restricted to this grammar; the proxy MUST accept it and MUST reject anything else at start-up:

$ORIGIN <absolute name> may appear once, before the first record; without it the SOA must come first with an absolute owner, which becomes the origin. $TTL <seconds> sets the TTL of following records that have none.
One record per line: [owner] [ttl] [IN] type rdata, in this order. A line starting with whitespace repeats the previous owner. @ is the origin; a name without a trailing dot is relative to it. Both rules apply to owners and to names in rdata.
ttl is 0..2147483647 seconds, no unit suffixes. SOA counters are 0..4294967295 (minimum 0..2147483647), MX preference 0..65535.
rdata of mandatory types: SOA (mname rname serial refresh retry expire minimum, no parentheses), NS (nsdname), A, AAAA (address), CNAME (cname), MX (preference exchange). Mnemonics are case-insensitive.
; starts a comment; blank lines and a trailing carriage return are ignored.
Errors:

not exactly one SOA, or its owner is not the origin;
an owner outside the zone;
a line not matching the record form;
a type not registered with IANA;
malformed rdata of a mandatory type;
a record without ttl and no preceding $TTL;
one type at one owner with different TTLs (RFC 2181);
a CNAME owner with other records;
a first record without owner.
Example home.lan.zone:

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
Blocklist format
Each line is cut at the first #, stripped of a trailing carriage return and surrounding whitespace, and split on whitespace; an empty line has no entries.

If the first token contains a :, it is an IPv6 address and is skipped without further checks: published Pi-hole lists use the hosts(5) format (0.0.0.0 name ..., :: name ...), and the address carries no meaning here.
Every other token MUST be a domain name of 1..127 labels of 1..63 letters, digits, -, or _, at most 253 characters excluding an optional trailing dot.
Each name is an entry, except that names of digits and dots only (this covers a leading IPv4 address) and the hosts(5) header names localhost, localhost.localdomain, local, broadcasthost, ip6-localhost, ip6-loopback, ip6-localnet, ip6-mcastprefix, ip6-allnodes, ip6-allrouters, ip6-allhosts MUST be ignored.
Anything else on a non-empty line is a start-up error.
Example ads.txt:

# advertising
ads.example.com
0.0.0.0 tracker.example.net telemetry.example.net
Query log
[!WARNING] The query log is parsed by automated tests. Write it to stdout exactly as specified.

Each received message MUST produce exactly one line on stdout, written as a single flushed write after the response was sent or the message dropped; lines MUST NOT interleave and their order across messages is unspecified. Nothing else goes to stdout except the -h usage text.

<timestamp> <client> <qname> <qtype> <verdict> <rcode>
Six fields separated by one space, terminated by \n:

Field	Format
<timestamp>	RFC 3339 with seconds precision, no fraction, numeric offset or Z, e.g. 2026-09-14T10:15:30+02:00.
<client>	IP address and port, 192.168.1.10:53412 or [fd00::10]:53412. IPv6 in RFC 5952 form without %zone; IPv4-mapped addresses from a dual-stack socket MUST be printed as IPv4.
<qname>	The name in lowercase (ASCII letters) with a trailing dot; the root is .. Inside a label, ., ;, (, ), @, $, ", \ are written \c and other bytes outside 0x21..0x7E as \DDD (RFC 1035 §5.1, as dig prints them).
<qtype>	The IANA RR TYPE mnemonic (A, AAAA, MX, ANY, HTTPS, ...) or TYPE<n> (RFC 3597).
<verdict>	local, blocked, forwarded, invalid, or dropped.
<rcode>	The IANA mnemonic of the 4-bit RCODE sent (NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, YXDOMAIN, ...) or RCODE<n>; - for dropped.
For invalid and dropped messages, <qname> and <qtype> are logged if the question was parsed (steps 3 and 4 passed), else -.

Tests validate every stdout line with the following regular expression and match lines as a multiset keyed by client, name, and type, never by position:

^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2}) ((?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:]+\]):\d{1,5} (-|\.|(?:(?:[^\sA-Z\\.;()@$"]|\\[0-9]{3}|\\[.;()@$"\\])+\.)+) (-|[A-Z][A-Z0-9-]*|TYPE\d+) (local|blocked|forwarded|invalid|dropped) (-|[A-Z]+|RCODE\d+)$
Execution examples
Example files are in examples/. The outputs below come from a reference implementation with dig 9.20; timestamps, client ports, query IDs, TTLs, and the content of forwarded responses vary, while flags, sections, verdicts, and the log format MUST match. dig sends an OPT record, so every response carries the proxy's own OPT (ADDITIONAL: 1).

$ ./isa-dnsproxy -u https://cloudflare-dns.com/dns-query -p 5300 -z examples/home.lan.zone -b examples/ads.txt
listening on 0.0.0.0:5300
listening on 0.0.0.0:5300
listening on [::]:5300
listening on [::]:5300
Two sockets per address family, UDP and TCP. Which addresses appear depends on the implementation (one dual-stack socket per transport prints two lines in total); stdout stays empty until the first message arrives.

1. A name in a loaded zone
$ dig @127.0.0.1 -p 5300 router.home.lan A +noall +comments +answer +authority
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31658
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
router.home.lan.	3600	IN	A	192.168.1.1
aa is set because the answer comes from a loaded zone; the TTL is the zone's $TTL.

2. A CNAME chain inside the zone
$ dig @127.0.0.1 -p 5300 media.home.lan A +noall +comments +answer +authority
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8476
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
media.home.lan.		3600	IN	CNAME	nas.home.lan.
nas.home.lan.		3600	IN	A	192.168.1.20
The CNAME is returned first, the chain is followed to nas.home.lan., and the A records of the last name reached are appended; that name also decides the RCODE. dig media.home.lan CNAME would return only the first record.

3. A name below the apex that does not exist
$ dig @127.0.0.1 -p 5300 printer.home.lan A +noall +comments +answer +authority
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 35423
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; AUTHORITY SECTION:
home.lan.		3600	IN	SOA	ns1.home.lan. admin.home.lan. 2026091401 7200 3600 1209600 3600
Authoritative NXDOMAIN with the zone SOA in the authority section, TTL min(SOA TTL, MINIMUM). A name that exists without the queried type (dig router.home.lan MX) looks the same except for status: NOERROR.

4. A blocked name
$ dig @127.0.0.1 -p 5300 www.ads.example.com AAAA +noall +comments +answer +authority
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 13727
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
www.ads.example.com lies below the entry ads.example.com. Unlike the zone case there is no aa and no SOA, whatever the QTYPE; nothing is sent to the upstream.

5. A forwarded query, over TCP
$ dig @127.0.0.1 -p 5300 www.fit.vut.cz A +tcp +noall +comments +answer +authority
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28651
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; ANSWER SECTION:
www.fit.vut.cz.		10588	IN	A	147.229.9.65
Everything after the ID is the upstream's message: the ad flag, the TTL, and the OPT are the resolver's, not the proxy's. The same query over UDP gives the same answer; TCP only changes the framing.

Resulting query log
The query log on stdout after the five queries, one line per message in the order they were answered:

2026-09-15T09:57:29+02:00 127.0.0.1:50417 router.home.lan. A local NOERROR
2026-09-15T09:57:29+02:00 127.0.0.1:44669 media.home.lan. A local NOERROR
2026-09-15T09:57:29+02:00 127.0.0.1:37223 printer.home.lan. A local NXDOMAIN
2026-09-15T09:57:29+02:00 127.0.0.1:51555 www.ads.example.com. AAAA blocked NXDOMAIN
2026-09-15T09:57:29+02:00 127.0.0.1:35694 www.fit.vut.cz. A forwarded NOERROR
Automated testing expectations
Every MUST under Required functionality is exercised by at least one test. Tests use dig (+tries=1 +time=TIMEOUT+2), kdig, and a raw-socket client, and inspect responses, the query log, and the upstream's request log.

No upstream is provided: choose a public DoH resolver that satisfies this assignment (RFC 8484 POST, publicly trusted certificate) and document your choice; evaluation uses an upstream chosen by the instructors, so the proxy MUST NOT depend on a particular one. Throwaway test upstreams on non-standard ports offer HTTP/1.1 (and HTTP/2 over TLS), use trusted, untrusted, or no certificates, serve randomized answers, and record every request: a forwarded verdict without a matching request (other than SERVFAIL above the printed cap), or a response differing from the upstream's, is a forwarding failure.

Timing tests run with -w at least 2 s above any upstream delay. The concurrency test delays the upstream by 3 s and fires ten forwarded queries plus one local query: the local one within 200 ms, the forwarded ones within 5 s.

Scenarios a literal reading may miss:

a name both in a zone and on a blocklist; a blocklist entry above a zone apex;
several queries on one TCP connection, a message split across segments, an idle TCP connection that must not stall UDP, SIGTERM with a query in flight;
two clients using the same query ID at once;
forwarded responses with a non-NOERROR RCODE or with an OPT, relayed unchanged; a redirecting upstream;
dig +bufsize=512 against a zone response over 512 octets; +noedns against a forwarded one over 512 octets;
a port in use on any of the four sockets; -a with a specific IPv4 and IPv6 address; -h; a missing -u;
a zero-length UDP datagram, labels over 63 octets, QDCOUNT = 0, QCLASS = CH, QTYPE = HTTPS and ANY;
published blocklists with CRLF endings, hosts(5) headers, and several names per line.
Documentation requirements
Beyond the guidelines, your README.md MUST describe:

the architecture and how concurrency is achieved;
the libraries used (project URL, version, license, responsibility);
the public DoH resolver you tested against and how you verified it satisfies RFC 8484 as used here;
how DNS messages are parsed and built, including truncation;
how zones are stored and looked up (CNAME chains, negative responses, optional types supported);
a tcpdump or tshark excerpt of one client query and the corresponding HTTPS exchange.
Evaluation
Automated evaluation and the mandatory oral defence follow the guidelines; registration opens after the automated results appear in IS VUT. The defence focuses on DNS message handling, the concurrency model, and the libraries used; expect to make a small change to your code on the spot.

Of the automatically tested points, forwarding counts about one half, blocking and zones one quarter each. Every violated MUST is deducted from its area, even without an automated test.

A submission MAY be rejected as unacceptable in particular if:

queries over any required transport (UDP, TCP, IPv4, IPv6) are not answered;
forwarded responses are altered or carry a wrong ID;
blocked names or names in a loaded zone reach the upstream;
the query log breaks the format or misses messages;
the required CLI is not supported.
A dry run (see the guidelines) MAY be offered about one week before the deadline. The instructors reserve the right not to run it, or not to publish its results.
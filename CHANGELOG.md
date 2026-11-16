# Changelog

All notable changes to `isa-dnsproxy`, newest first. Each entry refers to the commit in the
project repository. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

AI usage: this file was written with the help of an AI assistant (Claude, Anthropic) from the
author's commit history, see "Use of AI" in README.md.

## 2026-11-16 – `4825643`

### Added
- `examples/home.lan.zone` and `examples/ads.txt` (example files from the assignment).
- `make test`, `make test-fast` and `make zip` targets in the Makefile; build with `-std=c17`.
- Full README: architecture, libraries, design decisions, test results (automated tests, `dig`,
  `kdig`, `curl`, tcpdump, valgrind), known limitations, Use of AI, references.
- This changelog.
- `.gitignore` for build artifacts and caches.

### Changed
- Automated tests converted from pytest to `unittest` from the Python standard library, so they
  run in the unmodified dev-envs devShell (pytest is not available there).

### Fixed
- `-h` / `--help` prints the full usage text.

### Removed
- Build artifacts (`build/`, the binary) and pytest caches from the repository.

### Known issues
- The blocklist hash table is not freed at exit; zones are not freed on an error exit.

## 2026-11-16 – `d82e8fd`

### Added
- Event loop: single-threaded, non-blocking UDP and TCP (IPv4 and IPv6), TCP framing,
  10 s idle timeout, UDP truncation, SIGINT/SIGTERM handling.
- Lookup in local zones: longest apex, CNAME chains (at most 8 hops), NXDOMAIN/NODATA with SOA.
- Query log on stdout.

## 2026-11-13 – `98eb31e`

### Added
- Forwarding over DNS-over-HTTPS (RFC 8484, POST) using libcurl multi; upstream timeout (`-w`),
  `--insecure`, SERVFAIL on upstream errors, cap on outstanding requests.

## 2026-10-22 – `2073e07`

### Added
- Parser of the DNS question section.

## 2026-10-22 – `919963a`

### Added
- Parser of the DNS message header.

## 2026-10-19 – `f6959c4`

### Added
- Zone file parser.
- Socket initialization.

## 2026-10-05 – `d212872`

### Added
- Blocklist parser.

## 2026-10-03 – `366ab87`

### Added
- Hash table (`hash_table.c`, `hash_table.h`).

## 2026-10-02 – `22a980b`

### Fixed
- Argument parser.

## 2026-10-02 – `fefffc3`

### Added
- Argument parser, configuration data structure and its initialization.
- Empty Makefile.

## 2026-09-19 – `d2fc9c3`

### Added
- Directories `src`, `include`, `tests`; license; README.

## 2026-09-19 – `56d8ff7`

### Added
- README.

## 2026-09-19 – `cd660cf`

### Added
- Initial commit.
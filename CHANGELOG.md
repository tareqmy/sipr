# Changelog

All notable changes to sipr are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Injection files** — `-inf FILE` (repeatable) loads SIPp-style injection
  files: a `SEQUENTIAL`/`RANDOM`/`USER` mode header, `;`-separated fields,
  `#` comments, blank-line terminator. One line is drawn per call per file
  (SEQUENTIAL cycles, RANDOM picks uniformly, USER defers to `-users`). The
  `[fieldN]` keyword substitutes field N of the drawn line. `file=NAME`
  selects another file by its basename (SIPp's key), or by a 0-based `-inf`
  index (sipr extension); `line=` overrides the per-call line and is rendered
  at send time, so `line=[$var]` works. Unknown field/file names are rejected
  at load. See `docs/SIPP_COMPAT.md` §6.
- **Indexed injection** — `-infindex FILE FIELD` builds a key→line index over
  one field of an `-inf` file (matched by basename; last line wins on
  duplicate keys). Actions `<lookup assign_to=… file=… key=…/>` (stores the
  matched line or -1), `<insert file=… value=…/>` (appends a row), and
  `<replace file=… line=… value=…/>` (swaps a row) operate on that data at
  runtime. The canonical use is `lookup → [fieldN line=[$var]]`.

## [0.1.0] — 2026-08-16

First release. A SIPp-compatible SIP testing tool and traffic generator,
feature-complete for signaling over UDP. Built entirely on the Rust standard
library — no external crates.

### Added

- **Scenarios** — SIPp-compatible XML: `send`, `recv`, `pause`, `nop`,
  `label`, `timewait`, `Reference`, and the response/call-length repartition
  tables. Loud diagnostics with file:line context; `--check` lint mode that
  prints the compiled IR.
- **Keywords** — `[service]`, `[remote_ip]`/`[remote_port]`,
  `[local_ip]`/`[local_port]`, `[transport]`, `[call_id]`, `[call_number]`,
  `[cseq]`, `[branch]`, `[msg_index]`, `[pid]`, `[routes]`, `[next_url]`,
  `[peer_tag_param]`, `[len]`, `[last_*:]`, `[$var]`, `[authentication]`, and
  the `[media_*]` placeholders.
- **Actions** — `ereg` (capture groups via an in-tree POSIX-ERE engine),
  `assign`/`assignstr`/`strcmp`/`test`, arithmetic (`add`/`subtract`/
  `multiply`/`divide`), `todouble`, `trim`, `urlencode`/`urldecode`,
  `gettimeofday`, `jump`, `log`/`warning`/`error`, `exec int_cmd`. Plus
  `test`/`condexec` branching, `chance`, named counters, and per-call
  variables.
- **Engine** — UAC and UAS roles; open-loop pacer (`-r`/`-rp`/`-l`/`-m`) with
  rate smoothing; single event-loop over UDP, timers, and the pacer. Recv
  matching (optional-recv windows, backward contiguous scan, CSeq-method
  guard) verified against SIPp's `call.cpp`.
- **Transport** — UDP with RFC 3261 T1→T2 retransmission, inbound
  retransmission handling, simulated loss (`lost`), and an in-tree SIP
  message parser proven panic-free by a fuzz suite.
- **Authentication** — digest MD5 and SHA-256 (`qop=auth`, proxy 407), with
  in-tree hash primitives verified against the RFC 1321 / FIPS 180-4 /
  RFC 2617 / RFC 7616 vectors.
- **Statistics** — SIPp counter set with failure breakdown, response-time
  histograms and RTDs, repartition tables, `-trace_stat`/`-stf`/`-fd` CSV,
  and `-trace_msg`/`-trace_err` files.
- **Live TUI** — main / per-step scenario / repartition screens, live rate
  keys (`+ - * /`), pause (`p`), screen cycling (`s`), and safe terminal
  restore on every exit path. Ferrous brand colors, honoring `NO_COLOR`.
- **CLI** — SIPp-style single-dash flags with did-you-mean suggestions;
  SIPp-compatible exit codes (0 ok, 1 failures, 99 no calls, 2 usage,
  255 fatal).
- **Tooling** — six-crate workspace, `Makefile` convenience targets, CI
  (fmt + clippy + tests, and an interop job against real SIPp), and the
  Ferrous brand kit under `brand/`.

### Known limitations

- Signaling only over UDP. TCP/TLS, `-inf` injection files (and the
  `lookup`/`insert`/`replace` actions), 3PCC, RTP/pcap media, IPv6, and an
  HTTP control API are on the post-v1 roadmap.
- The `ereg` regex engine is leftmost-first greedy (PCRE-style), not POSIX
  leftmost-longest — identical on the patterns real scenarios use; see
  `docs/SIPP_COMPAT.md` §6.

[Unreleased]: https://github.com/tareqmy/sipr/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tareqmy/sipr/releases/tag/v0.1.0

# Changelog

All notable changes to sipr are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — 2026-09-04

### Added

- **RTP streaming and DTMF (`exec rtp_stream=`, `exec play_dtmf=`)** —
  SIPp's `rtpstream.cpp` semantics on the M14 scheduler: raw codec files or
  `apattern`/`vpattern` fills with SIPp's fixed payload table, looping,
  `pause`/`resume` (the clock keeps running, as in SIPp), SSRC
  `0xCA110000`-based, plus RFC 4733 DTMF bursts with SIPp's exact timing.
  `[rtpstream_audio_port]`/`[rtpstream_video_port]` keywords with per-call
  allocation, `-rtp_payload`, `-max_rtp_port`, `-random_base_ssrc`. sipr
  streams from the port the SDP advertised (SIPp binds an unrelated one)
  and numbers DTMF packets consecutively (SIPp skips every other warm-up
  number). Divergences in `docs/SIPP_COMPAT.md` §6.

## [0.3.0] — 2026-09-04

### Added

- **pcap replay (`exec play_pcap_audio|video|image=`)** — SIPp's media
  feature, without the raw socket: a new std-only `sipr-media` crate reads
  classic pcap files (Ethernet/802.1Q, raw IP, Linux cooked, BSD loopback;
  IPv4/IPv6 UDP), learns the peer's media endpoint from its SDP, and replays
  the UDP payloads verbatim on the capture's timeline from one scheduler
  thread, through ordinary UDP sockets bound to the advertised media port —
  no root, no libpcap. `-mi`/`-mp` (`-min_rtp_port`), `[auto_media_port]`,
  `[media_port+N]`, `<recv ignoresdp>`. RTP counters on the TUI, `-bg` line,
  and the final summary. Divergences from SIPp in `docs/SIPP_COMPAT.md` §6.

## [0.2.0] — 2026-09-03

### Added

- **TLS transport (`-t l1`)** — SIP over TLS with SIPp's exact semantics:
  same connection-per-peer model and Content-Length framing as TCP, no SIP
  retransmissions, port 5060, `[transport]` renders `TLS`. `-tls_cert` /
  `-tls_key` (defaults `cacert.pem`/`cakey.pem`), `-tls_ca` / `-tls_crl`
  (presence enables SIPp-style verification: chain but not hostname on the
  client, mandatory client cert on the server), `-tls_version 1.2|1.3`.
  Built on `rustls` with the `ring` provider — the workspace's first
  external dependency, still no system OpenSSL required. Divergences from
  SIPp documented in `docs/SIPP_COMPAT.md` §6.

### Changed

- The `dependencies: std-only` claim is retired: `sipr-net` now carries
  `rustls`/`rustls-pemfile` for the TLS transport. Everything else remains
  std; the build still needs no system libraries.

- **IPv6** — targets accept bracketed (`[::1]`, `[2001:db8::1]:5060`) and
  bare-literal (`::1`) IPv6, with automatic `::` binding when a v6 target is
  given without `-i`. `[local_ip]`/`[remote_ip]` render bracketed inside URIs
  and Via (SIPp's `local_ip_w_brackets`), while `[media_ip]` stays raw for SDP.
  See `docs/SIPP_COMPAT.md` §6.

## [0.1.1] — 2026-08-17

Post-v1 feature drop: TCP transport, injection files with indexed lookups,
classic 3PCC, and closed-loop `-users` mode. Still standard-library only.

### Added

- **Closed-loop `-users`** — `-users N` keeps N concurrent calls, each holding
  a stable 1-based user id; a finished call's id is recycled into a replacement
  immediately. Adds the `[userid]`/`[users]` keywords and lights up USER-mode
  `-inf` injection (line = user id − 1). Mutually exclusive with `-l`. See
  `docs/SIPP_COMPAT.md` §6.
- **Classic 3PCC** — `-3pcc HOST:PORT` plus `<sendCmd>`/`<recvCmd>` steps let
  two sipr instances coordinate over a separate ESC-delimited TCP "twin"
  socket. The role is derived from the scenario's first twin command
  (`sendCmd`-first dials, `recvCmd`-first listens); `<recvCmd>` blocks the call
  until a command arrives and runs its actions against the command text. See
  `docs/SIPP_COMPAT.md` §6.
- **TCP transport** — `-t t1` runs SIP over TCP. A stream framer de-frames
  messages by `Content-Length` (RFC 3261 §7.5); the client keeps one
  connection to the target, the server accepts connections and replies on the
  one each request arrived on. Reliable transport, so no SIP retransmissions
  are scheduled. `-t tn` is accepted as an alias. See `docs/SIPP_COMPAT.md` §6.
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

### Fixed

- Body-less SIP messages (180, ACK, empty 200) now always include the
  mandatory `\r\n\r\n` header/body separator. UDP tolerated its absence; TCP
  framing and real-SIPp interop require it.

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

[Unreleased]: https://github.com/tareqmy/sipr/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/tareqmy/sipr/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/tareqmy/sipr/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tareqmy/sipr/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/tareqmy/sipr/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tareqmy/sipr/releases/tag/v0.1.0

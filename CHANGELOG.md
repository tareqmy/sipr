# Changelog

All notable changes to sipr are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.0] — 2026-09-05

### Added

- **SIPp's unexpected-message handler** — `<label id="_unexp.main"/>`,
  `_unexp.retaddr`, `_unexp.pausedaddr`, `<jump variable=>` and
  `<pauserestore>`: an unexpected in-call message jumps to the handler,
  which answers it and resumes the interrupted pause for exactly its
  remaining time. Verified both ways against real sipp.
- **`<closecon/>`** is accepted (a no-op, as SIPp's reference-count drop is
  on every mono-socket transport).

## [0.15.0] — 2026-09-05

### Added

- **`<verifyauth>`** — sipr can play a digest-checking registrar: the
  received `Authorization:` header is verified against a username and
  password (MD5 or SHA-256, qop auth/auth-int, `-auth_uri`) and the
  boolean verdict drives `test=` branching, exactly SIPp's documented
  recipe. Verified in both directions against real sipp.

## [0.14.0] — 2026-09-05

### Added

- **SRTP echo server** — `exec rtp_echo="startaudio|updateaudio|stopaudio|
  startvideo|updatevideo|stopvideo[,pt[,name]]"`: the call echoes (S)RTP on
  its advertised media port, re-keyed from the SDES negotiation with the
  caller's SSRC and sequence numbers preserved. SIPp's
  `pfca_uas_*_crypto_*.xml` scenarios now run unchanged, and real sipp's
  UAC passes its own RTP check against them.

### Fixed

- `ereg search_in="hdr"` now hands the regexp what SIPp does: the rest of
  the first matching line after the header string (so `header="CSeq:"`
  works and `CSeq: [$1]` replays the caller's CSeq), and an absent header
  fails the call under `check_it`.

## [0.13.0] — 2026-09-05

### Added

- **`[authentication]` from an injection field** — a CSV column holding
  `[authentication username=… password=…]` (or AKA parameters) is
  re-parsed as the keyword at send time, SIPp's documented way to give
  each call its own credentials.

### Fixed

- `[authentication]` now renders the whole header line as SIPp does
  (`Authorization:` after a 401, `Proxy-Authorization:` after a 407), so
  SIPp scenarios that place the keyword on its own line work unchanged.
  sipr's earlier `Authorization: [authentication …]` spelling still works.

## [0.12.0] — 2026-09-05

### Added

- **SRTP with SDES keying** — SIPp's crypto keywords (`[cryptotag1audio]`,
  `[cryptosuiteaescm128sha1801audio]`, `[cryptokeyparams1audio]`, the
  `ue…` unencrypted forms, secondary and video variants) render offers
  and answers; the peer's `a=crypto:` lines are parsed; `rtp_stream`
  packets are protected with AES-CM-128 or the NULL cipher and HMAC-SHA1
  80/32, and the echo check unprotects the echo before comparing. All
  cryptography is in-tree and verified against RFC 3711's vectors. Unlike
  SIPp, the authentication tag uses the packet's own rollover counter, so
  streams stay valid past sequence 65535.

### Fixed

- The CSeq-method guard on `recv response=` now follows SIPp exactly: a
  response matches when its CSeq method is any request method sent so
  far, not only the most recent one. A 200 to the INVITE arriving after a
  PRACK was wrongly treated as unexpected.

## [0.11.0] — 2026-09-04

### Added

- **`hide` and `display` attributes, and SIPp's screen keys** — `hide="true"`
  keeps a step off the scenario screen while `set hide true` (the default)
  holds; `display="…"` replaces its label. Both reach `/stats`. The `1`/`2`/`3`
  keys switch screens at the keyboard and over the control socket.

## [0.10.0] — 2026-09-04

### Added

- **`-auth_uri`** — SIPp's flag for the digest `uri=`; the value gets a
  `sip:` prefix exactly as SIPp does.
- **Keywords inside `[authentication]` parameters** — `username=[field0]`,
  `password=[$p]`, `aka_K=[field2]` and friends are rendered before use,
  as SIPp renders them, so credentials can come from injection files.

### Changed

- The default digest `uri=` is now SIPp's `sip:remote_ip:remote_port`
  (no user part) instead of `sip:service@remote_ip:remote_port`. Servers
  verify against the header's own `uri=`, so runs are unaffected; the
  wire form now matches SIPp byte for byte.

## [0.9.0] — 2026-09-04

### Added

- **Rate ramps** — SIPp's `-rate_increase N`, `-rate_interval TIME`
  (seconds or `ms`/`s`/`m`/`h`), `-rate_max N`, and `-no_rate_quit`:
  the rate climbs every interval and, when it would pass the cap, is
  clamped there and the run drains (unless told not to). Also
  `-rate_scale` for the hot-key step.

## [0.8.0] — 2026-09-04

### Added

- **AKA resynchronisation (AUTS)** — `[authentication … aka_sqn=0x…]`
  gives the client's SQN_MS; a challenge whose SQN is not above it (or any
  challenge with `aka_resync=1`) is answered with `auts=` and an
  empty-password digest per RFC 3310 §3.2 / TS 33.102 §6.3.3, then the
  server's fresh challenge is answered normally. SIPp's resync code is
  unreachable, so this is new ground for SIPp scenarios.

## [0.7.0] — 2026-09-04

### Added

- **RTP echo and the RTP check** — `-rtp_echo` (with `-mb`) echoes RTP
  received on the media port and media port + 2 back to its sender, with
  SIPp's counters and the `<rtp_echo value="0|1"/>` action to toggle it;
  `rtp_stream` sockets now read back what the peer echoes and compare it
  to what was sent, and `-audiotolerance` / `-videotolerance` turn that
  into SIPp's verdict: a failed check exits 253 (SIPp's -3). Unlike SIPp,
  a stream is judged only when a tolerance flag is given. New counters on
  the TUI, the `-bg` line, and `/stats`.

## [0.6.0] — 2026-09-04

### Added

- **Runtime control** — SIPp's UDP control socket (`-cp`, `-ci`: hot keys
  and `c`-prefixed `set/trace/dump/reset` commands with SIPp's grammar and
  warning texts; default bind is loopback and `-cp 0` disables it) and a
  new HTTP/JSON API (`--sipr-http [HOST:]PORT`, `--sipr-http-token`):
  `/health`, `/stats`, `/control`, `/quit`, `/command`, `/scenario`.
  See `docs/CONTROL_API.md`. New std-only crate `sipr-control`.
- Hot keys now follow SIPp exactly: `set rate-scale` steps, user-count
  keys in `-users` mode, and a second `q` aborts like `Q`.

## [0.5.0] — 2026-09-04

### Added

- **IMS AKA authentication (`AKAv1-MD5`, RFC 3310)** — `[authentication
  aka_K=0x… aka_OP=0x… aka_AMF=0x…]` (SIPp's parameters, plus `aka_OPc=`)
  against an `algorithm=AKAv1-MD5` challenge: the nonce's RAND/AUTN go
  through an in-tree Milenage (AES-128, verified on 3GPP TS 35.208 test
  sets), the MAC is checked, and RES becomes the digest password. A MAC
  mismatch fails the call with a clear reason where SIPp aborts the whole
  process. No new dependency.

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

[Unreleased]: https://github.com/tareqmy/sipr/compare/v0.16.0...HEAD
[0.16.0]: https://github.com/tareqmy/sipr/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/tareqmy/sipr/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/tareqmy/sipr/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/tareqmy/sipr/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/tareqmy/sipr/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/tareqmy/sipr/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/tareqmy/sipr/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/tareqmy/sipr/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/tareqmy/sipr/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/tareqmy/sipr/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/tareqmy/sipr/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/tareqmy/sipr/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/tareqmy/sipr/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/tareqmy/sipr/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tareqmy/sipr/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/tareqmy/sipr/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tareqmy/sipr/releases/tag/v0.1.0

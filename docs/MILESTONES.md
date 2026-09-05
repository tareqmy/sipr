# Milestones and acceptance criteria

Live tracking document. Check items in the same commit that completes them.
Rationale and detail: `PLAN.md` §4. Do not start milestone N+1 while N has
unchecked *required* items (unchecked stretch items are fine, move them down).

## M0 — Scaffolding ✅

- [x] Workspace + six crates compile empty; `#![forbid(unsafe_code)]` everywhere
      (workspace lint, `unsafe_code = "forbid"`)
- [x] CLI accepts the v1 flag set (SIPP_COMPAT §3) with help text; unknown
      flags error out with a did-you-mean suggestion. NOTE: implemented as a
      bespoke table-driven parser in `src/cli.rs`, not clap — SIPp's
      single-dash multi-char flags (`-sf`, `-trace_msg`) can't be expressed in
      clap without an argv-rewriting shim, and zero deps keeps M0 buildable
      anywhere. Revisit only if flag complexity outgrows the table.
- [x] `-sn uac|uas` selects embedded default scenarios (clean-room ports of
      SIPp's defaults, `crates/sipr-scenario/assets/`); `-sd` prints them
- [x] CI: fmt + clippy(-D warnings) + test on push
- [x] `rust-toolchain.toml`, MSRV (1.85) recorded in CONVENTIONS.md

## M1 — Scenario front end ✅

- [x] XML parser → IR for full v1 tier of SIPP_COMPAT §1 (elements, attrs,
      actions), with file:line errors. NOTE: hand-rolled XML subset parser
      (`sipr-scenario/src/xml.rs`, like SIPp's own `xp_parser.cpp`) instead of
      quick-xml — zero deps, exact line tracking; swap only if the XML surface
      outgrows it.
- [x] Keyword tokenizer: full v1 keyword list (+ `[media_*]` placeholders);
      unknown keyword = loud warning, verbatim passthrough (IPv6 literals in
      URIs rely on this)
- [x] Label/next/ontimeout references validated and resolved to step indices;
      variables interned to table ids; read-never-set = error, set-never-read
      = warning, `Reference` suppresses
- [x] `--check` mode: lint + print compiled IR; exit 1 on any diagnostic
      (warnings included — check mode is strict); `-sf` role detection now
      drives the remote-target requirement
- [x] Golden corpus passing (`tests/corpus/{positive,negative}`), incl.
      negative goldens for media/3PCC/unknown-element scenarios with expected
      error markers

## M2 — Net + message layer ✅

- [x] UDP transport: bind `-i`/`-p`, recv loop, inbound parse, Call-ID
      routing fields, sharded call table. NOTES: (a) inbound parsing is an
      in-tree lazy parser (`sipr-net/src/message.rs`) instead of rsip —
      start-line classification, compact forms, folding, Call-ID/CSeq/
      branch/tags — panic-free on arbitrary bytes; (b) runtime is std-only
      threads feeding one mpsc event channel (SIPp's single-event-loop
      shape) instead of tokio — see the note in ARCHITECTURE §2; pure logic
      (TimerQueue, RetransSchedule, Inbound) is driver-agnostic if tokio
      lands later.
- [x] Timer service: pure `TimerQueue` (arm/cancel/pop_due, unit-tested
      without sleeping) + condvar thread driver; retransmission schedule
      with T1→T2 doubling, `retrans` override (incl. `retrans="0"` = off,
      base > T2 respected), max-retrans cap, `-nr` kill switch
- [x] `lost` simulation on send and recv paths (deterministic seeded
      xorshift; per-send override beats transport default)
- [x] No panic on arbitrary inbound datagrams: deterministic fuzz-style
      suite (`tests/no_panic.rs`) — random bytes, random ASCII, all
      truncations, single-byte mutations, pathological shapes. proptest is
      unavailable in this build env; the seeded equivalent is reproducible
      by construction.

## M3 — UAC end to end ✅ — first interop milestone

- [x] Embedded uac scenario completes against real `sipp -sn uas`; 0 failed.
      Verified 2026-08-17 on the dev machine against SIPp v3.7.7 (Homebrew,
      on PATH): `cargo test -p sipr --test interop` — both directions pass.
      The same flow is also verified end-to-end in-container against a
      scripted UAS (`tests/e2e.rs`): INVITE–180–200–ACK–pause–BYE–200,
      20 000 calls at 2000 cps, 0 failed, plus lost-first-INVITE
      retransmission recovery.
- [x] Pacer: `-r`, `-rp`, `-l` (non-queuing cap), `-m`; smoothing within the
      rate period (≤20 ms sub-ticks); runtime rate change API
      (`EngineControl::set_rate`, consumed by the TUI at M5)
- [x] optional-recv window semantics verified against `call.cpp` and
      recorded in SIPP_COMPAT §6 (forward scan, backward contiguous scan,
      CSeq-method guard, retrans cancel — incl. SIPp's own stall wart)
- [x] Soft quit (`q`+Enter / `-m` drain) and hard quit (`Q`); exit codes
      0/1/99 per SIPp's documented table (+2 usage, 255 fatal; 97 lands
      with `exec int_cmd` at M6); global `-timeout` fails active calls
- [x] Interop job added to CI (installs sip-tester on the runner); loopback
      cps baseline recorded in `benches/BASELINES.md` (~2000 cps sustained,
      far-end-bound)

## M4 — UAS mode + stats ✅

- [x] UAS call creation from initial requests (unknown Call-ID matching the
      initial window creates a call bound to the packet's source address);
      embedded uas scenario runs; sipr↔sipr self-test green (E2E test +
      50 000 calls at 5000 cps in BASELINES.md); retransmitted inbound
      requests are answered by re-sending the last response; timewait
      absorbs late traffic without failing (deadcall behavior)
- [x] sipp-uac ↔ sipr-uas: verified 2026-08-17 against real SIPp v3.7.7
      (`cargo test -p sipr --test interop`), same run as the M3 gate
- [x] `[last_*]`, `rrs`+`[routes]`, `[peer_tag_param]` correct as callee —
      proven by the self-test (the uac's ACK/BYE dialogs only complete if
      the uas mirrors correctly)
- [x] `-aa` auto-answers in-dialog OPTIONS/INFO/UPDATE/NOTIFY with a
      mirrored 200 (E2E test drives an unexpected in-dialog OPTIONS)
- [x] Stats: SIPp counter set incl. failure breakdown and auto-answered;
      RTDs via an in-tree 1 ms-bucket histogram (hdrhistogram unavailable —
      same dependency situation as always, recorded in the crate docs);
      both repartitions; `-trace_stat`/`-stf`/`-fd` CSV (pragmatic subset
      of SIPp's columns with (P)/(C) naming — SIPP_COMPAT §6);
      `-trace_msg`/`-trace_err` files with SIPp-style framing
- [x] Periodic stat line in `-bg` mode incl. rtd1 avg/p99

## M5 — TUI ✅

- [x] Main screen (rates target/period/avg, call counts, message counters,
      failure breakdown, RTD table, call length) ≈ SIPp layout. NOTE:
      hand-rolled ANSI + `stty` raw mode instead of ratatui/crossterm
      (unreachable registry, same as every dependency decision) — rendering
      is pure `Snapshot → Vec<String>` functions in `sipr-tui/src/render.rs`
      and fully unit-tested; the interactive shell is a thin guard layer.
- [x] Scenario screen: per-step sent/recv/retrans/timeout/unexpected table
      (per-step counters wired through the engine into `StatSet`)
- [x] Repartition screen (both tables, placeholder when unconfigured)
- [x] Keys: `+ - * /` live rate, `p` pause (pacer skips), `q` soft quit,
      `Q` hard quit, `s` screen cycle; TUI reads 1 s snapshots over a
      channel and never touches engine state; keys flow back through the
      same bridge (`run_with_ui`), verified without a terminal in
      `sipr-engine/tests/ui_bridge.rs`
- [x] Terminal restored on every path: RawGuard drop (`stty -g` save /
      restore), panic hook chaining the restore, alternate-screen leave —
      verified under a real pty (`script`): restore sequence emitted once,
      exit 0. TUI auto-enables only when stdin+stdout are terminals and
      `-bg` is absent; headless behavior unchanged.

## M6 — Actions, variables, auth ✅ — v1 shipped

- [x] Per-call variable store + action executor: `ereg` (capture groups via
      an in-tree ERE engine), `assign`/`assignstr`/`strcmp`/`test`,
      `add`/`subtract`/`multiply`/`divide`, `todouble`, `trim`,
      `urlencode`/`urldecode`, `gettimeofday`, `jump`, `log`/`warning`/
      `error`, `exec int_cmd`. `test`/`condexec` branching, `chance`, named
      `counter`s, and `pause variable=` all live. NOTE: the regex engine is
      in-tree (`sipr-scenario/src/regex.rs`) — leftmost-first greedy with a
      backtracking budget, POSIX classes; divergence from POSIX
      leftmost-longest noted in SIPP_COMPAT §6. `insert`/`replace`/`lookup`
      stay in the v1.x tier (they need `-inf`).
- [x] `[authentication]` digest MD5 + SHA-256, `qop=auth`, cnonce/nc, opaque,
      proxy (407); verified end-to-end against a scripted registrar that
      recomputes and compares the response server-side
      (`tests/e2e.rs::digest_authentication_round_trips`). Hash primitives
      are in-tree (`sipr-auth/src/hash.rs`), checked against the RFC 1321 /
      FIPS 180-4 / RFC 2617 / RFC 7616 vectors. Stale-nonce retry: the
      challenge exposes `stale`; a scenario re-auths by looping to the send.
- [x] rtd/start_rtd/repeat_rtd + counters flow into the stats/CSV/TUI (M4/M5)
- [x] Docs pass: README quickstart, SIPP_COMPAT §6 updated (regex semantics,
      auth, action executor). v1 ships here.

**v1 is feature-complete for signaling over UDP.** The two interop gates
(sipr↔real-sipp, both directions) remain open only because the build
sandbox has no sipp binary — run `SIPP_BIN=... cargo test --test interop`
on a machine with sipp to close them.

## M7 — Injection files ✅

- [x] `-inf FILE` (repeatable): SEQUENTIAL / RANDOM / USER mode header (matched
      by substring, per SIPp), `;`-separated fields, `#` comments, blank line
      terminates. One line is drawn per call per file — SEQUENTIAL cycles
      (wrapping), RANDOM picks uniformly, USER defers to `-users` (not yet
      wired, so USER renders empty with a load-time warning, matching SIPp).
      Parser is pure (`sipr-scenario/src/inject.rs`), assignment happens once
      at call birth in the engine.
- [x] `[fieldN]` keyword resolves to field N of this call's drawn line.
      sipr extensions over SIPp: `[fieldN file=K]` selects the K-th `-inf`
      (0-based) and `[fieldN line=M]` pins a literal line. Unknown field/file
      indices are rejected at load. Verified end-to-end
      (`tests/e2e.rs::injection_file_fields_land_in_sent_messages`).
- [x] SIPP_COMPAT §6 documents the injection semantics and the deferral of
      `lookup`/`insert`/`replace` (indexed-file mutation needs the file store).

## M8 — Indexed injection: lookup / insert / replace ✅

- [x] `-infindex FILE FIELD` builds a key→line index over one field of an
      `-inf` file (matched by basename, SIPp-style); duplicate keys resolve to
      the last line. Index/lookup/insert/replace live in
      `sipr-scenario/src/inject.rs` (pure) with `RefCell`-wrapped files in the
      engine so `[fieldN]` reads and `insert`/`replace` mutations share them on
      the one event-loop thread.
- [x] `<lookup assign_to=… file=… key=…/>` stores the matched line (or -1),
      `<insert file=… value=…/>` appends, `<replace file=… line=… value=…/>`
      swaps — all with rendered-template arguments (`compile.rs`, executed in
      `sipr-engine/src/actions.rs`).
- [x] `[fieldN]` gained SIPp-faithful selectors: `file=NAME` (basename key, or
      a numeric `-inf` index as a sipr extension) and `line=EXPR` rendered at
      send time — `line=[$var]` is what makes `lookup` usable. The tokenizer
      now balances nested brackets to parse `line=[$1]`. Verified end-to-end
      (`tests/e2e.rs::lookup_reads_indexed_field_by_key`). SIPP_COMPAT §6.

## M9 — TCP transport (`-t t1`) ✅

- [x] `sipr-net/src/tcp.rs`: a `TcpFramer` that de-frames a byte stream into
      SIP messages by `Content-Length` (RFC 3261 §7.5), skipping keep-alive
      CRLFs, and a `TcpTransport` with one connection per peer — the UAC dials
      the target once, the UAS accepts, each connection gets a framed reader
      thread, and writes route back by peer address. Unit + integration tested.
- [x] Engine transport abstracted into a `Udp`/`Tcp` enum; `-t t1` binds TCP by
      role (connect for UAC, listen for UAS), `[transport]` renders `TCP`, and
      SIP retransmissions are gated off for reliable transports (RFC 3261
      §18.2). CLI accepts `t1`/`tn`. Both directions covered end to end
      (`tcp_uac_places_call_over_stream`, `tcp_uas_answers_over_stream`).
- [x] Fixed a latent framing bug the stream transport exposed: body-less
      messages were missing the mandatory `\r\n\r\n` header/body separator
      (UDP hid it). SIPP_COMPAT §6.

## M10 — Classic 3PCC (`sendCmd`/`recvCmd`) ✅

- [x] `sipr-net/src/twin.rs`: an `EscFramer` (0x1B-delimited) and a
      `TwinChannel` over one TCP connection — `connect()` for controller A,
      `listen()` for controller B, with a framed reader thread delivering
      commands. Unit + loopback tested.
- [x] Scenario `<sendCmd>` (rendered CDATA command) and `<recvCmd>` (blocks the
      call; its `<action>`s' `ereg` searches the raw command text). Compiler +
      model, with extended-3PCC `dest=`/`src=` rejected. `-3pcc HOST:PORT` CLI.
- [x] Engine wiring: the twin role is derived from the scenario's first twin
      command (sendCmd→dial, recvCmd→listen); `Event::TwinCmd` wakes a call
      blocked on `<recvCmd>`, with a pending-command queue for ordering.
      Verified end to end (`tests/e2e.rs::threepcc_controller_a_round_trips_a_command`
      drives SIP → twin → SIP through the real binary). SIPP_COMPAT §6.

## M11 — `-users` closed loop ✅

- [x] `-users N`: closed-loop generation keeping N concurrent calls. A free-user
      pool (1..=N) hands each call a 1-based user id; a finished call returns its
      id and `refill_users` opens a replacement immediately, so the population
      stays constant until `-m` total. The rate pacer is disabled in users mode;
      `-users` and `-l` are mutually exclusive.
- [x] `[userid]`/`[users]` keywords, and USER-mode `-inf` files now resolve
      line = userId-1 (the M7 stub is lit up). Verified end to end
      (`tests/e2e.rs::users_closed_loop_binds_user_to_injection_line`: three
      users each run twice under `-users 3 -m 6`, each `[field0]` matching its
      `[userid]`). SIPP_COMPAT §6.
- [x] Deferred: per-user persistent variables and runtime user-count changes.

## M12 — IPv6 ✅

- [x] Targets accept bracketed IPv6 (`[::1]`, `[2001:db8::1]:5060`) and bare
      literals (`::1`); `resolve_target` handles all forms, and a v6 target with
      no `-i` auto-binds the `::` family. `-i` already took a v6 local address.
- [x] `[local_ip]`/`[remote_ip]` render bracketed for IPv6 (SIPp
      `local_ip_w_brackets`) so URIs/Via are well-formed; `[media_ip]` stays raw
      for SDP. Unit-tested (`resolve_target`, render bracketing); the loopback
      e2e (`ipv6_uac_places_call_over_loopback`) runs where `::1` binds and
      self-skips in the v6-less build sandbox. SIPP_COMPAT §6.

## M13 — TLS transport (`-t l1`) ✅

Behavioral oracle: `sslsocket.cpp` / `socket.cpp` in the SIPp source. TLS is
the TCP path with a TLS layer on top — same framing, same connection-per-peer
model, same no-retransmission rule, same default port 5060, no `sips:` scheme.
First external dependency of the workspace: `rustls` (with the `ring`
provider — pure-ish Rust, builds with `cc` only, no system OpenSSL; this is a
selling point vs SIPp's mandatory OpenSSL) + `rustls-pemfile`; `rcgen`
dev-only for generating test certs at test time. Rationale recorded in
CONVENTIONS §Dependencies.

- [x] `sipr-net/src/tls.rs`: `TlsTransport` mirroring `TcpTransport`
      (connect/listen/local_addr/send_to), reusing `TcpFramer`. rustls
      connection per peer: handshake completes in connect/accept, a reader
      thread feeds the framer, writes lock the connection briefly to encrypt.
      A failed *inbound* handshake drops that connection with a loud warning —
      deliberate divergence from SIPp, which kills the whole process on
      `SSL_accept` failure (SIPP_COMPAT §6).
- [x] Config/CLI, SIPp names: `-t l1` (and `ln`, collapsing onto
      connection-per-peer like `tn`); `-tls_cert` [cacert.pem], `-tls_key`
      [cakey.pem], `-tls_ca`, `-tls_crl`, `-tls_version`. Verification matches
      SIPp: OFF unless `-tls_ca`/`-tls_crl` given; when on, the client checks
      the chain but NOT the hostname, and the server demands + verifies a
      client cert (mutual TLS); the client always presents its cert if asked.
      Documented divergences: `-tls_version 1.0/1.1` errors (rustls has no
      TLS ≤1.1; SIPp's floor is 1.0), encrypted keys rejected (SIPp uses a
      hardcoded passphrase `ksgr`).
- [x] Engine: `TransportKind::TlsMono`, `Transport::Tls` arm, `[transport]`
      renders `TLS` (Via `SIP/2.0/TLS`, `transport=TLS` in Contact),
      `reliable = true` so retransmissions stay off.
- [x] Tests: tls.rs unit tests (roundtrip, mutual TLS, mute-peer handshake
      failure, missing-cert error, 1.3 pin); e2e loopback both directions with
      an rcgen cert (`tls_uac_places_call_over_stream`,
      `tls_uas_answers_over_stream`); interop vs real sipp (`-t l1` both
      roles), self-skipping when the sipp binary lacks TLS — and the
      sipp-as-client direction also self-skips on macOS, where sipp's own
      stream-client bind fails (EADDRINUSE; note in SIPP_COMPAT §6).
      fmt/clippy/test all green.

## M14 — pcap replay (`exec play_pcap_*`) ✅

Behavioral oracle: `prepare_pcap.c` / `send_packets.c` / `call.cpp`
(`get_remote_media_addr`, `[media_port]`/`[auto_media_port]`), studied
alongside gossipper's Go media engine (scale lessons: one scheduler thread,
absolute timeline, sockets per stream, no per-stream threads). Design and
divergences in SIPP_COMPAT §6.

- [x] New std-only crate `sipr-media`: a pure-Rust classic-pcap reader
      (`pcap.rs`: µs/ns magic either byte order; Ethernet + one 802.1Q tag,
      raw IP, Linux SLL v1/v2, BSD null/loop; IPv4 any IHL, IPv6 without
      extension headers; non-UDP packets skipped and counted; truncated
      captures rejected with SIPp's `-s0` hint), the SDP endpoint scan
      (`sdp.rs`: session/media-level `c=`, first live `m=<kind>`, port 0
      skipped), and the replay scheduler (`replay.rs`: one `sipr-media`
      thread, min-heap of due streams, frames sent at `start + offset` on the
      capture's absolute timeline with burst catch-up, one UDP socket per
      destination-port offset preserving SIPp's `port_diff` mapping, RTP
      bytes verbatim). No libpcap, no raw sockets, no root.
- [x] Scenario: `exec play_pcap_audio|video|image=` → `Action::PlayPcap`
      (one per exec; `play_pcap=` is rejected as SIPp never implemented it;
      `rtp_stream`/`rtp_echo`/`play_dtmf` are clear "M15" errors);
      `<recv ignoresdp>` (and the DTD's `ignosesdp`) accepted;
      `[auto_media_port]` and `[media_port+N]`/`[auto_media_port+N]` keyword
      forms. Corpus: `negative/media_pcap.xml` became
      `positive/pcap_play.xml`; `negative/media_rtp_stream.xml` added.
- [x] Engine: `-mi`/`-mp` (`-min_rtp_port` alias) → `[media_ip]`,
      `[media_port]` (default 6000; `auto` = `+ 4*(call-1) % 10000`), pcaps
      resolved next to the `-sf` file then the CWD and parsed once at startup
      (missing/malformed = fatal, like SIPp), remote endpoints learned from
      any response body or INVITE/ACK/PRACK request SDP (stale values kept),
      the local port per kind read off the SDP template's `m=` line at load
      (SIPp's runtime "audio"/"video"/"image" line scan, done once), replay
      stopped on every call teardown path, socket/send failures logged and
      the call continues. Stats: `rtp_streams_started`/`rtp_packets_sent`/
      `rtp_bytes_sent` sampled once a second into the stat set, TUI main
      screen line, `-bg` line, and the final summary (`rtp-sent N`).
- [x] Tests: 23 unit tests in `sipr-media` (incl. a deterministic no-panic
      sweep of truncations/mutations), compiler tests for every exec form,
      e2e `play_pcap_audio_replays_capture_to_the_sdp_endpoint` (two calls,
      distinct `auto_media_port` blocks, every payload verbatim) and
      `play_pcap_with_a_missing_file_is_fatal_at_startup`, interop
      `uac_pcap_against_real_sipp_uas` (sipp `-rtp_echo` UAS answers with
      its own SDP; 30/30 frames sent). fmt/clippy/test green.
- [x] Deferred to M15: `rtp_stream` (file/pattern streaming, pause/resume),
      `play_dtmf` (RFC 4733 generation), `rtp_echo`, `-rtpcheck`, `-key`
      lookups in `play_pcap_*` values, `~` expansion in media paths.

## M15 — RTP streaming and DTMF (`exec rtp_stream=`, `exec play_dtmf=`) ✅

Behavioral oracle: `rtpstream.cpp` (`rtpstream_playrtptask`,
`rtpstream_get_localport`, `rtpstream_cache_file`), `actions.cpp`
`setRTPStreamActInfo` (the payload table), `prepare_pcap.c` `prepare_dtmf`,
`call.cpp` `E_Message_RTPStream_*_Port`. Divergences in SIPP_COMPAT §6.

- [x] `sipr-media::rtp`: SIPp's payload table verbatim (0/8/9 → 160 B/20 ms,
      13 → 1 B/150 ms, 18 → 20 B/20 ms, dynamic `H264/90000` → 1280 B/160 ms
      video, `iLBC/8000` → 50 B/30 ms; missing/mismatched names error with
      SIPp's wording), RIFF/WAVE header skip (not a decoder — as SIPp),
      `apattern`/`vpattern` 1..=6 fills, and `RtpSource`: 12-byte header
      (V=2, no marker, seq from 0, wall-clock-derived timestamp advancing by
      `ticks_per_packet`, SSRC `0xCA110000 + 2*(call-1) + video`), payload
      spliced across the file end when looping, loop count `-1` = forever,
      pause fast-forwards the clock (SIPp `TI_PAUSERTP`).
- [x] `sipr-media::dtmf`: RFC 4733 bursts with SIPp's exact shapes/timing
      (20 warm-up PT 97 packets 20 ms apart, per-digit starts every 20 ms at
      `400 + (k+1)*2*tone + cur` with marker on the first and `duration =
      cur*8`, three end packets 1 ms apart, one RTP timestamp per event,
      digits `0-9*#A-D`, tone clamped to 50..=2000 else 200). Generated as a
      synthetic `PcapStream` and replayed on the audio stream, as SIPp does.
      Fixed on purpose: sequence numbers are consecutive (SIPp's warm-up
      steps by two).
- [x] Scheduler: `Source::{Pcap, Rtp}`; generated packet `n` is due at
      `start + n*interval` (burst catch-up, no drift); `pause`/`resume`
      commands per call or per `rtp-audio`/`rtp-video` tag.
- [x] Scenario: `rtp_stream="file|apattern|vpattern|pause|resume|
      pause[av]pattern|resume[av]pattern[,loops|id[,pt[,name]]]"` →
      `Action::RtpStream`, `play_dtmf="digits[,tone]"` → `Action::PlayDtmf`
      (a template — keywords render, as SIPp), `[rtpstream_audio_port]` /
      `[rtpstream_video_port]` (+`N`) keywords. `rtp_echo=` stays a clear
      error. Corpus `positive/rtp_stream.xml`, `negative/media_rtp_echo.xml`.
- [x] Engine/CLI: `-rtp_payload` (default 8), `-max_rtp_port`,
      `-random_base_ssrc`; files loaded and codec parameters validated at
      startup (fatal, like SIPp); `[rtpstream_*_port]` allocated per call
      from `-mp` in steps of two when first rendered (SIPp's cursor, minus
      the trial bind); a stream sends **from the port the SDP advertised**
      (the allocated rtpstream port, else the `[media_port]` form on that
      `m=` line) — SIPp binds a fresh unrelated port; DTMF sequence per
      call from 1200; streams stop with the call.
- [x] Tests: 12 new unit tests (payload table, WAV skip, patterns, splice/
      loop/pause/timestamp math, DTMF shapes, scheduler pacing + pause),
      compiler tests for the whole grammar, e2e
      `rtp_stream_and_play_dtmf_send_generated_rtp` (every packet checked:
      PT, seq, SSRC, payload, DTMF bodies) and a fatal bad-payload case,
      interop `uac_rtp_stream_against_real_sipp_uas` (endless stream vs
      `sipp -rtp_echo`, stops with the call).
- [x] Deferred: `exec rtp_echo=` SRTP echo control and `-rtp_echo`'s global
      echo sockets, `-rtpcheck`/`-audiotolerance` (RTP check verdicts, exit
      -3), SRTP (`a=crypto`), `-key` lookups and `~` expansion in media
      paths, `-rtp_threadtasks` (meaningless for one scheduler).

## M16 — IMS AKA authentication (`AKAv1-MD5`) ✅

Behavioral oracle: `auth.cpp` (`createAuthHeader`, `createAuthHeaderAKAv1MD5`),
`milenage.c`, `message.cpp` `parseAuthenticationKeyword`/`getHexStringParam`,
`docs/scenarios/sipauth.rst`. Divergences in SIPP_COMPAT §6.

- [x] In-tree primitives in `sipr-auth`: AES-128 block encryption (FIPS 197
      Appendix B/C vectors), Milenage f1/f1*/f2345/f5* with OPc derivation
      (3GPP TS 35.208 Test Sets 1 and 2, every output), base64 (RFC 4648
      vectors, unpadded input tolerated). No new dependency.
- [x] `Algorithm::AkaV1Md5` (case-insensitive prefix match on `algorithm=`,
      as SIPp); `aka_challenge_response` decodes the nonce as base64(RAND ‖
      SQN⊕AK ‖ AMF ‖ MAC-A), recovers SQN, verifies MAC-A against f1, and
      yields RES/CK/IK; `digest_response` uses the 8 raw RES bytes as the
      password (NUL bytes survive — SIPp passes RESLEN explicitly for the
      same reason). `authorization_header` now returns `Result`.
- [x] `[authentication ... aka_K= aka_OP= aka_AMF=]` with SIPp's `0x` hex
      values (exact length enforced — SIPp never validates) or raw bytes;
      `aka_OPc=` as a sipr addition (SIPp only takes OP); SIPp's documented
      fallback of K = first 16 password bytes honoured when the password is
      long enough; missing OP/OPc, a malformed nonce, or a MAC mismatch
      **fails the call** with a clear reason — SIPp aborts the whole process.
      XMAC uses `aka_AMF` when given (SIPp always) else AUTN's AMF.
- [x] Tests: unit (AES, Milenage, base64, a full AKAv1-MD5 digest over Test
      Set 1 incl. wrong-AMF/bad-nonce/no-keys errors), corpus
      `positive/register_aka.xml` (SIPp's documented example), e2e
      `aka_v1_md5_registration_round_trips` (a registrar built from Test
      Set 1 verifies the response with RES) and
      `aka_with_the_wrong_key_fails_the_call_not_the_process`.
- [x] Deferred: AUTS resynchronisation (dead code in SIPp: `if (1/*…*/)`),
      `AKAv2-MD5` (SIPp rejects it too), `-auth_uri`, keyword-rendered
      `aka_*` values (SIPp renders them as sub-messages so `[field0]` works;
      sipr takes them literally for now), AKA as a challenging server.

## M17 — Runtime control: SIPp's control socket + the HTTP API ✅

Behavioral oracle: `socket.cpp` `setup_ctrl_socket` / `handle_ctrl_socket` /
`process_command` / `process_set` / `process_trace` / `process_key`,
`docs/controlling.rst`. gossipper's HTTP API studied for shape (its single
`Summary` struct for live + final stats, partial-update control POST, and
token-via-query for browsers were copied; its three `/stats` shapes,
unitless nanosecond durations, open-by-default bind, and missing quit/limit
controls were avoided). Spec in `docs/CONTROL_API.md`.

- [x] New std-only crate `sipr-control`: SIPp's command grammar with SIPp's
      warning texts (`command.rs`: byte-0 hot key vs `c` + `set rate|
      rate-scale|users|limit|display|hide` / `trace error|messages|logs|
      shortmessages on|off` / `dump tasks|variables` / `reset stats`,
      first-space tokenization, `strtol` base-0 numbers), the UDP socket
      (`udp.rs`: `-cp` tried once and fatal, else 8888..8947 probed and a
      warning; fire-and-forget), a tiny HTTP/1.1 server (`http.rs`), a
      minimal JSON reader/writer (`json.rs`), and the API routes (`api.rs`).
- [x] Engine: `Event::Control`; every command runs on the event-loop thread
      and answers over a reply channel (HTTP) or not at all (UDP, as SIPp).
      Hot keys now follow SIPp: rate keys step by `rate-scale` and act on
      the user count in `-users` mode, `q` twice = `Q`. `set users` grows
      the id pool or lets excess calls finish; `set limit` updates the cap;
      `trace messages|error on|off` opens/closes trace files at runtime
      with SIPp's names; `dump tasks` lists active calls in the error trace;
      `reset stats` zeroes counters and histograms (new `StatSet::reset`).
      Mode-dependent refusals use SIPp's exact wording.
- [x] HTTP API (`--sipr-http [HOST:]PORT`, `--sipr-http-token`): `/health`,
      `/stats` (the once-a-second snapshot the TUI renders, SIPp counter
      names, `_ms` durations), `/control` GET/POST (partial update),
      `/quit` (drain or force), `/command` (any control-socket line),
      `/scenario`. Bearer or `?token=` with constant-time compare; a
      non-loopback bind without a token is refused at startup.
- [x] Divergences (SIPP_COMPAT §6): control socket defaults to loopback
      (SIPp: every interface), `-cp 0` disables it, the chosen port is
      printed, screen digits are ignored, `set display ooc|rx` and
      `trace logs|shortmessages` warn instead of silently doing nothing.
- [x] Tests: unit (grammar with SIPp's errors, JSON round trips, HTTP
      parsing, UDP datagrams → requests + warnings, every API route against
      a fake engine incl. auth/405/404), e2e
      `control_socket_speaks_sipp_protocol` (a `cset rate` datagram finishes
      a slow run, `q` drains early, a bad command warns),
      `http_api_reports_stats_and_controls_the_run`, and the token gate.
- [x] Deferred: `set hide`/`display` semantics in the TUI, a streaming
      endpoint, scenario hot-replace, Prometheus.

## M18 — RTP echo and the RTP check ✅

Behavioral oracle: `sipp.cpp` `rtp_echo_thread` / `setup_media_sockets` /
`bind_rtp_sockets` / `sipp_exit`, `rtpstream.cpp` `rtpstream_playrtptask`
(post-send recv + compare) and the thread-exit verdict, `call.cpp`
`E_AT_RTP_ECHO`, `scenario.cpp` `<rtp_echo>`. Divergences in SIPP_COMPAT §6.

- [x] `-rtp_echo` / `-mb`: `sipr-media::echo` binds the media port and
      `+2` (probing upward in steps of two, like SIPp, and the port that
      bound is what `[media_port]` renders), two threads with SIPp's 100 ms
      receive timeout echo every datagram to its sender; counters
      `rtp_echo_packets` / `rtp_echo2_packets` (SIPp's 1st/2nd stream) on
      the TUI, `-bg` line, and `/stats`.
- [x] `<rtp_echo value="0|1"/>` action → `Action::RtpEchoState`: flips the
      process-wide switch (SIPp `rtp_echo_state`); a scenario using it
      without `-rtp_echo` gets a startup warning. `variable=` is rejected.
- [x] The RTP check: generated streams' sockets are non-blocking and after
      every send the scheduler drains what came back, comparing the last
      datagram's payload to the one just sent (SIPp's semantics — an echo
      lags a packet, so only constant-payload patterns pass); tallies per
      stream travel as `MediaEvent::CheckResult` when the stream ends.
      `-audiotolerance` / `-videotolerance` (0.0..=1.0): `failed/sent ≥
      tolerance` fails the check. `rtp_check_ok` / `rtp_check_failed` /
      `rtp_bytes_received` stats; a failed check makes the exit code 253
      (SIPp's `EXIT_RTPCHECK_FAILED` = -3 as the shell sees it) and the
      summary says `rtpcheck N/M failed`. Tallies of streams ending with
      their calls are collected at shutdown before the report.
- [x] Deliberate divergence: sipr judges a stream **only when a tolerance
      flag was given**. SIPp judges always with a default of 1.0, so any
      `rtp_stream` run against a peer that does not echo exits -3.
- [x] Tests: echo unit tests (both sockets, counters, the toggle, probing
      past a taken port), a scheduler test proving the check passes against
      an echo peer, e2e sipr-vs-sipr `rtp_echo_uas_makes_the_uac_rtpcheck_pass`,
      the silent-peer 253 case (and its non-judged 0 twin), the missing
      `-rtp_echo` warning, interop `rtpcheck_against_real_sipp_echo`
      (`sipp -rtp_echo` echoes, sipr passes 1/1).
- [x] Deferred: `exec rtp_echo=startaudio|…` (SIPp's per-call SRTP echo
      threads — SRTP is out of scope), `-rtpcheck_debug` hex dumps.

## M19 — AKA resynchronisation (AUTS) ✅

Behavioral oracle: RFC 3310 §3.2 and 3GPP TS 33.102 §6.3.3 — SIPp's own
resync branch is dead code (`auth.cpp` `if (1/*…*/)`), so this is the real
flow SIPp only sketched. Divergences (all additions) in SIPP_COMPAT §6.

- [x] `sipr-auth`: `AkaKeys` gains `sqn_ms` (the client's highest accepted
      SQN) and `force_resync`; `aka_challenge_response` still verifies
      MAC-A first, then — when the challenge's SQN is not above SQN_MS, or
      when forced — computes `AUTS = (SQN_MS ⊕ AK*) ‖ MAC-S` with
      `AK* = f5*(RAND)` and `MAC-S = f1*(K, RAND, SQN_MS, AMF* = 0x0000)`.
      `authorization_header` then carries `auts="base64(AUTS)"` and a
      digest computed with the **empty password**, as RFC 3310 requires.
      A forced resync without `sqn_ms` echoes the challenge's own SQN.
- [x] Keyword params (sipr additions): `aka_sqn=0x<12 hex>` (SQN_MS) and
      `aka_resync=1` (force AUTS on every challenge, to exercise a server's
      resync path). Corpus `positive/register_aka_resync.xml`.
- [x] Tests: unit (AUTS bytes verified against f5*/f1* over Test Set 1,
      empty-password response, forced resync), e2e
      `aka_resynchronisation_round_trips` — a registrar at the client's
      SQN_MS rejects nothing but gets AUTS, verifies it (SQN_MS recovered
      with AK*, MAC-S with AMF* = 0, empty-password digest), re-challenges
      at SQN_MS + 1, and accepts the RES digest.
- [x] Deferred: a full TS 33.102 Annex C window (Δ, wrap-around; sipr uses
      "must be greater than SQN_MS"), keyword-rendered `aka_*` values,
      `-auth_uri`.

## M20 — Rate ramps (`-rate_increase`, `-rate_max`, `-rate_interval`, `-no_rate_quit`) ✅

Behavioral oracle: `ratetask.cpp` (`ratetask::run`/`wake`), `sipp.cpp` option
table (`SIPP_OPTION_TIME_SEC`), `include/sipp.hpp` defaults.

- [x] `-rate_increase N`: a ramp that exists only when set; every
      `-rate_interval` (SIPp time values: seconds, or `ms`/`s`/`m`/`h`
      suffixes; default the `-fd` interval) `rate += N`. `-rate_max N`: a
      tick that would exceed it clamps the rate to N and, unless
      `-no_rate_quit`, quits with a drain (SIPp `quitting += 10`).
      Reaching the cap exactly does not quit — only the next tick does
      (`ramp_step`, unit-tested against SIPp's arithmetic). The task dies
      once quitting and is inert in `-users` mode, as in SIPp.
      `-rate_scale N` (SIPp's CLI flag for the `+ - * /` step) added too.
- [x] Tests: unit `ramp_step_follows_sipp_ratetask`, e2e
      `rate_increase_ramps_the_rate_up` (a 1 cps run finishes 40 calls in
      seconds after the ramp) and
      `rate_max_quits_when_exceeded_unless_no_rate_quit` (both branches).
- [x] Note: sipr's `-fd` default is 1 s, so an unqualified ramp ticks every
      second; SIPp's `-fd` default is 60 s. Give `-rate_interval` explicitly
      for scripts shared between the two.

## M21 — `-auth_uri` and rendered `[authentication]` parameters ✅

Behavioral oracle: `call.cpp` (~l.4149-4170: the `sip:` + `-auth_uri` /
`remote_ip:remote_port` digest uri, and the per-parameter
`createSendingMessage` rendering), `message.cpp` `parseAuthenticationKeyword`,
`sipp.cpp` option table.

- [x] The digest `uri=` now follows SIPp exactly: `sip:` + (`-auth_uri`,
      else `remote_ip:remote_port`). sipr used to sign `sip:service@ip:port`
      — a visible-on-the-wire difference, now gone. SIPp's `sip:sip:…`
      quirk for a value that already carries a scheme is kept for fidelity
      and warned about at startup.
- [x] Every `[authentication]` parameter value is rendered as a sub-message
      before use (`username=[field0] password=[field1]`, `aka_K=[$k]`,
      `aka_sqn=[field3]`…), as SIPp does; the compiler registers the
      `[$var]` reads inside them so read-never-set diagnostics still fire.
- [x] Tests: e2e `authentication_params_render_keywords` (credentials from
      an `-inf` file verify against the digest registrar),
      `auth_uri_flag_and_default_follow_sipp` (the message trace shows
      `uri="sip:ip:port"` by default and `uri="sip:ims.example.com"` with
      the flag).
- [x] Deferred: a whole `[authentication …]` keyword arriving from an
      injection field (SIPp re-parses rendered text at runtime).

## M22 — TUI `hide` / `display` and SIPp's screen keys ✅

Behavioral oracle: `scenario.cpp` (~l.1852: `hide` bool and `display` text
read for every message command, though the DTD lists `display` only on
`nop`), `screen.cpp` (`do_hide`, default true; hidden rows skipped on the
scenario screen), `socket.cpp` `process_key` (`1`..`9` screens).

- [x] `hide="true"` and `display="…"` on any message command land in
      `StepCommon`; `display` replaces the derived scenario-screen label,
      `hide` marks the row. `set hide true|false` (control socket / HTTP
      `/command`) now has its SIPp effect: hidden rows are skipped while it
      is true (the default). Both flags reach `/stats` (`hidden` per step,
      `hide` overall) so headless runs can see them too.
- [x] Screen keys: `1` scenario, `2` statistics, `3` repartition work at
      the TUI keyboard and over the control socket (forwarded through the
      snapshot as a sequenced request); `4`/`5` (variables, TDM map) and
      `6`..`9` (secondary repartitions) have no sipr screen and are ignored.
      `s` still cycles.
- [x] Tests: compiler (`hide`/`display` on recv, nop, pause; blank display
      is none), TUI render (hidden rows follow the switch; digit mapping),
      corpus `positive/hide_display.xml`, e2e
      `hidden_steps_and_display_labels_reach_the_stats_api` (`display`
      label and `hidden` flag in `/stats`; `set hide false` over `/command`
      flips `hide`).
- [x] Deferred: `set display ooc|rx` (no out-of-call / rx scenarios in
      sipr), `-hide` CLI default.

## M23 — SRTP (SDES) ✅

Behavioral oracle: `jlsrtp.cpp`/`jlsrtp.hpp` (JLSRTP: AES-CM-128 or NULL
cipher, HMAC-SHA1 80/32, kdr 0, no MKI, no replay list, no SRTCP, 12-byte
header), `call.cpp` (crypto keywords ~l.2860-3300, `extract_srtp_remote_info`
~l.564-886, session state machine, `swapCrypto` on answer), `message.cpp`
keyword table, `rtpstream.cpp` (SRTP in the sender's echo check and the
per-call echo), SIPp's `pfca_*crypto*` scenarios. Divergences in SIPP_COMPAT §6.

- [x] Crypto in-tree, no new dependency: SHA-1 + HMAC-SHA1 (FIPS / RFC 2202
      vectors), AES-CM keystream and the RFC 3711 §4.3 KDF (Appendix B
      vectors) in `sipr-auth::srtp_kdf`; `sipr-media::srtp` — the four
      suites, SDES `inline:` encode/decode (40 base64 chars, `|lifetime|MKI`
      ignored), `SrtpContext::protect`/`unprotect` with RFC 3711 §3.3.1 ROC
      estimation, `UNENCRYPTED_SRTP` (authenticate only). `sipr-media` now
      depends on `sipr-auth`.
- [x] SIPp's keywords verbatim: `[cryptotag{1,2}{audio,video}]`,
      `[cryptosuite{aescm128sha180,aescm128sha132,nullsha180,nullsha132}{1,2}{audio,video}]`,
      `[cryptokeyparams{1,2}{audio,video}]` (+ the `-N` offset that reuses
      the key on re-INVITE), `[ue{aescm128sha180,aescm128sha132}{1,2}{audio,video}]`
      → `UNENCRYPTED_SRTP`. Keys are generated before rendering (a
      `prepare_crypto` pass, like rtpstream ports), from the seeded RNG.
- [x] SDP: the first two `a=crypto:` lines of the live `m=` section are the
      peer's primary/secondary (`sdp::crypto_attributes`). Negotiation at
      stream start: send under the local slot whose suite the peer's
      primary names (slot 2 only if slot 1 does not match — SIPp's swap),
      receive under the peer's primary; no peer line → plain RTP; an
      unsupported suite or undecodable key logs and falls back to plain.
- [x] Media thread: generated streams are protected on send and the echo
      check unprotects with the peer's key before comparing plaintext (an
      auth failure counts as a miss). pcap replays stay as captured.
- [x] `-srtpcheck_debug` / `-rtpcheck_debug` accepted as no-ops.
- [x] Tests: KDF/keystream/HMAC vectors, transform round trips for every
      suite incl. rollover and tampering, SDP crypto parsing, keyword
      tokenizing, corpus `positive/srtp_sdes.xml` (two suites, pattern
      stream, reuse on re-INVITE), e2e
      `srtp_stream_passes_the_echo_check_against_an_srtp_echo_peer` (a
      scripted peer that re-keys the echo, as SIPp's does), interop
      `srtp_against_real_sipp_echo` (sipr's SDES offer + PRACK against
      `pfca_uas_audio_crypto_simple.xml`; self-skips without the SIPp tree).
- [x] Interop finding: sipp's `-srtpcheck_debug` log proves it accepts
      sipr's SRTP (`rc == 0` on every packet), but its echo `sendto` fails
      with EISCONN on macOS (connected socket + explicit address), so the
      interop test asserts SIPp's acceptance and notes the missing echo;
      the e2e SRTP echo peer covers the round trip.
- [x] Found by the interop run: the CSeq-method guard kept only the last
      sent method, so the INVITE's 200 after a PRACK was "unexpected";
      it now concatenates every sent method like SIPp's
      `recv_response_for_cseq_method_list` (SIPP_COMPAT §6 corrected).
- [x] Deferred: `exec rtp_echo=start…` (sipr as an SRTP echo *server*),
      SRTCP, MKI, per-call video crypto beyond the keywords, SRTP on pcap
      replays.

## M24 — `[authentication]` from an injection field ✅

Behavioral oracle: `call.cpp` `E_Message_Injection` (~l.4022-4045) and
the header-line rendering (~l.4149-4155); `docs/scenarios/sipauth.rst`
("Make a CSV like this…").

- [x] A `[fieldN]` whose text contains `[authentication …]` is re-parsed as
      the keyword at send time (up to the first `]`, as SIPp's temporary
      NUL does); the rest of the field stays literal. So a CSV column can
      hold per-call credentials or AKA secrets, exactly SIPp's recipe.
- [x] Found on the way and fixed: SIPp's `[authentication]` renders the
      **whole header line** (`Authorization:` for a 401,
      `Proxy-Authorization:` for a 407) and its scenarios put the keyword
      on a line of its own; sipr rendered only the value, so a real SIPp
      scenario produced a nameless header. sipr now renders the full line
      like SIPp and still accepts its older `Authorization: [authentication]`
      spelling (the name already on the line → value only).
- [x] Tests: e2e `authentication_keyword_from_an_injection_field` (SIPp's
      documented CSV + `[field1]` on its own line) and
      `bare_authentication_keyword_renders_the_full_header_line`; the
      existing `Authorization: [authentication …]` tests keep passing.
- [x] Deferred: SIPp's "only one [authentication] per message" error.

## M25 — SRTP echo server (`exec rtp_echo=`) ✅

Behavioral oracle: `actions.cpp` `setRTPEchoActInfo` (grammar
`<verb>,<payload_type>,<payload_name>`), `scenario.cpp` ~l.1729 (verbs by
prefix: `startaudio`/`updateaudio`/`stopaudio` and the `…video` trio),
`rtpstream.cpp` `rtpstream_audioecho_thread`/`rtpstream_videoecho_thread`
(~l.2519-2665), and SIPp's own pair `pfca_uas_audio_crypto_simple.xml` /
`pfca_uac_apattern_crypto_simple.xml`.

- [x] `exec rtp_echo="<verb>[,pt[,name]]"` compiles to `Action::RtpEcho`
      (`RtpEchoCmd{verb, video, payload_type, payload_name}`); unknown verbs,
      a payload type > 127 and a codec SIPp would not know (via
      `RtpParams::resolve`, checked at load) are errors, as in SIPp.
- [x] `start`: one echo thread per `(call, audio|video)` bound to the port the
      call advertised (`[rtpstream_*_port]`, else the `[media_port]` form),
      keyed from `CallCrypto::negotiate` — receive under the peer's SDES key,
      re-protect under ours keeping the caller's SSRC and sequence numbers,
      `send_to` the packet's source. Plain RTP when the peer offered no
      crypto. `update`: restart with the current negotiation (SIPp re-derives
      keys in place). `stop`, call teardown: the thread is woken and joined so
      the port is free at once. Counters feed `rtp_echo_packets`/
      `rtp_echo2_packets` alongside the global `-rtp_echo` echo.
- [x] Found on the way and fixed: `ereg search_in="hdr"` handed the regexp
      whole `Name: value` lines and could not match SIPp's `header="CSeq:"`
      spelling at all; SIPp's `extractSubMessage` yields the rest of the first
      line *after* the header string (leading space included) and fails the
      call under `check_it` when the header is absent. SIPp's UAS scenarios
      replay `CSeq: [$1]` from that capture.
- [x] Tests: media unit (plain echo, SRTP re-key round trip with the caller's
      key, unauthenticated packet dropped, port released synchronously);
      compile `rtp_echo_exec_parses_sipp_verbs`; corpus
      `positive/srtp_echo_uas.xml`; e2e
      `srtp_echo_server_passes_a_peers_echo_check` (sipr UAC's rtpcheck
      against a sipr echo server) and `rtp_echo_with_an_unknown_codec_fails_at_load`;
      interop `real_sipp_srtp_uac_against_sipr_echo_server` — real sipp plays
      its SRTP UAC scenario against sipr running SIPp's UAS scenario
      **unchanged** and passes its own RTP check (exit 0).
- [x] Deferred: SIPp's per-process echo state shared across calls (its echo
      threads are global singletons; sipr's are per call), forwarding of
      packets that fail authentication (sipr drops them).

## M26 — `<verifyauth>` ✅

Behavioral oracle: `scenario.cpp` ~l.1572 (attributes `assign_to`,
`username`, `password`), `call.cpp` ~l.5946 (`E_AT_VERIFY_AUTH`: method from
the start line, `Authorization:` only, body for auth-int), `auth.cpp`
`verifyAuthHeader` + `createAuthResponseMD5/SHA256`, and its gtests
(`DigestAuth.BasicVerification*`); `docs/scenarios/actions.rst` recipe.

- [x] `<verifyauth assign_to= username= password=/>` compiles to
      `Action::VerifyAuth` with both credentials as message templates
      (rendered at execution, `[$var]`/`[fieldN]` allowed).
- [x] `sipr_auth::verify_authorization`: MD5 and SHA-256, with or without
      qop (`cnonce` present selects the RFC 2617 form, as SIPp), `auth-int`
      body hashing, `-auth_uri` override of the header's `uri=`; non-Digest
      and other algorithms are typed errors → false + a warning line.
- [x] Engine: the verdict is stored as a boolean (`test=` branches on it);
      the method is the received start line's first token, the credential
      the first `Authorization:` header.
- [x] Tests: auth unit (SIPp's own MD5 and SHA-256 vectors, sipr's qop=auth
      header, `-auth_uri`, auth-int, scheme/algorithm errors); compile
      `verifyauth_compiles_with_templated_credentials`; e2e
      `verifyauth_accepts_the_right_password_and_branches_to_200` /
      `…rejects_a_wrong_password_and_branches_to_403` (SIPp's registrar
      recipe verbatim, branching with `test=`/`next=`); interop
      `sipr_verifyauth_judges_real_sipp_credentials` and
      `real_sipp_verifyauth_judges_sipr_credentials` — both directions,
      right and wrong password.
- [x] Deferred: SIPp's `TRACE_CALLDEBUG` line with the expected and received
      response values.

## M27 — `_unexp.main` handler, `pauserestore`, `jump variable=`, `closecon` ✅

Behavioral oracle: `scenario.cpp` ~l.1065 (`_unexp.main`, `_unexp.retaddr`,
`_unexp.pausedaddr`), ~l.1344 `handle_rhs`; `call.cpp` ~l.5449 (the jump on
an unexpected message, `queue_up`), ~l.1975 / ~l.2315 (`paused_until`),
~l.6003 (`E_AT_PAUSE_RESTORE`), ~l.5836 (`E_AT_CLOSE_CON`); `socket.cpp`
`SIPpSocket::close` refcount; `docs/scenarios/actions.rst` (jump).

- [x] `<label id="_unexp.main"/>` turns an unexpected in-call message into a
      jump: `_unexp.retaddr` ← interrupted index, `_unexp.pausedaddr` ←
      the running pause's deadline (ms since start, 0 = none), timers
      cancelled, the message re-offered to the handler's `<recv>`; refused
      while `_unexp.retaddr` is non-zero (SIPp's "already in a jump").
- [x] `<jump value=|variable=>` (SIPp's `handle_rhs`; the variable form is
      the recipe's return); out of range fails the call.
- [x] `<pauserestore value=|variable=>`: the deadline is served before the
      next step executes and that step is then skipped (`run()` + `next()`),
      so an interrupted `<pause>` resumes for exactly its remaining time.
- [x] `<closecon/>`: accepted as a no-op — in SIPp it is a reference-count
      drop that never closes a mono-socket transport (§6 note). The
      per-call socket modes (`un`/`tn`/`ln`) stay out of scope.
- [x] Tests: compile `unexp_handler_pauserestore_jump_variable_and_closecon_compile`
      + corpus `positive/unexp_handler.xml` (SIPp-loadable); e2e
      `unexp_handler_restores_the_interrupted_pause` (an INFO 0.5 s into a
      3 s pause; the BYE after the pause must come ~2.5 s later, and the
      run must last the full 3 s) and `closecon_is_accepted_over_tcp`;
      interop `sipr_unexp_handler_against_real_sipp_uac` and
      `real_sipp_unexp_handler_against_sipr_uac` — the same corpus
      scenario played by each tool against the other's INFO.
- [x] Deferred: `un`/`tn`/`ln` per-call sockets (the only mode where
      `closecon` closes a connection), `-rsa`.

## M28 — per-call sockets: `-t un|tn|ln`, `-max_socket` ✅

Behavioral oracle: `sipp.cpp` ~l.1660 (`multisocket`), `call.cpp`
`connect_socket_if_needed` ~l.1419 / `createSendingMessage` ~l.1737 /
`E_Message_Local_Port` ~l.2753, `socket.cpp` `new_sipp_call_socket` ~l.1340
and the call-creation branches ~l.1148-1185.

- [x] `sipr-net`: `UdpTransport::open_call_socket` (own recv thread, woken
      and reaped on drop), `TcpTransport::client_pool` + `connect_call`,
      `TlsTransport::client_pool` + `connect_call` (handshake per call),
      `send_via` on each; a dropped call socket/connection closes.
- [x] Engine: a client call opens (or, past `-max_socket`, shares
      round-robin) its socket at its first send; sends and retransmissions
      go out on it; `[local_port]` renders its port; the socket closes with
      the last call holding it; `<closecon/>` drops the reference and the
      next send opens a fresh one. Servers keep the socket the call arrived
      on, as SIPp. A per-call connect failure fails only that call.
- [x] CLI: `-t un|tn|ln`, `-max_socket <n>` (≥ 1, default 50000); `-t ui`
      stays a clear error.
- [x] Tests: net unit (`per_call_socket_round_trips_and_closes`,
      `per_call_connections_are_distinct_and_close_on_drop`); e2e
      `udp_per_call_sockets_give_each_call_its_own_port` (source port ==
      Via port, all distinct), `max_socket_makes_calls_share_sockets`,
      `tcp_per_call_connections_one_per_call` (a counting TCP UAS),
      `tls_per_call_connections_complete_calls`; interop
      `sipr_per_call_sockets_against_real_sipp_uas` (`un`, `tn`) and
      `real_sipp_per_call_uac_against_sipr_uas` (`un`, `tn`).
- [x] Deferred: `-t ui`, `-rsa`, `-max_reconnect`/`-reconnect_close`/
      `-reconnect_sleep`, SCTP.

## M29 — `-rsa` remote sending address ✅

Behavioral oracle: `sipp.cpp` ~l.1827, `call_generation_task.cpp` ~l.152,
`socket.cpp` ~l.1146-1230 / ~l.2588, `call.cpp` ~l.1489 / `send_raw`
~l.1570-1600 / `E_Message_Remote_IP` ~l.2741.

- [x] `-rsa host[:port]` (default 5060) resolves like the target; a UAC's
      calls send there (mono and per-call TCP/TLS dial it), a UAS's calls
      answer there from a socket of their own (shared, or per call under
      `un`/`tn`/`ln`), and `[remote_ip]`/`[remote_port]`/digest `uri=`
      keep rendering the nominal remote (`CallState::render_remote`).
- [x] Tests: CLI parse; e2e `rsa_uac_sends_to_the_sending_address_but_renders_the_target`,
      `rsa_uas_answers_towards_the_sending_address` (responses reach the
      rsa address from a non-`-p` port, the caller gets nothing),
      `rsa_tcp_uas_dials_the_sending_address`; interop
      `rsa_both_ways_against_real_sipp` (sipr UAC `-rsa` → sipp, sipp UAC
      `-rsa` → sipr, sipp UAS `-rsa` answering sipr from its extra socket).
- [x] Deferred: `[remote_ip]` on a UAS follows SIPp's `remote_ip` global.

## M30 — TCP/TLS reconnection: `-max_reconnect`, `-reconnect_close`, `-reconnect_sleep` ✅

Behavioral oracle: `socket.cpp` `reconnect_allowed` ~l.2257,
`reset_connection` ~l.2265, `close_calls`, the recv/send error paths
~l.1866-1880 / ~l.1940-1970, `write_primitive` ~l.2098; `sipp.cpp` ~l.551,
~l.635; `docs/transport.rst` "TCP reconnections".

- [x] `sipr-net`: `NetEvent::Disconnected { peer, local, clean }` from every
      TCP/TLS read loop (clean = FIN / close_notify), `TcpTransport::reconnect`
      and `TlsTransport::reconnect` re-dialing the mono connection under the
      same peer key.
- [x] Engine: SIPp's reset in SIPp's order — a clean close invalidates the
      mono connection and (under `-reconnect_close`) closes its calls; the
      call whose send next hits it fails ("cannot send message"), then the
      socket is re-dialed within the `-max_reconnect` budget after
      `-reconnect_sleep`, or the run ends with exit 255 ("Max number of
      reconnections reached"); an error close resets at once. The reader
      only reports a connection's end and the engine forgets it when it
      processes the event, so a queued ACK still leaves on the half-closed
      socket as SIPp's does. Counters `failed_cannot_send` /
      `failed_tcp_closed` / `failed_tcp_connect`; `RunReport::fatal`.
      Servers close the affected calls only; per-call connections re-dial
      lazily.
- [x] CLI: `-max_reconnect <n>` (default 0, -1 unlimited),
      `-reconnect_close true|false` (default true), `-reconnect_sleep <ms>`
      (default 1000).
- [x] Tests: net unit `disconnect_is_reported_and_reconnect_restores_sending`;
      e2e against a hanging-up TCP UAS: `reconnect_between_calls_with_budget`
      (the call that finds the socket dead fails, the next completes on the
      new connection), `no_reconnect_budget_is_fatal_like_sipp` (exit 255),
      `reconnect_close_fails_the_interrupted_call`,
      `reconnect_close_false_keeps_the_interrupted_call` (its BYE goes out
      on the connection another call's failure re-dialed); interop
      `sipr_tcp_uac_reconnects_to_real_sipp` and
      `real_sipp_tcp_uac_reconnects_to_sipr` (the UAS is restarted between
      two calls).
- [x] Deferred: budgeted re-dial of per-call connections; a start-up connect
      failure consuming the budget; a UAS re-dialing its client.

## M31 — `-t ui`: one UDP socket per injected IP, `-ip_field`, `[server_ip]` ✅

Behavioral oracle: `sipp.cpp` ~l.316/~l.1572/~l.1996, `socket.cpp`
`open_connections` ~l.2466-2560, `call.cpp` `connect_socket_if_needed`
~l.1430-1475 and `E_Message_Server_IP` ~l.2768, `docs/transport.rst`
"UDP with one socket per IP address".

- [x] `-t ui` (UDP only, needs `-inf`) and `-ip_field <n>` (default 0): the
      main socket binds line 0's IP; a client call sends from the socket of
      the IP in its own line (created once, kept for the run; unbindable →
      fatal); a server binds every distinct listed IP on the same port and
      answers on the socket a request arrived on.
- [x] `[server_ip]`: the IP of the socket the call sends from
      (`InboundPacket::local` carries the receiving address for every
      transport).
- [x] Tests: net unit `call_socket_at_binds_the_given_address_and_packets_carry_local`;
      CLI parse; e2e `ui_client_sends_each_call_from_its_lines_ip` (source
      IP alternates with the file, `[server_ip]` in the Via matches it) and
      `ui_server_answers_on_the_ip_the_request_hit`; interop with real
      sipp's `-t ui` in both roles (skipped when the host has no second
      local IPv4 address).
- [x] Deferred: host names in the IP column.

## M32 — SCTP (`-t s1|sn`) — PROPOSAL, decision needed before any code

Findings (2026-09-05, from `sipp.cpp` ~l.209-243 and `socket.cpp`
~l.806-850, ~l.888-905, ~l.1694-1775, ~l.2076):

- SIPp's SCTP surface: `-t s1|sn` (one-to-one `SOCK_STREAM` SCTP sockets,
  mono or per call), `-multihome <ip>` (`sctp_bindx` a second local
  address), `-heartbeat <ms>`, `-assocmaxret`, `-pathmaxret`, `-pmtu`
  (`SCTP_PEER_ADDR_PARAMS` per peer address after `sctp_getpaddrs`),
  `-gracefulclose` (SHUTDOWN vs ABORT). It subscribes to `SCTP_EVENTS`,
  sets `SCTP_NODELAY`, receives with `sctp_recvmsg` one SIP message per
  SCTP message (no Content-Length framing), treats `MSG_NOTIFICATION`
  records (`SCTP_ASSOC_CHANGE` → `SCTP_COMM_UP`, `SCTP_SHUTDOWN_EVENT`)
  as state, and holds sends until the association is up. All of it is
  behind `#ifdef USE_SCTP`; a SIPp built without it says "SCTP support is
  not enabled!".
- This development host cannot do SCTP at all: macOS has no SCTP stack
  (`socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)` → "Protocol not
  supported") and the local `sipp` is `v3.7.7-TLS-PCAP-SHA256` — built
  without SCTP. Neither an e2e nor an interop test can run here; only
  Linux with the `sctp` kernel module and a sipp built with `USE_SCTP`
  can exercise it.
- Rust `std` has no SCTP. Reaching it means one of: (A) the `socket2`
  crate (safe API, pure Rust over `libc`, which is already in the lock
  file transitively) to open `SOCK_STREAM`/`IPPROTO_SCTP` sockets and use
  plain `send`/`recv` — SCTP preserves message boundaries, so one `recv`
  is one SIP message — but none of SIPp's tunables (`SCTP_EVENTS`,
  `SCTP_NODELAY`, peer-address params, `sctp_bindx`) are reachable
  without SCTP-specific `setsockopt` structs; (B) `libc` FFI directly,
  i.e. an `unsafe` exception in one `sipr-net` module, which breaks the
  workspace-wide `#![forbid(unsafe_code)]` rule; (C) a libsctp-binding
  crate — a native C dependency, which CONVENTIONS.md rules out without
  discussion.

Proposal (not started): option A, Linux-only (`cfg(target_os = "linux")`),
behind a cargo feature `sctp` that is off by default, covering `-t s1|sn`
with SIPp's message-per-message framing and association-up gating, and
rejecting `-multihome`/`-heartbeat`/`-assocmaxret`/`-pathmaxret`/`-pmtu`
with a clear "needs libsctp" error; interop coverage only in a Linux CI
job running a sipp image built with `USE_SCTP`. Alternatively option (C′):
leave SCTP out of scope for good and say so in README/SIPP_COMPAT.

Decisions the owner must make before work starts (AGENTS.md: dependency
additions and PLAN.md deviations are asked, not assumed):

1. Add `socket2` to the sanctioned dependencies (option A), allow a scoped
   `unsafe` FFI exception (B), or declare SCTP out of scope (C′)?
2. Is a Linux-only, feature-gated transport acceptable for a project whose
   selling point is a portable single binary?
3. Is a Linux CI job with an SCTP-enabled sipp container acceptable as the
   only acceptance test (nothing here can run it)?

## Post-v1 backlog (ordered)

SCTP — blocked on the M32 decisions above. Otherwise the SIPp surface that
sipr targets is complete. (Checked after M30: the pacer's first call comes one
inter-call interval after start-up in SIPp too — `call_generation_task.cpp`
opens calls when `elapsed × rate / rate_period` reaches the count; no
divergence, see SIPP_COMPAT §6.)

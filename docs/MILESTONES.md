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
- [x] Deferred: per-user persistent variables (shipped as M35; runtime
      user-count changes shipped with the control socket, M17).

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
- [x] Deferred: `-hide` CLI default. (`set display ooc` shipped with M33,
      `set display rx` with M34.)

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

## M32 — SCTP `-t s1|sn` behind the `sctp` cargo feature ✅ (verified only in Linux CI)

Decision (owner, 2026-09-05): option A — `socket2` as a sanctioned dependency,
used only behind an off-by-default `sctp` feature; SCTP-specific socket
options stay out of scope. Findings that led here are in the git history of
this section (macOS has no SCTP stack and the local sipp lacks `USE_SCTP`;
Rust std has no SCTP; `libc` FFI would need an `unsafe` exception).

Behavioral oracle: `sipp.cpp` ~l.209-243, `socket.cpp` ~l.806-850 (notify),
~l.888-905 (`sctp_recvmsg`, one SIP message per SCTP message), ~l.1575-1590
(connect), ~l.1694-1775 (peer params, `SCTP_EVENTS`, `SCTP_NODELAY`).

- [x] `sipr-net::sctp` (feature `sctp`): one-to-one `SOCK_STREAM`/
      `IPPROTO_SCTP` sockets via socket2; blocking `connect` returns at
      association-up (SIPp's `SCTP_COMM_UP` gating); each read is one SCTP
      message = one SIP message (no Content-Length framing); `s1` mono and
      `sn` per-call associations, `reconnect`/`forget`, disconnect reports —
      the same shape as the TCP transport. `available()` probes the kernel
      at run time; the module compiles on every OS.
- [x] Engine: `TransportKind::SctpMono|SctpPerCall`, `[transport]` = `SCTP`,
      reliable (no retransmissions), per-call pool, reconnection. Without
      the feature or without a stack, `-t s1` is a clear start-up error
      (SIPp: "SCTP support is not enabled!").
- [x] CLI: `-t s1|sn`; SIPp's `-multihome`, `-heartbeat`, `-assocmaxret`,
      `-pathmaxret`, `-pmtu`, `-gracefulclose` are rejected with a message
      naming why (SCTP socket options socket2 cannot set).
- [x] Tests: net unit `messages_keep_their_boundaries_and_round_trip`
      (skips without a stack), e2e `sctp_mono_and_per_call_calls_complete`
      (skips) and `sctp_without_a_stack_or_feature_is_a_clear_error`,
      interop `sctp_both_ways_against_real_sipp` (skips unless sipp banners
      `-SCTP`). CI job `sctp` on ubuntu: `modprobe sctp`, sipp built from
      source with `USE_SCTP`, `cargo test --features sctp`, the interop test.
- [x] Verified in Linux CI (run 33977957760, 2026-09-05): `sctp` job green —
      `messages_keep_their_boundaries_and_round_trip`,
      `sctp_mono_and_per_call_calls_complete`, and
      `sctp_both_ways_against_real_sipp` all ran (not skipped) against a
      SIPp 3.7.7 built with `USE_SCTP`. The development host (macOS) still
      cannot run them.
- [x] Deferred for good: `SCTP_NODELAY`, notifications, per-path parameters,
      multi-homing, SHUTDOWN-vs-ABORT.

## Post-v1 backlog (ordered)

(Checked after M30: the pacer's first call comes one inter-call interval
after start-up in SIPp too — `call_generation_task.cpp` opens calls when
`elapsed × rate / rate_period` reaches the count; no divergence, see
SIPP_COMPAT §6.)

### M33 — Out-of-call scenarios: `-oocsf`, `-oocsn`, `set display ooc`

Behavioral oracle: `sipp.cpp` ~l.177 (option table), ~l.1792-1800 (parse:
`-oocsf <file>` loads a scenario file, `-oocsn <name>` an embedded one),
~l.2113-2116 (the `ooc_default` fallback is **commented out** — with no
`-oocs*` flag a UAC keeps discarding unmapped requests with the
"Discarding message which can't be mapped to a known SIPp call" warning),
~l.2147-2149 (fatal in server mode: "SIPp cannot use out-of-call scenarios
when running in server mode"); `socket.cpp` ~l.1195-1217 (dispatch: a
*request* whose Call-ID matches no call, in client mode, spawns a call on
the ooc scenario with no user id, counts `E_CREATE_INCOMING_CALL` on the
ooc scenario's stats plus the global `E_AUTO_ANSWERED`, logs the
"Received out-of-call %s message, using the out-of-call scenario" warning
and feeds it the message; an unmapped *response* only counts
`E_OUT_OF_CALL_MSGS`), ~l.191 (`set display ooc` swaps the TUI scenario);
`call.cpp` ~l.6641 (ooc calls may not use `-inf`: "Automatic calls
(created by -aa, -oocsn or -oocsf) cannot use input files!");
`scenario.cpp` ~l.1933 (embedded names `ooc_default`, `ooc_dummy`);
`docs/int_scenarios.rst` "UAC Out-of-call Messages" and
`docs/ooc_default.xml` (recv `request=".*" regexp_match="true"`, send
200 with `[last_*]` copies and a `Contact`, `timewait 4000`).

- [x] `-oocsf <file>` / `-oocsn <name>`: a second, independently compiled
      scenario next to the main one (own variable table, own per-step
      stats and repartitions — `OocScenario` in engine.rs). Client mode
      only — fatal at startup in server mode with SIPp's wording. Mutually
      exclusive with each other (usage error). The ooc scenario may not
      use `<sendCmd>`/`<recvCmd>` (startup error, sipr addition).
- [x] Embedded `ooc_default` (SIPp's XML, sipr's own comment header like
      `uac`/`uas`) and `ooc_dummy`; `-sd ooc_default|ooc_dummy` dumps them
      and `-sn` accepts them too. With no `-oocs*` flag sipr keeps the
      discard-and-count path (SIPp's commented-out fallback; SIPP_COMPAT §6).
- [x] Dispatch in `engine.rs` (`on_packet` → `spawn_ooc_call`): an unmapped
      *request* in client mode creates a call on the ooc scenario keyed by
      the incoming Call-ID, remote = the packet source (or `-rsa`), no user
      id, no injection line, replying on the per-IP/per-call socket the
      request hit when there is one; runs it from step 0 with the request
      as the first inbound message; counts an incoming call on the ooc
      stats and bumps the global auto-answered counter; logs SIPp's
      warning. Unmapped *responses* stay ignored. Ooc calls never count
      toward `-m`/`-l`/`-users` (`live_main`), and — correcting the entry
      above — SIPp's `open_calls` ignores them for the end of the run too,
      so the run ends when the main calls are done and lingering ooc calls
      are dropped (SIPp additionally BYEs them from its generic exit
      abort; not reproduced).
- [x] `[fieldN]` in an ooc scenario is a startup error with SIPp's wording
      ("Automatic calls (created by -aa, -oocsn or -oocsf) cannot use
      input files!"); `[userid]` renders 0.
- [x] TUI + control: `set display ooc|main` over the control socket (SIPp
      has no screen key for it — `sipp.cpp` key switch verified) swaps the
      scenario page to the ooc scenario's steps (`Snapshot::display_ooc`,
      HTTP `/stats` `display` field); the statistics stay the main
      scenario's. Correcting the entry above: SIPp never dumps ooc stats
      to CSV (`reporttask.cpp` `stattask::report` dumps `main_scenario`
      only), so neither does sipr.
- [x] `--check` lints the ooc scenario with the same rules and prints its
      IR after the main one; unknown elements are hard errors there too.
- [x] Found on the way and fixed: `regexp_match="true"` was compiled but
      never applied by the engine's matcher (`recv_matches` compared
      literally), so `ooc_default`'s `request=".*"` matched nothing. Now
      the regex runs over the method / decimal status code as in SIPp's
      `matches_scenario` (unit test
      `regexp_match_searches_the_method_and_the_status_code`).
- [x] Tests: scenario unit (embedded ooc scenarios parse; `[fieldN]`
      detection); CLI unit + binary (`-oocsf`/`-oocsn` parse and conflict,
      server-mode fatal, injection fatal, unknown name, `-sd`, `--check`);
      e2e `uac_answers_out_of_call_options_with_ooc_scenario` (ooc_default
      answers with the copied headers and the main flow is clean; no flag
      → discarded and counted; ooc_dummy → spawned, failed on the ooc
      stats, unanswered) and `set_display_ooc_swaps_the_scenario_screen`;
      interop `real_sipp_ooc_scenario_answers_siprs_out_of_call_options`
      and `sipr_ooc_scenario_answers_real_sipps_out_of_call_options`, both
      green against SIPp 3.7.x.
- [x] Docs: SIPP_COMPAT §3 flags and §6 behaviour note (commented-out
      default, client-only, no `-inf`, unmapped responses never spawn, the
      two SIPp quirks seen in interop), CONTROL_API, ARCHITECTURE "two
      scenarios, one engine", AGENTS state line; M22 deferral updated.
- [x] Out of scope here (recorded in SIPP_COMPAT §6): `-rxsf`/`-rxinf`
      mixed-mode receive scenario (`MODE_MIXED`, `rx_scenario`) — queued
      as M34.

### M34 — Mixed mode: `-rxsf`/`-rxsn` receive scenario, `-rxinf`, `set display rx`

A UAC that also terminates calls: the main scenario originates, a second
server-mode scenario answers whatever the peer originates towards us.

Behavioral oracle: `sipp.cpp` ~l.174-197 (option table: `rxsf` and
`rxrn` — the latter a typo; its help text names `-snrx`/`-sfrx`, which
exist nowhere), ~l.1778-1790 (parse: `-rxsf <file>` loads a file,
`-rxsn <name>` an embedded one, both set `creationMode = MODE_MIXED` —
but `rxsn` is missing from the option table, so SIPp rejects it as an
unknown option, and `-rxrn` reaches the "Internal error, I don't
recognize" branch: **in SIPp 3.7 only `-rxsf` works**), ~l.307 and
~l.1584-1605 (`-rxinf` registers the CSV in the shared `inFiles` map under
its basename and sets `rx_ip_file`/`rx_default_file`, which nothing ever
reads: a `[fieldN]` without `file=` in the rx scenario resolves to the
first `-inf` file — `message.cpp` ~l.294, "No injection file was
specified!" without one — and `[fieldN file=x.csv]` reaches a `-rxinf`
file by basename), ~l.2140-2148 (`runInit`/`computeSippMode` run for the
main and ooc scenarios only: the rx scenario's `<init>` section never
runs, and nothing enforces the help text's "rx MUST be server-mode, main
MUST be client-mode"), ~l.2203 (the call generator runs in MIXED as in
CLIENT), ~l.556-561 (`-m` and the end of the run look at
`main_scenario`'s counters only; rx calls are dropped by
`abort_all_tasks` at exit), ~l.1182 (the exit code's failed/successful
counters come from `display_scenario` — whichever scenario is displayed
at exit); `scenario.cpp` ~l.1249 (`computeSippMode` keeps MIXED,
`sendMode` still comes from the main scenario); `socket.cpp`
~l.1184-1195 (dispatch: in MIXED *any* message whose Call-ID matches no
call — request or response, quitting or not (the quitting check is
commented out) — creates a call on `rx_scenario` through the UAS
constructor, no user id, counts `E_CREATE_INCOMING_CALL` on the rx stats,
logs nothing; the ooc and `-aa` out-of-call branches are unreachable in
MIXED), ~l.193 (`set display rx`); `screen.cpp` ~l.83-90 and ~l.242-245
(`display_client()`/`display_server()`: header "Sipp Mixed Mode - main -
call originating scenario" / "Sipp Mixed mode - rx - call terminating
scenario", server-style columns when rx is displayed), ~l.294, ~l.710,
~l.796 (the main counters, the statistics screen and the repartition
screens all read `display_scenario->stats`); `call_generation_task.cpp`
~l.106-130 (`-l`/`-users` measured on `main_scenario`). No docs page and
no regress test mentions mixed mode.

- [x] `-rxsf <file>` / `-rxsn <name>`: a second, independently compiled
      server-mode scenario next to the main one (own variable table, own
      per-step stats and repartitions). Generalise M33's `OocScenario`
      into one secondary-scenario type carrying a role (ooc | rx) so the
      two share compile, stats, display and `--check` plumbing. `-rxsn`
      accepts `uas` and the other embedded names as SIPp's parser intends
      (record SIPp's table typo in SIPP_COMPAT §6; do not add `-rxrn`).
      `-rxsf`/`-rxsn` are mutually exclusive (usage error). Startup
      checks, all fatal with a clear message (sipr additions — SIPp
      promises them in its help and enforces none): the main scenario
      must be client-mode, the rx scenario server-mode (first
      significant step a `<recv>`), no `<sendCmd>`/`<recvCmd>` in the rx
      scenario, and `-rxs*` may not be combined with `-oocs*` (SIPp
      silently never reaches the ooc branch in mixed mode — a loud
      refusal beats a scenario that never fires).
- [x] Dispatch in `engine.rs` (`on_packet`, next to `spawn_ooc_call`): in
      mixed mode an unmapped *request* creates a call on the rx scenario
      keyed by the incoming Call-ID, remote = the packet source (or
      `-rsa`), no user id, replying on the per-IP/per-call socket the
      request hit; runs it from step 0 with the request as the first
      inbound message; counts an incoming call on the rx stats. Spawning
      continues while draining, as in SIPp. Unmapped *responses*: SIPp
      spawns an rx call for them too (the UAS quirk M33 already declined
      to reproduce) — sipr keeps discarding and counting them; record it.
      No warning line (SIPp logs none) but a `-trace_err`-level debug
      line is fine.
- [x] Rx calls never count toward `-m`/`-l`/`-users` (`live_main`) and
      never end the run; the run ends when the main calls are done and
      lingering rx calls are dropped (SIPp's exit abort may BYE an
      established one; not reproduced, as with M33). Exit code: SIPp
      derives it from whichever scenario is displayed at exit — sipr
      keeps the main scenario's counters and records the divergence.
- [x] `-rxinf <file>` (repeatable): registers the CSV in the shared
      injection-file table under its basename, reachable from either
      scenario with `[fieldN file=<basename>]`. A bare `[fieldN]` in the
      rx scenario resolves to the first `-inf` file, as in SIPp, and is a
      startup error without one (SIPp's wording). Rx calls draw lines the
      way sipr's UAS calls do (SEQUENTIAL/RANDOM; USER-mode files behave
      as they do for a UAS today); `[userid]` renders 0.
- [x] `<init>` in the rx scenario: SIPp never runs it — and sipr has no
      `<init>` support at all (an unknown element is a hard error), so
      there was nothing to decide; recorded in SIPP_COMPAT §6.
- [x] TUI + control: `set display rx|ooc|main` over the control socket
      (HTTP `/stats` `display` gains `rx`); the screen header reads SIPp's
      mixed-mode lines. **Align the display semantics with SIPp**: its
      main counters, statistics screen and repartition screens all follow
      `display_scenario`, with server-style columns when rx is displayed.
      This corrects M33's "the statistics stay the main scenario's" — fix
      `Snapshot::display_ooc` (a `display: Main|Ooc|Rx` enum with the
      displayed scenario's counters) so ooc gets the same treatment, and
      update the M33 wording in SIPP_COMPAT §6, CONTROL_API and the
      snapshot doc comment. `-trace_stat`/`-stf` stay main-only (SIPp
      `stattask::report`).
- [x] `--check` lints the rx scenario with the same rules and prints its
      IR after the main (and ooc) one; unknown elements are hard errors.
- [x] Tests: CLI unit (`mixed_mode_flags_parse_and_conflict`) + binary
      (`mixed_mode_flags_conflict_and_roles_are_checked`,
      `receive_scenario_with_a_bare_field_needs_an_inf_file`,
      `check_mode_lints_the_receive_scenario_too`); e2e
      `uac_terminates_incoming_calls_with_rx_scenario` (sipr UAC on the
      main scenario against a peer that originates an INVITE mid-run; the
      rx `uas` scenario answers 180/200 and the 200 to the BYE with the
      copied headers, the main flow is clean; without `-rxs*` the INVITE
      is discarded and counted), `rx_scenario_reads_rxinf_by_file_name`
      (named `-rxinf` field plus a bare `[fieldN]` from the first `-inf`),
      `set_display_rx_swaps_the_screens` (role, steps and counters follow;
      the M33 ooc display test updated to the corrected semantics);
      interop `real_sipp_and_sipr_terminate_each_others_calls_in_mixed_mode`
      (both sides `uac` + `-rxsf`/`-rxsn uas`, three calls each way, a
      timewait on the main scenario keeping each side up for the peer's
      last call) and `sipr_receive_scenario_answers_a_plain_real_sipp_uac`
      (sipr mixed between a sipp UAS and a sipp UAC), both green against
      SIPp 3.7.x.
- [x] Docs: SIPP_COMPAT §3 flags and §6 behaviour note (SIPp's
      `-rxsn`/`-rxrn` breakage, `-rxinf` files unread by SIPp, no rx init,
      unmapped responses, the exit-code quirk, the corrected display
      semantics), CONTROL_API, ARCHITECTURE "two scenarios, one engine" →
      secondary scenarios, README, AGENTS state line; the M22 `set
      display rx` deferral and M33's out-of-scope line updated.

### M35 — Dynamic users: `<User>`/`<Global>` variable scopes, SIPp's user-id retirement

Runtime user-count changes already exist (`set users N`, the `+ - * /`
keys, HTTP `/control`, M17). What is missing is the other half of SIPp's
user model: variables that outlive a call — per user (`<User
variables="…"/>`, one table per user id, `userVarMap`) and per run
(`<Global variables="…"/>`, one table for the process) — plus SIPp's exact
user-id bookkeeping when the count shrinks and grows again. Today both
elements are hard errors in sipr ("unknown element"), so any SIPp scenario
using them fails to load.

Behavioral oracle: `scenario.cpp` ~l.718 (every scenario's `allocVars`
is a child of `userVariables`), ~l.756-779 (`<Global variables>` and
`<User variables>` allocate the comma-separated names in
`globalVariables`/`userVariables`), ~l.780-790 (`<Reference>` must name an
existing variable); `variables.cpp` ~l.187-210 (a `VariableTable` chains
to its parent and carries a level), ~l.284-296 (`getVar` climbs to the
level encoded in the variable id), ~l.303-330 (`AllocVariableTable::find`:
the scenario's own map first, then the parents, then allocate — so a
name *used before* its `<User>`/`<Global>` declaration is already
call-scoped and the declaration changes nothing for it); `sipp.cpp`
~l.1450 (`userVariables` is a child of `globalVariables`), ~l.2123-2126
(one `VariableTable(userVariables)` per user id at startup), ~l.1097 (the
tables live for the whole run — a retired id keeps its values);
`call.cpp` ~l.1100-1115 (a call with a user id parents its table on
`userVarMap[userId]`; a call without one — UAS, ooc, rx, rate mode — gets
a fresh private table, so "user" variables are per call there), ~l.1296
(`free_user` at call end); `call_generation_task.cpp` ~l.252-290
(`set_users`: growth takes `retiredUsers` first, then `users + 1` with a
fresh table; `users = open_calls_allowed = new`; `free_user` retires an id
while `CurrentCall > open_calls_allowed`, else returns it to the pool);
`socket.cpp` ~l.164-176 (`set users` wordings, already matched),
~l.407-437 (keys step users by `rate_scale`, already matched); `sipp.dtd`
(declares `Reference` only — `Global`/`User` are accepted by the parser
and absent from the DTD and the docs; the regress suite never uses them).

- [x] Scenario: `<Global variables="a,b"/>` and `<User variables="x"/>`
      elements (`variables` required; unknown attributes warn). Each
      variable id carries a scope — `Call` (default), `User`, `Global` —
      (`VarTable::scope`/`in_scope`, `VarScope`) resolved at compile time
      so the hot path never searches; `dump()` prints the user and global
      name lists. SIPp's declaration-order quirk (a use before the
      declaration stays call-scoped): sipr applies the scope to the whole
      scenario and warns naming the line of the earlier use, so `--check`
      catches what SIPp silently gets wrong (SIPP_COMPAT §6). A name
      declared both `<User>` and `<Global>` is an error. `<Reference>`
      keeps rejecting unknown names. A `<Global>` read but never set is
      no diagnostic (`-set` or the other scenario may set it); a `<User>`
      one stays the usual error.
- [x] Engine: a layered variable store (`sipr-engine/src/vars.rs`) — the call's own store, the user's
      store (by user id, owned by the engine, created when the id is
      first handed out and kept for the run, SIPp's `userVarMap`) and one
      global store shared by every call of both scenarios (the secondary
      scenario's `allocVars` hangs off the same `userVariables`). Reads
      and writes from every action (`assign`, `assignstr`, `ereg`,
      arithmetic, `strcmp`, `test`, `lookup`, `gettimeofday`, `trim`,
      `urlencode`/`urldecode`, `todouble`, `jump variable=`) and `[$var]`
      rendering go through it by scope. Calls with no user id get a
      private "user" layer, as SIPp. Single engine thread: no locks, no
      allocation per access beyond what call-scoped variables do today
      (`VarStore::get` returns a `VarRef` borrowing the layer; the shared
      layers are `Rc<RefCell<…>>`). A `VarSpace` unions the user and
      global names of both scenarios so one name is one slot across them
      (SIPp's shared `userVariables`/`globalVariables`); a name scoped
      differently by the two is a start-up error. Also shipped: SIPp's
      `-set VARIABLE VALUE` (seeds a `<Global>`; fatal with SIPp's
      wording, plus the declared names, when none declares it).
- [x] User-id bookkeeping like SIPp's: growth takes retired ids first (so
      a returning user sees its old variables), then fresh ones; a shrink
      does not touch the pool — a finishing call's id is retired while
      the live count exceeds the target and returned otherwise (SIPp
      `free_user`), so whichever users happen to be live keep their ids
      and injection lines. sipr used to drop ids above the target
      regardless of liveness; now aligned, including SIPp's pool order
      (filled 1..N, served from the back — the first call is user N's —
      returned to the front). One divergence, recorded: fresh ids on a
      growth are never-used numbers, not SIPp's `users + 1` that can
      collide with a live id after a shrink. `[users]` keeps rendering
      the current count.
- [x] Control: `dump variables` — SIPp prints the displayed scenario's
      variable names by scope (`AllocVariableTable::dump`); implemented
      into the error trace with SIPp's lines (`N level 0 variables:` …
      global, user, call).
- [x] `--check` prints the scopes; embedded scenarios untouched.
- [x] Tests: scenario unit (both elements parse; scopes resolve; a use
      before the declaration warns; `<Reference>` to an undeclared name
      still errors); engine unit (a user variable survives into the same
      user's next call, a global one is visible to every call, a call
      variable resets, a UAS call's user variable does not leak into the
      next call); e2e `user_variables_persist_across_a_users_calls`
      (`-users 2 -m 6`: the scenario adds 1 to a `<User>` counter and 1
      to a `<Global>` counter per call and sends both in headers; the peer
      sees per-user 1,2,3 and global 1..6 in call order),
      `set_users_retires_and_reuses_ids_like_sipp` (control socket 3 → 1
      → 3 mid-run; the ids seen after the regrow are the ones that were
      retired, with their counters continuing); interop: the same
      counter scenario run by real sipp against a sipr UAS and by sipr
      against a sipp UAS, the header sequences compared.
- [x] Found on the way, recorded in SIPP_COMPAT §6: SIPp renders double
      variables as `%lf` (`3.000000`, sipr printed `3`) and treats a zero
      double / false bool as unset — fixed in v0.24.0 right after M35;
      and SIPp's one-step-per-call-per-turn scheduler interleaves
      same-tick calls' `<nop>` actions before their sends, visible only
      through globals — left as is.
- [x] Docs: SIPP_COMPAT §1 (the two elements), §3 (`-set`), §6 note (scope chain,
      declaration-order divergence, private user layer for id-less calls,
      retirement rules, `dump variables`); ARCHITECTURE variable-store
      paragraph; README feature bullet; the M11 deferral updated.

### M36 — Manual transactions: `start_txn`, `ack_txn`, `response_txn`

Today sipr matches a response to the call's outstanding request by CSeq
method (`expected_cseq_method`, SIPp's `recv_response_for_cseq_method_list`
guard), which cannot tell two concurrent transactions of the same method
apart — a re-INVITE racing the initial INVITE's late 200, an UPDATE
overlapping another, forked provisional responses. SIPp's manual
transactions name a request's Via branch so the scenario can say exactly
which transaction a `recv` answers. sipr's compiler rejects the three
attributes today ("not supported yet — v1.x").

Behavioral oracle: `scenario.cpp` ~l.343-400 (`get_txn`: names may not be
empty or contain `$`/`,`; one `txnControlInfo` per name with `started`/
`responses`/`acks` counts and `isInvite`), ~l.878-931 (a `send` request
may carry `start_txn` (not an ACK: "An ACK message can not start a
transaction!") or `ack_txn` (only an ACK: "The ack_txn attribute is valid
only for ACK messages!"); a `send` *response* may carry neither
("Responses can not start a transaction" / "Responses can not ACK a
transaction"); `response_txn` only on `recv response=` ("response_txn can
only be used for received messages." on a send, "… for received
responses." on `recv request=`); a request with `start_txn`/`ack_txn` is
**not** added to the CSeq-method list), ~l.588-602 (`validate_txn_usage`:
"Transaction %s is never started!", "… has no responses defined!", "… is
an INVITE transaction without an ACK!", "… is a non-INVITE transaction
with an ACK!"); `call.cpp` ~l.1128 (per-call `txnInstanceInfo`: `txnID`,
`txnResp` hash, `ackIndex`), ~l.2110-2116 (on send: `start_txn` stores the
sent message's top-Via `branch` (`extract_transaction`, ~l.4431-4450,
up to `;`/`,`/space), `ack_txn` records the ACK's message index),
~l.4581-4587 (`matches_scenario`: a `recv` with `response_txn` matches
only when the response's top-Via branch equals the stored one — before
and instead of the CSeq-method guard; `index == 0` and the method list
apply only without it), ~l.5395-5430 (a matching response for a `recv`
that is *not* the current step — an old transaction: a 1xx is ignored
with "Ignoring provisional %s message for transaction %s"; a final
response to an INVITE transaction re-sends the recorded ACK
(`ackIndex`); a final response to a non-INVITE transaction whose hash
equals the stored `txnResp` is ignored with a WARNING "Ignoring final %s
message for transaction %s (hash %lu)"), ~l.5502-5504 (the accepted
response's hash becomes `txnResp`); `docs/scenarios/ownscenarios.rst`
"start_txn"/"ack_txn"/"response_txn" rows. Note `[branch]` itself is
unchanged by transactions (`E_Message_Branch`, `z9hG4bK-pid-number-index`):
an `ack_txn` ACK carries its own branch, as in SIPp.

- [x] Scenario: the three attributes parse into a per-scenario
      transaction table (`Scenario::transactions`: name, `is_invite`;
      the use counts live in the compiler) and per-step `start_txn: Option<TxnId>` /
      `ack_txn: Option<TxnId>` on `SendStep`, `response_txn: Option<TxnId>`
      on `RecvStep`, ids resolved at compile time. All of SIPp's placement
      errors above with its wording; `validate_txn_usage` at `finish()`.
      A request step with `start_txn`/`ack_txn` stays out of the
      CSeq-method guard list (`precompute_cseq_methods` follows suit). The
      IR dump shows `start_txn=name` / `ack_txn=name` / `response_txn=name`
      and a `transactions:` line. sipr addition: `start_txn` and `ack_txn`
      on the same `<send>` is an error (SIPp silently takes the first).
- [x] Engine: per-call `txns: Vec<TxnInstance>` (`branch: Option<String>`,
      `final_hash: Option<u64>`, `ack_index: Option<StepIndex>`), sized
      from the scenario table (empty when unused — no cost for the common
      case). On send: a `start_txn` step stores the rendered message's
      top-Via branch, an `ack_txn` step its index. On receive
      (`scan_for_match`/`recv_matches`): a `response_txn` recv matches a
      response only by branch (parsed once per inbound message, alongside
      the CSeq method); the first-step and CSeq-method rules apply only
      to recvs without it. Out-of-window responses to a *named*
      transaction follow SIPp: provisional ignored (error-trace line),
      final to an INVITE transaction re-sends the recorded ACK, a repeat
      of the accepted final response (same hash — use the message bytes'
      hash) ignored with SIPp's WARNING; the accepted final's hash is
      stored. Everything without `response_txn` behaves exactly as today
      (`Scan::OldTxn`, `on_old_transaction_response`, `resend_step` over
      the extracted `render_send`; the backward scan only walks past the
      contiguous optional block when the scenario names transactions).
- [x] `--check` prints the transaction table; embedded scenarios untouched.
- [x] Tests: scenario unit (the attributes compile and resolve; each
      placement error and each `validate_txn_usage` error with SIPp's
      wording; a `start_txn` request leaves the method list); engine unit
      (branch extraction from a rendered Via with parameters and commas;
      `recv_matches` with a `response_txn` accepts the branch and rejects
      a same-method response from another branch); e2e
      `response_txn_matches_the_right_invite_of_two_overlapping_ones` (a
      UAC sends INVITE `start_txn="a"`, then a re-INVITE `start_txn="b"`
      before `a`'s 200 arrives; the scripted UAS answers `b` first — the
      scenario's `recv response="200" response_txn="a"` waits for the
      right one and both ACKs (`ack_txn`) go out; without the attributes
      the same flow mis-matches, proving the point) and
      `late_final_response_to_a_named_invite_transaction_is_acked_again`
      (after an INFO round trip the UAS sends a late 180 and the INVITE's
      200 again; sipr ignores the 180 with SIPp's trace line, re-sends the
      recorded ACK and does not fail the call — neither is a repeat of the
      last message received, so the generic dedupe cannot be what saves
      it); interop `manual_transactions_complete_against_real_sipp_both_ways`
      (SIPp's basic UAC flow with every transaction named, run by real
      sipp against a sipr UAS and by sipr against a sipp UAS: every call
      completes on both sides, nothing unexpected). The overlapping
      e2e also proves the strictness: with the peer answering `first`
      first, the call fails on that response, as in SIPp.
- [x] Docs: SIPP_COMPAT §1 (`send`: `start_txn`, `ack_txn`; `recv`:
      `response_txn`), the v1.x tier paragraph, §6 note (branch-based
      matching order, the out-of-window rules, `[branch]` unchanged);
      ARCHITECTURE §4 (per-call transaction slots next to the retrans
      context); README feature bullet.

### M37 — `exec command=` (external process) and `<setdest>`

The two remaining v1.x-tier actions. Both are hard errors in sipr's
compiler today ("exec command= (external process) is not supported yet",
"action `<setdest>` is not supported yet"), so SIPp's documented hook and
redirect idioms — `<exec command="echo [last_From] >> from_list.log"/>`,
`<setdest host="[$host]" port="[$port]" protocol="[$transport]"/>` after
an `ereg` over `[next_url]` — fail to load.

Behavioral oracle: `scenario.cpp` ~l.1596-1600 (`setdest`: `host`,
`port`, `protocol`, each a message template — `xp_get_string` — so
keywords and `[$var]` render at run time), ~l.1637-1640 (`exec
command="…"` is a message template too; the DTD, `sipp.dtd` ~l.90-95,
lists `command`, `int_cmd`, `play_pcap*`, `rtp_stream`, `rtp_echo`);
`call.cpp` ~l.6144-6178 (`E_AT_EXECUTE_CMD`: the rendered command runs
through a double `fork()` and `system()` — a shell — the parent reaps
only the intermediate child and **never waits for the command nor sees
its status**; the grandchild logs "system call error for %s" when
`system()` itself fails; stdin/stdout/stderr are inherited, which is why
the `>> file` idiom works and why output lands on the curses screen),
~l.5841-5935 (`E_AT_SET_DEST`: render host, port, protocol; port must be
numeric ("Invalid port for setdest: %s"); protocol is `udp|tcp|tls|sctp`
in either case ("Unknown transport for setdest: '%s'"); it must equal
the call's transport ("Can not switch protocols during setdest."); TLS
is refused ("Changing destinations is not supported for TLS."); TCP/SCTP
need per-call sockets ("Changing destinations for TCP or SCTP requires
multisocket mode.") and a socket nobody else shares ("Can not change
destinations for a TCP/SCTP socket that has more than one user."); the
host is resolved with a **blocking** `getaddrinfo` ("Unknown host '%s'
for setdest"); UDP then just retargets the call's peer; TCP/SCTP close
the call's connection and `reconnect()`, a failure logging "Unable to
connect a TCP/SCTP/TLS socket" and spending one `-max_reconnect` credit
— all of those are SIPp `ERROR`s, i.e. fatal for the whole run),
~l.2741 (`[remote_ip]`/`[remote_port]` keep rendering the global
remote: `setdest` moves the traffic, not the keywords);
`docs/scenarios/actions.rst` "External commands" and "setdest" (incl.
the IPv6-without-brackets warning: brackets would be read as a keyword).

- [x] Scenario: `<exec command="…"/>` compiles to `Action::ExecCommand
      (MsgTemplate)` (mutually exclusive with the other `exec`
      attributes, as today); `<setdest host= port= protocol=/>` to
      `Action::SetDest { host, port, protocol: MsgTemplate }` with the
      three attributes required (`xp_get_string` is fatal without them;
      SIPp's wording) and unknown attributes warning. Both run from
      `<recv>`, `<nop>`, `<send>` actions like any other; `--check` dumps
      them. The DTD's `sample` and the standalone `index` stay rejected.
- [x] Engine, `exec command=`: render the template (all keywords, the
      call's variables), then hand the string to an exec runner — one
      background thread (`sipr-engine/src/exec.rs`) that spawns `sh -c
      <cmd>` (`cmd /C` on Windows) with inherited stdout/stderr, stdin
      closed, and reaps each child when it exits, so the engine thread
      never forks, waits or blocks and no zombies accumulate under load.
      Fire-and-forget like SIPp: no exit status, no effect on the call; a
      spawn failure is one stderr warning ("system call error for `<cmd>`",
      SIPp's text — the runner thread has no error trace) and nothing
      more. Dropping the runner at the end of the run drains the queue
      (every command still starts) without waiting for running commands,
      as SIPp's grandchildren outlive it. The only hot-path cost is the
      render.
- [x] Engine, `<setdest>`: render the three values; validate exactly as
      SIPp (port numeric; protocol one of the four, case-insensitive;
      protocol == the run's transport; TLS refused; TCP/SCTP only in the
      per-call modes `tn`/`sn` — the call's own connection is closed and
      re-dialled to the new peer, a failure counting against
      `-max_reconnect` and failing the call with SIPp's "Unable to
      connect" warning) — but, as with "Jump statement out of range",
      **fail the call, not the run** (record). UDP retargets the call's
      `remote` only: `[remote_ip]`/`[remote_port]` and the digest URI keep
      the nominal remote (`render_remote`), as SIPp's globals do. A
      literal IP costs no I/O; a host name is resolved with a blocking
      lookup on the engine thread, SIPp's documented stall — an
      error-trace line notes it the first time. IPv6 literals bare, as
      in SIPp (bracketed ones read as keywords). `-rsa`: verified —
      SIPp copies the sending address into `remote_sockaddr` at start-up
      and `setdest` overwrites the call's peer, so setdest wins; sipr
      overwrites `call.remote` the same way. A call that has not sent
      yet is simply retargeted (its first send dials the new peer).
- [x] Tests: scenario unit (both actions compile; missing `setdest`
      attributes error; `exec command=` with a media attribute still
      errors); engine unit (setdest validation messages; protocol
      parsing incl. case); e2e `exec_command_runs_a_shell_per_matching_
      message` (a UAS scenario `echo [last_From] >> from_list.log` on
      each INVITE against 3 sipr UAC calls: the file holds the three From
      headers, sipr exits 0, no zombie — check `ps` shows no defunct
      children of sipr while it runs), `setdest_redirects_the_rest_of_
      the_call_over_udp` (the scripted UAS answers the INVITE with a
      Contact on a second socket; the scenario `ereg`s host and port out
      of `[next_url]`, `setdest`s, and the BYE arrives on the second
      socket while `[remote_ip]:[remote_port]` in it still name the
      first), `setdest_over_per_call_tcp_reconnects` (`-t tn`: the BYE
      arrives on a second TCP listener) and `setdest_is_refused_where_
      sipp_refuses_it` (mono TCP → the call fails with SIPp's wording;
      TLS likewise; the run goes on); interop: SIPp's own setdest example
      shape (`[next_url]` → `ereg` → `setdest`) run by real sipp against
      a sipr UAS that answers with a Contact pointing at a second sipr
      UAS port, and by sipr against the same with sipp on the second
      port; and an `exec command=` scenario on both, each side's
      `>> file` output compared. Deviations from the plan, all recorded
      in SIPP_COMPAT §6: the zombie check is one `ps` after the calls
      (the runner reaps within 100 ms, so a poll can catch a child in
      between); the TLS refusal is a unit test (no certificates needed);
      the setdest scenarios `setdest` in a `<nop>` after the ACK so the
      redirecting peer sees INVITE and ACK and the second peer only the
      BYE (SIPp's `-sn uas`-style peers need that shape); real sipp's
      hook writes blank lines (`[last_*]` timing) so the interop test
      compares line counts on the sipp side and content on the sipr side.
- [x] Found on the way: `ereg search_in="body"` and `search_in="var"
      variable=` were missing (SIPp's setdest idiom needs `var`) — added;
      `[next_url]` in SIPp needs `rrs="true"` on the recv to carry the
      Contact (sipr does not — left as is); SIPp's `[last_*]` inside a
      recv's own actions still name the previous message (sipr: the one
      just received — left as is); SIPp's docs example `echo [last_From]`
      needs quoting under any shell. All in SIPP_COMPAT §6.
- [x] Docs: SIPP_COMPAT §1 (actions table: `exec command=`, `setdest`),
      the v1.x tier paragraph, §6 note (fire-and-forget exec, the fatal
      → per-call divergence, blocking resolution, keywords unchanged by
      setdest); ARCHITECTURE (the exec runner thread next to the media
      threads); README feature bullet; CONVENTIONS if the runner needs a
      dependency (it should not — `std::process` suffices).

## Second backlog (ordered, after M37)

Drawn up 2026-09-20 from a sweep of what still fails loudly: SIPp's CLI
option table (`sipp.cpp`) against `sipr -h`, its keyword table
(`message.cpp`) against the renderer, `sipp.dtd` against the compiler, the
"not supported yet" errors in the source, and the "post-v1" / "left as is"
notes in `docs/SIPP_COMPAT.md` §6. Every DTD element is handled; the gaps
are inside attributes, keywords and flags. Ordered by how often real
SIPp scenarios and CI wrappers hit them. Each entry states its behavioral
oracle; read the C++ before implementing, as before. Parity first (M38–M44),
sipr's own additions after (M45+).

### M38 — Statistical pauses: SIPp's `distribution=` attributes, all kinds, and `<sample>` ✅

The last v1.x-tier item in PLAN.md §3.4. Found on the way: sipr's
`distribution=` took a positional form of its own invention,
`distribution="uniform(200,3000)"`, and rejected SIPp's real syntax —
separate attributes, `distribution="uniform" min="200" max="3000"` — so
every SIPp scenario with a distributed pause failed to load. Beyond that,
`<pause>` accepted only `fixed`, `uniform`, `normal` and `exponential`;
the engine rejected `lognormal`, `weibull`, `pareto`, `gpareto`, `gamma`
and `negbin` ("pause distribution '…' is not implemented yet"; `poisson`
was listed but SIPp has none), and `<sample>` was a compile error.

Behavioral oracle: `scenario.cpp` ~l.1112 `parse_distribution` (the
attribute names per kind, read from the source: `fixed` `value`;
`uniform` `min`/`max`; `normal` and `lognormal` `mean`/`stdev`;
`exponential` `mean`; `weibull` `lambda`/`k`; `pareto` `k`/`x_m`;
`gpareto` `shape`/`scale`/`location`; `gamma` `k`/`theta`; `negbin`
`n`/`p`; no poisson; plus the old-style `<pause>` spellings —
`min`/`max` alone, or a bare `normal`/`exponential`/… flag), the
`CSample` subclasses in `stat.cpp` (`CFixed`, `CUniform`, `CNormal`,
`CLogNormal`, `CExponential`, `CWeibull`, `CPareto`, `CGPareto`,
`CGamma`, `CNegBin`) and their `sample()` / `textDescr()`
(the TUI shows the description), `HAVE_GSL` — SIPp builds all but `fixed`/`uniform`
only with GSL, so a GSL-less sipp errors "…requires GSL" at parse; that
is the interop baseline, not a behavior to copy; `actions.cpp`
`E_AT_ASSIGN_FROM_SAMPLE` (the sample lands in a double variable).

- [x] Scenario: parse every kind from SIPp's attribute names with SIPp's
      validation messages (`sipr-scenario/src/distribution.rs`), the
      old-style spellings, the `sanity_check` 99th-percentile guard;
      `<sample>` compiles to `Action::Sample { assign_to, distribution }`;
      `--check` and the scenario screen show SIPp's `textDescr`. The
      positional shorthand stays as a documented sipr extension.
- [x] Engine: samplers in-tree over the existing seeded xorshift
      generator (`sipr-engine/src/sample.rs`, no new dependency):
      Box–Muller normal, lognormal = exp(normal), Weibull/Pareto/gpareto by
      inverse CDF, gamma by Marsaglia–Tsang (with the shape<1 boost),
      Poisson by exponential arrivals below a mean of 30 and the normal
      approximation above, negbin as the gamma–Poisson mixture. A sample
      below 1 is no pause (SIPp's clamp). One draw per pause step or
      `<sample>`; the action runner takes the engine's RNG.
- [x] Tests: statistical unit tests (mean/variance/median over 200k
      seeded draws per kind), parse/describe/percentile unit tests, compile
      tests for every kind, the old style, `<sample>`, and SIPp's error
      wording; corpus `statistical_pauses.xml` (+ a negative `poisson`);
      an e2e run of that scenario with its `--check` dump; interop
      `statistical_pauses_both_ways_against_real_sipp` (sipr UAC vs sipp
      UAS and the reverse; a GSL-less sipp's "only available with GSL"
      refusal skips the sipp-side half visibly). CI builds sipp with
      `-DUSE_GSL=1` so both halves run there.
- [x] Docs: SIPP_COMPAT §1 (pause attributes, `sample` action, the v1.x
      tier paragraph) and §6 note (incl. SIPp's negbin argument swap and
      the gpareto shape-0 division, both diverged from deliberately);
      README "Not yet" loses `<sample>`; PLAN.md §3.4 v1.x row; CHANGELOG.

### M39 — Keyword parity: `-key`, `[fill]`, `[last_message]`, `[clock_tick]` and friends ✅

Ten keywords from SIPp's table render nothing in sipr today and are
warned as unknown: `[clock_tick]`, `[date]`, `[dynamic_id]`,
`[last_cseq_number]`, `[last_message]`, `[remote_host]`,
`[sipp_version]`, `[tdmmap]`, `[timestamp]`, `[fill variable=…]`; and
the generic `-key keyword value` flag (`[keyword]` expands to `value`)
is an unknown option. `-key` is the most common one in real wrappers.

Behavioral oracle: `message.cpp` the keyword table (~l.60-120) and
`SendingMessage::SendingMessage` (bracketed-value parsing; the `-key`
values are themselves message templates — "Bracketed `-key` values"
in SIPP_COMPAT §6 M14 note); `call.cpp` `createSendingMessage` for each
`E_Message_*`: `Clock_Tick` (ms since start), `Timestamp` (SIPp's
`%Y-%m-%d %H:%M:%S.%f`-style — verify), `Date` (RFC 1123, for the
`Date:` header), `Sipp_Version`, `Dynamic_ID` (a per-run counter
starting at a random base — used for `[dynamic_id]` REGISTER contacts),
`Last_CSeq_Number`, `Last_Message` (the whole last received message),
`Remote_Host` (the `-rsa`/target host as given, not resolved), `Fill`
(`variable=` names a numeric variable, emits that many `X`s — verify
the fill character), `TDM_Map` (`-tdmmap` circuit map keyword);
`sipp.cpp` `-tdmmap` parsing (`{a-b}{c-d}{e-f}{g-h}` form).

- [x] CLI: `-key <keyword> <value>` (repeatable; the value is a literal,
      as SIPp's), `-tdmmap <map>` (SIPp's bad-form wording),
      `-dynamicStart`/`-dynamicMax`/`-dynamicStep` (found on the way:
      SIPp has them, the option-table sweep missed their help shape) and
      `-rfc3339` for `[timestamp]`. A `-key` name that is also a built-in
      keyword loses: SIPp checks its table first, so does sipr.
- [x] Renderer: eleven new `Keyword` variants (the ten plus `[file
      name=]`, SIPp's prefix-handled keyword the table sweep missed) and
      `Generic` for `-key`; a `RunInfo` on the render context carries the
      run-wide inputs (clock, `-key` pairs, the `[dynamic_id]` counter,
      the TDM table, the `[file]` cache). `[sipp_version]` renders the
      bare version number like SIPp's; `[timestamp]` is UTC (documented).
      `-tdmmap` circuits are handed to outgoing calls and released with
      them (`engine::alloc_tdm`/`release_tdm`); `[tdmmap]` without the
      flag is refused at start-up with SIPp's wording.
- [x] Tests: tokenizer, renderer, clock and TDM unit tests; compile
      test (dump names, `[fill]` counts as a variable read, `-key` names
      via `CompileOptions`); corpus `keywords_m39.xml`; CLI tests for the
      two-argument `-key` and `-tdmmap`'s wording; e2e runs asserting the
      rendered headers a responder receives (`-key`, `[remote_host]`,
      `[dynamic_id]`, `[fill]`, `[last_cseq_number+1]`, `[tdmmap]`);
      interop `m39_keywords_both_ways_against_real_sipp` (sipr and sipp
      each run the same `-key` scenario as UAC against the other's
      responder). Byte comparison modulo the clock values was dropped:
      `[timestamp]` is UTC here and local time there.
- [x] Docs: SIPP_COMPAT §2, §3 and a §6 note (incl. SIPp's TDM
      off-by-one, not copied); README "Not yet" loses `-key`; CHANGELOG.

### M40 — Statistics files at parity: `-trace_stat` columns, `-trace_rtt`, `-trace_counts`, `-trace_error_codes` ✅

`-trace_stat` writes "a pragmatic subset" of SIPp's columns (SIPP_COMPAT
§6 M4: "full column parity is a v1-polish item"); wrappers that parse
the CSV by column name break on the missing ones. `-trace_rtt`/
`-rtt_freq`, `-trace_counts`, `-trace_error_codes`, `-periodic_rtd`,
`-stat_delimiter`, `-f` and `-trace_screen`/`-screen_file` are unknown
options.

Behavioral oracle: `stat.cpp` `CStat::dumpData` (the exact header —
every counter with `(P)`/`(C)`, the repartition columns
`ResponseTimeRepartition1_<n>` / `CallLengthRepartition_<n>`, per-code
columns from `-trace_error_codes`? — verify — and the `;` delimiter
default), `dumpDataRtt` (`-trace_rtt`: `Date_ms;response_time_ms;rtd_no`
per call every `-rtt_freq` calls), `CStat::displayData` +
`dumpScreens` (`-trace_screen` writes the final screens as text, the
`-bg` idiom), `-trace_counts` (`<scenario>_<pid>_counts.csv`: one row per
`-f` interval with every message-command counter — the `counter=` and
per-step send/recv counts), `-trace_error_codes`
(`<scenario>_<pid>_error_codes.log`: unexpected response codes),
`-periodic_rtd` (reset repartition counters each interval), `-f` (screen
refresh period; sipr's TUI tick is fixed at 1 s — keep the flag for the
file dump period).

- [x] `-trace_stat`: every SIPp column in SIPp's order (`sipr-stats`
      `csv_header`/`csv_row`, the fixed set as a checked-in list), the
      per-RTD mean/stdev and repartition blocks sized from the scenario's
      `<ResponseTimeRepartition>`/`<CallLengthRepartition>`, SIPp's
      `hh:mm:ss` / `hh:mm:ss:uuuuuu` / three-decimal formats, `(P)` as a
      per-dump period; `-stat_delimiter`; `-periodic_rtd`; `-fd` default
      60 s as SIPp's. Counters sipr cannot source are 0 (listed in §6).
- [x] `-trace_rtt` + `-rtt_freq` (rows buffered in the stat set, flushed
      from the engine loop's tick), `-trace_counts` (per-step columns
      from a `StepKind` per step), `-trace_error_codes` (codes captured
      where an unexpected response fails a call), `-trace_screen` +
      `-screen_file` (main renders the TUI's three screens from the run
      report's final snapshot), `-f` (the snapshot/`-bg` line period).
      File names `<scenario>_<pid>_{,rtt,counts,error_codes}.csv` and
      `_screens.log` as SIPp's. Rows are built off the per-message path,
      in the `-fd` dump and the once-a-second tick.
- [x] Tests: stats unit tests (header column set and positions, period
      roll-over, periodic RTD, counts columns, error-code and RTT rows,
      SIPp's number formats); an e2e run with every file on asserting the
      headers, names, delimiter and row widths; interop
      `statistics_file_headers_match_real_sipps` — sipr and real sipp run
      the same embedded UAC and the `-trace_stat`, `-trace_rtt` and
      `-trace_counts` headers must be byte-for-byte equal (the M40
      acceptance criterion), rows the headers' width on both sides.
- [x] Docs: SIPP_COMPAT §3 (tracing flags), §6 M4 note closed and an M40
      note (formats, zero columns, the seconds-not-ms RTT quirk, the
      `-fd` default change); CHANGELOG.

### M41 — Message and error logs at parity: short messages, `<log>` files, calldebug, rotation ✅

`<log>` actions print to stderr with a `[log]` prefix; SIPp writes them
to `<scenario>_<pid>_logs.log` under `-trace_logs`. `-trace_shortmsg`
(one CSV line per message, the format most SIPp CI wrappers grep),
`-trace_calldebug`, `-trace_timeout`, `-error_file`, `-message_file`,
`-log_file`, `-shortmessage_file`, `-calldebug_file`, the `*_overwrite`
flags, `-ringbuffer_files`/`-ringbuffer_size`/`-max_log_size` rotation,
`-rfc3339` timestamps and `-deadcall_wait` (how long a finished call's
Call-ID stays known so late messages log against it) are unknown
options.

Behavioral oracle: `logger.cpp` (`print_message`/`print_short_message`
formats — the shortmessage CSV fields: date, call id, direction, message
type, method/code, ...; the `*_overwrite` semantics — default overwrite
true; `rotate_*` and the ringbuffer scheme `<name>_<n>.log`), `sipp.cpp`
the option table defaults, `call.cpp` `~call` / deadcall handling and
`-deadcall_wait` (keeps `Call-ID → final status` for the error log:
"Received message for a dead call"), `-trace_calldebug` (`call.cpp`
`dumpCall`: the message history of aborted calls).

- [x] `-trace_logs`/`-log_file` (`<log>` lines go there and nowhere
      else, as SIPp's `LOG_MSG`; `<warning>` stays in the error trace);
      `-trace_shortmsg`/`-shortmessage_file` with SIPp's tab layout and
      its receive-side time quirk; `-trace_calldebug`/`-calldebug_file`
      with SIPp's entries, dumped on abort only; `-trace_timeout`
      accepted as the no-op it is in SIPp; `-error_file`, `-message_file`;
      the message frame and error line rewritten to SIPp's exact shapes
      (`-rfc3339` aware). Found on the way: the frame used to carry the
      peer address and the error lines no timestamp.
- [x] Rotation: `-ringbuffer_files`/`-ringbuffer_size`/`-max_log_size`
      with SIPp's rotated names and the `-<kind>_overwrite` flags, in the
      stats crate's `TraceFile` (the writes stay on the engine thread as
      before — a buffered `write_all` per event, the same cost as the
      existing message trace; moving them to a thread is not needed at
      the rates measured so far).
- [x] `-deadcall_wait`: finished calls stay in a map (Call-ID → reason,
      expiry) consulted before the unknown-call handling: a late message
      counts as `DeadCallMsgs`, warns and traces as SIPp's `deadcall`
      does, and spawns nothing; expired entries are swept once a second.
- [x] Tests: stats unit tests for every line format and the ring-buffer
      rotation and size cap; e2e `log_files_have_sipps_shapes` (logs,
      timestamped errors under the header, short messages' seven
      columns, rotated message files, a dead-call message) and
      `calldebug_dumps_aborted_calls`; interop
      `short_message_log_matches_real_sipps` — the (S|R, start line)
      sets of sipr's and sipp's short-message logs for the same run are
      equal.
- [x] Docs: SIPP_COMPAT §3 (the flags) and a §6 note (naming, formats,
      the receive-side time quirk, rotation, dead calls, SIPp's
      `fixedname` bug not copied); the M17 note on `trace logs`; CHANGELOG.

### M42 — Timer and behavior knobs: retransmission counts, timeouts, `-lost`, `-default_behaviors` ✅

The retransmission policy is SIPp's default with only `-max_retrans`
and `-nr`; `-max_invite_retrans`, `-max_non_invite_retrans`,
`-timer_resol`, `-recv_timeout`, `-send_timeout`, `-timeout_error`,
`-lost` (default `lost=` for every send), `-pause_msg_ign`,
`-default_behaviors`, `-callid_slash_ign`, `-sleep`, `-nostdin` are
unknown options. Also two SIPP_COMPAT "post-v1" notes: UAS replies go to
the request's source address, not Via `received`/`rport` (§6 M4), and
the digest `uri=` shape (§6 M6, partly closed by `-auth_uri`).

Behavioral oracle: `call.cpp` `call::run` / `sendmsg` retransmission
schedule (`DEFAULT_T1_TIMER`, the INVITE vs non-INVITE caps, when
`-max_retrans` applies to both), `-recv_timeout` (`recv_timeout` on
every recv without its own `timeout=`), `-send_timeout`, `-lost` (the
per-send default `lost` percentage — scenario `lost=` overrides),
`-pause_msg_ign` (messages arriving during a `<pause>` are dropped
without "unexpected"), `-default_behaviors` (`all|none|bye|abortunexp|
pingreply|cseq` and the `-` prefixed removals; `-nd` = `none`;
`cseq` = check CSeq on responses), `-callid_slash_ign` (the `///`
3PCC Call-ID prefix rule), `-timeout_error` (exit non-zero when
`-timeout` fires), `-timer_resol` (the scheduler tick — sipr's pacer is
elapsed-time based, so this becomes the wake-up granularity, verify it
has any observable effect worth matching), `-sleep`, `-nostdin`;
`socket.cpp` `process_message` for where SIPp sends responses
(it does **not** honour `received`/`rport` either — verify before
implementing, and if SIPp replies to the source address as sipr does,
close the §6 note as no divergence).

- [x] CLI + engine: each flag with SIPp's default and unit parsing
      (`parse_time` shared; a `parse_time_ms` variant for SIPp's
      `TIME_MS` options whose bare number is milliseconds).
- [x] `-default_behaviors` as a `Behaviors` bitset (`-nd` = `none`)
      driving SIPp's `abortCall` messages from its own built-in templates,
      the unexpected BYE/CANCEL/PING answers, the continue-on-unexpected
      mode and the ACK CSeq guard; `-lost` as the send and recv default;
      `RetransCaps` split INVITE/non-INVITE with `-max_retrans` as the
      ceiling and the T2 cap only for non-INVITE. Found on the way: sipr
      parsed `-nd` but never used it, never sent abort messages, capped
      INVITE retransmissions at T2 and defaulted every message to 5.
- [x] Tests: schedule unit tests (both caps, the INVITE doubling, the
      ceiling), `Behaviors::parse`, Call-ID trimming, the default
      templates; e2e `default_behaviors_abort_or_continue_on_an_unexpected_message`
      (default abort + abort BYE, `-nd` continue, `all,-bye`,
      `-pause_msg_ign`) and `timeout_retrans_and_loss_knobs`
      (`-recv_timeout`, `-max_invite_retrans 1`, `-timeout_error`,
      `-lost 100`); interop `max_invite_retrans_counts_like_real_sipp`
      (both send the INVITE three times and give up within seconds).
- [x] Docs: SIPP_COMPAT §3 and a §6 note; the Via received/rport
      question closed (SIPp replies to the source address too); the `-nd`
      sentence; CHANGELOG.

### M43 — Extended 3PCC: `-master`/`-slave`/`-slave_cfg`, `sendCmd dest=`, `recvCmd src=` ✅

The last "Not yet" README item with a real user base (IMS and
conference testing). `sendCmd dest=` and `recvCmd src=` were compile
errors ("extended 3PCC is not supported yet — classic -3pcc only");
`-master`, `-slave`, `-slave_cfg` were unknown options; optional
`recvCmd` fall-through and twin reconnection were listed as unsupported
in SIPP_COMPAT §6 M10.

Behavioral oracle: `sipp.cpp` the twin-socket setup for extended mode
(`-slave_cfg` file format: `master` / `slave` sections of `name;host:port`
lines — verify), `socket.cpp` `open_connections` / `connect_to_peer` /
`process_twin_command` / `free_peer_socket` (the master listens, slaves
connect, peers are named; a command carries the destination peer name;
reconnection on a dropped twin), `call.cpp` `E_AT_SEND_CMD` with `dest`
(routing by name) and `recvCmd src` (accept only from that peer;
`optional`? — the fall-through rule), `docs/3pcc.rst` "Extended 3PCC".

- [x] Scenario: `dest=`/`src=` attributes compile to peer names; the
      classic form stays the default.
- [x] Net/engine: named peer connections from `-slave_cfg`, master
      accept loop, slave dial with reconnection, commands routed by
      name; `recvCmd src=` matched by origin; fall-through for optional
      `recvCmd`.
- [x] Tests: unit tests for the cfg parser and routing; e2e with three
      sipr processes (master + two slaves); interop: sipr master with
      sipp slaves and the reverse, on SIPp's documented extended 3PCC
      example scenarios.
- [x] Docs: SIPP_COMPAT §1 and §6 M10 note; README "Not yet" loses
      extended 3PCC.

Findings (from the C++; the full note is SIPP_COMPAT §6 M43): SIPp has
no twin reconnection at all — a closed control connection ends the run
with a warning, in classic mode too — so "slave dial with reconnection"
became "slave dials back on first contact, and a closed twin ends the
run at once, aborting the calls still open". `src=` is matched against the command's own `From:` line, not the
socket; commands are routed by their Call-ID like SIP messages, and the
3PCC server sides (controller B, slaves) open calls on the commands that
name them. Both of those replaced sipr's earlier "hand it to whichever
call is waiting" routing, so classic peers must now echo the Call-ID.
Extended mode never sends `3pcc_abort`; classic mode does on an
unexpected-message abort, and both sides now honor `internal-cmd:
abort_call`. `-trace_msg` still does not log twin commands.

### M44 — Leftovers that still reject loudly

Small, independent items; ship in any order, each its own commit:

- [x] `PRINTF=` virtual-line injection files (`infile.cpp`: a header
      line `PRINTF=<n>` and a `printf`-style template expanded to n
      lines — verify the exact substitution) — the last injection-file
      mode missing. Done: `PRINTF=`/`PRINTFOFFSET=`/`PRINTFMULTIPLE=`,
      `%[0-9.-]*d` and `%%`, virtual lines over cycling rows, indexing
      and `-users` over the virtual count, `insert`/`replace` refused;
      the two divergences are in SIPP_COMPAT §1.
- [ ] `<rtp_echo variable="…">` (toggle from a variable, `call.cpp`
      `E_AT_RTP_ECHO`).
- [ ] `-bind_local` (UAS listens on `-i` only, not all interfaces),
      `-buff_size`, `-sendbuffer_warn`; `-bind_to_device` on Linux
      (`SO_BINDTODEVICE`, needs root; reject clearly elsewhere).
- [ ] pcapng input for `play_pcap_*` (sipr addition: `tcpdump`/Wireshark
      write pcapng by default now; SIPp rejects it — keep the `-s0`
      advice for the classic format). Sanctioned-dependency check: an
      in-tree block reader, no crate.
- [ ] Decide and document the three "left as is" divergences in
      SIPP_COMPAT §6 M37 (`[next_url]` without `rrs`, `[last_*]` inside
      the matching recv's own actions, and the M35 action-step
      interleaving): either match SIPp behind a `--sipr-strict-sipp`
      flag or state them as permanent in §6 with the reason. No silent
      status quo.
- [ ] `-watchdog_*`, `-max_recv_loops`, `-max_sched_loops`,
      `-rtp_threadtasks`, `-skip_rlimit`, `-plugin` and the SCTP socket
      options (`-multihome` etc.): accept with one loud
      "no effect in sipr" warning each (they tune SIPp's scheduler and
      process, which sipr does not have) so wrapper scripts written for
      sipp keep running. This is the one sanctioned exception to "unknown
      flag is an error": each is named in the table with the reason.

### M45+ — sipr's own additions (after parity)

Candidates, to be promoted into numbered milestones once M38–M44 are
done and in the order the users of the HTTP API ask for them:

- Structured stats: `--sipr-stats-json <file>` (the 1 s snapshot as
  JSON lines) and a Prometheus `/metrics` on the existing HTTP API.
- A load-comparison bench: criterion + a documented `make bench-vs-sipp`
  that runs both tools at 500/2000/5000 cps on loopback and records
  CPU, memory, retransmissions and max concurrent calls in
  `docs/PERFORMANCE.md`; the hot-path rules were designed but never
  measured against SIPp.
- Library API: `sipr-engine` embedded in another Rust test harness
  (scenario in, stats out, no CLI, no TUI) — needs a stable
  `EngineConfig` and a documented public surface.
- Scenario linting beyond `--check`: unreachable labels, `optional`
  recv ordering traps, `[len]` without a body — the folklore in
  SIPP_COMPAT §6 turned into diagnostics.

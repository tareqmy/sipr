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

## M3 — UAC end to end  ← first interop milestone (one gate pending)

- [ ] Embedded uac scenario completes against real `sipp -sn uas`; 0 failed.
      STATUS: the harness exists (`tests/interop.rs`, resolves `$SIPP_BIN` /
      PATH, visible skip otherwise) but no sipp binary exists in the build
      sandbox — run `SIPP_BIN=~/development/cprojects/sipp/sipp cargo test
      --test interop` on the dev machine to close this box. The equivalent
      flow IS verified end-to-end in-container against a scripted UAS
      (`tests/e2e.rs`): INVITE–180–200–ACK–pause–BYE–200, 20 000 calls at
      2000 cps, 0 failed, plus lost-first-INVITE retransmission recovery.
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

## M4 — UAS mode + stats ✅ (one interop gate pending, same as M3)

- [x] UAS call creation from initial requests (unknown Call-ID matching the
      initial window creates a call bound to the packet's source address);
      embedded uas scenario runs; sipr↔sipr self-test green (E2E test +
      50 000 calls at 5000 cps in BASELINES.md); retransmitted inbound
      requests are answered by re-sending the last response; timewait
      absorbs late traffic without failing (deadcall behavior)
- [ ] sipp-uac ↔ sipr-uas: harness ready (`tests/interop.rs`), needs a sipp
      binary — same local run as the M3 gate closes both
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

## M6 — Actions, variables, auth  ← v1 ships when green

- [ ] Variable store + full v1 action set (ereg capture groups, math, strcmp,
      test/condexec branching, chance, insert/replace/trim, log/warning/error,
      exec int_cmd)
- [ ] `[authentication]` digest MD5 + SHA-256, qop=auth, stale-nonce retry;
      verified against a challenging registrar scenario (sipp counterpart uses
      401 + `[authentication]` check or verifyauth when we add it)
- [ ] rtd/start_rtd/repeat_rtd + counters wired into stats screens/CSV
- [ ] Docs pass: README quickstart, `--help` polish, SIPP_COMPAT §6 updated
      with everything learned

## Post-v1 backlog (ordered)

`-inf` injection + `lookup` → TCP → TLS → 3PCC (`sendCmd`/`recvCmd`) → `-users`
closed loop → pcap/RTP media (study gossipper first) → AKA auth → IPv6 → HTTP
control API.

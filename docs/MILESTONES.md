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

## M3 — UAC end to end  ← first interop milestone

- [ ] Embedded uac scenario completes INVITE–(100/180)–200–ACK–pause–BYE–200
      against real `sipp -sn uas`; 0 failed at `-r 10 -m 1000`
- [ ] Pacer: `-r`, `-rp`, `-l` (non-queuing cap), `-m`; runtime rate change API
      (consumed by TUI later)
- [ ] optional-recv window semantics verified against C++ (record in
      SIPP_COMPAT §6)
- [ ] Soft/hard shutdown; SIPp-compatible exit codes (verify table, update
      SIPP_COMPAT §5)
- [ ] Interop harness in CI (TESTING §4); loopback cps baseline recorded

## M4 — UAS mode + stats

- [ ] UAS call creation from initial requests; embedded uas scenario; sipr↔sipr
      self-test green; sipp-uac ↔ sipr-uas green
- [ ] `[last_*]`, `rrs`+`[routes]`, `[peer_tag_param]` correct as callee
- [ ] `-aa` auto-answers in-dialog OPTIONS/INFO/UPDATE/NOTIFY
- [ ] Stats: SIPp counter set, RTDs (hdrhistogram), both repartitions,
      `-trace_stat`/`-stf`/`-fd` CSV output, `-trace_msg`/`-trace_err` files
- [ ] Periodic stat line output in `-bg` headless mode

## M5 — TUI

- [ ] ratatui main screen (rates, counts, response codes, retrans) ≈ SIPp layout
- [ ] Scenario screen: per-step sent/recv/retrans/timeout/unexpected table
- [ ] Repartition screen
- [ ] Keys: `+ - * / p q Q s` per SIPP_COMPAT §4; TUI reads snapshots only
- [ ] Terminal restored correctly on panic/exit (no wrecked shells)

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

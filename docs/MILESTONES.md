# Milestones and acceptance criteria

Live tracking document. Check items in the same commit that completes them.
Rationale and detail: `PLAN.md` §4. Do not start milestone N+1 while N has
unchecked *required* items (unchecked stretch items are fine, move them down).

## M0 — Scaffolding

- [ ] Workspace + six crates compile empty; `#![forbid(unsafe_code)]` everywhere
- [ ] clap CLI accepts the v1 flag set (SIPP_COMPAT §3) with help text; unknown
      flags error out with suggestion
- [ ] `-sn uac|uas` selects embedded default scenarios (ported from SIPp `-sd`
      output; stored as assets); `-sd` prints them
- [ ] CI: fmt + clippy(-D warnings) + test on push
- [ ] `rust-toolchain.toml`, MSRV recorded in CONVENTIONS.md

## M1 — Scenario front end

- [ ] quick-xml parser → IR for full v1 tier of SIPP_COMPAT §1 (elements,
      attrs, actions), with file:line errors
- [ ] Keyword tokenizer: full v1 keyword list; unknown keyword = loud warning,
      verbatim passthrough
- [ ] Label/next/jump references validated at compile; variables resolved to
      indices; `Reference` suppresses unused warnings
- [ ] `--check` mode: lint + print compiled IR; non-zero exit on error
- [ ] Golden corpus passing (see TESTING §2), incl. negative goldens for
      unsupported media scenarios

## M2 — Net + message layer

- [ ] UDP transport: bind `-i`/`-p`, send/recv loops, rsip inbound parse,
      Call-ID router, call table
- [ ] Timer service: arm/cancel, pause timers, retransmission schedule
      (T1→T2 doubling, `retrans` override, max-retrans cap), recv timeouts
- [ ] `lost` simulation on send/recv paths
- [ ] proptest: no panic on arbitrary inbound datagrams

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

---
name: interop-testing
description: Use when running or writing interop tests between sipr and the real SIPp binary, when validating milestone acceptance criteria (M3+), or when debugging behavioral differences between sipr and SIPp. Covers building SIPp, the harness layout, debugging with traces, and how to turn a divergence into a fix + regression test.
---

# Interop testing: sipr vs real SIPp

Real SIPp is the behavioral oracle. Every engine/net/scenario change from M3 on
must keep the interop suite green: `cargo test -p sipr --test interop`.

## Getting a sipp binary

Preferred: build the sibling checkout —
```
cd ../../cprojects/sipp && ./build.sh    # or: cmake . && make
export SIPP_BIN=$PWD/sipp
```
Fallback: `brew install sipp` / `apt install sip-tester`, then ensure `sipp -v`
works. The harness resolves `$SIPP_BIN`, then PATH, then marks tests ignored
with a visible reason — a silently green suite that ran nothing is a bug.

## Harness pattern (tests/interop/)

Each test: pick two free 127.0.0.1 ports → spawn UAS side → wait until it's
listening (poll the port, don't sleep blindly) → spawn UAC side with `-m N
-timeout 30s` → wait both → assert both exit codes are 0 and parse final stats
(CSV via `-trace_stat`/`-stf` or the `-bg` summary) for: N calls created, N
succeeded, 0 failed, 0 unexpected messages. Run matrix per scenario pair:

1. sipr-UAC ↔ sipp-UAS   (our caller against oracle)
2. sipp-UAC ↔ sipr-UAS   (oracle calls us)
3. sipr-UAC ↔ sipr-UAS   (self-consistency)

Keep tests parallel-safe: unique ports per test, tempdir per test for trace
files, kill child processes on panic (use a guard/drop killer — orphaned sipp
processes poison later runs).

## Debugging a divergence

1. Re-run both sides with `-trace_msg -trace_err` (works on sipp and sipr) into
   the test tempdir; diff the message flows side by side.
2. Classify: message content bug (template/keyword fill — compare byte-exact),
   sequencing bug (optional-window/retransmission/timing), or stats bug
   (both flows fine, counters differ).
3. For sequencing questions, the answer is in SIPp's C++:
   `../../cprojects/sipp/src/call.cpp` (recv matching ~`Call::process_incoming`,
   retrans handling), `scenario.cpp` (compile-time semantics). Read it, decide,
   then **record the finding in `docs/SIPP_COMPAT.md` §6** with a pointer.
4. Fix, then encode the divergence as a permanent regression: a corpus scenario
   + interop pair or a unit test on the state machine — whichever pins the
   behavior tighter.
5. If SIPp's behavior is itself buggy/inconsistent, we still match it when
   scenarios in the wild depend on it; note the wart in SIPP_COMPAT §6 and move
   on. Compatibility beats elegance.

## Milestone gates that live here

M3: basic uac flow at `-r 10 -m 1000`, 0 failed, both directions. M4: uas mode
+ stats cross-check (sipr's counters vs sipp's for the same run must agree on
created/succeeded/failed). M6: auth scenario against a challenging counterpart.
Loopback cps baseline (sipr↔sipr) is recorded per TESTING.md §5 — update
`benches/BASELINES.md` when the number moves materially.

# Testing

Five layers. A change is done when the layers it touches pass.

## 1. Unit tests (`cargo test --workspace`)

Colocated `#[cfg(test)]` modules. Required coverage by crate:
- `sipr-scenario`: parser (every element/attr in SIPP_COMPAT v1 tier), keyword
  tokenizer (goldens: template in → span list out), action semantics, compile
  errors (bad label refs, unknown attrs → correct file:line in error).
- `sipr-net`: retransmission schedule math (T1 doubling, T2 cap, overrides),
  timer service ordering, router matching (Call-ID extraction incl. torture
  inputs).
- `sipr-engine`: state machine transitions per step type, optional-recv window
  matching, jump/branch logic (`next`/`test`/`chance` distributions), dialog
  bookkeeping (tags, CSeq, route set from `rrs`).
- `sipr-auth`: RFC 7616 test vectors (MD5, SHA-256, qop=auth), stale-nonce path.
- `sipr-stats`: counter aggregation, repartition bucketing, CSV column goldens.

## 2. Golden corpus tests

`crates/sipr-scenario/tests/corpus/` contains scenario XML files that must
compile without warnings, plus `*.expected` IR dumps for a subset.
Seed corpus: the embedded uac/uas defaults, signaling-only files from
`../../cprojects/sipp/sipp_scenarios/` (registration ones: `mcd_register.xml`,
`uc360_register*.xml`), and examples from SIPp docs. Media/SRTP scenarios from
that directory are *negative* goldens for now: they must fail loudly with the
correct "unsupported: rtp_stream" style message, not crash or silently skip.

## 3. Property tests (proptest)

Keyword tokenizer never panics on arbitrary bytes; tokenize→render round-trips
templates without keywords byte-identically; inbound parser (rsip wrapper)
never panics on arbitrary datagrams (fuzz-shaped corpus incl. truncated
messages, huge headers, non-UTF8).

## 4. Interop suite (M3+): `cargo test -p sipr --test interop`

Runs sipr against a **real sipp binary**, both directions:

- sipr `-sn uac` ↔ sipp `-sn uas`, and sipp `-sn uac` ↔ sipr `-sn uas`
- then every corpus scenario with a paired counterpart scenario
- assertions: both processes exit 0, call counts match (`-m N` completed = N,
  0 failed), no unexpected-message counters incremented.

Locating sipp: `$SIPP_BIN` env var, else `sipp` on PATH, else skip with a
**visible** `ignored — set SIPP_BIN` marker (never silently green). Build it
from `../../cprojects/sipp` (`cmake . && make`, or `./build.sh`) or
`apt/brew install sipp`. Tests bind ephemeral ports on 127.0.0.1 and must run
in parallel safely; each test gets its own port pair.

## 5. Performance (M3+)

`criterion` benches: template fill, inbound parse+route, timer churn — plus a
loopback end-to-end cps test (sipr↔sipr, `-r` ramp until failure) reported in
CI logs. Regression rule: >10% drop on hot-path benches blocks merge. Baselines
kept in `benches/BASELINES.md` per machine class. Target trajectory: match
single-core SIPp cps by M3 review; exceed it multi-core by v1.

## CI order

fmt → clippy → unit+golden+property → build sipp (cached) → interop → benches
(benches on-demand/nightly, not per-PR).

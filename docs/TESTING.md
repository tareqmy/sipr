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
- `sipr-control`: SIPp command grammar (with its warning texts), JSON round
  trips, HTTP request parsing, UDP datagram → request, every API route
  against a fake engine.

## 2. Golden corpus tests

`crates/sipr-scenario/tests/corpus/` contains scenario XML files that must
compile without warnings — `--check` lints included (docs/LINTS.md) — plus
`*.expected` IR dumps for a subset.
Seed corpus: the embedded uac/uas defaults, signaling-only files from
`../../cprojects/sipp/sipp_scenarios/` (registration ones: `mcd_register.xml`,
`uc360_register*.xml`), and examples from SIPp docs. `play_pcap_*` scenarios
are positive goldens since M14; `rtp_stream`/SRTP scenarios from that
directory are *negative* goldens for now: they must fail loudly with the
correct "not supported yet" message, not crash or silently skip. Media e2e
tests fabricate their pcap fixtures with `sipr_media::pcap::build` — no
binary captures are checked in.

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
from `../../cprojects/sipp` (`cmake . -DUSE_GSL=1 && make`, or
`./build.sh`; GSL — `libgsl-dev` / `brew install gsl` — is what lets sipp
run statistical pauses, so the M38 interop test's sipp-side half skips
visibly without it) or `apt/brew install sipp`.
Building it on macOS needs a little more than `./build.sh --common` says
(M44): `git submodule update --init` first (pugixml is required and gtest
must exist for the `sipp_unittest` target CMake references), `pkg-config`
must be installed or CMake cannot see Homebrew's OpenSSL, and GSL's headers
are not on clang's default search path — sipp adds the GSL *library* but
never its include directory, so pass
`-DCMAKE_C_FLAGS=-I/opt/homebrew/include -DCMAKE_CXX_FLAGS=-I/opt/homebrew/include`.
Configuring in-tree also writes `include/version.cmake`; `cmake -B <dir> -S
<src>` keeps the build out of the checkout. Tests bind ephemeral ports on 127.0.0.1 and must run
in parallel safely; each test gets its own port pair.

Lessons from driving real sipp in tests (M26): a scenario file handed to
sipp must start with the `<?xml version="1.0" encoding="ISO-8859-1" ?>`
declaration or its loader reports "Unable to load or parse"; never assert
on the exit code of a sipp started with `-bg` (the forked parent exits 99 at
once) — run it in the foreground with stdin/stdout/stderr null and reap it;
sipp as a UAS ignores SIGTERM once curses is up — kill it with SIGKILL.
A sipp whose stdin is `/dev/null` busy-polls it, a full core each and
mostly kernel time, so pass `-nostdin` (sipr takes it too) where a test
runs several at once.

On macOS a child can inherit a socket another test thread has only just
created: there is no `SOCK_CLOEXEC`, so std sets `FD_CLOEXEC` a moment
after `socket()`. A `free_port()` probe socket inherited that way keeps
the probed port bound for as long as the child lives, and the sipp or sipr
the port is handed to exits with "Address already in use". `tests/interop.rs`
therefore starts every child through `spawn_outside_probes()` /
`output_outside_probes()`, which never overlap a probe; use them for any
new one.

SCTP cannot be tested on this development host: macOS has no SCTP stack and
the Homebrew sipp is built without `USE_SCTP` (its banner lacks `-SCTP`).
SCTP therefore lives behind the `sctp` cargo feature, its tests skip when
the host has no stack, and the CI job `sctp` (ubuntu: `modprobe sctp`, a
sipp built with `-DUSE_SCTP=1`) is where it is actually exercised:
`cargo test --workspace --features sctp` and
`SIPP_BIN=... cargo test --features sctp --test interop sctp`.

## 5. Performance (M3+)

`criterion` benches: template fill, inbound parse+route, timer churn — plus a
loopback end-to-end cps test (sipr↔sipr, `-r` ramp until failure) reported in
CI logs. Regression rule: >10% drop on hot-path benches blocks merge. Baselines
kept in `benches/BASELINES.md` per machine class. Target trajectory: match
single-core SIPp cps by M3 review; exceed it multi-core by v1.

`make bench-vs-sipp` (M45) is the other half: `scripts/bench-vs-sipp.sh` runs
sipr and real sipp against themselves at 500/2000/5000 cps and reports CPU,
peak RSS, retransmissions and concurrency for each, read from `/usr/bin/time`
and from each tool's own `-trace_stat` CSV. Results and their caveats live in
`docs/PERFORMANCE.md`; rerun it when the engine's hot path changes.

## CI order

fmt → clippy → unit+golden+property → build sipp (cached) → interop → benches
(benches on-demand/nightly, not per-PR).

Both benches run from `.github/workflows/bench.yml` on a nightly cron and on
`workflow_dispatch` (which takes the rates and the window as inputs). Neither
job fails the build: a shared runner's numbers move enough between runs that
gating on them would cost more in false alarms than it caught, so the results
go to the job summary and an artifact, and a >10% move is for a human to
judge against `benches/BASELINES.md`.

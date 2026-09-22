# Performance

sipr's hot-path rules (`docs/ARCHITECTURE.md` §3 — no allocations beyond
template slot filling, no synchronous I/O, no per-send string scanning) were
designed from the start but never measured against the tool they exist to
match. This page is that measurement.

Reproduce it with:

```
make bench-vs-sipp            # SIPP_BIN=... if sipp is not in the sibling checkout
```

## Method

`scripts/bench-vs-sipp.sh` runs both tools against themselves — sipr-UAC to
sipr-UAS, sipp-UAC to sipp-UAS — on loopback, at each rate, for a fixed
**window** of seconds rather than a fixed call count, so every rate spends the
same time under load. Both sides use each tool's *embedded* `uac`/`uas`
scenarios, which are the same call flow (INVITE / 200 / ACK / pause / BYE /
200), with `-d 10` for a 10 ms pause.

Everything measured comes from the same two sources for both tools:

- **CPU and peak RSS** from `/usr/bin/time` around each process (BSD `-l` on
  macOS, GNU `-v` on Linux). Neither tool gets a background flag: sipp's `-bg`
  forks and the parent exits immediately, leaving nothing to measure, and sipr
  skips its TUI on its own when stdout is not a terminal — so both run in the
  foreground with output redirected, and both pay for the same once-a-second
  screen refresh.
- **Calls, retransmissions and concurrency** from each tool's own
  `-trace_stat` CSV, parsed by column *name*. sipr writes SIPp's columns
  byte-for-byte (M40), so one parser reads both files.

## Results

Host: MacBook (Darwin 27.0.0, arm64), sipr 0.27.1 release build, sipp
v3.7.7-40-g5dff0ec. 10 s per rate, both processes on the same machine.

| Tool | Rate (cps) | Created | OK | Failed | Retrans | CPU UAC | CPU UAS | RSS UAC (MiB) | RSS UAS (MiB) | Peak concurrent |
|---|---|---|---|---|---|---|---|---|---|---|
| sipr | 500 | 5000 | 5000 | 0 | 0 | 1.05 s | 1.08 s | 5.6 | 17.7 | 17 |
| sipp | 500 | 5000 | 5000 | 0 | 0 | 9.94 s | 13.91 s | 8.2 | 48.0 | 6 |
| sipr | 2000 | 20000 | 20000 | 0 | 0 | 3.01 s | 2.91 s | 10.2 | 59.1 | 72 |
| sipp | 2000 | 20000 | 20000 | 0 | 0 | 9.95 s | 13.95 s | 12.7 | 171.5 | 28 |
| sipr | 5000 | 50000 | 50000 | 0 | 0 | 6.67 s | 6.88 s | 16.8 | 196.5 | 125 |
| sipp | 5000 | 50000 | 50000 | 0 | 24 | 9.97 s | 13.96 s | 23.1 | 419.2 | 70 |

Both tools placed and completed every call at every rate, with no failures.
CPU and RSS reproduced within a few percent across runs.

### What the numbers say

**sipp's CPU is flat; sipr's scales with load.** sipp burns ~9.9 s of CPU on
the UAC and ~13.9 s on the UAS whatever the rate — 500 cps costs it the same
as 5000. That is its event loop polling, not work done per call. sipr spends
1.0 s at 500 cps and 6.7 s at 5000, roughly in proportion to the traffic.

Normalising to CPU per call makes the comparison fair to sipp, since its
constant cost is amortised as the rate climbs:

| Rate | sipr | sipp |
|---|---|---|
| 500 cps | 0.21 ms/call | 1.99 ms/call |
| 2000 cps | 0.15 ms/call | 0.50 ms/call |
| 5000 cps | 0.13 ms/call | 0.20 ms/call |

sipr's per-call cost *falls* as the rate rises (fixed start-up amortised, and
batching helps), converging toward ~0.13 ms. sipp converges toward ~0.20 ms.
At the rates that matter, sipr does the same work for roughly two-thirds of
the CPU; at low rates it is idle where sipp is not, which is the difference
between a generator you can leave running and one you cannot.

**Memory.** sipr's peak RSS is consistently lower — about 70% of sipp's on
the UAC side and under half on the UAS side (196 MiB vs 419 MiB at 5000 cps).
Both grow with concurrency, as expected when every live call holds state.

**Retransmissions.** sipr sent none at any rate. sipp retransmitted ~24-30
times at 5000 cps, i.e. it dropped or delayed enough inbound messages under
its own load to trip the UDP timers.

## Caveats, and what these numbers are not

- **One machine, both processes.** UAC and UAS contend for the same cores, so
  absolute cps is not a ceiling — it is what this laptop sustains with both
  ends of the call on it. Neither tool was pushed to failure; 5000 cps was
  clean for both, and the ceiling was not probed.
- **A macOS laptop**, with shared cores and thermal throttling. The numbers
  are meaningful *relative to each other* — same host, same run, same flow —
  and not portable as absolute figures. `benches/BASELINES.md` records
  sipr-only loopback runs from a Linux host for that purpose.
- **Peak concurrency is sampled once a second**, so it is coarse and the
  noisiest column here; treat it as an order of magnitude. It is read from
  the UAC side on purpose: on the *UAS* side both tools keep finished calls
  counted for a while (dead-call retention), so that figure measures
  retention rather than live dialogs. Verified identical in both tools.
- **sipp was built without SCTP** (`USE_GSL=1 USE_PCAP=1 USE_SCTP=0`); that
  does not affect a UDP run.

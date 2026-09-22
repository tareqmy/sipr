# Performance

sipr's hot-path rules (`docs/ARCHITECTURE.md` §3 — no allocations beyond
template slot filling, no synchronous I/O, no per-send string scanning) were
designed from the start but never measured against the tool they exist to
match. This page is that measurement.

Reproduce it with:

```
make bench-vs-sipp            # SIPP_BIN=... if sipp is not in the sibling checkout
```

On Debian and Ubuntu that needs the `time` package: the script reads CPU and
peak RSS from `/usr/bin/time`, not the shell's `time` keyword.

The same comparison runs nightly on Linux from `.github/workflows/bench.yml`,
which is where to look for numbers off this laptop — see the caveats below.

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

Two hosts. The Linux figures come from `.github/workflows/bench.yml` and are
the ones worth quoting; the macOS ones are the development host, kept because
they show how much the platform matters.

**Linux** (GitHub Actions, `Linux 6.17 x86_64`, 4 cores), sipr 0.27.1 release,
sipp v3.7.7, 10 s per rate:

| Tool | Rate (cps) | Created | OK | Failed | Retrans | CPU UAC | CPU UAS | RSS UAC (MiB) | RSS UAS (MiB) | Peak concurrent |
|---|---|---|---|---|---|---|---|---|---|---|
| sipr | 500 | 5000 | 5000 | 0 | 0 | 0.49 s | 0.51 s | 6.2 | 14.2 | 10 |
| sipp | 500 | 5000 | 5000 | 0 | 0 | 10.01 s | 0.42 s | 15.0 | 54.1 | 6 |
| sipr | 2000 | 20000 | 20000 | 0 | 0 | 1.59 s | 1.70 s | 9.4 | 43.9 | 41 |
| sipp | 2000 | 20000 | 20000 | 0 | 0 | 10.02 s | 1.38 s | 21.6 | 176.1 | 24 |
| sipr | 5000 | 50000 | 50000 | 0 | 0 | 3.93 s | 4.22 s | 13.6 | 83.4 | 101 |
| sipp | 5000 | 50000 | 50000 | 0 | 50 | 10.07 s | 3.27 s | 32.6 | 421.3 | 70 |

**macOS** (MacBook, Darwin 27.0.0, arm64), same versions and window:

| Tool | Rate (cps) | Created | OK | Failed | Retrans | CPU UAC | CPU UAS | RSS UAC (MiB) | RSS UAS (MiB) | Peak concurrent |
|---|---|---|---|---|---|---|---|---|---|---|
| sipr | 500 | 5000 | 5000 | 0 | 0 | 1.05 s | 1.08 s | 5.6 | 17.7 | 17 |
| sipp | 500 | 5000 | 5000 | 0 | 0 | 9.94 s | 13.91 s | 8.2 | 48.0 | 6 |
| sipr | 2000 | 20000 | 20000 | 0 | 0 | 3.01 s | 2.91 s | 10.2 | 59.1 | 72 |
| sipp | 2000 | 20000 | 20000 | 0 | 0 | 9.95 s | 13.95 s | 12.7 | 171.5 | 28 |
| sipr | 5000 | 50000 | 50000 | 0 | 0 | 6.67 s | 6.88 s | 16.8 | 196.5 | 125 |
| sipp | 5000 | 50000 | 50000 | 0 | 24 | 9.97 s | 13.96 s | 23.1 | 419.2 | 70 |

Both tools placed and completed every call at every rate on both hosts, with
no failures. CPU and RSS reproduce within a few percent across runs on the
same host.

### What the numbers say

The two sides of a run behave differently, and the honest summary needs them
apart. Per call:

| Rate | UAC: sipr | UAC: sipp | UAS: sipr | UAS: sipp |
|---|---|---|---|---|
| 500 cps | 0.098 ms | 2.00 ms | 0.102 ms | 0.084 ms |
| 2000 cps | 0.080 ms | 0.501 ms | 0.085 ms | 0.069 ms |
| 5000 cps | 0.079 ms | 0.201 ms | 0.084 ms | 0.065 ms |

**Generating load: sipr costs a fraction of sipp.** sipp's UAC burns ~10 s of
CPU whatever the rate — 500 cps costs it exactly what 5000 does, which is a
pacing loop spinning, not work done per call. sipr's scales with traffic, so
it is 2.6x cheaper per call at 5000 cps and 20x cheaper at 500. At low rates
sipr is genuinely idle where sipp is not, which is the difference between a
generator you can leave running next to the thing you are testing and one you
cannot.

**Answering load: sipp is slightly cheaper.** On Linux sipp's UAS spends about
20% less CPU per call than sipr's (0.065 ms against 0.084 ms at 5000 cps).
sipr is not faster at everything, and this is the half where SIPp's C receive
path with `epoll` still has the edge. sipr also carries more calls
concurrently at the same rate (101 against 70 at 5000 cps), i.e. its calls
live a little longer, which is consistent with spending a little more per
call on the answering side.

**Beware the macOS UAS column.** There sipp's UAS looks catastrophic — a flat
~13.9 s — and that is an artifact, not a property of sipp. A macOS build of
sipp reports `Looking for sys/epoll.h - not found` and falls back to
`poll`/`select`; on Linux the same code is efficient. Anyone comparing
receive-side cost should use the Linux table.

**Memory is sipr's clearest win, and it grows with the load.** Peak RSS is
lower everywhere, and on the UAS at 5000 cps it is 83 MiB against 421 MiB —
a fifth. Both tools grow with concurrency, as they must when every live call
holds state, but sipp grows far faster.

**Retransmissions.** sipr sent none at any rate on either host. sipp
retransmitted 50 times at 5000 cps on Linux (24 on macOS): under its own load
it dropped or delayed enough inbound messages to trip the UDP timers.

## Where the per-call time actually goes

`cargo bench --bench hot_path` measures the three primitives §3 makes rules
about, in isolation (numbers in `benches/BASELINES.md`): on the Linux runner,
filling the INVITE template costs 531 ns, parsing a 200 OK and reading the
four fields needed to route it 842 ns, arming and cancelling a retransmission
timer 54 ns.

A call in this scenario carries about six messages, so those primitives
account for roughly **8 µs of the ~79 µs of CPU a call costs on the UAC at
5000 cps** — a tenth. The rest is syscalls, call-table bookkeeping and stats.

Two CI runs of the same commit put `parse_and_route` at 842 ns and 973 ns, a
15% spread on identical code. That is why the >10% regression rule is a
prompt to investigate by hand and not a gate: on a shared runner the noise
reaches the threshold on its own.

That is worth knowing before anyone optimises: the hot path the rules protect
is already cheap, and the remaining cost is in the machinery around it. The
one primitive with obvious headroom is message routing, where the accessors
(`call_id`, `cseq`, `top_via_branch`) re-scan headers the parse already
walked, costing about as much again as the parse itself.

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

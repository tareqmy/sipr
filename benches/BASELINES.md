# Performance baselines

Loopback cps runs of the embedded uac scenario (`-d 10`, release build)
against a scripted Python UAS (8 MB rcvbuf). Wall time ≈ m/r + drain.
Update this file when the number moves materially (docs/TESTING.md §5).

These are sipr-only throughput runs. For the side-by-side comparison against
real sipp — CPU, memory, retransmissions and concurrency at 500/2000/5000 cps
— see `docs/PERFORMANCE.md` (`make bench-vs-sipp`).

| Date | Machine | Command | Result |
|---|---|---|---|
| 2026-08-16 | cloud sandbox (Linux, shared vCPUs) | `-r 500 -m 5000` | 5000/5000 ok, 0 retrans, 10.1s |
| 2026-08-16 | cloud sandbox (Linux, shared vCPUs) | `-r 2000 -m 20000` | 20000/20000 ok, 0 retrans, 10.1s (~2000 cps sustained, 60k msgs) |

Notes: at M3 the far end (single-threaded Python) is the likely bottleneck
above ~2000 cps, not sipr; a sipr-UAS peer (M4) will let us probe higher.

## M4: sipr ↔ sipr self-test (both ends real)

| Date | Machine | Command | Result |
|---|---|---|---|
| 2026-08-16 | cloud sandbox (Linux, shared vCPUs) | uac `-r 2000 -m 20000 -d 10` vs uas | both sides 20000/20000 ok, 0 retrans, 10.1s |
| 2026-08-16 | cloud sandbox (Linux, shared vCPUs) | uac `-r 5000 -m 50000 -d 10` vs uas | both sides 50000/50000 ok, ~0.45% retrans covering kernel drops, 10.3s (~5000 cps sustained, 150k msgs) |

## Hot-path micro-benches (`cargo bench --bench hot_path`)

The three things `docs/ARCHITECTURE.md` §3 makes rules about, measured in
isolation. Regression rule (docs/TESTING.md §5): a >10% drop blocks merge.

| Date | Machine | Bench | Result |
|---|---|---|---|
| 2026-09-22 | MacBook (Darwin 27, arm64) | `template_fill/invite` | 739 ns |
| 2026-09-22 | MacBook (Darwin 27, arm64) | `template_fill/ack_with_last_headers` | 356 ns |
| 2026-09-22 | MacBook (Darwin 27, arm64) | `inbound_parse/response_200` | 589 ns |
| 2026-09-22 | MacBook (Darwin 27, arm64) | `inbound_parse/parse_and_route` | 1.14 µs |
| 2026-09-22 | MacBook (Darwin 27, arm64) | `timer_churn/arm_then_cancel` | 53 ns |
| 2026-09-22 | MacBook (Darwin 27, arm64) | `timer_churn/arm_1000_then_drain` | 50 µs (50 ns/timer) |

Notes: `parse_and_route` is the parse plus the four fields the engine reads to
route a message to its call, and costs roughly twice the parse alone — the
accessors re-scan headers. That is the one number here with obvious headroom,
though see `docs/PERFORMANCE.md` for why it is not where the per-call time
actually goes.

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

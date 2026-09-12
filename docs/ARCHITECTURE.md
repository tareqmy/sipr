# Architecture

Authoritative reference for how sipr is structured. `PLAN.md` §3 is the summary;
this file is the working detail. Update it when structure changes.

## 1. Workspace layout

```
sipr/
├── Cargo.toml            # workspace root
├── crates/
│   ├── sipr-scenario/    # XML → Scenario IR; keyword tokenizer; actions; (later) infile
│   ├── sipr-net/         # UDP transport, socket mgmt, timer service, retransmit schedule
│   ├── sipr-engine/      # call state machine, call table, pacer, dialog bookkeeping
│   ├── sipr-auth/        # digest auth (RFC 2617/7616) for [authentication]
│   ├── sipr-stats/       # counters, RTD histograms, repartitions, CSV export
│   ├── sipr-media/       # pcap reader, SDP endpoint scan, RTP replay scheduler (M14)
│   ├── sipr-control/     # SIPp's UDP control socket + the HTTP/JSON API (M17)
│   └── sipr-tui/         # terminal screens, key handling
└── src/main.rs           # bin: SIPp-style CLI → assemble and run
```

Dependency direction (must stay acyclic):
`sipr-tui` → `sipr-stats` → (nothing internal);
`sipr-engine` → `sipr-scenario`, `sipr-net`, `sipr-auth`, `sipr-stats`, `sipr-media`,
`sipr-control`; `sipr-control` → `sipr-stats`;
`sipr-media` → `sipr-auth` (AES/HMAC/KDF for SRTP);
`sipr-scenario`, `sipr-net`, `sipr-auth` depend on no internal crate.
The control front ends (UDP socket, HTTP server) are threads that only send
`ControlRequest`s into the engine's channel and read the shared once-a-second
snapshot — the same rule as the TUI: nothing outside the loop touches a call.
The media thread (`sipr-media::replay`) follows the same rule as every other
thread: it owns its sockets, receives owned stream specs over a channel, and
reports back with events — it never touches engine state.
The binary depends on all. `rsip` types may appear in `sipr-net` and `sipr-engine`
APIs; scenario IR types must not leak rsip types (templates are raw bytes + slots).

## 2. Runtime model

> **As built (M2): std-first, no tokio.** SIPp's own architecture is a single
> event loop — so the runtime is dedicated std threads (recv loops, timer
> thread, the pacer) all sending into ONE `mpsc` channel drained by the
> engine's event loop thread. The only external dependency is `rustls`
> (M13, TLS transport); SIP over UDP/TCP is pure std. The diagram below still describes the moving parts accurately;
> read "task" as "thread". The pure logic (TimerQueue, RetransSchedule,
> Inbound parsing, call state machines) is driver-agnostic: if tokio joins
> the workspace later, only the thin thread drivers in `sipr-net` change.
> Multi-core scaling comes from sharding engine loops (N loops × 1 socket
> each with `SO_REUSEPORT`), not from a work-stealing runtime.

The moving parts:

```
                    ┌────────────┐   rate ticks    ┌──────────────┐
                    │   Pacer    │ ───────────────▶│              │
                    └────────────┘  new UAC calls  │              │
┌──────────┐ datagrams ┌─────────┐  route by       │  Call table  │
│ UDP recv │──────────▶│ Router  │  Call-ID        │ (sharded map │
│  loop(s) │           │(parse + │ ───────────────▶│  call-id →   │
└──────────┘           │ match)  │  new UAS calls  │  CallState)  │
                       └─────────┘                 └──────┬───────┘
┌──────────┐ fired timers    ▲                            │ events drive
│  Timer   │─────────────────┘                            ▼ step execution
│ service  │◀───── arm/cancel ────────────── per-call state machines
└──────────┘                                              │
                                                          ▼ sends
                                                   UDP send path
```

- **Recv loop**: owns the socket(s), parses inbound with `rsip`, routes by Call-ID.
  Unmatched initial requests spawn UAS calls (server mode) or count `OutOfCall`.
- **Call table**: sharded concurrent map, Call-ID → call state. Calls are state
  machine *objects*, not spawned tasks — events (message-in, timer-fired,
  pause-done) are delivered to worker tasks that advance the machine. Target:
  100k concurrent calls without per-call task overhead.
- **Pacer**: open-loop arrival. Every `rate_period` (default 1s) start `rate` new
  calls, smoothed within the period; respects `-l` (concurrent cap → calls beyond
  it are *not queued*, they're simply not started, matching SIPp), `-m` (total).
- **Timer service**: single hashed-wheel/DelayQueue task arming retransmission
  timers, recv timeouts, pauses, timewait, watchdog. Timer resolution 10ms is fine;
  SIPp uses the same order.
- **Stats**: per-worker atomic/thread-local counters, aggregated each second into
  an immutable `StatsSnapshot` (Arc). TUI and CSV writer are pure readers of
  snapshots. Nothing on the hot path takes the stats lock.
- **Two scenarios, one engine** (M33): `-oocsf`/`-oocsn` load an out-of-call
  scenario next to the main one. Both are compiled independently and each
  owns its stat set, CSeq guard and step labels; a call carries which one
  it runs (`CallState::ooc`) and every per-call path — recv-window scan,
  step execution, actions, timers, stats routing — resolves the scenario
  through that flag. Global concerns (pacer, `-l`/`-users`, end of run,
  the auto-answered counter, CSV dump, twin socket, transports) stay on
  the main scenario, as SIPp's `open_calls`/`main_scenario` do. The router
  spawns an ooc call for a request of no known call in client mode only;
  unmapped responses are counted and dropped.

## 3. Hot path rules (enforced in review)

The per-message path is: event → look up call → advance state machine → fill
template slots → sendto. On this path:

1. No heap allocation except the outbound buffer fill (reuse per-call buffers).
2. Message templates are pre-tokenized at scenario load into
   `Vec<Span>` = `Literal(&'static [u8]) | Keyword(KeywordId)`. Per-send work is
   slot substitution only. Never scan/parse template strings per send.
3. No regex execution unless a scenario step explicitly uses `ereg` (that cost is
   the user's choice); regexes are compiled once at scenario load.
4. No lock held across `.await`; prefer message passing to shared mutation.
5. Inbound parse uses rsip's lazy header parsing — extract only the headers the
   current `recv` step and dialog bookkeeping need (Call-ID, CSeq, Via branch,
   To/From tags, and `rrs`-requested Record-Route/Contact).

## 4. Call state machine essentials

Per-call state: scenario index (position in the flat `Vec<Step>` IR), variable
store (`Vec<Option<Value>>`, indexed — variable names resolve to indices at
compile), dialog state (local/remote tag, CSeq counters both directions, route
set, remote target), last-received message per `[last_*]`, RTD start timestamps,
retransmission context for the in-flight `send`, and per-step counters.

Execution loop for a call: advance through IR steps until blocked (waiting on
recv/pause/timer), then park. `optional="true"` recv steps form a *window*: an
inbound message is matched against the current non-optional recv plus any
preceding optional ones, in SIPp's documented order. On unexpected message:
count it, apply SIPp semantics (abort call unless the message matches an
`optional` or auto-answer list). `next`/`test`/`chance` and `label` implement
jumps by IR index; validate all label references at compile time.

UDP retransmission (RFC 3261 §17.1.1 shape, but scenario-driven like SIPp):
sends retransmit on T1=500ms doubling to T2=4s cap until the step's expected
response arrives; `retrans="N"` on a send overrides the base interval;
`-max_retrans`-equivalent caps attempts. INVITE vs non-INVITE differences and
ACK/2xx handling follow SIPp behavior, not full RFC state machines — the C++
(`call.cpp`) is the oracle when in doubt.

## 5. Shutdown semantics

Soft quit (`q`, SIGINT once, or `-m` reached): stop the pacer, let active calls
finish, run `timewait`, exit with SIPp-compatible exit codes: 0 all calls passed,
1 some failed, 97 aborted by user, 99 aborted on error (check exact codes vs
SIPp docs before M3 completion). Hard quit (`Q`, second SIGINT): drop everything.

## 6. Where things will NOT go

- No global mutable state; SIPp's C++ is a museum of it and it's the main reason
  `call.cpp` is 300KB. Configuration is built once and passed as `Arc<Config>`.
- No protocol logic in `sipr-tui` or `sipr-stats`.
- No scenario semantics in `sipr-net` (it moves bytes and fires timers; it does
  not know what an INVITE is beyond what routing requires).

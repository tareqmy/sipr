# sipr — Implementation Plan

A SIPp-like SIP testing tool and traffic generator, written in Rust.

**Decisions locked in:** our own SIP message layer + transport + transaction layer
(a tester's stack, not a compliant one) · SIPp XML-compatible scenarios · v1 scope is
signaling-only over UDP · CLI + live TUI.

> **Status (2026-09-03):** v1 shipped (M0–M6) and the post-v1 milestones through M13
> are done — see `docs/MILESTONES.md`. The crate choices below were revisited during
> implementation: almost everything ended up in-tree (§3.1). The architecture and
> milestone rationale are otherwise as written.

---

## 1. Goal and non-goals

sipr is a scenario-driven SIP traffic generator: it plays call flows described in SIPp's
XML scenario format, as UAC or UAS, at a controlled rate, and reports live and aggregate
statistics. The target for v1 is that the classic workflow works end to end:

```
sipr -sn uas -p 5060                    # terminal side
sipr -sn uac -r 50 -m 10000 127.0.0.1   # caller side, 50 cps, 10k calls
```

and that real-world custom `-sf scenario.xml` files (signaling-only ones) run unmodified.

Non-goals for v1 (planned later, see roadmap): TCP/TLS/WS transports, RTP media
(pcap replay, rtp_stream), 3PCC (`sendCmd`/`recvCmd`), SRTP, IPv6 (stretch), distributed
control API. Explicit non-goal overall: being a general-purpose SIP stack — the transaction
layer is deliberately a *tester's* transaction layer (it must be able to send broken
messages, ignore retransmission rules on demand, inject `lost`/`retrans` behavior).

This is why we build our own message and transaction layer instead of using a
full stack like `rsipstack`: a compliant stack actively prevents the rule-breaking a
test tool needs.

## 2. What SIPp actually is (component map from the C++ source)

From `cprojects/sipp/src`, the tool decomposes into roughly ten functional areas. This is
the checklist of what "SIPp-like" ultimately means:

| SIPp source | Responsibility | sipr home (crate/module) |
|---|---|---|
| `sipp.cpp` | main loop, CLI parsing, global options | `sipr` bin, `cli.rs` |
| `xp_parser.cpp`, `scenario.cpp` | XML parsing → scenario model, keyword substitution | `sipr-scenario` |
| `call.cpp` (300KB!) | per-call state machine executing scenario steps | `sipr-engine::call` |
| `call_generation_task.cpp`, `ratetask.cpp` | open-loop call arrival at rate `-r`/`-rp` | `sipr-engine::pacer` |
| `socket.cpp` | transport, socket mgmt, retransmissions | `sipr-net` |
| `sip_parser.cpp`, `message.cpp` | SIP message parse/build | `sipr-net::message` (in-tree lazy parser) + `sipr-scenario` templates |
| `auth.cpp`, `milenage.c` | digest + AKA authentication | `sipr-auth` (digest only in v1) |
| `actions.cpp`, `variables.cpp` | `<action>` exec: ereg/assign/test/…, call variables | `sipr-scenario::actions` |
| `stat.cpp` | counters, RTDs, repartitions, CSV dumps | `sipr-stats` |
| `screen.cpp` | ncurses live UI | `sipr-tui` (hand-rolled ANSI) |
| `infile.cpp` | `-inf` CSV injection files | `sipr-scenario::infile` |
| `rtpstream.cpp`, `jlsrtp.cpp`, `prepare_pcap.c`, `send_packets.c` | media | out of v1 scope |
| `watchdog.cpp`, `logger.cpp` | health, trace files | `sipr-stats` trace writers + small glue |

Two structural lessons from the C++ worth keeping in mind: `call.cpp` grew to 300KB
because scenario execution, message building, retransmission logic and stats all live in
one class — our crate boundaries above are chosen specifically to prevent that; and SIPp
is single-threaded with a select() loop, which is why its per-process ceiling is
~1–3k cps — an async multi-core design is our chance to beat it decisively.

## 3. Architecture

### 3.1 Workspace layout

```
sipr/
├── Cargo.toml            # workspace
├── crates/
│   ├── sipr-scenario/    # XML parser → Scenario IR; keywords; actions; injection files
│   ├── sipr-net/         # UDP transport, socket pool, timer wheel, retransmit schedule
│   ├── sipr-engine/      # call state machine, pacer, call table, dialog bookkeeping
│   ├── sipr-auth/        # RFC 2617/7616 digest for [authentication]
│   ├── sipr-stats/       # counters, HDR histograms, repartitions, CSV export
│   └── sipr-tui/         # ANSI screens + key handling
└── src/main.rs           # thin bin: table-driven SIPp-style CLI → wire everything together
```

**External crates (as shipped):** `rustls` + `rustls-pemfile` for the TLS transport
(M13, `ring` provider — no system OpenSSL), and dev-only `rcgen` + `tempfile` for
test certificates. That is the whole list. The original plan named `rsip`, `tokio`,
`quick-xml`, `clap`, `ratatui`/`crossterm`, `regex`, `hdrhistogram`, `tracing`,
`rand`, `md-5`/`sha2`; each was replaced by a small in-tree implementation, and the
per-milestone notes in `docs/MILESTONES.md` record why:

| Need | Planned crate | Shipped instead |
|---|---|---|
| CLI parsing | `clap` | table-driven parser in `src/cli.rs` (SIPp's single-dash multi-char flags don't fit clap) |
| Scenario XML | `quick-xml` | `sipr-scenario/src/xml.rs`, a subset parser with exact line tracking (like SIPp's `xp_parser.cpp`) |
| Inbound SIP parse | `rsip` | `sipr-net/src/message.rs`, lazy and panic-free on arbitrary bytes; templates are raw bytes with slot filling |
| Runtime, UDP, timers | `tokio`, `tokio-util` | std threads feeding one mpsc event channel; pure `TimerQueue` + condvar driver |
| `ereg` regex | `regex` | `sipr-scenario/src/regex.rs`, a backtracking ERE engine with a step budget |
| RTD histograms | `hdrhistogram` | `sipr-stats/src/histogram.rs`, 1 ms buckets |
| TUI | `ratatui` + `crossterm` | hand-rolled ANSI + `stty` raw mode, rendering as pure `Snapshot → Vec<String>` |
| Trace files | `tracing` | plain writers in `sipr-stats` with SIPp-style framing |
| Randomness | `rand` | seeded xorshift (deterministic, reproducible `lost`/`chance`) |
| Digest hashes | `md-5`, `sha2` | `sipr-auth/src/hash.rs`, checked against the RFC/FIPS vectors |

The sanctioned set for future additions is in `docs/CONVENTIONS.md` §Dependencies.

### 3.2 Runtime model

The core is an **open-loop pacer feeding a sharded call table**, on std threads
(one event-loop thread fed by an mpsc channel — SIPp's single-loop shape — with the
socket reader and timer driver as separate threads):

- One (later N, `SO_REUSEPORT`) UDP socket driven by a recv loop task. Inbound datagrams
  are parsed by the in-tree message parser and routed by Call-ID to their call in a
  sharded call table. Unmatched inbound requests either
  spawn a new UAS call (server mode) or count as `OutOfCall` messages.
- Each active call is a small state machine object — **not** one spawned task per call by
  default. Calls advance via events (message-in, timer-fired, pause-elapsed) delivered to
  worker tasks; scenario position + variables + last-messages live in the call struct.
  This keeps 100k concurrent calls cheap and mirrors SIPp semantics closely.
- The pacer implements SIPp's open-loop arrival: every `rate_period` (default 1s), start
  `-r` new calls, respecting `-l` (max concurrent), `-m` (total), with burst smoothing
  within the period. Rate changes come from the TUI (`+`/`-`/`*`/`/` keys) or CLI.
- A timer service (pure `TimerQueue` + condvar thread driver) owns retransmission timers
  (T1=500ms doubling to T2=4s for unreliable transport, as in RFC 3261 §17), `recv`
  timeouts, pauses, and global watchdog deadlines.
- Stats are lock-free-ish: per-worker counters aggregated by a 1s ticker into the
  snapshot the TUI and CSV writer read. RTDs (`start_rtd`/`rtd` attrs) use the in-tree
  1 ms-bucket histogram.

### 3.3 Scenario IR and execution

`sipr-scenario` compiles XML into a flat `Vec<Step>` IR at startup — exactly SIPp's
message-index model, which `next`/`label`/`jump` semantics depend on:

```rust
enum Step {
    Send { template: MsgTemplate, retrans: Option<u32>, lost: Option<f32>,
           start_rtd: .., common: StepCommon },
    Recv { expect: Expect /* response code | request method */, optional: bool,
           timeout: Option<Duration>, ontimeout: Option<Label>, auth: bool,
           rrs: bool, actions: Vec<Action>, common: StepCommon },
    Pause { duration: PauseSpec /* fixed | variable | distribution */, common: StepCommon },
    Nop { actions: Vec<Action>, common: StepCommon },
    Label(LabelId),
    Timewait { ms: u64 },
}
```

`MsgTemplate` is the raw CDATA pre-tokenized once at parse time into literal spans +
keyword slots, so per-call message building is just slot filling — no per-send string
scanning. That single decision is worth more to throughput than anything else.

### 3.4 SIPp XML compatibility matrix (from sipp.dtd)

| Tier | Surface | When |
|---|---|---|
| **v1 (M1–M6)** | `send`, `recv`, `pause`, `nop`, `label`, `timewait`; `Reference`, `ResponseTimeRepartition`, `CallLengthRepartition`; step attrs `next/test/chance/condexec/optional/timeout/ontimeout/rrs/auth/lost/retrans/crlf/counter/rtd/start_rtd/repeat_rtd`; actions `ereg, log, warning, assign, assignstr, strcmp, test, add/subtract/multiply/divide, jump, lookup, insert, replace, gettimeofday, exec int_cmd, todouble, trim, urlencode/urldecode, error`; keywords `[service] [remote_ip] [remote_port] [local_ip] [local_ip_type] [local_port] [transport] [call_id] [call_number] [cseq] [branch] [msg_index] [pid] [routes] [next_url] [peer_tag_param] [field0..N] [$var] [last_*] [authentication] [len] [tdmmap?no]` | core |
| **v1.x** | `-inf` injection files (`[fieldN]`, `lookup`), `-key` keywords, `sendCmd`/`recvCmd` (3PCC), `setdest`, `sample`/statistical pauses, `exec command=` (external), regexp variants | done through M38 except `-key` (second backlog, M39) |
| **later** | `exec play_pcap*`, `rtp_stream`, `rtp_echo`, `verifyauth`, `closecon`, `pauserestore`, TCP/TLS-dependent attrs | with media/transport milestones |

Unknown elements/attributes must produce a **loud warning with file:line**, never a
silent skip — half of SIPp debugging misery is silent scenario behavior.

## 4. Milestones

Each milestone ends with something runnable, and from M3 on, every milestone is
validated against real SIPp from `cprojects/sipp` as the interop peer.

**M0 — Scaffolding (small).** Workspace + crates, CLI skeleton mirroring SIPp flag
names (`-sf -sn -r -rp -l -m -d -s -p -i -t u1 -trace_msg -trace_err -trace_stat -nd
-timeout -bg`), CI (fmt, clippy, test), embedded `uac`/`uas` default scenarios as string
constants (port them from SIPp's `-sd` dumps).

**M1 — Scenario front end.** XML → IR for the v1 surface; keyword tokenizer;
golden tests: parse every signaling-only XML in `sipp/sipp_scenarios/` and the docs
examples without error; `sipr --check -sf x.xml` lint mode that prints the compiled IR.

**M2 — Net + message layer.** UDP transport with message round-trip (parse → build byte-
identical where possible); timer wheel; UDP retransmission schedule with per-send
override (`retrans` attr) and `lost` simulation; Call-ID router + call table.

**M3 — UAC engine end to end.** Execute IR for outbound calls: send/recv/pause matching,
optional messages, `next`/`label` jumps, default `uac` scenario completes
INVITE–180–200–ACK–pause–BYE–200 against **real sipp -sn uas**. Pacer with `-r/-rp/-l/-m`,
clean shutdown (`q` semantics: stop placing, drain, timewait). Exit codes matching SIPp
(0 ok, 1 some calls failed, 97/99 aborts) so scripts/CI ports work.

**M4 — UAS mode + stats.** Inbound call creation from initial requests, `[last_*]`
keywords, `rrs`/`[routes]`/`[peer_tag_param]` for dialog correctness as callee; sipr-uac
↔ sipr-uas self-test; stats engine: the full SIPp counter set (created/completed/failed
breakdowns, retransmissions, response-code tallies), RTDs + repartitions, `-trace_stat`
CSV with SIPp-compatible column naming where sane, periodic `-fd` dumps.

**M5 — TUI.** Terminal screens replicating SIPp's ncurses layout: main stats screen and
per-step scenario screen (messages sent/recv/retrans/timeout/unexpected per step),
repartition screen; keys `+ - * /` (rate), `p` (pause traffic), `q` (soft quit), `Q`
(hard quit), `s` screens cycle. Also `-bg`-style headless mode with periodic stat lines,
since CI is a first-class user.

**M6 — Actions, variables, auth.** Variable store per call + `ereg` capture,
arithmetic/string actions, `test`/`condexec` branching, `chance`; `[authentication]`
with digest (MD5, SHA-256, qop=auth) against a challenging registrar; `-aa` auto-answer
of in-dialog OPTIONS/INFO/UPDATE/NOTIFY like SIPp. **← v1 ships here.**

**Post-v1 roadmap, in rough order:** `-inf` injection + `lookup` (it's the most-used
feature not in v1 — could be pulled into M6 if appetite), TCP then TLS transports, 3PCC,
`-users` closed-loop mode, pcap replay/RTP streaming (study gossipper's Go approach
before designing), AKA auth (`milenage`), IPv6, HTTP control API.

## 5. Testing strategy

Unit tests per crate (parser goldens, keyword expansion, timer math, digest vectors from
RFC 7616). Integration: a `tests/interop` harness that shells out to the real `sipp`
binary — every scenario runs sipr-as-UAC vs sipp-as-UAS and the reverse, asserting both
sides exit 0 and counters agree. Fuzz-style no-panic tests on the inbound parser and
tokenizer (`crates/sipr-net/tests/no_panic.rs`: seeded random bytes, truncations, mutations — proptest
was unavailable, the seeded equivalent is reproducible by construction). Performance
gate from M3: `make bench` (loopback sipr-UAC vs sipr-UAS) with numbers recorded in
`benches/BASELINES.md`; target ≥ SIPp's single-core cps early.

## 6. Risks and open questions

The big one is **compatibility depth**: SIPp's DTD is small but its *behavior* is folklore
(exact keyword expansion quirks, default header injection, when Contact/tags are added,
`optional` recv reordering rules). Mitigation: interop harness from M3 onward, and
`call.cpp`/`scenario.cpp` as the reference — read the C++ when behavior is ambiguous,
the docs lie less than they omit. Second: an off-the-shelf SIP parser's strictness
may reject the deliberately-malformed messages testers send — mitigation (adopted):
templates are raw bytes with slot filling, and the in-tree inbound parser is lazy and
tolerant. Third: TUI + high cps contention — keep the TUI a pure reader of 1s
snapshots, never on the hot path.

## 7. Next steps

M0–M37 are done (v0.27.1). The ordered backlog lives at the bottom of
`docs/MILESTONES.md`: the second backlog (M38+) closes the remaining SIPp
parity gaps — statistical pauses, keyword parity incl. `-key`, the statistics
and log file families, timer/behavior knobs, extended 3PCC, leftovers — and
then sipr's own additions.

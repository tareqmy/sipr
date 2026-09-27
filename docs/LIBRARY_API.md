# Library API — `sipr-engine` in your own harness

sipr's engine is a library. The `sipr` binary is one program that uses it;
a Rust integration test that owns a SIP server under test is another:
scenario in, statistics out, no CLI, no TUI, nothing on the process's
stdin, stdout or stderr. This page is the reference for that use. The
history of how the surface got this shape is at the end.

## 1. In one page

```toml
[dev-dependencies]
sipr-engine = "0.29"
sipr-scenario = "0.29"
```

```rust
use std::time::Duration;
use sipr_engine::{EngineConfig, Run, run};
use sipr_scenario::{CompileOptions, compile_strict};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Compile: any diagnostic, warnings included, is an error here.
    let uas = compile_strict("uas", sipr_scenario::embedded("uas").ok_or("no uas")?,
                             &CompileOptions::default())
        .map_err(|diagnostics| format!("{diagnostics:?}"))?;

    // 2. Configure: SIPp's defaults, then the fields you want otherwise.
    let mut cfg = EngineConfig::uas();
    cfg.local_ip = Some("127.0.0.1".parse()?);
    cfg.port = Some(0);                        // any free port
    cfg.control_port = Some(0);                // no SIPp control socket

    // 3. Run: the engine gets its own thread; start returns once bound.
    let server = Run::start(uas, cfg)?;
    let listening_on = server.local_addr();    // where the UAS answers

    // ... point the system under test at `listening_on`, exercise it ...

    // 4. End it and read the report.
    server.control().stop();                   // SIPp's q: drain, then stop
    let report = server.wait()?;
    assert_eq!(report.exit_code(), 0, "{}", report.summary());
    Ok(())
}
```

`crates/sipr-engine/examples/embed.rs` is the full version, with a UAC in
the same process placing calls at that UAS and the engine's notices read
as values:

```sh
cargo run -p sipr-engine --example embed
```

## 2. Compile

A scenario is SIPp XML, compiled by `sipr-scenario`:

- `compile_strict(name, xml, &options) -> Result<Scenario, Vec<Diagnostic>>`
  is the binary's `--check` policy as a function: the lints run, and any
  diagnostic — a warning included — is a failure. Use it unless you have a
  reason to run a scenario that warns.
- `compile_with(name, xml, &options) -> CompileOutcome` gives you the
  scenario (when there were no errors) and the diagnostics to print or
  ignore, which is what the binary does on a normal run.
- `CompileOptions::generic_keywords` names your `-key` keywords so
  `[NAME]` is not an unknown-keyword warning; `lint` asks for the lints.
- `sipr_scenario::embedded("uac" | "uas" | "ooc_default" | "ooc_dummy")`
  is SIPp's own default scenarios as text; `include_str!` yours.

`Scenario` is `Clone` and `Send`. Compile once per test and reuse it.

## 3. Configure

`EngineConfig` is one struct with a public field per SIPp flag, each
documented by the flag it stands for. Start from a constructor:

- `EngineConfig::uac(target)` — placing calls at `target`. `[remote_host]`
  renders the target's IP, and an IPv6 target binds `::` unless
  `local_ip` says otherwise.
- `EngineConfig::uas()` (also `Default`) — answering calls, on every
  interface at 5060 until `local_ip` and `port` say otherwise.

Both carry SIPp's defaults: rate 10 per 1000 ms, `-d` 3000 ms, `-fd` 60 s,
5 INVITE and 9 non-INVITE retransmissions, every `-default_behaviors` on,
and so on. Assign the fields you want otherwise; the struct is
`#[non_exhaustive]`, so a field added in a later release breaks nothing.

The fields a harness usually touches:

| Field | SIPp flag | Note |
|---|---|---|
| `local_ip`, `port` | `-i`, `-p` | `port = Some(0)` picks a free port; `Run::local_addr()` says which |
| `rate`, `rate_period`, `limit`, `max_calls`, `users` | `-r`, `-rp`, `-l`, `-m`, `-users` | how many calls, how fast |
| `pause_default`, `timeout`, `recv_timeout` | `-d`, `-timeout`, `-recv_timeout` | keep `timeout` set in a test, so a stuck run ends |
| `transport`, `tls` | `-t`, `-tls_*` | `TlsMono`/`TlsPerCall` need `tls: Some(TlsConfig { .. })` |
| `inf`, `rxinf`, `inf_index` | `-inf`, `-rxinf`, `-infindex` | `InjectionSource::Path(..)` or `InjectionSource::text(name, csv)` |
| `auth_user`, `auth_password`, `auth_uri` | `-au`, `-ap`, `-auth_uri` | for `[authentication]` |
| `generic_keywords`, `global_sets` | `-key`, `-set` | `[NAME]` values and `<Global>` variables |
| `notices` | — | where the engine's messages go, see §5 |
| `control_port`, `control_ip`, `http_addr`, `http_token` | `-cp`, `-ci`, `--sipr-http`, `--sipr-http-token` | `control_port = Some(0)` disables SIPp's UDP control socket (its default probes 8888..); `http_addr` starts the HTTP API |
| `trace_msg`, `trace_err`, `trace_stat`, `stats_json`, ... | `-trace_*`, `--sipr-stats-json` | log and statistics files, by path |

Everything else is there too (media, 3PCC, reconnection, log rotation,
timer knobs); `docs/SIPP_COMPAT.md` §3 explains each flag.

## 4. Run

```rust
let mut run = Run::start(scenario, config)?;           // or start_with(main, Some((kind, second)), config)
let control = run.control().clone();                   // EngineControl, cheap to clone
let snapshots = run.snapshots();                       // Receiver<Snapshot>, ~1 a second
let report = run.wait()?;                              // RunReport
```

- **`Run::start`** validates the pair, spawns the engine thread and returns
  once `Engine::new` has bound its sockets — a UAC has also made its first
  connection — so a port in use, a missing TLS configuration or a scenario
  keyword the configuration does not provide is an `Err` here, not
  something a later `wait` reports. `start_with` takes a secondary
  scenario, `SecondaryKind::OutOfCall` (`-oocsf`) or `SecondaryKind::Receive`
  (`-rxsf`), under SIPp's rules for them.
- **`control()`**: `set_rate`, `rate`, `pause`, `resume`, `stop` (SIPp's
  `q`: no new calls, the live ones finish, then the report), `abort`
  (`Q`: every live call fails, the loop ends on its next turn), and
  `key(char)` for any of SIPp's screen keys. Every method returns at once;
  a handle that outlives its run does nothing.
- **`snapshots()`** hands over the receiver once; a second call gets one
  that yields nothing. The channel holds a few snapshots: a reader that
  falls behind misses some rather than stalling the engine.
- **`local_addr()`**: the bound signaling address.
- **`wait()`** joins the thread and returns the `RunReport`. Dropping a
  `Run` without waiting aborts it and joins, so a test that panics leaves
  no engine and no bound port behind.
- **`run(&scenario, &config)`** is `Run::start(..)?.wait()` for a scenario
  that ends on its own (`max_calls`, `timeout`).

## 5. Observe

- **`RunReport`**: `created`, `successful`, `failed`, `fatal`, the message
  and retransmission counters, `elapsed`, the final `snapshot`, and
  `exit_code()` — SIPp's exit code (0 all calls passed, 1 some failed, 99
  nothing processed, 253 an RTP check failed, 255 fatal), so a harness can
  assert exactly what a shell script would. `summary()` is the one-line
  form the binary prints.
- **`Snapshot`** (`sipr_stats::Snapshot`): the live counters, rates, the
  per-step rows, RTD rows and generic counters — what the TUI, `-trace_stat`
  and the HTTP API's `/stats` show, one a second from `Run::snapshots()`.
- **Notices**: everything the binary would print to stderr — the bound
  address, the control-API banners, every warning and error — is a
  `Notice` (`Info`, `Warning`, `Error`, each with its message and a
  `Display` that is the binary's exact line) sent where
  `config.notices` points: `NoticeSink::Stderr` (the default),
  `NoticeSink::Channel(sender)` to read them as values, or
  `NoticeSink::Discard`. The engine never prints; the crate denies it.

## 6. Errors

`EngineError` implements `std::error::Error`, so `?` into `anyhow` or
`Box<dyn Error>` works, and says which side to look at:

| Variant | Meaning | Example |
|---|---|---|
| `Config(msg)` | the configuration is wrong or incomplete for this run | a UAC without a target; TLS without `tls` |
| `Scenario(msg)` | the scenario cannot run as given | `[field0]` with no injection file; a 3PCC rule |
| `Bind { what, source }` | a socket could not be opened; `source` is the `io::Error` | `cannot bind UDP socket: Address already in use` |
| `Io { what, path, source }` | a file could not be read or created | an injection file, a log file |
| `Fatal(msg)` | the engine thread could not start, or died without a report | — |

Several messages are SIPp's own wording. The enum is `#[non_exhaustive]`.

## 7. Threads, ports, numbers

- A run owns its threads: the engine loop, the transport's receive or
  accept loop, the control listeners, the media and exec helpers. They end
  when the run does, and the ports go with them — the next run may bind
  the same port. Nothing waits for process exit.
- Call numbers (`[call_number]`, the `%u` of the default Call-ID
  `<number>-<pid>@<ip>`, the auto media port) come from one counter per
  process. Two runs in one process — a harness's UAS and its UAC, or one
  run after another — never reuse a Call-ID, which a peer would otherwise
  take for a late message of a call it just finished and drop.
- The engine is synchronous by design (`docs/ARCHITECTURE.md` §2). From a
  tokio test, `spawn_blocking(move || run.wait())`; the crate takes no
  runtime dependency.
- A `Run`'s thread panicking is a bug in sipr; `wait()` reports it as
  `EngineError::Fatal` rather than propagating the panic.

## 8. The supported surface and its stability

The items this page and the crate documentation describe are the supported
surface of `sipr-engine`:

- `EngineConfig` and the types its fields use: `TransportKind`,
  `Behaviors`, `LogOverwrite`, `Extended3pcc` with `PeerTable`,
  `InjectionSource`, `NoticeSink` and `Notice`, `TdmMap`, `SocketOpts`,
  `TlsConfig` and `TlsVersion`, `sipr_stats::LogRotation`;
- `Run`, `EngineControl`, `RunReport`, `SecondaryKind`, `run`;
- `EngineError`;
- `sipr_stats::Snapshot` and its rows;
- in `sipr-scenario`: `compile`, `compile_with`, `compile_strict`,
  `CompileOptions`, `CompileOutcome`, `Diagnostic`, `Scenario` as an
  opaque value, and `embedded`.

Everything else that is `pub` — the blocking `run_with_*` entry points
`Run` superseded, the message renderer the bench uses — is hidden from the
documentation and may change in any release.

The crates are `0.x`. Within a minor series (`0.29.*`) the supported
surface only grows: fields, variants and methods are added, never removed
or changed in meaning, and every config and report type is
`#[non_exhaustive]` so that is source-compatible. A minor bump (`0.30.0`)
may change it, and `CHANGELOG.md` says what and how to migrate. `1.0` waits
for an embedder outside this repository to have used the API for a release
cycle.

## 9. Non-goals

- **No async API.** See §7.
- **No scenario DSL.** Scenarios are SIPp XML; a Rust builder for call
  flows would fork the compatibility surface that is the product.
- **No FFI.** Rust embedders only.
- **No TUI in the library.** `sipr-tui` reads `Snapshot`s; wire it as the
  binary does if you want a screen.

## 10. How it got here (M49)

The surface above was built in the order of `docs/MILESTONES.md` M49, as
decisions D1–D8 of the design note this page replaced:

- D1 `Default` + constructors + `#[non_exhaustive]` on the config;
  `Cli::default` reads the SIPp defaults from the engine, and a unit test
  keeps a bare command line equal to the constructors field for field.
- D3 `NoticeSink` in place of the engine's 38 `eprintln!`s, enforced by
  `deny(clippy::print_stderr)`; the stdin key reader moved to the binary.
- D4 `EngineError` as a `thiserror` enum. `Fatal` came with D2 rather than
  D4, for the thread cases; the engine's own fatal errors stay in
  `RunReport::fatal`.
- D2 `Run`. Its drop promise exposed that every listener thread held its
  port until process exit, fixed in `sipr-net` and `sipr-control` first.
- D5 `InjectionSource`; the fields are `inf` and `rxinf`, named after the
  flags. Its test exposed Call-ID reuse between engines in one process,
  fixed with the per-process call counter.
- D7 `compile_strict`, the hidden render family, the crate docs, the
  example, this page. The binary keeps `compile_with`: its `--check` also
  prints the compiled steps, which `compile_strict` cannot return with the
  diagnostics.
- D8 the stability wording in §8.

Open questions from the design were settled as: `Run::start` takes the
`Scenario` by value (it is `Clone`; compile once, clone per run); the HTTP
API is part of the surface as the `http_addr` field starts it; `RunReport`
is `#[non_exhaustive]` like the config.

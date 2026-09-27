# Library API — design note for M49

Status: **draft, 2026-09-27**. This is the design for the first item of the
M49+ backlog in `docs/MILESTONES.md`: `sipr-engine` embedded in another Rust
test harness — scenario in, stats out, no CLI, no TUI. Nothing here is
implemented yet; the acceptance criteria live in the M49 section of
`docs/MILESTONES.md` and point back at the numbered decisions below.

## 1. Who this is for

A Rust integration test (or a CI harness) that owns a SIP server under test
and wants to drive it with SIPp scenarios from inside `cargo test`:

- start a UAS scenario in-process on a free port, point the server at it;
- run a UAC scenario against the server at a rate, for N calls;
- stop it early from the test, or let it run to `-m`;
- read the counters and the per-step statistics as Rust values, not by
  scraping `-trace_stat` or the screen;
- see every warning the engine would have printed, as values;
- never touch stdin, stdout or stderr of the test process.

Everything the binary can do today stays reachable — the binary becomes the
first embedder — but this note is about the surface that embedders program
against, and what has to change so that surface can be promised.

## 2. What exists today (v0.28.0)

The engine's public entry point is one blocking function, and the binary is
its only real client:

```text
run_scenarios(&Scenario, Option<(SecondaryKind, &Scenario)>, &EngineConfig,
              Option<UiChannels>) -> Result<(RunReport, EngineControl), EngineError>
```

with `run`, `run_with_control` and `run_with_ui` as thinner wrappers. A
scenario comes from `sipr_scenario::compile_with`, which returns the
`Scenario` plus a `Vec<Diagnostic>`. Measured against §1, the gaps are:

1. **`EngineConfig` is 90 public fields, no `Default`, no constructor.** It
   is "distilled from the CLI": every field documents a SIPp flag and the
   defaults live in the clap definitions in `src/cli.rs`. An embedder has
   to fill all 90 (the engine's own `ui_bridge` test does exactly that),
   and every new flag breaks every embedder at compile time.
2. **Control arrives too late.** `EngineControl` is returned *with* the
   report, after the run has finished; the binary never even binds it. The
   only in-flight control is `UiChannels::keys`, a `Receiver<char>` fed the
   TUI's key letters (`q`, `Q`, `p`, `+`, `-`, `*`, `/`). The soft-stop
   flag (`stop_pacer`) is private. A test that wants "run until my server
   has seen 10 REGISTERs, then stop" has no clean way to say so.
3. **The engine talks to the terminal.** 37 `eprintln!` sites in
   `engine.rs` (the control-socket banner, "warning:" lines, socket
   errors), plus a stdin watcher thread spawned unless `nostdin` is set.
   A library must not own the process's stdio.
4. **`EngineError` is a `String` newtype** with `Display` only — it does
   not implement `std::error::Error`, so `?` into `anyhow`/`Box<dyn Error>`
   does not work, and there is nothing to match on.
5. **Input is paths.** Injection files (`inf_files`, `rx_inf_files`) are
   read with `std::fs::read_to_string` inside the engine; log and trace
   destinations are paths too. A test wants to hand over a few CSV lines
   from a string.
6. **Stats out is adequate but tied to the UI.** Periodic
   `sipr_stats::Snapshot`s (`Clone`, `Default`, public fields, the same
   shape `/stats` serialises) only flow when a `UiChannels` is attached,
   over an `mpsc::Sender` the engine drops when it exits. `RunReport`
   carries the final counters and a boxed final `Snapshot`. This part
   mostly needs promising, not redesigning.
7. **The public surface is what the binary and the bench happened to
   need.** `RenderCtx`, `VarCtx`, `DynamicId`, `FieldSource`, `RunInfo`
   and `render` are `pub` for `benches/hot_path.rs` alone; `PeerTable`,
   `SocketOpts`, `TlsConfig`, `TlsVersion` are re-exported from `sipr-net`
   for the binary. None of that is API an embedder should build on, and
   today nothing says which items are.

None of this is a defect in the binary; it is the shape of a crate that
has had one caller. The decisions below change the shape without changing
what the binary does — the `cli` and `e2e` test suites are the regression
net for that.

## 3. Decisions

### D1. `EngineConfig`: `Default` with SIPp's defaults, `#[non_exhaustive]`, fields stay public

```rust
let mut cfg = EngineConfig::uac(target);   // or EngineConfig::uas()
cfg.rate = 5.0;
cfg.max_calls = Some(20);
```

- `impl Default for EngineConfig` carries **SIPp's defaults** (rate 10,
  `-rp` 1000 ms, `-d` 0, `-max_socket` 50000, `-base_cseq` 1, media port
  6000, and so on). The clap definitions in `src/cli.rs` stop being the
  source of truth for those numbers: the CLI builds `EngineConfig::default()`
  and overwrites what the user passed. One place, one number.
- `#[non_exhaustive]` forbids struct-literal construction outside the
  crate, so adding a field is no longer a breaking change, while the
  fields stay `pub` for reading and assignment. No 90-method builder: a
  builder would double the surface for nothing, and `cfg.field = value`
  is already the most readable form.
- Two constructors, `uac(target: SocketAddr)` and `uas()`, because the
  role decides the one field with no sensible default (`target`) and
  reads better at the call site than `Default` plus an assignment.
- Parity test: `Cli::parse_from(["sipr", "-sn", "uac", "127.0.0.1"])`
  converted to a config must equal `EngineConfig::uac(...)` field for
  field. That test is what keeps the CLI and the library defaults from
  drifting apart, and it fails the moment someone adds a flag default in
  only one place.

### D2. A run handle: start now, control while running, wait for the report

```rust
let run = Run::start(&scenario, cfg)?;          // spawns the engine thread
let ctl = run.control();                        // EngineControl, cloneable
ctl.set_rate(20.0);
ctl.pause(); ctl.resume();
ctl.stop();                                     // soft: stop the pacer, drain
ctl.abort();                                    // hard: drop everything
for snap in run.snapshots() { ... }             // Receiver<Snapshot>, ~1/s
let report: RunReport = run.wait()?;            // joins the thread
```

- The engine already runs on one thread and already owns a control
  channel (`ControlRequest`, fed by the UDP and HTTP front ends). `Run`
  is that thread with a name: `start` moves the compiled scenario and the
  config in (the thread cannot borrow them — `run_scenarios` today borrows
  because the caller blocks), spawns, and hands back the handle.
- `EngineControl` grows `pause`, `resume`, `stop` and `abort`, wired to
  the same paths the `p`/`q`/`Q` keys take today (`stop_pacer`,
  `hard_quit`). The key-letter channel stays for the TUI; the control
  socket's `ControlRequest` path is untouched.
- `run()` stays as the blocking convenience: `Run::start(..)?.wait()`.
  The binary keeps calling the blocking form; only its TUI branch changes
  to `snapshots()` instead of building `UiChannels` by hand.
- Secondary scenarios (`-oocsf`, `-rxsf`) are a field of the request, not
  a second entry point: `Run::start_with(main, Some((kind, second)), cfg)`.
  `run_scenarios`, `run_with_control` and `run_with_ui` become
  `#[doc(hidden)]` wrappers for one minor release, then go.
- Dropping a `Run` without `wait` aborts the run (hard quit, thread
  joined), so a panicking test does not leave a UAS bound to a port.

### D3. Notices instead of `eprintln!`

```rust
pub enum Notice { Info(String), Warning(String), Error(String) }
pub enum NoticeSink { Stderr, Channel(Sender<Notice>), Discard }
cfg.notices = NoticeSink::Channel(tx);
```

- Every `eprintln!` in `sipr-engine` becomes `self.notify(Notice::..)`.
  The sink defaults to `Stderr` with today's exact `sipr: ...` wording,
  so the binary's output is byte-identical (the `cli` tests check it).
- `Discard` exists so a test can opt out explicitly; silence is never the
  default, per the "never silently ignore" rule.
- The stdin watcher moves out of the engine into the binary: it is a
  `Receiver<char>` producer like the TUI, and the binary attaches it when
  `-nostdin` is absent. `EngineConfig::nostdin` goes away (the CLI flag
  stays; it now decides whether the binary attaches the watcher).
- Enforced, not reviewed: `sipr-engine/src/lib.rs` gets
  `#![deny(clippy::print_stderr, clippy::print_stdout)]`, so the crate
  cannot grow a new print site.

### D4. `EngineError` becomes an enum that implements `std::error::Error`

```rust
#[non_exhaustive]
pub enum EngineError {
    Config(String),      // bad or contradictory configuration
    Scenario(String),    // the scenario needs something the config lacks
    Bind(io::Error),     // a socket could not be bound or connected
    Io { path: PathBuf, source: io::Error },  // injection/log/trace files
    Fatal(String),       // the run was cut short (SIPp's ERROR, exit 255)
}
```

- `Display` keeps every current wording (several are SIPp's own and the
  interop tests match on them), so this is a type change, not a message
  change.
- `thiserror` per `docs/CONVENTIONS.md`, `#[non_exhaustive]` so variants
  can be added.

### D5. Injection data from memory

```rust
pub enum InjectionSource { Path(PathBuf), Text { name: String, csv: String } }
cfg.injection = vec![InjectionSource::Text { name: "users.csv".into(), csv }];
```

- Replaces `inf_files: Vec<PathBuf>` and `rx_inf_files: Vec<PathBuf>`
  with one ordered list plus the `rx` marker where it matters (the
  first `-inf` file is still what a bare `[fieldN]` means). The engine
  already parses through `InjectionFile::parse(name, text)`; `Path` just
  reads the file first, exactly as now. `-infindex` keeps matching by
  basename, which for `Text` is the given `name`.
- Log and trace destinations stay paths. A test that wants
  `-trace_msg` can point it at a `tempfile`; making every log a
  `Box<dyn Write>` would touch the rotation code for no embedder need
  yet (YAGNI).

### D6. Stats out: promise what is there

- `Snapshot` (and `StepRow`, `RtdRow`, `CounterRow`) are the stats
  surface. They already serialise to the `/stats` JSON in
  `sipr-control`; that mapping stays the one documented shape.
- `Run::snapshots()` delivers the engine's own once-a-second tick, the
  same one `--sipr-stats-json` writes; the last snapshot before exit is
  also in `RunReport::snapshot`.
- `RunReport::exit_code()` stays the SIPp exit-code oracle so a harness
  can assert on it exactly as a shell script would.

### D7. Name the supported surface, hide the rest

- The supported public items of `sipr-engine` after M49 are exactly:
  `EngineConfig` (+ `TransportKind`, `Behaviors`, `LogOverwrite`,
  `Extended3pcc`, `SecondaryKind`, `InjectionSource`, `NoticeSink`,
  `Notice`), `Run`, `EngineControl`, `RunReport`, `EngineError`, `run`,
  and the re-exports an embedder needs to fill the config (`SocketOpts`,
  `TlsConfig`, `TlsVersion`, `PeerTable`, `TdmMap`,
  `sipr_stats::Snapshot` and its rows). That list is §5 of this document
  once implemented, and the crate-level rustdoc repeats it.
- The render family (`RenderCtx`, `VarCtx`, `DynamicId`, `FieldSource`,
  `RunInfo`, `render`) stays `pub` for the bench but goes
  `#[doc(hidden)]` with a "not part of the supported API" note. Moving the
  bench in-crate would be cleaner and is a follow-up, not a blocker.
- `sipr-scenario` needs one addition: `compile_strict(name, xml,
  &options) -> Result<Scenario, Vec<Diagnostic>>` — the `--check` policy
  ("any diagnostic, warnings included, fails") as a function, so an
  embedder gets it in one call and the binary stops re-implementing it.
  `compile`/`compile_with` stay for callers who want to print warnings and
  continue, which is what the binary does without `--check`.

### D8. Stability promise

- The crates stay `0.x`. Within a minor series (`0.29.*`) the surface in
  D7 is additive only; a minor bump may break it, and `CHANGELOG.md` says
  what and how to migrate. That is what the pinned internal versions
  already imply, written down.
- `1.0` is not on the table until an embedder outside this repo has used
  the API for a release cycle.

## 4. Non-goals

- **No async API.** The engine is one thread and sync channels by design
  (`docs/ARCHITECTURE.md` §2). A tokio harness wraps `Run::wait` in
  `spawn_blocking`; the crate does not take a runtime dependency for that.
- **No scenario DSL.** Scenarios are SIPp XML, compiled by `sipr-scenario`;
  a Rust builder for call flows would fork the compatibility surface that
  is the product. Embedders write XML (or `include_str!` it).
- **No FFI, no C header.** Rust embedders only.
- **No new external dependency.** `thiserror` is already sanctioned;
  everything else is std channels and threads the engine already uses.
- **No TUI in the library.** `sipr-tui` stays a separate crate that reads
  `Snapshot`s; an embedder that wants a screen wires it exactly as the
  binary does.

## 5. What the embedder sees (target)

```rust
use sipr_engine::{EngineConfig, Run, Notice, NoticeSink};
use sipr_scenario::{compile_strict, CompileOptions};

let uas = compile_strict("uas", sipr_scenario::embedded("uas").unwrap(),
                         &CompileOptions::default())?;
let mut cfg = EngineConfig::uas();
cfg.local_ip = Some("127.0.0.1".parse()?);
cfg.port = Some(0);                       // pick a free port
cfg.notices = NoticeSink::Channel(tx);
let server = Run::start(uas, cfg)?;
let bound = server.local_addr();          // where the UAS is listening

// ... point the system under test at `bound`, exercise it ...

server.control().stop();
let report = server.wait()?;
assert_eq!(report.exit_code(), 0, "{}", report.summary());
assert_eq!(report.successful, 20);
```

`local_addr()` is new and small: the bound signaling address, for the
`port = Some(0)` case tests need. Today the binary prints it on the
control-socket banner; nothing returns it.

## 6. Order of work

Each step is one commit that keeps the binary's behaviour and the gates
green; the `cli`, `e2e` and interop suites are the regression net.

1. D1 — `Default` + `#[non_exhaustive]` + constructors; the binary and
   `ui_bridge` switch to them; the CLI-vs-default parity test.
2. D3 — notices and the print lints; the stdin watcher moves to the
   binary.
3. D4 — the error enum.
4. D2 — `Run`, the control methods, `local_addr()`; `run_scenarios` and
   friends hidden.
5. D5 — `InjectionSource`.
6. D7 — `compile_strict`, `#[doc(hidden)]` on the render family, the
   crate-level docs listing the surface, an `examples/embed.rs` that CI
   builds, and this document rewritten from "design" to "reference".

Steps 1–3 are mechanical and unblock the rest; step 4 is the only one
with real design inside it (thread ownership, drop semantics) and gets
its own review.

## 7. Open questions

- **Should `Run::start` take the `Scenario` by value or `Arc`?** By value
  is simplest; an embedder running the same scenario in several `Run`s
  clones it (it is `Clone`, and compiled once per test anyway). `Arc`
  only if a test shows cloning a compiled scenario is measurable.
- **Does the HTTP API belong in the library path?** `http_addr` in the
  config already starts it inside the engine, so an embedder gets
  `/stats` and `/metrics` for free by setting the field. Leaving it as is
  costs nothing; the question is only whether D7's supported list names
  it. Proposal: yes, as-is.
- **`RunReport` growth.** It has 15 public fields and no
  `#[non_exhaustive]`; the same treatment as D1 (attribute, keep fields
  public) is the obvious call and is folded into D1.

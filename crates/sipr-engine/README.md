# sipr-engine

The sipr traffic engine as a library: per-call state machines, pacer, dialogs and transports. Scenario in, statistics out.

- Compile a SIPp XML scenario with `sipr-scenario`, configure with `EngineConfig::uac()` or `EngineConfig::uas()` (SIPp's defaults, each field named after the SIPp flag it stands for), then `Run::start` it.
- `Run::control` drives a live run, `Run::snapshots` reports once a second, and `Run::wait` ends with a `RunReport` and an exit code.
- Engine output is delivered as values (`Notice`) instead of being printed, so it embeds cleanly in a test harness.

```rust
use sipr_engine::{EngineConfig, Run};
use sipr_scenario::{CompileOptions, compile_strict};

let xml = sipr_scenario::embedded("uas").ok_or("no uas")?;
let uas = compile_strict("uas", xml, &CompileOptions::default())
    .map_err(|diagnostics| format!("{diagnostics:?}"))?;
let mut cfg = EngineConfig::uas();
cfg.port = Some(0);
let server = Run::start(uas, cfg)?;
let listening_on = server.local_addr();
// ... exercise the system under test against `listening_on` ...
server.control().stop();
let report = server.wait()?;
assert_eq!(report.exit_code(), 0, "{}", report.summary());
# Ok::<(), Box<dyn std::error::Error>>(())
```

A complete example, a UAS and a UAC in one process, is in `examples/embed.rs`:
`cargo run -p sipr-engine --example embed`.

## About sipr

[sipr](https://github.com/tareqmy/sipr) is a SIPp-compatible SIP testing tool
and traffic generator written in Rust: it plays SIPp XML scenarios as caller
(UAC) or callee (UAS) at a controlled rate, over UDP, TCP, TLS and WebSocket,
with a live terminal dashboard. Documentation: <https://tareqmy.github.io/sipr/>.

## Stability

This is the one library surface sipr supports. `EngineConfig`, `Run`, `EngineControl`, `RunReport`, `EngineError` and the types the config fields use are additive within a `0.x` minor series, and the changelog says what each minor bump changed. Everything else that is `pub` exists for the `sipr` binary and may change in any release. See [`docs/LIBRARY_API.md`](https://github.com/tareqmy/sipr/blob/master/docs/LIBRARY_API.md).

## License

MIT.

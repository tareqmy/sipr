# sipr-stats

Counters, response-time histograms, repartitions and CSV export for sipr.

- The statistics set the engine updates once per event, with periodic and cumulative counters.
- Response-time histograms and the repartition tables built from them.
- The per-second `Snapshot` that the dashboard and the HTTP API read, so neither touches the engine.
- SIPp's `-trace_stat` CSV format, column for column, plus message and error trace files and log rotation.
- No dependencies.

## About sipr

[sipr](https://github.com/tareqmy/sipr) is a SIPp-compatible SIP testing tool
and traffic generator written in Rust: it plays SIPp XML scenarios as caller
(UAC) or callee (UAS) at a controlled rate, over UDP, TCP, TLS and WebSocket,
with a live terminal dashboard. Documentation: <https://tareqmy.github.io/sipr/>.

## Stability

This crate exists so the `sipr` workspace can be published as separate crates. Its API is internal to sipr and may change in any release; `Snapshot` and its rows are the one part exposed through `sipr-engine`. To embed sipr in your own Rust code depend on `sipr-engine` (see its `docs/LIBRARY_API.md`), or install the `sipr` binary.

## License

MIT.

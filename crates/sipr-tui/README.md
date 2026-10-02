# sipr-tui

The live terminal dashboard for sipr, drawn with plain ANSI escapes.

- A pure render step (`Snapshot` to screen lines) that is unit-tested without a terminal.
- A thin interactive shell for raw mode, the alternate screen and key handling, which restores the terminal on drop and on panic.
- SIPp-style screens (main, scenario, repartition) with a colour palette.

The dashboard only reads one-second statistics snapshots; it never touches the engine.

## About sipr

[sipr](https://github.com/tareqmy/sipr) is a SIPp-compatible SIP testing tool
and traffic generator written in Rust: it plays SIPp XML scenarios as caller
(UAC) or callee (UAS) at a controlled rate, over UDP, TCP, TLS and WebSocket,
with a live terminal dashboard. Documentation: <https://tareqmy.github.io/sipr/>.

## Stability

This crate exists so the `sipr` workspace can be published as separate crates. Its API is internal to sipr and may change in any release; depend on `sipr-engine` if you want to embed sipr in your own Rust code (see its `docs/LIBRARY_API.md`), or install the `sipr` binary.

## License

MIT.

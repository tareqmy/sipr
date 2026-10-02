# sipr-control

Runtime control for sipr: SIPp's UDP control socket and a JSON/HTTP API with Prometheus metrics.

- Parsing for SIPp's `-cp` control socket: hot keys and `set` / `trace` / `dump` / `reset` command lines, one datagram per command.
- sipr's own HTTP/JSON API (`--sipr-http`): the same commands with answers, plus the live statistics snapshot and a Prometheus endpoint.
- Hand-written HTTP and JSON handling on `std` only.

The engine owns all state; this crate parses input into commands and renders snapshots out.

## About sipr

[sipr](https://github.com/tareqmy/sipr) is a SIPp-compatible SIP testing tool
and traffic generator written in Rust: it plays SIPp XML scenarios as caller
(UAC) or callee (UAS) at a controlled rate, over UDP, TCP, TLS and WebSocket,
with a live terminal dashboard. Documentation: <https://tareqmy.github.io/sipr/>.

## Stability

This crate exists so the `sipr` workspace can be published as separate crates. Its API is internal to sipr and may change in any release; depend on `sipr-engine` if you want to embed sipr in your own Rust code (see its `docs/LIBRARY_API.md`), or install the `sipr` binary.

## License

MIT.

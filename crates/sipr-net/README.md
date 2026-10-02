# sipr-net

Transports and timers for sipr: UDP, TCP, TLS, WebSocket and SCTP, SIP message parsing, and the RFC 3261 retransmission schedule.

- Thread-based transports (no async runtime) that funnel events into the engine's single channel.
- Tolerant inbound SIP message parsing and TCP/WebSocket framing.
- A timer service and the retransmission schedule (T1/T2/T4 and the timer caps).
- TLS through `rustls` with the `ring` provider, so no system OpenSSL is needed; SCTP behind the `sctp` cargo feature.
- Socket options (`-buff_size`, `-bind_to_device` and friends) and the call-to-socket table.

## About sipr

[sipr](https://github.com/tareqmy/sipr) is a SIPp-compatible SIP testing tool
and traffic generator written in Rust: it plays SIPp XML scenarios as caller
(UAC) or callee (UAS) at a controlled rate, over UDP, TCP, TLS and WebSocket,
with a live terminal dashboard. Documentation: <https://tareqmy.github.io/sipr/>.

## Stability

This crate exists so the `sipr` workspace can be published as separate crates. Its API is internal to sipr and may change in any release; depend on `sipr-engine` if you want to embed sipr in your own Rust code (see its `docs/LIBRARY_API.md`), or install the `sipr` binary.

## License

MIT.

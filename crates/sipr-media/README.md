# sipr-media

RTP and pcap media for sipr: a pure-Rust pcap reader, a packet scheduler, RTP/DTMF generation, RTP echo and SRTP.

- A pcap and pcapng reader (no libpcap; sipr only reads captures) that extracts UDP payloads and their timing.
- SDP scanning to learn where the peer wants media.
- A single scheduler thread that replays every active stream on its capture's timeline, plus RTP streaming and DTMF events.
- An RTP echo server and RTP checking, and SRTP with an SRTP echo server.

## About sipr

[sipr](https://github.com/tareqmy/sipr) is a SIPp-compatible SIP testing tool
and traffic generator written in Rust: it plays SIPp XML scenarios as caller
(UAC) or callee (UAS) at a controlled rate, over UDP, TCP, TLS and WebSocket,
with a live terminal dashboard. Documentation: <https://tareqmy.github.io/sipr/>.

## Stability

This crate exists so the `sipr` workspace can be published as separate crates. Its API is internal to sipr and may change in any release; depend on `sipr-engine` if you want to embed sipr in your own Rust code (see its `docs/LIBRARY_API.md`), or install the `sipr` binary.

## License

MIT.

# sipr

A SIPp-like SIP testing tool and traffic generator, written in Rust.

sipr plays SIP call flows described in SIPp-compatible XML scenarios — as caller
(UAC) or callee (UAS) — at a controlled call rate, with live terminal statistics.
Think `sipp -sn uac -r 50` with a modern async, multi-core engine.

**Status: pre-implementation.** The design is settled; code lands milestone by
milestone.

- `PLAN.md` — architecture and roadmap
- `docs/` — architecture, SIPp compatibility surface, conventions, testing, glossary
- `AGENTS.md` / `CLAUDE.md` — instructions for AI agents contributing to the repo

## Planned v1 (signaling, UDP)

SIPp XML scenario compatibility (send/recv/pause/nop/label + actions + keywords),
built-in `uac`/`uas` scenarios, open-loop rate control (`-r/-rp/-l/-m`), digest
auth, SIPp-style live TUI and CSV statistics, interop-tested against real SIPp.

Later: TCP/TLS, injection files, 3PCC, RTP/pcap media, IPv6, HTTP control API.

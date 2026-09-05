<p align="center">
  <img src="brand/logo/lockup-1600.png" alt="sipr" width="360">
</p>

<p align="center">
  <a href="https://github.com/tareqmy/sipr/actions/workflows/ci.yml"><img src="https://github.com/tareqmy/sipr/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-B7410E" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B-B7410E" alt="Rust 1.85+">
  <img src="https://img.shields.io/badge/dependencies-no%20system%20libs-5E7A52" alt="no system libraries">
</p>

# sipr

A SIPp-like SIP testing tool and traffic generator, written in Rust.

sipr plays SIP call flows described in SIPp-compatible XML scenarios — as caller
(UAC) or callee (UAS) — at a controlled call rate, with a live terminal
dashboard. Think `sipp -sn uac -r 50`, rebuilt in safe, dependency-free Rust.

**Status: v1 feature-complete for signaling over UDP, TCP, and TLS.** In loopback benchmarks
it sustains tens of thousands of calls per second with zero failures — see
`benches/BASELINES.md`.

## Install

sipr builds from source with a stock Rust toolchain (1.85+), no system
libraries required (TLS is pure-Rust `rustls` — no OpenSSL):

```sh
git clone https://github.com/tareqmy/sipr && cd sipr
cargo build --release        # binary at target/release/sipr
cargo install --path .       # or install it onto your PATH
```

## Quick start

```sh
cargo build --release

# Terminal 1 — answer calls (UAS) on port 5060:
sipr -sn uas -p 5060

# Terminal 2 — place 1000 calls at 50 cps (UAC):
sipr -sn uac -r 50 -m 1000 127.0.0.1:5060
```

The UAC opens a live dashboard (when run in a terminal): press `+`/`-`/`*`/`/`
to change the call rate, `p` to pause, `s` to cycle screens (main / per-step /
repartitions), `q` to drain and quit, `Q` to abort.

Run your own scenario, lint it first, or dump a built-in:

```sh
sipr -sf my_scenario.xml -r 10 sip.example.com
sipr -sf my_scenario.xml --check      # compile + print the IR, exit non-zero on any issue
sipr -sd uac                          # print an embedded scenario to stdout
```

Headless (CI) mode with traces and a stats CSV:

```sh
sipr -sn uac -m 10000 -bg -trace_msg -trace_err -trace_stat sip.example.com
```

Flags use SIPp's single-dash names (`-sf`, `-r`, `-l`, `-m`, `-d`, `-trace_msg`,
`-au`/`-ap`, `-aa`, `-nr`, ...); run `sipr -h` for the full list.

## What works today (v1)

- SIPp-compatible XML scenarios: `send`/`recv`/`pause`/`nop`/`label`/`timewait`,
  the full v1 action set (`ereg` with capture groups, arithmetic, `test`/
  `strcmp`, `jump`, `log`/`warning`/`error`, `exec int_cmd`, ...), `test`/
  `condexec` branching, `chance`, and named counters.
- Keywords incl. `[call_id]`, `[branch]`, `[cseq]`, `[last_*:]`, `[$var]`,
  `[routes]`, `[peer_tag_param]`, `[len]`, `[fieldN]`, and `[authentication]`.
- `-inf FILE` injection files (SEQUENTIAL/RANDOM/USER), one line drawn per call;
  `[fieldN]` pulls a field, with `file=NAME` and `line=[$var]` selectors.
- Indexed injection: `-infindex FILE FIELD` plus `<lookup>`/`<insert>`/
  `<replace>` actions for keyed, mutable CSV data.
- Classic 3PCC (`-3pcc HOST:PORT`) with `<sendCmd>`/`<recvCmd>` over an
  ESC-framed twin socket.
- Closed-loop `-users N` mode with `[userid]`/`[users]` and per-user USER-mode
  injection (line = user id − 1).
- IPv6 targets (`[::1]`, `[2001:db8::1]:5060`, bare `::1`) with automatic v6
  binding; `[local_ip]`/`[remote_ip]` are bracketed in URIs and Via.
- UAC and UAS roles; open-loop pacing (`-r/-rp/-l/-m`) with rate smoothing
  and SIPp's ramps (`-rate_increase`, `-rate_max`, `-rate_interval`).
- UDP, TCP, and TLS transports, one socket (`-t u1|t1|l1`) or one per call
  (`-t un|tn|ln`, `-max_socket`); streams frame by
  Content-Length and carry no SIP retransmissions (reliable transports). TLS
  takes SIPp's `-tls_cert`/`-tls_key`/`-tls_ca`/`-tls_crl`/`-tls_version`
  flags with SIPp's verification semantics.
- UDP retransmission (T1→T2), recv-window matching verified against SIPp's C++.
- Digest authentication (MD5 + SHA-256, `qop=auth`, proxy 407) and IMS AKA
  (`AKAv1-MD5` with in-tree Milenage: `[authentication aka_K=0x… aka_OP=0x…]`),
  including AUTS resynchronisation (`aka_sqn=`, `aka_resync=1`).
- pcap replay: `<exec play_pcap_audio="file.pcap"/>` streams a capture's RTP
  to the peer's SDP endpoint from `-mi`/`-mp` (`[media_port]`,
  `[auto_media_port]`) — ordinary UDP sockets, so no root needed.
- RTP streaming and DTMF: `<exec rtp_stream="file.g711a,-1,8"/>` with
  SIPp's codec table, patterns, `pause`/`resume`, `[rtpstream_audio_port]`;
  `<exec play_dtmf="1234#"/>` sends RFC 4733 events.
- RTP echo (`-rtp_echo`) and the echo check (`-audiotolerance`): a pattern
  stream against an echoing peer is verified packet by packet, exit 253 on
  failure as in SIPp.
- SRTP (SDES): SIPp's `[cryptotag1audio]`/`[cryptosuite…]`/`[cryptokeyparams…]`
  keywords, AES-CM-128 + HMAC-SHA1 80/32, all in-tree — no OpenSSL.
- Runtime control: SIPp's UDP control socket (`-cp`) and an HTTP/JSON API
  (`--sipr-http 8080`: `/stats`, `/control`, `/quit`, `/command`; see
  `docs/CONTROL_API.md`).
- Live TUI, `-bg` headless stat lines, `-trace_msg`/`-trace_err`/`-trace_stat`
  files, RTDs and repartition tables.

Everything is built on the Rust standard library, plus `rustls` for the TLS
transport — no system libraries (no OpenSSL even for SRTP, no libpcap), no
root for media.

## Documentation

- `PLAN.md` — architecture and roadmap
- `docs/` — architecture, SIPp compatibility surface, conventions, testing,
  glossary, milestones
- `AGENTS.md` / `CLAUDE.md` — instructions for AI agents contributing to the repo

## Not yet (post-v1 roadmap)

The SIPp scenario surface is covered. Remaining SIPp corners are transport
modes: `-rsa`, `-t ui`, the reconnect options, SCTP.

## Brand

sipr's visual identity is "Ferrous" — an oxidized-orange industrial slab that
wears the Rust heritage openly. Logos, the color palette, fonts, and a terminal
color mapping live in [`brand/`](brand/); the live dashboard uses those colors
(rust title, sage for successful calls), honoring `NO_COLOR`.

## License

Licensed under the [MIT License](LICENSE).

Note: sipr is an independent clean-room reimplementation. The original SIPp is
GPL-licensed; no SIPp source is copied into this project — only its scenario
format and observable behavior are reproduced, which are not themselves subject
to copyright.

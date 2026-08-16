<p align="center">
  <img src="brand/logo/lockup-1600.png" alt="sipr" width="360">
</p>

<p align="center">
  <a href="https://github.com/tareqmy/sipr/actions/workflows/ci.yml"><img src="https://github.com/tareqmy/sipr/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-B7410E" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B-B7410E" alt="Rust 1.85+">
  <img src="https://img.shields.io/badge/dependencies-std--only-5E7A52" alt="std-only">
</p>

# sipr

A SIPp-like SIP testing tool and traffic generator, written in Rust.

sipr plays SIP call flows described in SIPp-compatible XML scenarios — as caller
(UAC) or callee (UAS) — at a controlled call rate, with a live terminal
dashboard. Think `sipp -sn uac -r 50`, rebuilt in safe, dependency-free Rust.

**Status: v1 feature-complete for signaling over UDP.** In loopback benchmarks
it sustains tens of thousands of calls per second with zero failures — see
`benches/BASELINES.md`.

## Install

sipr builds from source with a stock Rust toolchain (1.85+), no external
crates or system libraries required:

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
- UAC and UAS roles; open-loop pacing (`-r/-rp/-l/-m`) with rate smoothing.
- UDP (`-t u1`) and TCP (`-t t1`) transports; TCP frames by Content-Length and
  carries no SIP retransmissions (reliable transport).
- UDP retransmission (T1→T2), recv-window matching verified against SIPp's C++.
- Digest authentication (MD5 + SHA-256, `qop=auth`, proxy 407).
- Live TUI, `-bg` headless stat lines, `-trace_msg`/`-trace_err`/`-trace_stat`
  files, RTDs and repartition tables.

Everything is built on the Rust standard library only — no external crates.

## Documentation

- `PLAN.md` — architecture and roadmap
- `docs/` — architecture, SIPp compatibility surface, conventions, testing,
  glossary, milestones
- `AGENTS.md` / `CLAUDE.md` — instructions for AI agents contributing to the repo

## Not yet (post-v1 roadmap)

TLS transport, 3PCC (`sendCmd`/`recvCmd`), RTP/pcap media, IPv6, and an HTTP
control API.

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

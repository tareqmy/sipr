<img class="sipr-lockup sipr-lockup-light" src="img/lockup.png" alt="sipr">
<img class="sipr-lockup sipr-lockup-dark" src="img/lockup-dark.png" alt="sipr">

<p class="sipr-tagline">A SIP testing tool and traffic generator written in Rust,
compatible with <a href="https://github.com/SIPp/sipp">SIPp</a> scenarios.</p>

sipr plays SIP call flows described in SIPp's XML scenario format, as caller
(UAC) or callee (UAS), at a controlled call rate, with a live terminal
dashboard. It takes the same scenario files and the same command-line flags
as SIPp, so `sipr -sn uac -r 50` does what `sipp -sn uac -r 50` does.

sipr is an independent implementation, not a fork. SIPp remains the reference
tool for this format; its documentation and behavior are what sipr is tested
against, and every release runs an interoperability suite with a real SIPp on
the other end of the call. sipr exists for people who want that workflow in a
single static binary with no system libraries. It is not intended to replace
SIPp.

Source, issues and releases live at
[github.com/tareqmy/sipr](https://github.com/tareqmy/sipr).

## Install

Prebuilt binaries for macOS, Linux (static) and Windows come with every
release; the full list of methods is on the [Installation](INSTALLATION.md)
page.

```sh
brew tap tareqmy/tap && brew install sipr                                   # Homebrew (macOS, Linux)
curl -fsSL https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/install.sh | sh   # shell script
cargo install sipr                                                          # from crates.io
nix run github:tareqmy/sipr                                                 # Nix flake
```

```powershell
irm https://raw.githubusercontent.com/tareqmy/sipr/master/scripts/install.ps1 | iex   # Windows
```

## Quick start

```sh
# Terminal 1 — answer calls (UAS) on port 5060:
sipr -sn uas -p 5060

# Terminal 2 — place 1000 calls at 50 cps (UAC):
sipr -sn uac -r 50 -m 1000 127.0.0.1:5060
```

The UAC opens a live dashboard when run in a terminal: `+`/`-`/`*`/`/` change
the call rate, `p` pauses, `s` cycles the screens (main, per-step,
repartitions), `q` drains and quits, `Q` aborts.

Run your own scenario, lint it first, or dump a built-in one:

```sh
sipr -sf my_scenario.xml -r 10 sip.example.com
sipr -sf my_scenario.xml --check      # compile, lint, print the IR; exit non-zero on any issue
sipr -sd uac                          # print an embedded scenario to stdout
```

Headless (CI) mode with traces and a statistics CSV:

```sh
sipr -sn uac -m 10000 -bg -trace_msg -trace_err -trace_stat sip.example.com
```

Flags use SIPp's single-dash names (`-sf`, `-r`, `-l`, `-m`, `-d`,
`-trace_msg`, `-au`/`-ap`, `-aa`, `-nr`, …); `sipr -h` prints the full list.

## Where to look

- **[SIPp compatibility surface](SIPP_COMPAT.md)**: every scenario element,
  action, keyword and flag sipr implements, the deliberate gaps, and the
  behavior notes learned from SIPp's source.
- **[Runtime control](CONTROL_API.md)**: SIPp's UDP control socket and
  sipr's HTTP/JSON API for driving a run from outside.
- **[Glossary](GLOSSARY.md)**: transactions, dialogs, calls, RTDs,
  repartitions, 3PCC.
- **[Architecture](ARCHITECTURE.md)**, **[Testing](TESTING.md)** and
  **[Contributing](contributing.md)** if you want to change sipr.
- **[Changelog](changelog.md)** for what each release changed.

## License

sipr is licensed under the
[MIT License](https://github.com/tareqmy/sipr/blob/master/LICENSE). SIPp is
GPL-licensed, and no SIPp C++ source is copied into this project: its code
was read to learn the behavior, which was then implemented separately. The
scenario format, keywords and command-line flags are reproduced as an
interface so existing SIPp scenarios keep working.

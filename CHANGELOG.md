# Changelog

All notable changes to sipr are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Timer and behavior knobs at parity (M42): `-max_invite_retrans`,
  `-max_non_invite_retrans` (SIPp's 5 and 9, with `-max_retrans` as a
  ceiling; an INVITE's timer keeps doubling past T2 as SIPp's does),
  `-recv_timeout`, `-timeout_error`, global `-lost`, `-pause_msg_ign`,
  `-default_behaviors` (with `-nd` as `none`) including SIPp's abort
  messages (ACK/BYE/CANCEL from its own built-in templates) and its
  handling of unexpected BYE, CANCEL and PING, `-callid_slash_ign`,
  `-sleep`, `-nostdin`; `-send_timeout` and `-timer_resol` are accepted
  with a warning. The `[last_Request_URI]` keyword.
- Message and error logs at parity (M41): `-trace_msg` frames and
  `-trace_err` lines take SIPp's exact shapes (timestamps, the
  `The following events occurred:` header), `<log>` actions go to the new
  `-trace_logs`/`-log_file`, and `-trace_shortmsg`/`-shortmessage_file`,
  `-trace_calldebug`/`-calldebug_file`, `-error_file`, `-message_file`,
  the `-<kind>_overwrite` flags, `-ringbuffer_files`/`-ringbuffer_size`/
  `-max_log_size` rotation and `-deadcall_wait` are implemented as SIPp's;
  `-trace_timeout` is accepted (a no-op in SIPp too). `trace
  logs|shortmessages on|off` work on the control socket.
- Statistics files at parity (M40): `-trace_stat` writes SIPp's full
  column set (`StartTime` … `WatchdogMinor`, `ResponseTime<rtd>` mean and
  standard deviation per RTD, `CallLength`, a repartition block per RTD
  and for the call length, SIPp's time formats and trailing delimiter);
  new `-trace_rtt`/`-rtt_freq`, `-trace_counts`, `-trace_error_codes`,
  `-trace_screen`/`-screen_file`, `-stat_delimiter`, `-periodic_rtd` and
  `-f`, all with SIPp's file names and formats.
- Keyword parity (M39): `[clock_tick]`, `[timestamp]`, `[date]`,
  `[sipp_version]`, `[dynamic_id]`, `[remote_host]`, `[tdmmap]`,
  `[last_message]`, `[last_cseq_number]` (with `+N`/`-N`), `[fill
  variable= text=]` and `[file name=]` render as in SIPp, and `-key
  KEYWORD VALUE` defines generic keywords. New flags `-tdmmap`,
  `-dynamicStart`/`-dynamicMax`/`-dynamicStep` and `-rfc3339`.
  `[timestamp]` is UTC where SIPp uses local time (SIPP_COMPAT §6).
- Statistical pauses at SIPp parity: `<pause distribution="…">` now takes
  SIPp's attribute form (`distribution="normal" mean="…" stdev="…"`) and
  all ten of SIPp's kinds — `fixed`, `uniform`, `normal`, `lognormal`,
  `exponential`, `weibull`, `pareto`, `gpareto`, `gamma`, `negbin` — plus
  the old-style `<pause min= max=>` spellings and SIPp's `sanity_check`.
  The `<sample assign_to= distribution=…>` action draws into a variable.
  A pause sample below 1 ms is no pause, as in SIPp. The interop CI build
  of sipp now includes GSL so the comparison runs both ways.

### Changed

- Non-INVITE messages retransmit up to 9 times by default (SIPp's
  `-max_non_invite_retrans`), not 5; an aborted client call now sends
  SIPp's BYE/CANCEL/ACK unless `-nd` or `-default_behaviors …,-bye`; a
  `///` prefix in an inbound Call-ID is stripped as SIPp's 3PCC marker
  unless `-callid_slash_ign`.
- The `-trace_msg` frame no longer carries the peer address, and
  `-trace_err` lines are timestamped: both are now SIPp's formats. `<log>`
  lines no longer go to the error trace with a `[log]` prefix; they need
  `-trace_logs`.
- `-fd` defaults to 60 s as in SIPp (it was 1 s); the final statistics
  row is still written at exit. The `-trace_stat` header changed from
  sipr's earlier subset to SIPp's columns, so parsers keyed on column
  position need SIPp's layout.
- `--check` and the scenario screen label a distributed pause the way
  SIPp's screen does (`N(60000.000,15000.000)`, `Exp(…)`, `Wb(…)`, …).
- The scenario-side positional form `distribution="uniform(200,3000)"`
  still parses but is documented as a sipr extension; SIPp's attributes
  are canonical. `poisson`, which SIPp never had, is now an error.

### Fixed

- On Windows an ICMP port-unreachable for a peer that is down no longer
  kills the UDP socket: the receive loop rides out `ConnectionReset`
  (the `WSAECONNRESET` quirk on unconnected sockets) instead of ending
  the run with "socket error".

## [0.27.1] — 2026-09-20

### Changed

- The release workflow publishes crates one at a time, skipping versions
  already on crates.io, so a partial publish resumes instead of failing on
  the first already-published crate. A manually triggered "Publish crates"
  workflow does the same for any existing tag.

## [0.27.0] — 2026-09-20

### Security

- rustls updated to 0.23.45 for RUSTSEC-2026-0285 (TLS 1.3 handshake messages
  accepted across encryption level boundaries).

### Added

- Release automation modelled on gitwig's: a tag-triggered `CD` workflow
  that builds static Linux (x86_64, arm64), macOS (Intel, Apple Silicon)
  and Windows binaries, publishes the GitHub release, and, when the
  matching secret is present, publishes the crates to crates.io, updates
  the `tareqmy/homebrew-tap` formula, and pushes a Chocolatey package.
- Install and uninstall scripts for macOS/Linux (`scripts/install.sh`) and
  Windows (`scripts/install.ps1`), a Nix flake, a reference Homebrew
  formula, and `docs/INSTALLATION.md` covering every method.
- `cargo-deny` policy (`deny.toml`) checked in CI, and a CI portability job
  building and testing on macOS and Windows.
- `SECURITY.md` and `CONTRIBUTING.md`.

### Changed

- TLS PEM files (`-tls_cert`, `-tls_key`, `-tls_ca`, `-tls_crl`) are now parsed
  with `rustls-pki-types`, the crate rustls itself uses, replacing the
  unmaintained `rustls-pemfile` (RUSTSEC-2025-0134). Same formats, and a
  malformed file is now reported with its name.
- README rewritten to describe sipr's relationship to SIPp neutrally, state
  the benchmark numbers `benches/BASELINES.md` actually records, and list
  every deliberate compatibility gap.

### Fixed

- The call pacer now credits new calls from elapsed wall-clock time
  (`rate × elapsed / rate_period`, as SIPp does) instead of counting timer
  ticks, so a delayed or coalesced tick no longer lowers the achieved rate.

## [0.26.0] — 2026-09-19

### Added

- **`exec command=`** (M37): run a shell command from an action, with
  keywords and variables rendered into it. Fire-and-forget as in SIPp, but
  spawned and reaped by one runner thread, so the engine never forks or
  blocks and no zombies accumulate under load.
- **`<setdest host= port= protocol=/>`** (M37): send the rest of a call
  to another peer — retargeting over UDP, re-dialling the call's own
  connection over per-call TCP — with every check SIPp makes and its
  wording. A rejected `setdest` fails that call rather than the run.
  `[remote_ip]`/`[remote_port]` keep the nominal remote, as in SIPp.
- `ereg search_in="body"` and `search_in="var" variable="…"`, which
  SIPp's documented setdest idiom relies on.

### Notes

- Three SIPp behaviors met on the way are recorded in
  `docs/SIPP_COMPAT.md` §6 and deliberately not copied: `[next_url]`
  needs `rrs="true"` to carry the Contact in SIPp, `[last_*]` inside a
  recv's own actions still name the previous message there, and SIPp's
  `echo [last_From]` example breaks under any shell without quoting.

## [0.25.0] — 2026-09-19

### Added

- **Manual transactions** (M36): `start_txn` and `ack_txn` on `<send>`,
  `response_txn` on `<recv>`. A recv so named matches only a response
  whose top Via branch is the one its request carried, which tells
  concurrent transactions of the same method apart. SIPp's placement and
  usage errors are reported with its wording, requests naming a
  transaction leave the CSeq-method guard list, and late responses to a
  named transaction are handled as SIPp does: a provisional is ignored, a
  final one for an INVITE transaction gets the recorded ACK sent again,
  and a repeat of the final already taken is ignored. `--check` lists the
  transactions. Verified against real sipp both ways.

## [0.24.0] — 2026-09-19

### Added

- **Dynamic users** (M35): `<User variables="…"/>` and
  `<Global variables="…"/>` give variables a life beyond the call — one
  table per user id, kept for the run, and one for the whole process,
  shared by both scenarios — resolved at compile time into a layered
  store with no allocation on the hot path. `set users` now follows
  SIPp's id bookkeeping exactly: the pool is served from the back, a call
  ending while more calls are live than the target retires its id, and a
  later growth reactivates retired ids (with their variables) before
  creating fresh ones. SIPp's `-set VARIABLE VALUE` seeds a global;
  `dump variables` over the control socket lists the scopes; `--check`
  prints them. Verified against real sipp both ways.

### Fixed

- Variable values now render and test exactly as in SIPp: a double is
  written with `%lf` (`3.000000`, sipr used to print `3`), a true bool as
  `true`, and a zero double, a false bool or an unset variable as
  nothing at all; `test="var"` and `condexec` on a message take the same
  "is set" view (a `"0"` or `"false"` string is set, a zero counter is
  not). Scenarios that compared a rendered counter against `3` should
  compare against `3.000000` — that is what SIPp sends.

## [0.23.0] — 2026-09-13

### Added

- **Mixed mode** (`-rxsf <file>` / `-rxsn <name>`, `-rxinf <file>`) — a
  second, server-mode scenario terminates the calls the peer originates
  towards us while the client-mode main scenario originates ours, as in
  SIPp: own statistics, rx calls never counting toward `-m`/`-l`/`-users`,
  `-rxinf` files joining the injection table after the `-inf` ones, and
  `set display rx` over the control socket. sipr enforces the role rules
  SIPp's help text only promises. Verified against real sipp both ways.

### Changed

- `set display ooc|main|rx` now switches every screen — counters,
  statistics, repartitions and the scenario page — to the displayed
  scenario, as SIPp does; 0.22.0 swapped only the scenario page. The HTTP
  `/stats` document gains a `mixed` flag.

## [0.22.0] — 2026-09-12

### Added

- **Out-of-call scenarios** (`-oocsf <file>` / `-oocsn <name>`) — a second,
  independently compiled scenario that answers requests mapping to no
  known call, as in SIPp: client mode only, the embedded `ooc_default`
  and `ooc_dummy` (dumpable with `-sd`), own per-step statistics, no
  `[fieldN]`/`-inf` in ooc calls, and ooc calls never count toward
  `-m`/`-l`/`-users`. `set display ooc|main` over the control socket swaps
  the TUI scenario page. Verified both ways against real sipp.

### Fixed

- `regexp_match="true"` on `<recv>` was parsed but never applied by the
  matcher, so a `request=".*"` step matched nothing.

## [0.21.0] — 2026-09-06

### Added

- **SCTP transport** (`-t s1|sn`) behind the new off-by-default `sctp`
  cargo feature, via `socket2`: one SCTP message per SIP message as SIPp
  does, mono and per-call associations, reconnection. Needs an OS SCTP
  stack at run time (Linux with the `sctp` module); SIPp's SCTP option
  flags are rejected with an explanation. Exercised in Linux CI against a
  SIPp built with `USE_SCTP`.

### Fixed

- CI now runs on pushes to `master` (it only ran for pull requests) and
  builds SIPp 3.7.7 from source for the interop suite; a few tests that
  raced the echo threads' counters or assumed macOS socket timing are
  settled.

## [0.20.0] — 2026-09-05

### Added

- **`-t ui`** — one UDP socket per IP address from the injection file
  (`-ip_field`): each client call sends from its line's IP, a server
  binds every listed IP and answers on the one the request hit, and the
  new `[server_ip]` keyword renders the IP a call sends from — SIPp's
  per-IP mode for emulating many user agents.

## [0.19.0] — 2026-09-05

### Added

- **TCP/TLS reconnection** — `-max_reconnect`, `-reconnect_close`,
  `-reconnect_sleep`: when the mono TCP/TLS connection drops, the calls on
  it fail (or, with `-reconnect_close false`, live on), the call whose send
  finds it dead fails, and the connection is re-dialed within the budget
  after the sleep — SIPp's reset, in SIPp's order; with no budget left the
  run ends with exit 255 like SIPp's fatal error. Verified both ways
  against real sipp.

## [0.18.0] — 2026-09-05

### Added

- **`-rsa host[:port]`** — the remote sending address: a UAC sends every
  message there instead of to the target, a UAS answers there (from a
  socket of its own) instead of to the request's source, and the keywords
  keep naming the nominal remote, as in SIPp. Verified both ways against
  real sipp.

## [0.17.0] — 2026-09-05

### Added

- **Per-call sockets** — `-t un`, `-t tn`, `-t ln`: every call opens its
  own UDP socket or TCP/TLS connection at its first send (SIPp's
  multisocket modes), `[local_port]` names it, and `-max_socket` caps how
  many are open before calls share them round-robin. `<closecon/>` now
  closes a per-call socket for real. Verified both ways against real sipp.

## [0.16.0] — 2026-09-05

### Added

- **SIPp's unexpected-message handler** — `<label id="_unexp.main"/>`,
  `_unexp.retaddr`, `_unexp.pausedaddr`, `<jump variable=>` and
  `<pauserestore>`: an unexpected in-call message jumps to the handler,
  which answers it and resumes the interrupted pause for exactly its
  remaining time. Verified both ways against real sipp.
- **`<closecon/>`** is accepted (a no-op, as SIPp's reference-count drop is
  on every mono-socket transport).

## [0.15.0] — 2026-09-05

### Added

- **`<verifyauth>`** — sipr can play a digest-checking registrar: the
  received `Authorization:` header is verified against a username and
  password (MD5 or SHA-256, qop auth/auth-int, `-auth_uri`) and the
  boolean verdict drives `test=` branching, exactly SIPp's documented
  recipe. Verified in both directions against real sipp.

## [0.14.0] — 2026-09-05

### Added

- **SRTP echo server** — `exec rtp_echo="startaudio|updateaudio|stopaudio|
  startvideo|updatevideo|stopvideo[,pt[,name]]"`: the call echoes (S)RTP on
  its advertised media port, re-keyed from the SDES negotiation with the
  caller's SSRC and sequence numbers preserved. SIPp's
  `pfca_uas_*_crypto_*.xml` scenarios now run unchanged, and real sipp's
  UAC passes its own RTP check against them.

### Fixed

- `ereg search_in="hdr"` now hands the regexp what SIPp does: the rest of
  the first matching line after the header string (so `header="CSeq:"`
  works and `CSeq: [$1]` replays the caller's CSeq), and an absent header
  fails the call under `check_it`.

## [0.13.0] — 2026-09-05

### Added

- **`[authentication]` from an injection field** — a CSV column holding
  `[authentication username=… password=…]` (or AKA parameters) is
  re-parsed as the keyword at send time, SIPp's documented way to give
  each call its own credentials.

### Fixed

- `[authentication]` now renders the whole header line as SIPp does
  (`Authorization:` after a 401, `Proxy-Authorization:` after a 407), so
  SIPp scenarios that place the keyword on its own line work unchanged.
  sipr's earlier `Authorization: [authentication …]` spelling still works.

## [0.12.0] — 2026-09-05

### Added

- **SRTP with SDES keying** — SIPp's crypto keywords (`[cryptotag1audio]`,
  `[cryptosuiteaescm128sha1801audio]`, `[cryptokeyparams1audio]`, the
  `ue…` unencrypted forms, secondary and video variants) render offers
  and answers; the peer's `a=crypto:` lines are parsed; `rtp_stream`
  packets are protected with AES-CM-128 or the NULL cipher and HMAC-SHA1
  80/32, and the echo check unprotects the echo before comparing. All
  cryptography is in-tree and verified against RFC 3711's vectors. Unlike
  SIPp, the authentication tag uses the packet's own rollover counter, so
  streams stay valid past sequence 65535.

### Fixed

- The CSeq-method guard on `recv response=` now follows SIPp exactly: a
  response matches when its CSeq method is any request method sent so
  far, not only the most recent one. A 200 to the INVITE arriving after a
  PRACK was wrongly treated as unexpected.

## [0.11.0] — 2026-09-04

### Added

- **`hide` and `display` attributes, and SIPp's screen keys** — `hide="true"`
  keeps a step off the scenario screen while `set hide true` (the default)
  holds; `display="…"` replaces its label. Both reach `/stats`. The `1`/`2`/`3`
  keys switch screens at the keyboard and over the control socket.

## [0.10.0] — 2026-09-04

### Added

- **`-auth_uri`** — SIPp's flag for the digest `uri=`; the value gets a
  `sip:` prefix exactly as SIPp does.
- **Keywords inside `[authentication]` parameters** — `username=[field0]`,
  `password=[$p]`, `aka_K=[field2]` and friends are rendered before use,
  as SIPp renders them, so credentials can come from injection files.

### Changed

- The default digest `uri=` is now SIPp's `sip:remote_ip:remote_port`
  (no user part) instead of `sip:service@remote_ip:remote_port`. Servers
  verify against the header's own `uri=`, so runs are unaffected; the
  wire form now matches SIPp byte for byte.

## [0.9.0] — 2026-09-04

### Added

- **Rate ramps** — SIPp's `-rate_increase N`, `-rate_interval TIME`
  (seconds or `ms`/`s`/`m`/`h`), `-rate_max N`, and `-no_rate_quit`:
  the rate climbs every interval and, when it would pass the cap, is
  clamped there and the run drains (unless told not to). Also
  `-rate_scale` for the hot-key step.

## [0.8.0] — 2026-09-04

### Added

- **AKA resynchronisation (AUTS)** — `[authentication … aka_sqn=0x…]`
  gives the client's SQN_MS; a challenge whose SQN is not above it (or any
  challenge with `aka_resync=1`) is answered with `auts=` and an
  empty-password digest per RFC 3310 §3.2 / TS 33.102 §6.3.3, then the
  server's fresh challenge is answered normally. SIPp's resync code is
  unreachable, so this is new ground for SIPp scenarios.

## [0.7.0] — 2026-09-04

### Added

- **RTP echo and the RTP check** — `-rtp_echo` (with `-mb`) echoes RTP
  received on the media port and media port + 2 back to its sender, with
  SIPp's counters and the `<rtp_echo value="0|1"/>` action to toggle it;
  `rtp_stream` sockets now read back what the peer echoes and compare it
  to what was sent, and `-audiotolerance` / `-videotolerance` turn that
  into SIPp's verdict: a failed check exits 253 (SIPp's -3). Unlike SIPp,
  a stream is judged only when a tolerance flag is given. New counters on
  the TUI, the `-bg` line, and `/stats`.

## [0.6.0] — 2026-09-04

### Added

- **Runtime control** — SIPp's UDP control socket (`-cp`, `-ci`: hot keys
  and `c`-prefixed `set/trace/dump/reset` commands with SIPp's grammar and
  warning texts; default bind is loopback and `-cp 0` disables it) and a
  new HTTP/JSON API (`--sipr-http [HOST:]PORT`, `--sipr-http-token`):
  `/health`, `/stats`, `/control`, `/quit`, `/command`, `/scenario`.
  See `docs/CONTROL_API.md`. New std-only crate `sipr-control`.
- Hot keys now follow SIPp exactly: `set rate-scale` steps, user-count
  keys in `-users` mode, and a second `q` aborts like `Q`.

## [0.5.0] — 2026-09-04

### Added

- **IMS AKA authentication (`AKAv1-MD5`, RFC 3310)** — `[authentication
  aka_K=0x… aka_OP=0x… aka_AMF=0x…]` (SIPp's parameters, plus `aka_OPc=`)
  against an `algorithm=AKAv1-MD5` challenge: the nonce's RAND/AUTN go
  through an in-tree Milenage (AES-128, verified on 3GPP TS 35.208 test
  sets), the MAC is checked, and RES becomes the digest password. A MAC
  mismatch fails the call with a clear reason where SIPp aborts the whole
  process. No new dependency.

## [0.4.0] — 2026-09-04

### Added

- **RTP streaming and DTMF (`exec rtp_stream=`, `exec play_dtmf=`)** —
  SIPp's `rtpstream.cpp` semantics on the M14 scheduler: raw codec files or
  `apattern`/`vpattern` fills with SIPp's fixed payload table, looping,
  `pause`/`resume` (the clock keeps running, as in SIPp), SSRC
  `0xCA110000`-based, plus RFC 4733 DTMF bursts with SIPp's exact timing.
  `[rtpstream_audio_port]`/`[rtpstream_video_port]` keywords with per-call
  allocation, `-rtp_payload`, `-max_rtp_port`, `-random_base_ssrc`. sipr
  streams from the port the SDP advertised (SIPp binds an unrelated one)
  and numbers DTMF packets consecutively (SIPp skips every other warm-up
  number). Divergences in `docs/SIPP_COMPAT.md` §6.

## [0.3.0] — 2026-09-04

### Added

- **pcap replay (`exec play_pcap_audio|video|image=`)** — SIPp's media
  feature, without the raw socket: a new std-only `sipr-media` crate reads
  classic pcap files (Ethernet/802.1Q, raw IP, Linux cooked, BSD loopback;
  IPv4/IPv6 UDP), learns the peer's media endpoint from its SDP, and replays
  the UDP payloads verbatim on the capture's timeline from one scheduler
  thread, through ordinary UDP sockets bound to the advertised media port —
  no root, no libpcap. `-mi`/`-mp` (`-min_rtp_port`), `[auto_media_port]`,
  `[media_port+N]`, `<recv ignoresdp>`. RTP counters on the TUI, `-bg` line,
  and the final summary. Divergences from SIPp in `docs/SIPP_COMPAT.md` §6.

## [0.2.0] — 2026-09-03

### Added

- **TLS transport (`-t l1`)** — SIP over TLS with SIPp's exact semantics:
  same connection-per-peer model and Content-Length framing as TCP, no SIP
  retransmissions, port 5060, `[transport]` renders `TLS`. `-tls_cert` /
  `-tls_key` (defaults `cacert.pem`/`cakey.pem`), `-tls_ca` / `-tls_crl`
  (presence enables SIPp-style verification: chain but not hostname on the
  client, mandatory client cert on the server), `-tls_version 1.2|1.3`.
  Built on `rustls` with the `ring` provider — the workspace's first
  external dependency, still no system OpenSSL required. Divergences from
  SIPp documented in `docs/SIPP_COMPAT.md` §6.

### Changed

- The `dependencies: std-only` claim is retired: `sipr-net` now carries
  `rustls`/`rustls-pemfile` for the TLS transport. Everything else remains
  std; the build still needs no system libraries.

- **IPv6** — targets accept bracketed (`[::1]`, `[2001:db8::1]:5060`) and
  bare-literal (`::1`) IPv6, with automatic `::` binding when a v6 target is
  given without `-i`. `[local_ip]`/`[remote_ip]` render bracketed inside URIs
  and Via (SIPp's `local_ip_w_brackets`), while `[media_ip]` stays raw for SDP.
  See `docs/SIPP_COMPAT.md` §6.

## [0.1.1] — 2026-08-17

Post-v1 feature drop: TCP transport, injection files with indexed lookups,
classic 3PCC, and closed-loop `-users` mode. Still standard-library only.

### Added

- **Closed-loop `-users`** — `-users N` keeps N concurrent calls, each holding
  a stable 1-based user id; a finished call's id is recycled into a replacement
  immediately. Adds the `[userid]`/`[users]` keywords and lights up USER-mode
  `-inf` injection (line = user id − 1). Mutually exclusive with `-l`. See
  `docs/SIPP_COMPAT.md` §6.
- **Classic 3PCC** — `-3pcc HOST:PORT` plus `<sendCmd>`/`<recvCmd>` steps let
  two sipr instances coordinate over a separate ESC-delimited TCP "twin"
  socket. The role is derived from the scenario's first twin command
  (`sendCmd`-first dials, `recvCmd`-first listens); `<recvCmd>` blocks the call
  until a command arrives and runs its actions against the command text. See
  `docs/SIPP_COMPAT.md` §6.
- **TCP transport** — `-t t1` runs SIP over TCP. A stream framer de-frames
  messages by `Content-Length` (RFC 3261 §7.5); the client keeps one
  connection to the target, the server accepts connections and replies on the
  one each request arrived on. Reliable transport, so no SIP retransmissions
  are scheduled. `-t tn` is accepted as an alias. See `docs/SIPP_COMPAT.md` §6.
- **Injection files** — `-inf FILE` (repeatable) loads SIPp-style injection
  files: a `SEQUENTIAL`/`RANDOM`/`USER` mode header, `;`-separated fields,
  `#` comments, blank-line terminator. One line is drawn per call per file
  (SEQUENTIAL cycles, RANDOM picks uniformly, USER defers to `-users`). The
  `[fieldN]` keyword substitutes field N of the drawn line. `file=NAME`
  selects another file by its basename (SIPp's key), or by a 0-based `-inf`
  index (sipr extension); `line=` overrides the per-call line and is rendered
  at send time, so `line=[$var]` works. Unknown field/file names are rejected
  at load. See `docs/SIPP_COMPAT.md` §6.
- **Indexed injection** — `-infindex FILE FIELD` builds a key→line index over
  one field of an `-inf` file (matched by basename; last line wins on
  duplicate keys). Actions `<lookup assign_to=… file=… key=…/>` (stores the
  matched line or -1), `<insert file=… value=…/>` (appends a row), and
  `<replace file=… line=… value=…/>` (swaps a row) operate on that data at
  runtime. The canonical use is `lookup → [fieldN line=[$var]]`.

### Fixed

- Body-less SIP messages (180, ACK, empty 200) now always include the
  mandatory `\r\n\r\n` header/body separator. UDP tolerated its absence; TCP
  framing and real-SIPp interop require it.

## [0.1.0] — 2026-08-16

First release. A SIPp-compatible SIP testing tool and traffic generator,
feature-complete for signaling over UDP. Built entirely on the Rust standard
library — no external crates.

### Added

- **Scenarios** — SIPp-compatible XML: `send`, `recv`, `pause`, `nop`,
  `label`, `timewait`, `Reference`, and the response/call-length repartition
  tables. Loud diagnostics with file:line context; `--check` lint mode that
  prints the compiled IR.
- **Keywords** — `[service]`, `[remote_ip]`/`[remote_port]`,
  `[local_ip]`/`[local_port]`, `[transport]`, `[call_id]`, `[call_number]`,
  `[cseq]`, `[branch]`, `[msg_index]`, `[pid]`, `[routes]`, `[next_url]`,
  `[peer_tag_param]`, `[len]`, `[last_*:]`, `[$var]`, `[authentication]`, and
  the `[media_*]` placeholders.
- **Actions** — `ereg` (capture groups via an in-tree POSIX-ERE engine),
  `assign`/`assignstr`/`strcmp`/`test`, arithmetic (`add`/`subtract`/
  `multiply`/`divide`), `todouble`, `trim`, `urlencode`/`urldecode`,
  `gettimeofday`, `jump`, `log`/`warning`/`error`, `exec int_cmd`. Plus
  `test`/`condexec` branching, `chance`, named counters, and per-call
  variables.
- **Engine** — UAC and UAS roles; open-loop pacer (`-r`/`-rp`/`-l`/`-m`) with
  rate smoothing; single event-loop over UDP, timers, and the pacer. Recv
  matching (optional-recv windows, backward contiguous scan, CSeq-method
  guard) verified against SIPp's `call.cpp`.
- **Transport** — UDP with RFC 3261 T1→T2 retransmission, inbound
  retransmission handling, simulated loss (`lost`), and an in-tree SIP
  message parser proven panic-free by a fuzz suite.
- **Authentication** — digest MD5 and SHA-256 (`qop=auth`, proxy 407), with
  in-tree hash primitives verified against the RFC 1321 / FIPS 180-4 /
  RFC 2617 / RFC 7616 vectors.
- **Statistics** — SIPp counter set with failure breakdown, response-time
  histograms and RTDs, repartition tables, `-trace_stat`/`-stf`/`-fd` CSV,
  and `-trace_msg`/`-trace_err` files.
- **Live TUI** — main / per-step scenario / repartition screens, live rate
  keys (`+ - * /`), pause (`p`), screen cycling (`s`), and safe terminal
  restore on every exit path. Ferrous brand colors, honoring `NO_COLOR`.
- **CLI** — SIPp-style single-dash flags with did-you-mean suggestions;
  SIPp-compatible exit codes (0 ok, 1 failures, 99 no calls, 2 usage,
  255 fatal).
- **Tooling** — six-crate workspace, `Makefile` convenience targets, CI
  (fmt + clippy + tests, and an interop job against real SIPp), and the
  Ferrous brand kit under `brand/`.

### Known limitations

- Signaling only over UDP. TCP/TLS, `-inf` injection files (and the
  `lookup`/`insert`/`replace` actions), 3PCC, RTP/pcap media, IPv6, and an
  HTTP control API are on the post-v1 roadmap.
- The `ereg` regex engine is leftmost-first greedy (PCRE-style), not POSIX
  leftmost-longest — identical on the patterns real scenarios use; see
  `docs/SIPP_COMPAT.md` §6.

[Unreleased]: https://github.com/tareqmy/sipr/compare/v0.27.0...HEAD
[0.27.1]: https://github.com/tareqmy/sipr/compare/v0.27.0...v0.27.1
[0.27.0]: https://github.com/tareqmy/sipr/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/tareqmy/sipr/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/tareqmy/sipr/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/tareqmy/sipr/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/tareqmy/sipr/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/tareqmy/sipr/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/tareqmy/sipr/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/tareqmy/sipr/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/tareqmy/sipr/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/tareqmy/sipr/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/tareqmy/sipr/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/tareqmy/sipr/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/tareqmy/sipr/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/tareqmy/sipr/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/tareqmy/sipr/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/tareqmy/sipr/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/tareqmy/sipr/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/tareqmy/sipr/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/tareqmy/sipr/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/tareqmy/sipr/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/tareqmy/sipr/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/tareqmy/sipr/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/tareqmy/sipr/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/tareqmy/sipr/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/tareqmy/sipr/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/tareqmy/sipr/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/tareqmy/sipr/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tareqmy/sipr/releases/tag/v0.1.0

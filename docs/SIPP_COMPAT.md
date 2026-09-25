# SIPp compatibility surface

What "SIPp-compatible" means, precisely. Source of truth for the grammar:
`../../cprojects/sipp/sipp.dtd`; for behavior: the SIPp docs
(https://sipp.readthedocs.io) and, where those are ambiguous, the C++ source
(`../../cprojects/sipp/src/`, mainly `scenario.cpp` and `call.cpp`).

Rule zero: anything we do not implement must fail **loudly** (warning with
file:line at load; hard error under `--check`). No silent skips, ever.

## 1. Scenario elements and attributes

### v1 tier (M1–M6)

| Element | Attributes (v1) | Notes |
|---|---|---|
| `scenario` | `name` | |
| `send` | common⁺, `retrans`, `lost`, `crlf`, `start_txn`, `ack_txn` | CDATA body = message template; the `_txn` attrs name a transaction (M36, §6) |
| `recv` | common⁺, `response`, `request`, `optional`, `timeout`, `ontimeout`, `rrs`, `auth`, `lost`, `regexp_match`, `response_txn` | |
| `pause` | common⁺, `milliseconds`, `variable`, `distribution` + its parameters, `sanity_check` | all ten SIPp distributions, SIPp's attribute names and old-style `min`/`max` (M38, §6) |
| `nop` | common⁺, `display` | carries actions |
| `label` | `id` | jump target; validated at compile |
| `timewait` | `milliseconds` | end-of-call linger |
| `Reference` | `variables` | suppress unused-var warnings |
| `Global` | `variables` | comma list of run-wide variables (M35, §6) |
| `User` | `variables` | comma list of per-user-id variables (M35, §6) |
| `ResponseTimeRepartition` | `value` | ms bucket list |
| `CallLengthRepartition` | `value` | ms bucket list |

⁺ common attrs: `start_rtd`, `rtd`, `repeat_rtd`, `crlf`, `next`, `test`,
`chance`, `condexec`, `condexec_inverse`, `counter`.

### v1 actions (inside `<action>` on recv/nop)

`ereg` (with `assign_to`, `check_it`, `header`, `regexp`, `search_in`
= `msg|hdr|body|var`, `variable`, `start_line`), `log`, `warning`, `error`, `assign` (`value`/`variable`), `assignstr`, `strcmp`,
`verifyauth` (with `assign_to`, `username`, `password`), `pauserestore`
(`value`/`variable`), `closecon`, `test`, `add`, `subtract`, `multiply`, `divide`, `todouble`, `jump`, `trim`,
`gettimeofday`, `urlencode`, `urldecode`, `sample` (`assign_to`, `distribution`
+ its parameters; M38, §6), `jump` (`value`/`variable`; the
`_unexp.main` label, `_unexp.retaddr` and `_unexp.pausedaddr` recipe),
`exec` with `int_cmd` (`stop_now`, `stop_gracefully`, `stop_call`) or
`command=` (an external shell command, M37), `setdest` (`host`, `port`,
`protocol`; M37, §6).

### v1.x tier (fast follow)

Manual transactions (`start_txn`/`ack_txn`/`response_txn`) shipped in
M36, `exec command=` and `setdest` in M37, statistical pauses and `sample`
in M38 — the tier is complete. `index` as a standalone action stays out — sipr builds the index from `-infindex` at load,
not from a scenario action. Extended 3PCC (`-master`/`-slave`/`-slave_cfg` with
`dest=`/`src=` peer routing) shipped in M43; classic `-3pcc` in M10 (both in §6).

`-inf` injection + `[fieldN]` and `lookup`/`insert`/`replace` shipped in M7,
classic 3PCC (`sendCmd`/`recvCmd`) in M10 (see §6).

### Media (M14–M15)

Shipped: `exec play_pcap_audio|video|image=` and `<recv ignoresdp>` (M14),
`exec rtp_stream=` (file/pattern/pause/resume) and `exec play_dtmf=` (M15) —
`-rtp_echo` + rtpcheck (M18), SRTP (M23), `exec rtp_echo=` (M25) — see §6.

## 2. Keywords (v1)

`[service]` `[remote_ip]` `[remote_port]` `[server_ip]` (the IP this call sends from; `-t ui`) `[local_ip]` `[local_ip_type]`
`[local_port]` `[transport]` `[call_id]` `[call_number]` `[userid]` `[users]`
`[cseq]` `[branch]` `[msg_index]` `[pid]` `[routes]` `[next_url]` `[peer_tag_param]`
`[last_*]` (verbatim copy of header(s) from last received message, e.g.
`[last_Via:]`, `[last_From:]`) `[$var]` `[authentication]` (+ `username=`/
`password=` params) `[len]` (Content-Length auto-compute) `[field0..N]` (v1.x,
with injection files).
M39 keywords (§6): `[clock_tick]` `[timestamp]` `[date]` `[sipp_version]`
`[dynamic_id]` `[remote_host]` `[tdmmap]` `[last_message]`
`[last_cseq_number]` (with `+N`/`-N`) `[fill variable= text=]`
`[file name=]` and the `-key KEYWORD VALUE` generic keywords `[KEYWORD]`.

Media keywords (M14): `[media_ip]` (`-mi`, default the local IP),
`[media_ip_type]`, `[media_port]` (`-mp`, default 6000, the same value for
every call — as in SIPp), `[auto_media_port]` (per-call 4-port block:
`base + 4*(call_number-1) % 10000`, SIPp's undocumented keyword), and the
`+N` offset forms `[media_port+1]` / `[auto_media_port+2]` (RTCP, video).
`[authentication]` params (M16/M19): `username=` `password=` `aka_K=` `aka_OP=`
`aka_AMF=` (SIPp), `aka_OPc=` `aka_sqn=` `aka_resync=` (sipr additions);
`0x`-prefixed hex or raw bytes.
SRTP/SDES (M23): `[cryptotag{1,2}{audio,video}]`,
`[cryptosuite<suite>{1,2}{audio,video}]`, `[cryptokeyparams{1,2}{audio,video}]`
(`-N` offset = reuse the key), `[ue<suite>{1,2}{audio,video}]`
(`UNENCRYPTED_SRTP`), `<suite>` ∈ `aescm128sha180 aescm128sha132 nullsha180
nullsha132`.
`[rtpstream_audio_port]` / `[rtpstream_video_port]` (M15): a port allocated
to the call from `-mp`..`-max_rtp_port` in steps of two the first time it
renders; `+N` forms never allocate (`a=rtcp:[rtpstream_audio_port+1]`).

Keyword parameters use SIPp syntax `[keyword param=value]`. Unknown keywords:
loud warning + left verbatim in the message (match SIPp behavior — verify in
C++ and record below).

## 3. CLI flags (v1 set, SIPp names)

Scenario/mode: `-sf <file>` `-sn uac|uas|ooc_default|ooc_dummy` `-sd` (dump
embedded) `-oocsf <file>` / `-oocsn ooc_default|ooc_dummy` (out-of-call
scenario, client mode only, M33) `-rxsf <file>` / `-rxsn uas|…` (mixed
mode: a server-mode receive scenario next to the client-mode main one,
M34) `-rxinf <file>` (injection files loaded after the `-inf` ones, for
`[fieldN file=NAME]` in either scenario) `--check` (sipr addition: lint
scenario — and the ooc/rx one — and exit; the lints are in
[LINTS.md](LINTS.md)).
Traffic: `-r <rate>` `-rp <ms>` `-l <max concurrent>` `-m <total calls>`
`-d <pause ms default>` `-users` (v1.x closed loop) `-set <variable>
<value>` (seed a `<Global>` variable, M35) `-rate_increase <n>`
`-rate_max <n>` `-rate_interval <time>` `-no_rate_quit` `-rate_scale <n>`
(M20 ramps).
Network: `-p <local port>` `-i <local ip>` `-t u1|un|ui|t1|tn|l1|ln` (UDP /
TCP / TLS, one socket, one socket per call, or one UDP socket per injected
IP; `s1|sn` = SCTP, only in a build with the `sctp` cargo feature on a host
with an SCTP stack) `-ip_field <n>` (the `-inf` column holding that IP)
`-max_socket <n>` (per-call modes share sockets past n) `-rsa <host[:port]>`
(remote sending address) `-max_reconnect <n>` `-reconnect_close <bool>`
`-reconnect_sleep <ms>` (TCP/TLS reconnection) `-s <service>` (called number)
`-bind_local` `-buff_size <bytes>` `-sendbuffer_warn <bool>`
`-bind_to_device <name>` (M44, §6)
`-tls_cert`/`-tls_key`/`-tls_ca`/`-tls_crl`/`-tls_version` (TLS material,
SIPp defaults `cacert.pem`/`cakey.pem`).
Media: `-mi <ip>` (media address; default local IP) `-mp <port>` (base media
port, default 6000; `-min_rtp_port` is SIPp's alias — note SIPp's `-mp` is
*that* alias too, not a fixed port) `-max_rtp_port` `-rtp_payload <pt>`
(default 8) `-random_base_ssrc` `-rtp_echo` `-mb <bytes>` `-audiotolerance`
`-videotolerance` (M18).
Auth: `-au`/`-ap` (username/password defaults for `[authentication]`)
`-auth_uri` (digest `uri=` after SIPp's `sip:` prefix; default
`remote_ip:remote_port`, M21).
Control (M17): `-cp <port>` `-ci <ip>` (SIPp's UDP control socket; `-cp 0`
disables — sipr addition) and sipr's `--sipr-http [HOST:]PORT` /
`--sipr-http-token` (docs/CONTROL_API.md). Statistics out (M46, sipr
additions): `--sipr-stats-json <file>` (a JSON object per snapshot tick) and
the `/metrics` endpoint on that API (Prometheus text). SIPp has neither.
Tracing/output: `-trace_msg` `-trace_err` `-trace_stat` `-stf <file>`
`-fd <interval s>` (default 60, the `(P)` period) `-f <interval s>` (screen
and `-bg` line refresh, default 1) `-trace_rtt` `-rtt_freq <n>`
`-trace_counts` `-trace_error_codes` `-trace_screen` `-screen_file <file>`
`-stat_delimiter <s>` `-periodic_rtd` (M40, §6) `-trace_logs` `-log_file`
`-trace_shortmsg` `-shortmessage_file` `-trace_calldebug` `-calldebug_file`
`-error_file` `-message_file` `-<kind>_overwrite <bool>` (message, error,
log, shortmessage, calldebug, screen) `-ringbuffer_files` `-ringbuffer_size`
`-max_log_size` `-deadcall_wait <ms>` `-trace_timeout` (accepted; a no-op
in SIPp 3.7 too) (M41, §6) `-nd` (no defaults) `-timeout <s>` `-bg`
(headless).
Behavior toggles: `-aa` (auto-answer OPTIONS/INFO/UPDATE/NOTIFY in-dialog),
`-base_cseq`, `-cid_str` (Call-ID format), `-max_retrans`, `-nr` (no retrans),
`-max_invite_retrans`, `-max_non_invite_retrans`, `-recv_timeout`,
`-timeout_error`, `-lost`, `-pause_msg_ign`, `-default_behaviors`,
`-callid_slash_ign`, `-sleep`, `-nostdin` (M42, §6); `-send_timeout` and
`-timer_resol` are accepted with a warning (no send queue, exact timers).
Keywords (M39): `-key <keyword> <value>` (repeatable), `-tdmmap <map>`,
`-dynamicStart`/`-dynamicMax`/`-dynamicStep` (the `[dynamic_id]` counter),
`-rfc3339` (`[timestamp]` form).
Accepted with a "no effect in sipr" warning (M44, §6): `-watchdog_interval`
`-watchdog_reset` `-watchdog_minor_threshold` `-watchdog_major_threshold`
`-watchdog_minor_maxtriggers` `-watchdog_major_maxtriggers`
`-max_recv_loops` `-max_sched_loops` `-rtp_threadtasks` `-skip_rlimit`
`-plugin` and the SCTP socket options `-multihome` `-heartbeat`
`-assocmaxret` `-pathmaxret` `-pmtu` `-gracefulclose`.

Where sipr needs a flag SIPp lacks, prefix long-form `--sipr-*` to keep the two
namespaces distinct.

`hide="true"` and `display="…"` on any message command (M22): the scenario
screen skips hidden rows while `set hide true` (default) holds, and shows
`display` text instead of the derived label.

### 3.1 Flags accepted but without effect

These steer machinery sipr does not have: SIPp's event-loop scheduler and
watchdog task (`-watchdog_*`, `-max_recv_loops`, `-max_sched_loops`), its
RTP playback thread pool (`-rtp_threadtasks`), its file-descriptor rlimit
tuning (`-skip_rlimit`), its `dlopen` plugins (`-plugin`), and the SCTP
socket options only libsctp can set (`-multihome`, `-heartbeat`,
`-assocmaxret`, `-pathmaxret`, `-pmtu`, `-gracefulclose`). sipr parses each,
prints one `sipr: warning: -<flag> has no effect in sipr: <why>` line, and
carries on, so a CI wrapper written for sipp keeps working instead of dying
at argument parsing. This is the **only** sanctioned exception to "an
unknown flag is an error": a flag not in this list and not implemented is
still a usage error. `-send_timeout` and `-timer_resol` (M42) warn the same
way for the same reason.

## 4. Runtime key bindings (TUI)

`+`/`-` rate ±1 (`*`,`/` ±10), `p` pause traffic, `s`..screens cycle, `q` soft
quit (drain), `Q` hard quit. Match SIPp muscle memory exactly.
SIPp's screen digits `1` (scenario) `2` (statistics) `3` (repartition) also
work, at the keyboard and over the control socket (M22).

## 5. Exit codes

0 = all calls successful; 1 = at least one call failed; 97 = exit on internal
command / user abort; 99 = aborted, no calls processed; -1/255 = fatal error;
-3/253 = an RTP echo check failed (`EXIT_RTPCHECK_FAILED`, M18; wins over the
call-failure code, as in `sipp_exit`). sipr adds 2 = usage error.

## 6. Behavior notes (folklore learned from docs/C++ — append as discovered)

- Recv matching — VERIFIED in `call.cpp` (`process_incoming`, the two scan
  loops around line 5360, and `matches_scenario`); implemented in
  `sipr-engine/src/engine.rs::scan_for_match`:
  - *Forward scan* from the current index: unmatched optional recvs are
    skipped; the scan stops at the first mandatory recv (inclusive) or any
    non-recv step. A match may land on any step in that window; execution
    resumes after the matched step (skipped optionals are passed for good).
  - *Backward scan* when forward fails: only the contiguous optional block
    immediately behind the window may re-match (out-of-order provisionals);
    `contig` is broken by ANY non-optional message including sends — a late
    180 arriving after the ACK is *unexpected* and kills the call, exactly
    as in SIPp. (`optional="global"` would bypass contig; sipr rejects that
    value until implemented.)
  - *CSeq-method guard*: beyond index 0, a response only matches a recv if
    its CSeq method occurs in the list of **all** request methods sent so
    far (`recv_response_for_cseq_method_list`, built by concatenating each
    send's method in `scenario.cpp` and tested with `strstr`) — so after
    INVITE and PRACK both 200s match the following recvs, while a response
    to a method never sent cannot. (Until M23 sipr kept only the nearest
    preceding method, which rejected the INVITE's 200 after a PRACK.)
- `regexp_match="true"` (verified in `call.cpp` `matches_scenario`
  ~l.4540-4575): the request expectation runs as an unanchored POSIX
  extended regex (`REG_NOSUB`) over the **method**, the response one over
  the **decimal status code** (`snprintf("%u")`), and the CSeq-method guard
  above still applies afterwards. So `request=".*"` takes any request and
  `response="18[0-9]"` any 18x. Until M33 sipr compiled the regex but then
  matched literally — fixed with M33 (`recv_matches`).
- Out-of-call scenarios (M33; verified in `sipp.cpp` ~l.1792-1800 (parse),
  ~l.2113-2116 (the `ooc_default` fallback is **commented out**),
  ~l.2147-2149 (server-mode fatal), `socket.cpp` ~l.1160-1240
  (`process_message` dispatch), `call.cpp` ~l.6641 (`-inf` fatal),
  `scenario.cpp` ~l.1933 (embedded names), `reporttask.cpp` ~l.94 (only
  the main stats are ever dumped)): `-oocsf <file>` / `-oocsn <name>` load
  a second, independently compiled scenario with its own variable table,
  per-step stats and repartitions. In **client mode** a *request* whose
  Call-ID matches no live call spawns a call on it — keyed by that Call-ID,
  remote = the packet's source (or `-rsa`), no user id and no injection
  line (`[userid]` renders 0; any `[fieldN]` in the ooc scenario is fatal at
  startup: "Automatic calls (created by -aa, -oocsn or -oocsf) cannot use
  input files!") — logs "Received out-of-call METHOD message, using the
  out-of-call scenario", counts an incoming call on the **ooc** stats plus
  the global auto-answered counter, and feeds it the request at step 0
  (`ooc_dummy` then fails it as unexpected, on the ooc stats). An unmapped
  *response* is only counted (`E_OUT_OF_CALL_MSGS` = sipr's `unexpected`)
  and never spawns anything, ooc scenario or not. Without `-oocs*` a UAC
  keeps discarding unmapped requests the same way — SIPp's default since
  the fallback was commented out. Server mode is fatal ("SIPp cannot use
  out-of-call scenarios when running in server mode"); `-oocsf` and
  `-oocsn` are mutually exclusive. SIPp's `open_calls` counts main-scenario
  calls only, so ooc calls never count toward `-l`, `-users` or `-m`, and
  the run ends when the main calls are done — lingering ooc calls (the
  default's 4 s timewait) are dropped. `set display ooc|main` swaps
  *every* screen — the main counters, the statistics and repartition
  screens and the scenario page — to that scenario, as SIPp's `screen.cpp`
  reads `display_scenario->stats` throughout (v0.22.0 had only the
  scenario page follow; corrected with M34); `-trace_stat` never writes an
  ooc CSV (SIPp's `stattask::report` dumps `main_scenario->stats` only)
  and the exit code always reflects the main scenario. Two SIPp
  behaviours seen in the interop runs and *not* reproduced: on exit SIPp
  aborts its lingering ooc calls with a BYE (its generic established-call
  abort, `sipp_exit`); and a SIPp **UAS** spawns a main-scenario call for
  *any* unmapped message, responses included — the 200 answering its own
  out-of-call OPTIONS fails a call and eats its `-m` budget — where a sipr
  UAS keeps discarding unmapped responses. Mixed mode (`-rxsf`) is the
  next note.
- Mixed mode `-rxsf <file>` / `-rxsn <name>` + `-rxinf` (M34; verified in
  `sipp.cpp` ~l.174-197, 1778-1790, 1584-1605, 2140-2148, 556-561, 1182,
  `socket.cpp` ~l.1184-1195, `screen.cpp` ~l.83-90, 242-245, 294, 710,
  796): a second, server-mode scenario terminates the calls the peer
  originates towards a client-mode main scenario. SIPp quirks worth
  knowing: (1) in SIPp 3.7 **only `-rxsf` works** — the option table
  spells the embedded variant `rxrn` while the parser expects `rxsn`, so
  `-rxsn` is an unknown option and `-rxrn` an "Internal error" (the help
  text's `-snrx`/`-sfrx` exist nowhere); sipr accepts `-rxsn` as the
  parser intends and `-rxrn` not at all. (2) `-rxinf` registers the CSV in
  the shared file map under its basename, but the `rx_default_file` it
  sets is never read: a bare `[fieldN]` in the rx scenario means the first
  `-inf` file ("No injection file was specified!" without one) and
  `[fieldN file=name.csv]` reaches a `-rxinf` file by name — sipr does the
  same, loading `-rxinf` files after the `-inf` ones into one table.
  (3) SIPp enforces none of its help text's "rx MUST be server-mode, main
  MUST be client-mode"; sipr does, at startup, and also refuses
  `<sendCmd>`/`<recvCmd>` in the rx scenario and `-rxs*` together with
  `-oocs*` (`process_message` takes the `MODE_MIXED` arm first, so an ooc
  scenario never fires in mixed mode). (4) Dispatch: SIPp spawns an rx
  call for *any* unmapped message, responses included and even while
  quitting (that check is commented out), logging nothing; sipr spawns for
  unmapped *requests* only — no user id, injection lines drawn like a UAS
  call's, counted as an incoming call on the rx stats, a sipr-only line in
  the error trace — and keeps discarding unmapped responses as its UAS
  does. (5) Rx calls never count toward `-l`/`-users`/`-m`
  (`call_generation_task.cpp` and the main loop look at `main_scenario`),
  so the run ends with the main calls and lingering rx calls are dropped:
  a `timewait` at the end of the main scenario is how a mixed-mode side
  stays up for the peer's last call (the interop tests do this). (6) `set
  display rx|main` switches every screen, see the ooc note; SIPp's header
  reads "Sipp Mixed Mode - main|rx". (7) Not reproduced: SIPp's exit code
  comes from whichever scenario is *displayed* at exit (`sipp.cpp`
  ~l.1182) — sipr's always reflects the main scenario — and SIPp's exit
  abort BYEs lingering rx calls. (8) `<init>`: SIPp never runs the rx
  scenario's; sipr has no `<init>` support at all (an unknown element is a
  hard error), so there was nothing to decide. `-trace_stat` stays
  main-only.
- A matched recv cancels the pending retransmission of the last send
  (`next_retrans = 0`) — including a matched *provisional*. SIPp's own code
  carries a TODO admitting this can erroneously stop retransmission (e.g.
  180 received, 200 lost → the call stalls until a timeout). sipr reproduces
  the behavior faithfully; scenarios can mitigate with `timeout`/`ontimeout`
  on the mandatory recv.
- Pacing: SIPp smooths call starts within the rate period rather than
  bursting `-r` calls at once; sipr ticks every ≤20 ms and accumulates
  fractional starts.
- UAS behaviors (M4): an inbound retransmission (same branch/CSeq/start
  line) is answered by re-sending our last message; during `timewait` the
  call absorbs traffic without failing (SIPp deadcall). `-aa` answers
  in-dialog OPTIONS/INFO/UPDATE/NOTIFY with a 200 mirroring
  Via/From/To/Call-ID/CSeq. UAS calls reply to the request's source
  address — as SIPp does: it keeps the source as `call_peer` and never
  reads Via `received`/`rport` (checked in M42; no divergence).
- `-trace_stat` CSV (M4, at parity since M40 — see the M40 note): SIPp's
  columns, names, order, `(P)`/`(C)` naming and `;` delimiter.
- `-l` cap: calls above the concurrent cap are not queued — the pacer simply
  does not start them; effective rate drops.
- `[branch]` must be unique per transaction and RFC 3261 magic-cookie prefixed
  (`z9hG4bK`); SIPp derives it from call number + msg index — mirror the shape.
- Retransmission: applies to UDP sends awaiting a matching recv; `recv` with
  `timeout` + `ontimeout` jump is the scenario-level timeout mechanism.
- `auth="true"` on a recv of 401/407 stores the challenge; the next send's
  `[authentication]` keyword consumes it. Stale nonce handling: re-auth once.
- Default headers: SIPp does NOT auto-add headers to templates (what you write
  is what is sent), except Content-Length when `[len]` present or body exists
  (verify), and CRLF normalization of line endings. `-nd` is
  `-default_behaviors none` (M42 note).
- Diagnostics policy as implemented (M1): unknown *elements* and *actions*
  are hard errors (skipping a step silently would change call flow); unknown
  *attributes* warn and are ignored; unknown *keywords* warn and pass through
  verbatim (IPv6 literals like `[2001:db8::1]` in URIs depend on this).
  `--check` treats any diagnostic, warnings included, as failure.
- Load-time checks SIPp makes and sipr does not (verified in M47 in
  `scenario.cpp`: `checkOptionalRecv` ~l.688 and the `found_timewait`
  check ~l.835; confirmed against real sipp): SIPp refuses a scenario in
  which an optional `<recv>`/`<recvCmd>` is followed, labels aside, by a
  `<send>`, `<pause>`, `<timewait>`, `<nop>` or `<sendCmd>` (`<recv> before
  <send> sequence without a mandatory message. Please remove one
  'optional=true'`), and one with any message after a `<timewait>`. sipr
  compiles and runs both: the optional recv then holds the call exactly
  as a mandatory one would, and the step after the `<timewait>` never
  runs. `--check` reports them as the `optional-window` and `unreachable`
  lints (docs/LINTS.md). SIPp does not look at the end of the scenario:
  a trailing optional recv loads, and without a timeout it holds the call
  forever in both tools, which `optional-window` also flags. Two
  divergences found on the way were **open**, and both are fixed since.
  (1) SIPp arms the waiting recv's *own* timeout, optional or not, where
  sipr armed the window's mandatory recv's, so a trailing `optional
  timeout="1000" ontimeout="end"` recv hung in sipr — see "Receive
  timeouts" below. (2) `<jump value="N"/>` is a SIPp *message*
  index, and a `<label>` is not a message (`labelMap[id] =
  messages.size()`), but sipr counted labels as steps, so N landed
  elsewhere when a label preceded it — fixed since, see "Message
  indices" below.
- Template CDATA normalization (M1, `template::normalize_cdata`): every line
  left-trimmed, line endings → CRLF, leading/trailing blank lines dropped,
  single trailing CRLF appended; internal blank line (header/body separator)
  preserved. TO VERIFY against `scenario.cpp` message construction at M3
  interop — especially whether SIPp appends CRLFCRLF or CRLF.
- `<pause sanity_check>` (default true) is SIPp's 99th-percentile guard on a
  distributed pause; implemented as of M38 (see the M38 note below).
- The DTD spells the recv SDP attribute `ignosesdp` (sic); SIPp docs use
  `ignoresdp`. sipr recognizes both spellings (and rejects them until media).
- Regex engine (M6, `sipr-scenario/src/regex.rs`): `ereg` and
  `regexp_match` recv patterns use an in-tree POSIX-ERE matcher — literals,
  `.` (not newline), classes incl. `[[:alpha:]]`-style POSIX classes,
  anchors, alternation, `* + ? {m,n}`, and capture groups. DIVERGENCE: it is
  a leftmost-first greedy backtracker (PCRE-style), NOT POSIX
  leftmost-longest. Identical on the patterns SIPp scenarios use (the SIPp
  default regexp scenario's IP/SDP-origin captures are covered by tests); a
  pattern that relies on POSIX longest-match semantics could differ. A
  backtracking step budget bounds pathological patterns — an over-budget
  match fails rather than hanging. `ereg assign_to="1,2,3"`: index 0 (first
  listed var) gets the whole match, the rest get capture groups in order.
- Digest auth (M6, `sipr-auth`): MD5 and SHA-256, `qop=auth` with
  cnonce/nc, opaque echo, 401 (`Authorization`) and 407
  (`Proxy-Authorization`). The `[authentication]` keyword computes the value
  from the last `recv auth="true"` challenge, using `-au`/`-ap` or the
  keyword's own `username=`/`password=` params. The digest URI is currently
  the `sip:[service]@remote` shape; a proxy keying strictly on the
  request-URI may need that widened (tracked for post-v1). Stale-nonce: the
  challenge exposes `stale`; scenarios re-auth by looping back to the send.
- Action executor (M6): variables are loosely typed (string/num/bool) with
  SIPp-style coercion; `strcmp` yields 0 on equality (C semantics);
  `test`/`condexec` truthiness = set and not zero/false/empty; `divide` by
  zero leaves the value unchanged. `exec int_cmd` maps to fail-call /
  graceful-stop / immediate-stop.
- Injection files `-inf` (M7, verified in `infile.cpp` / `call.cpp`
  `getFieldFromInputFile`): line 1 is the mode, matched by SUBSTRING —
  `SEQUENTIAL`, `RANDOM`, or `USER`, optionally with `PRINTF=` (below).
  Data lines follow; a line beginning `#` is a
  comment, trailing `\r` is stripped, a blank line ends the file. Field
  separator is `;`, fields are 0-indexed (`[field0]` = first). Each call is
  assigned ONE line per file at creation (`nextLine`): SEQUENTIAL = a shared
  per-file counter mod line-count, RANDOM = uniform pick, USER = userId-1
  (M11 — supported under `-users`; without `-users` the fields render empty and
  sipr warns at load).
  `[fieldN]` uses the default (first) file. `file=` selects another file by
  its SIPp key — the BASENAME of the `-inf` path (`sipp.cpp`
  `SIPP_OPTION_INPUT_FILE` strips the directory); sipr also accepts a 0-based
  `-inf` index there as an extension. `line=` overrides the per-call line and,
  per SIPp (`message.cpp` builds it as a `SendingMessage`, resolved in
  `getFieldFromInputFile`), is rendered at send time — so `line=[$var]` works
  and a value past the end / negative renders empty (SIPp sets line = -1).
- Indexed injection, `lookup`/`insert`/`replace` (M7, verified in `infile.cpp`
  `index`/`lookup`/`insert`/`replace`/`reIndex`/`deIndex` and `call.cpp`
  action execution): `-infindex FILE FIELD` builds a key→line map over one
  field; on duplicate keys the LAST line wins (`reIndex` erases then inserts).
  `<lookup assign_to="v" file="F" key="K"/>` stores the matched line number in
  `v`, or -1 on a miss (looking up a file with no `-infindex` is an error).
  `<insert file="F" value="…"/>` appends a `;`-split row; `<replace file="F"
  line="N" value="…"/>` swaps a row; both re-index around the change. `file`,
  `key`, `value`, `line` are all rendered templates. The typical chain is
  `lookup → [fieldN line=[$v]]`. Files are wrapped so reads (`[fieldN]`) and
  mutations (`insert`/`replace`) share them on the single engine thread. The
  standalone `<index>` action is not supported — use `-infindex`.
- `PRINTF=` injection files (M44, verified in `infile.cpp` — the header
  parse, `getField`'s printf branch, `numLines`, `insert`/`replace`): a
  header `PRINTF=<n>` (plus optional `PRINTFOFFSET=<o>`, default 0, and
  `PRINTFMULTIPLE=<m>`, default 1) makes the data lines *templates*. The
  file then has `n` virtual lines; virtual line `l` reads real line
  `l % rows` and every `%d` conversion in the field is filled with
  `o + l * m`, `%%` being a literal `%`. So one row,
  `SEQUENTIAL,PRINTF=10000\nuser%05d;[...]`, is ten thousand users. Only
  `%[0-9.-]*d` is a legal conversion; `insert`/`replace` on such a file are
  refused, as in SIPp. Two deliberate divergences: sipr splits the header
  into `,`/whitespace tokens, so `PRINTFOFFSET=` may precede `PRINTF=`
  (SIPp finds each with `strstr`, and that order makes its `PRINTF` match
  land inside `PRINTFOFFSET` — a parse error); and sipr checks every
  field's conversions at **load**, where SIPp errors at render time, the
  first time a call reads a bad field.
- TCP transport `-t t1` (M8): SIP over TCP is a byte stream, so message
  boundaries come from `Content-Length`, not packet edges (RFC 3261 §7.5). A
  framer reads headers up to the first `\r\n\r\n`, then exactly Content-Length
  body bytes; leading `\r\n` runs (keep-alive pings, RFC 5626) are skipped.
  sipr keeps one connection per peer — the client (`UAC`) dials the target
  once at start-up and the server (`UAS`) accepts, framing each; responses go
  back on the connection the request arrived on (keyed by peer address, like
  SIPp routes by the socket the message came in on). Reliable transports carry
  NO SIP retransmissions (RFC 3261 §18.2), so `retrans=`/`-max_retrans` are
  ignored under `t1`. Per-call connections (`tn`) are M28 below,
  reconnection after a drop M30, one socket per injected IP (`-t ui`) M31.
- Message framing fix surfaced by TCP: every SIP message must end with the
  header/body separator (`\r\n\r\n`) even with no body (RFC 3261 §7). sipr's
  CDATA normalization trimmed the trailing blank line for body-less messages
  (180, ACK, empty 200); UDP datagrams hid it, but TCP framing and real SIPp
  need it, so normalization now restores the separator when a message has no
  body.
- Classic 3PCC `-3pcc HOST:PORT` (M10, verified in `scenario.cpp` role
  detection, `call.cpp` `sendCmdMessage`/`sendCmdBuffer`, `sipp.cpp`
  `SIPP_OPTION_3PCC`): two instances coordinate over a separate TCP "twin"
  socket, exchanging command messages each terminated by a single ESC byte
  (0x1B — SIPp's `delimitor[0]=27`). The role comes from the scenario's first
  twin command: `sendCmd`-first dials the peer (controller A, started last),
  `recvCmd`-first listens (controller B); both take the same `-3pcc` address.
  `<sendCmd>` renders its CDATA (keywords/variables) and writes it plus ESC;
  `<recvCmd>` blocks the call until a command arrives, then runs its `<action>`s
  with `ereg` searching the raw command text (SIPp strips a trailing CRLF and
  matches against the blob). Commands are opaque text used to pass SDP/tags
  between the two controllers, e.g. `<sendCmd>` a captured offer then
  `<recvCmd>` the answer. Extended master/slave 3PCC, the optional-`recvCmd`
  fall-through, command routing by Call-ID and the twin-closed rule came in
  M43 (next note); SIPp has no twin reconnection to mirror.
- Extended 3PCC `-master NAME`/`-slave NAME`/`-slave_cfg FILE` with
  `sendCmd dest=` and `recvCmd src=` (M43, verified in `sipp.cpp`
  `SIPP_OPTION_3PCC_EXTENDED`/`SIPP_OPTION_SLAVE_CFG`, `scenario.cpp`
  `parse_slave_cfg`/`computeSippMode`/the `sendCmd`/`recvCmd` parse,
  `socket.cpp` `open_connections`/`connect_to_all_peers`/`pollset_process`/
  `read_error`/`process_message`, `call.cpp` `sendCmdMessage`/
  `process_twinSippCom`/`check_peer_src`/`checkInternalCmd`,
  `docs/3PCC_extended.rst`):
  - The table is one `name;host:port` per line — the first two `;`-fields,
    anything after them ignored, a line without `;` skipped (sipr warns).
    `-slave_cfg` needs `-master` or `-slave`, which exclude each other and
    `-3pcc`; the own name and every `dest=` must be in the table
    ("get_peer_addr: Peer X not found"). The scenario's role must match the
    flag ("Inconsistency between command line and scenario: master scenario
    but -master option not set" / "slave scenario but -slave option not
    set"): a master scenario reaches `sendCmd` before any `recvCmd`, a slave
    the other way round. In extended mode every `sendCmd` needs `dest=` and
    every `recvCmd` `src=` ("You must specify a 'dest' for sendCmd with
    extended 3pcc mode!").
  - Wiring: each instance listens on its own table address. The master
    dials every `dest=` peer at start-up — so it is launched last — while a
    slave dials its own `dest=` peers only when the first peer connects to
    it (`connect_to_all_peers` from the accept path); a slave that never
    `sendCmd`s dials nobody. A pair is joined by two one-way TCP
    connections and a command leaves on the sender's dialed link to that
    peer. There is no reconnection: any control connection closing ends
    the run at once — WARNING "One of the twin instances has ended ->
    exiting", then `quitting += 20`, which is past the main loop's `>= 11`
    hard-exit bar, so the calls still open are aborted (`abort_all_tasks`,
    they count as failed) and the process exits. Classic controller B does
    the same ("3PCC controller A has ended -> exiting"); controller A only
    sets `quitting = 1` and drains. Hence the docs' rule that slaves run
    without `-m` and the master is launched last: the master's normal end
    is what stops the slaves, and it comes after their calls are done.
  - Routing: a twin command is keyed by its own `Call-ID:` line exactly like
    a SIP message (`get_trimmed_call_id`, `///` marker included; a command
    without one is discarded). An unknown Call-ID opens a new outgoing call
    with that id on the 3PCC "server" sides — controller B and every slave,
    whose first send/recv/sendCmd/recvCmd is a `recvCmd` (`computeSippMode`
    → `MODE_SERVER` creation) — so `[call_id]` on a slave is the master's
    and the pacer plays no part there (`-m` still caps them); a master or
    controller A discards it ("Discarding message which can't be mapped to
    a known SIPp call"). `src=` is checked against the first token of the
    command's own `From:` line, never against the socket it came in on: the
    sender writes its name into the command (`From: m`, as the SIPp docs
    show). A mismatch is WARNING "Unexpected sender for the received peer
    message" and the call is rejected.
  - Matching (`process_twinSippCom`): from the current step forward,
    optional steps and nops are skipped and the first `recvCmd` takes the
    command (trailing CRLFs stripped before its actions run); a mandatory
    step of any other kind is "Unexpected control message received" and the
    call is rejected (`rejectCall`: a failed call, no abort messages). The
    same skip rule in `process_incoming` is the optional-`recvCmd`
    fall-through: a SIP message for the recv behind an optional `recvCmd`
    passes over it, so sipr keeps that recv window open while it waits.
    `internal-cmd: abort_call` (SIPp's `3pcc_abort` default message,
    `call-id: [call_id]`) fails the named call; a controller sends it to its
    twin when it aborts a call past its first step on an unexpected message
    or BYE/CANCEL — classic mode only, extended mode has no single twin
    socket and sends nothing.
  - sipr before M43 handed a twin command to whichever call was blocked on
    `recvCmd` and queued early ones, so a peer's reply did not need the
    Call-ID; it must carry it now, as with SIPp. Controller B used to pace
    its calls with `-r`; they now open on the commands that name them.
    Still open: `-trace_msg` does not log twin commands (SIPp logs them
    tagged "control").
- `-users N` closed loop (M11, verified in `call_generation_task.cpp`
  `run`/`free_user`/`set_users`, `call.cpp` `init` line assignment and
  `[userid]`/`[users]` keywords, `sipp.cpp` `SIPP_OPTION_USERS`): instead of
  open-loop rate pacing, keep N concurrent calls, each holding a 1-based user
  id drawn from a free pool (1..N). A finished call returns its id and a
  replacement opens immediately (`calls_to_open = users - current_calls`), so
  the population stays constant until `-m` total is reached. `-users` and `-l`
  are mutually exclusive. USER-mode `-inf` files resolve line = userId-1
  (SIPp `nextLine(userId)`); `[userid]` renders the id, `[users]` the count.
  The count changes at runtime through `set users N` (control socket, HTTP
  `/control`) and the `+ - * /` keys (M17); see the M35 note below for the
  id bookkeeping and the per-user variables.
- IPv6 (M12, verified in `call.cpp` `E_Message_Local_IP`/`E_Message_Remote_IP`
  → `local_ip_w_brackets`/`remote_ip_w_brackets` vs `E_Message_Media_IP` →
  raw `media_ip`): `[local_ip]`/`[remote_ip]` render the address bracketed when
  it is IPv6 (`[2001:db8::1]`), so URIs and Via lines are well-formed, while
  `[media_ip]` stays raw for SDP `c=`/`o=` lines (SIPp brackets `[local_ip]`
  even in the SDP `o=` line — sipr matches that verbatim). Targets accept
  bracketed (`[::1]`, `[2001:db8::1]:5060`) and bare-literal (`::1`) IPv6; a v6
  target with no `-i` auto-binds the `::` family. `[local_ip_type]`/
  `[media_ip_type]` render `6` for a colon-bearing address. `-i` takes a v6
  local address directly. Not exercised in the build sandbox (no v6 loopback);
  the e2e self-skips there and runs where `::1` binds.
- TLS `-t l1` (M13, verified in `sslsocket.cpp` `TLS_init_context`/
  `SSL_new_client`/`SSL_new_server`, `socket.cpp` handshake/read/write paths,
  `sipp.cpp` option table): TLS is exactly the TCP path with a TLS layer —
  same Content-Length framing, same connection-per-peer model (`ln` collapses
  onto it like `tn`), no SIP retransmissions, default port stays 5060 (SIPp
  has no 5061 constant), no `sips:` scheme anywhere, `[transport]` renders
  `TLS`. Cert/key default to `cacert.pem`/`cakey.pem` in the CWD and are
  required to start (SIPp loads them into both client and server contexts, so
  the client always presents its cert when asked). **Peer verification is OFF
  unless `-tls_ca` or `-tls_crl` is given**; when on, the client validates
  the chain but never the hostname (no `X509_check_host` in SIPp), and the
  server demands + verifies a client cert (`SSL_VERIFY_PEER |
  FAIL_IF_NO_PEER_CERT` — mutual TLS is a side effect of `-tls_ca`). SNI is
  sent only for named (non-IP) targets; sipr resolves targets before dialing,
  so like SIPp with an IP target it sends none. Deliberate divergences:
  (1) a failed inbound handshake drops that connection with a warning — SIPp
  kills the whole process on `SSL_accept` failure; (2) `-tls_version 1.0/1.1`
  are rejected (rustls starts at 1.2; SIPp's floor is 1.0); (3) encrypted
  keys are rejected — SIPp silently decrypts with the hardcoded passphrase
  `ksgr` (`sslsocket.cpp` `passwd_call_back_routine`); (4) `setdest` to TLS
  is fatal in SIPp and unsupported here too. Also noted: sipp's *client*
  stream bind (TCP and TLS) reuses its own listening port, which fails with
  EADDRINUSE on macOS — the reverse interop test self-skips there.
- pcap replay `exec play_pcap_*` (M14; verified in `prepare_pcap.c`
  `prepare_pkts`, `send_packets.c` `send_packets`/`do_sleep`, `call.cpp`
  `get_remote_media_addr` (~l.349), the `media_port`/`auto_media_port`
  keyword handler (~l.2789), `E_AT_PLAY_PCAP_*` execution (~l.6196),
  `sipp.cpp` `setup_media_sockets`): SIPp parses the file once at scenario
  load (missing/truncated = fatal; "recapture with `-s0`"), keeps the UDP
  header + payload of every UDP packet with no RTP filtering, and replays
  on a **raw socket** rewriting only the UDP ports (`port_diff` = packet's
  destination port minus the lowest destination port in the file, added to
  the SDP-learned remote port and the advertised local port) — the RTP
  header is sent **verbatim**, so every call replaying one file emits the
  same SSRC/seq/timestamps. Timing tracks the capture's absolute timeline
  (`didsleep` vs elapsed), out-of-order timestamps get no delay. The action
  is non-blocking (a `<pause>` must cover the file's duration) and one
  media thread per call means audio cancels video and vice versa. The
  remote endpoint is the first `c=IN IP4/IP6` + `m=audio|video|image` of any
  *response* with a body or any INVITE/ACK/PRACK request, unless the recv
  has `ignoresdp`; streams absent from a later SDP keep their old address.
  `[media_port]` is `min_rtp_port` (6000) for every call unless `-rtp_echo`
  bumps it at startup; `[auto_media_port]` = `+ 4*(call-1) % 10000`; the
  *local* port used by a replay is whatever `[media_port]` rendered on the
  SDP line containing "audio"/"video"/"image". sipr matches all of that
  with these deliberate divergences: (1) ordinary UDP sockets bound to the
  media port — no raw socket, **no root**; the sockets are not `connect`ed
  so a silent peer's ICMP errors never abort a replay; (2) non-UDP/non-IP
  packets in a capture are skipped with a count, not fatal (SIPp aborts on
  an unknown EtherType); (3) audio/video/image streams of one call are
  independent — playing one does not cancel another; (4) a port-0 (held)
  `m=` line is skipped in favour of a later live one (SIPp's rtpstream path
  does this, its pcap path does not); (5) 802.11 captures are rejected
  (unsupported link type) — recapture on the wired side; (6) **pcapng**
  captures are read too (M44), which SIPp's `pcap_open_offline` refuses —
  its `-s0` advice covers only the classic format. An in-tree block reader
  (`sipr-media::pcapng`, no crate) handles Section Header, Interface
  Description (`if_tsresol`, decimal and binary), Enhanced Packet, Simple
  Packet and the obsolete Packet block, in either byte order and across
  sections; other block types are skipped by their length. The resulting
  stream is identical to the classic reader's, so everything above applies
  unchanged. `play_pcap=` (in the DTD, never implemented by SIPp) is an
  error pointing at `play_pcap_audio=`. `-key` shipped in M39 (§6).
- `exec rtp_stream=` / `exec play_dtmf=` (M15; verified in `rtpstream.cpp`
  `rtpstream_playrtptask` (~l.603), `rtpstream_get_localport` (~l.1789),
  `rtpstream_cache_file` / `get_wav_header_size` (~l.1619/2240),
  `actions.cpp` `setRTPStreamActInfo` (~l.677), `prepare_pcap.c`
  `prepare_dtmf` (~l.556), `call.cpp` `E_Message_RTPStream_Audio_Port`
  (~l.2827)): the value is `name,loops|pattern_id,payload_type,
  payload_name`; files are raw codec bytes with only a RIFF/WAVE header
  skipped ("Doesn't actually parse/convert anything!"), cached once at
  parse; the payload table is fixed (0/8/9 → 160 B per 20 ms, 18 → 20 B,
  13 → 1 B per 150 ms, dynamic `H264/90000` → 1280 B per 160 ms video,
  `iLBC/8000` → 50 B per 30 ms) and a missing name is fatal except for
  0/8/9/18; a mismatched name is a fatal "unknown payload type". Packets:
  V=2, marker never set, seq from 0, timestamp = wall-clock ms ×
  ticks-per-ms advancing by ticks-per-packet, SSRC `0xCA110000` + 2 per
  call (`-random_base_ssrc` randomizes the base), payload spliced across
  the file end when looping, `-1` loops forever. `pause` does NOT stop the
  clock — the timestamp is fast-forwarded so the stream "appears up to
  date" on resume. `[rtpstream_audio_port]` allocates a port from
  `min_rtp_port` in steps of two (wrapping at `max_rtp_port`) with a trial
  bind; `+N` never allocates. **SIPp streams from that allocated port even
  when the SDP advertised `[media_port]`** (its own `pfca_uac.xml` does
  this), and its RTCP socket is always destroyed by an inverted bind test.
  `play_dtmf="digits[,tone]"`: 20 warm-up packets (PT 97, 4 zero bytes,
  20 ms apart) then per digit start packets every 20 ms (marker on the
  first, `duration = elapsed*8`) at `400 + (k+1)*2*tone` ms and three end
  packets 1 ms apart; PT hard-coded 96 (the bundled scenario advertises
  101); per-call sequence from 1200; a fresh SSRC per burst; digits outside
  `0-9*#A-D` skipped; tone outside 50..=2000 → 200. sipr matches all of
  that with these divergences: (1) a stream sends from the port the SDP
  advertised — the allocated `[rtpstream_*_port]` when used, else the
  `[media_port]` form on that `m=` line; (2) DTMF sequence numbers are
  consecutive (SIPp's warm-up increments two counters and skips every
  other number); (3) the SIPp sender's post-send recv+memcmp ("RTP check")
  and the `-audiotolerance` verdict/exit −3 are not implemented; (4) the
  packet grid is per stream (`start + n*interval`), not SIPp's global
  wall-clock grid that fires every stream in the same millisecond; (5)
  `-rtp_threadtasks` is not needed (one scheduler thread) and not accepted.
- IMS AKA `AKAv1-MD5` (M16; verified in `auth.cpp` `createAuthHeader`
  (~l.158) / `createAuthHeaderAKAv1MD5` (~l.600), `milenage.c`,
  `message.cpp` `parseAuthenticationKeyword` (~l.547) /
  `getHexStringParam` (~l.498), `docs/scenarios/sipauth.rst`): SIPp
  matches `algorithm=` by case-insensitive **prefix** (`MD5-sess` → MD5;
  `AKAv2-MD5` is rejected: "must use MD5, AKAv1-MD5 or SHA-256"), decodes
  the nonce as base64(RAND(16) ‖ SQN⊕AK(6) ‖ AMF(2) ‖ MAC-A(8)) — extra
  server bytes ignored, unpadded base64 rejected, and an off-by-one that
  accepts 31 decoded bytes — computes f2345 then SQN = (SQN⊕AK)⊕AK, then
  XMAC = f1 with the **configured `aka_AMF`** (AUTN's AMF is read and
  discarded), and on MAC ≠ XMAC calls `ERROR()`, which **aborts the whole
  process**. RES (8 raw bytes, never hex) is the digest password with the
  length passed explicitly so NUL bytes survive; CK/IK are computed and
  discarded; `algorithm=AKAv1-MD5` is echoed. OP only, OPc derived as
  `E_K(OP)⊕OP` on every call; no OPc input. AUTS/resync is dead code
  (`if (1/*…*/)`) — SIPp never emits `auts=`. Keyword params: `aka_K`,
  `aka_OP`, `aka_AMF` as `0x` hex (nibble pairs, **no length validation,
  not NUL-terminated**) or quoted/bare strings; `aka_K` absent → the first
  16 bytes of the password (documented), `aka_OP`/`aka_AMF` absent → reads
  past a 1-byte buffer. No AKA CLI flags; no AKA test vectors in the tree.
  sipr matches the wire behavior (same nonce layout, RES-as-password,
  header shape, prefix matching, configured-AMF precedence) with these
  divergences: (1) a MAC mismatch, a malformed nonce, or missing keys
  **fails the call** with the reason in the error trace — the process
  continues; (2) hex values must be exactly 32/32/4 digits; (3) `aka_OPc=`
  is accepted directly; (4) when `aka_AMF` is absent, AUTN's AMF is used
  (SIPp would read garbage); (5) the password-as-K fallback requires a
  16+ byte password; (6) unpadded base64 is accepted. `aka_*` values are
  taken literally (SIPp renders them, so `[field0]` works there) — a
  follow-up.
- Remote control (M17; verified in `socket.cpp` `setup_ctrl_socket` (~l.497),
  `handle_ctrl_socket` (~l.472), `process_command`/`process_set`/
  `process_trace`/`process_dump`/`process_reset` (~l.134–330),
  `process_key` (~l.367), `docs/controlling.rst`): the control socket is
  UDP, created unconditionally (no flag disables it), bound to `-cp` once
  (failure fatal) or probing 8888..8947 (failure = warning, no socket) on
  **every interface**, and the chosen port is never printed. One datagram =
  one command: byte 0 is a hot key (`1`-`9` screens, `+ - * /` rate or —
  in `-users` mode — user count, stepped by `rate-scale`; `p` pause; `q`
  adds 10 to `quitting`, `Q` 20; ≥1 drains, ≥11 aborts, so `q q` = `Q`)
  and the rest is discarded, unless byte 0 is `c`: then the rest is a
  command line split on the **first space only** (tabs do not separate),
  verbs `set|trace|dump|reset`, numbers via `strtol(…, 0)` (hex/octal
  accepted) with strict trailing-garbage rejection, booleans `true|false`
  for `set hide` but `on|off|true|false` for `trace`. **No reply is ever
  sent** (`recv()` without a peer); errors go to the error log with the
  wordings reproduced in `sipr-control::command`. `set rate`/`set limit`
  are refused in users mode and `set users` in rate mode; `set limit`
  latches the cap so later `set rate` stops auto-sizing it. `reset stats`,
  `set display rx`, `dump variables` exist but are undocumented; the `s`
  key is dead code (`screenf` is never set). No HTTP anything. sipr
  matches the protocol, grammar, wordings, refusals and quit ladder, with
  these divergences: (1) default bind is loopback, `-ci` opts into more;
  (2) `-cp 0` disables the socket; (3) the bound address is printed;
  (4) screen digits are ignored (sipr's TUI cycles with `s`); (5) `set
  display rx` and `dump variables` warn that they are unsupported instead
  of silently succeeding (`set display ooc|main` works as SIPp's since
  M33; `trace logs|shortmessages on|off` work since M41); (6) `set
  limit` in sipr simply sets `-l` (sipr never auto-sizes the cap from the
  rate). The HTTP API is a sipr addition with no SIPp counterpart.
- RTP echo and the RTP check (M18; verified in `sipp.cpp` `rtp_echo_thread`
  (~l.650), `setup_media_sockets` (~l.1292), `sipp_exit` (~l.1146),
  `rtpstream.cpp` the post-send `select`/`recv`/compare block (~l.754) and
  the exit verdict (~l.1300), `call.cpp` `E_AT_RTP_ECHO` (~l.6253)):
  `-rtp_echo` binds *global* sockets on `media_port` and `media_port+2`
  (probing in steps of two only when `-rtp_echo` is on — otherwise
  `media_port` never moves), each thread `recvfrom`s with a 100 ms timeout
  and `sendto`s the bytes back unless the process-wide `rtp_echo_state`
  (default true, toggled by the `<rtp_echo>` action from *any* call) is
  false; counters `rtp_pckts`/`rtp_bytes` (1st stream) and
  `rtp2_*` (2nd). The RTP check lives inside the `rtp_stream` sender:
  after every successful send it `select`s + `recv`s on the same socket
  and `memcmp`s the payload of what arrived with the payload just sent; a
  mismatch **or nothing received** counts as a failure; at thread exit
  each task with packets sent is judged `failed/sent >= tolerance`
  (`-audiotolerance`/`-videotolerance`, default 1.0) and a failure sets a
  bit in `rtpresult`, which makes `sipp_exit` return
  `EXIT_RTPCHECK_FAILED` (-3, shell 253) ahead of the call-failure code.
  Consequence: with the defaults, an `rtp_stream` run against a peer that
  does not echo exits -3. `exec rtp_echo=startaudio|…` is a different
  feature (per-call SRTP echo threads with process-global state). sipr
  matches the echo sockets, probing, counters, toggle action, compare
  semantics, and exit code, with these divergences: (1) a stream is
  judged **only when `-audiotolerance`/`-videotolerance` was given**;
  (2) `<rtp_echo variable="v"/>` (M44) reads `v`, where SIPp parses the
  attribute through `handle_rhs` and then calls `getDoubleValue()` rather
  than `get_rhs()` — its literal slot, which `variable=` never fills — so
  in SIPp that form always switches echoing **off**. Every other rhs
  action (`jump`, `pauserestore`, `add`, …) reads the variable; sipr makes
  this one consistent instead of copying the slip. `exec rtp_echo=`
  (the per-call SRTP echo) is M25 below.
- Socket options and the local address (M44; verified in `socket.cpp`
  `open_connections` ~l.2372-2560 — `bind_specific`, the connect-probe,
  the `bind_local || peripsocket` re-resolve — `sipp_customize_socket`
  ~l.1735-1815, `SIPpSocket::bind_to_device` ~l.1645, `call.cpp`
  `sendBuffer` ~l.1627): SIPp keeps two addresses apart. The **advertised**
  one is `-i`; without `-i` it is `gethostname()` resolved when there is no
  remote host, else the source address a UDP socket connected to the remote
  reports (no packet is sent). The **bound** one is `INADDR_ANY` unless `-i`
  was given (which sets `bind_specific`), or `-bind_local`/`-t ui` asks for
  the advertised address. sipr now matches that split — before M44 it bound
  `-i` and rendered `[local_ip]` as `0.0.0.0` when `-i` was absent — with
  one divergence: for the no-remote case sipr runs the same connect-probe
  against the RFC 5737/3849 documentation prefixes (naming the default
  route's address) rather than resolving `gethostname()`, which SIPp's own
  comment calls "actually buggy". `-bind_local` is therefore a no-op
  alongside `-i`, exactly as in SIPp. `-buff_size` sets `SO_SNDBUF` and
  `SO_RCVBUF` on every SIP socket (`socket2`, since std exposes neither and
  `unsafe` is forbidden) — but only when given: SIPp always applies its own
  default of 65536, which is *below* Linux's default receive buffer and
  costs throughput at high rate. `-bind_to_device` is `SO_BINDTODEVICE`,
  which exists on Linux alone and needs `CAP_NET_RAW`; SIPp compiles the
  call out elsewhere and binds nothing silently, where sipr refuses the flag
  at argument parsing. `-sendbuffer_warn` governs a failed send of a
  *default* (non-scenario) message: despite its help text ("Produce warnings
  instead of errors"), SIPp's code reads `if (sendbuffer_warn) ERROR_NO(…)
  else WARNING_NO(…)`, so the flag makes the failure **fatal** and its
  default is the warning. sipr matches the code — the run ends with the
  flag, warns without it — and no longer ignores the failure outright.
- AKA resynchronisation (M19): SIPp's `auth.cpp` has an AUTS branch guarded
  by `if (1/*sqn[5] > sqn_he[5]*/)` (~l.676) whose real condition is
  commented out, so the always-taken branch stores one SQN byte into a
  write-only global and **SIPp never emits `auts=`**; had it run, it would
  have used the configured AMF instead of AMF* = 0 and an uninitialised
  SQN_MS. sipr implements the standard flow (RFC 3310 §3.2, TS 33.102
  §6.3.3): with `aka_sqn=` the challenge's SQN must be greater than
  SQN_MS, otherwise (or with `aka_resync=1`) the response carries
  `auts="base64((SQN_MS ⊕ f5*(RAND)) ‖ f1*(K, RAND, SQN_MS, 0x0000))"` and
  a digest over the empty password; the scenario then expects the
  server's fresh 401 (`<recv response="401" auth="true"/>` again). Pure
  addition — no SIPp behavior to match.
- Rate ramps (M20; verified in `ratetask.cpp` and the option table in
  `sipp.cpp` ~l.347-356): the ramp task is created only when
  `-rate_increase` is non-zero; it wakes every `rate_increase_freq`
  (`-rate_interval`, a `SIPP_OPTION_TIME_SEC` value; when 0 it takes
  `-fd`'s value, whose SIPp default is 60 s), does `rate += rate_increase`,
  and if `rate_max` is set and the new rate **exceeds** it, clamps to
  `rate_max` and — with `rate_quit` (default true; `-no_rate_quit`
  clears it) — `quitting += 10` (drain). The task deletes itself once
  `quitting >= 10`. It calls `set_rate`, which users mode ignores.
  sipr matches this; the only difference is the default interval, since
  sipr's `-fd` defaults to 1 s (recorded in M4).
- Digest `uri=` and rendered auth parameters (M21; verified in `call.cpp`
  ~l.4149-4170 and `message.cpp` ~l.547-585): SIPp's digest URI is
  literally `"sip:" + (auth_uri ? auth_uri : remote_ip ":" remote_port)`
  — no user part — so `-auth_uri sip:x` produces `uri="sip:sip:x"` (its
  own gtest expects that). Each `[authentication]` parameter is stored as
  a `SendingMessage` and rendered at send time, so keywords work inside
  them. sipr matched the wire form from M21 on (it previously signed
  `sip:service@ip:port`, which servers accepted since they verify against
  the header's own `uri=`, but which differed on the wire) and renders
  the parameters the same way; the `sip:sip:` quirk is kept, with a
  startup warning.
- `hide` / `display` (M22; verified in `scenario.cpp` ~l.1852 and
  `screen.cpp` ~l.282/493): `hide` is a boolean on every message command
  (`xp_get_bool("hide", …)`), `display` a free-text attribute read for
  every command even though `sipp.dtd` declares it only on `nop`; the
  scenario screen skips a hidden row only while the global `do_hide`
  (default true, `set hide true|false`) holds. sipr matches this. Screen
  keys: sipr maps `1`/`2`/`3` like SIPp and ignores `4`..`9` (no
  variables/TDM screens; secondary repartitions are not drawn separately).
- SRTP (M23; verified in `jlsrtp.cpp` — `pseudorandomFunction` ~l.66,
  `computePacketIV` ~l.416, `issueAuthenticationTag` ~l.639,
  `processOutgoingPacket` ~l.2055 / `processIncomingPacket` ~l.2158,
  `encodeMasterKeySalt` ~l.2518; `call.cpp` keyword handlers ~l.2860-3300,
  `extract_srtp_remote_info` ~l.564; `rtpstream.cpp` echo ~l.2519):
  JLSRTP is AES-CM-128 or NULL cipher × HMAC-SHA1 80/32, master key 16 +
  salt 14 always, kdr 0 (key ids `label || 0`), no MKI, no replay list,
  no SRTCP, a fixed 12-byte header and a *configured* payload length.
  `[cryptokeyparams…]` generates a fresh `RAND_bytes` key on **every**
  render (negative offset = reuse); `[cryptosuite…]` selects the local
  suite; `[ue…]` renders `UNENCRYPTED_SRTP` and switches the local cipher
  to NULL while still advertising the AES suite. Received SDP: the first
  `a=crypto:` in the media section is PRIMARY, the second SECONDARY (at
  most two, `sscanf`-parsed); only the primary attribute is ever active —
  `selectActiveCrypto` is never called — and `swapCrypto` swaps the two
  when the answer's primary suite is the offer's secondary. The sender's
  echo check decrypts the echo under the peer's key and compares
  payloads; the per-call echo re-encrypts under its own key with the
  *caller's* SSRC and sequence numbers. **Bug**: the auth tag is computed
  with the stale `_ROC` (updated after the tag is issued), so after
  sequence 65535 SIPp's packets are rejected by conforming stacks (two
  SIPps still agree). sipr matches the suites, sizes, KDF, SDES encoding,
  keyword names and side effects, two-line parse, swap rule, and check
  semantics, with these divergences: (1) the tag uses the packet's own
  estimated ROC (RFC 3711 §4.2) — interop with SIPp only diverges after
  a rollover; (2) master keys come from sipr's seeded RNG (reproducible
  across runs with the same seed) rather than `RAND_bytes`; (3) an
  unsupported peer suite or undecodable key logs and falls back to plain
  RTP instead of `rejectCall()`; (4) payload length is taken from the
  datagram, not configured. Interop verified with sipp's own
  `-srtpcheck_debug` log: it authenticates and decrypts sipr's packets
  (`processIncomingPacket() rc == 0`). Also found: sipp's per-call SRTP
  echo does `sendto()` with an explicit address on a socket it has
  `connect()`ed, which macOS rejects with EISCONN (errno 56) — on macOS a
  sipp SRTP echo server never answers (Linux allows it). Same family as
  the stream-client bind limitation.
- `[authentication]` placement and injection (M24; verified in `call.cpp`
  ~l.4022-4045 `E_Message_Injection` and ~l.4149-4155): the keyword renders
  the **entire header line** including its name — `Authorization: ` after
  a 401, `Proxy-Authorization: ` after a 407 — which is why SIPp's
  scenarios put `[authentication …]` alone on a line; and an injected
  field whose text contains `[authentication` is re-parsed as the keyword
  at send time (a temporary NUL at the first `]`), which is the documented
  way to give each call its own credentials from a CSV. Only one
  `[authentication]` per message is allowed (fatal). sipr renders the full
  line like SIPp, re-parses injected fields the same way, and additionally
  accepts `Authorization: [authentication …]` (its pre-M24 spelling) by
  emitting only the value when the header name is already on the line;
  the one-per-message check is not enforced.
- `exec rtp_echo=` (M25; verified in `actions.cpp` `setRTPEchoActInfo`,
  `scenario.cpp` ~l.1729, `rtpstream.cpp` ~l.2519-2665): the value is
  `<verb>,<payload_type>,<payload_name>`; verbs are matched by **prefix**
  (`startaudio`, `updateaudio`, `stopaudio`, `startvideo`, `updatevideo`,
  `stopvideo`), the payload type defaults to `-rtp_payload` and the name to
  SIPp's table for 0/8/9/18 — an unknown codec is a parse-time error. The
  echo thread `recvfrom`s on the call's `[rtpstream_*_port]`, and when the
  answer carried `a=crypto` it `processIncomingPacket`s under the peer's
  key, rebuilds the packet, `setSSRC`s the *incoming* SSRC, re-protects it
  under the local key with the incoming sequence number, and `sendto`s the
  packet's source; an authentication failure is only logged and the bytes
  go out anyway. Both threads are process singletons — a second call's
  `startaudio` re-keys the same thread. sipr matches the grammar, the
  defaults and validation, the port, the re-keying with the caller's SSRC
  and sequence numbers, and the counters, with these divergences: (1) one
  echo per `(call, kind)`, stopped with the call, instead of a shared
  singleton; (2) a packet failing authentication is dropped, not echoed;
  (3) `update` restarts the echo with the current negotiation (the port is
  released synchronously so nothing is lost but the packets in flight)
  rather than swapping keys in place. Verified against real sipp: its
  `pfca_uac_apattern_crypto_simple.xml` passes its own RTP check (exit 0)
  against sipr playing `pfca_uas_audio_crypto_simple.xml` unchanged.
- `ereg search_in="hdr"` (M25; verified in `call.cpp` `extractSubMessage`):
  the haystack is the text after the **first occurrence of the header
  string as a plain substring** (`header="CSeq:"` gives ` 1 INVITE`,
  leading space included; `header="CSeq"` gives `: 1 INVITE`) up to the
  end of that line; `start_line="true"` anchors the match to a line start;
  `case_indep` selects case-insensitive matching; and an absent header
  under `check_it` fails the call (`E_AR_HDR_NOT_FOUND`) regardless of the
  regexp. sipr matches this, matching the header string case-insensitively
  always (tolerance on the inbound side only).
- `<verifyauth>` (M26; verified in `scenario.cpp` ~l.1572, `call.cpp`
  ~l.5946 `E_AT_VERIFY_AUTH`, `auth.cpp` `verifyAuthHeader`): `username`
  and `password` are message templates rendered at execution (keywords and
  `[$var]` allowed — SIPp's documented recipe pulls them from a `<lookup>`
  line); the method is the received start line's **first token** (a start
  line without a space verifies false — and a response's "method" is
  `SIP/2.0`, so it never verifies); the credential is the first
  `Authorization:` header only (`Proxy-Authorization:` is never consulted);
  every digest parameter — `realm`, `uri`, `nonce`, `cnonce`, `nc`, `qop`,
  `algorithm` (default MD5; matched by prefix, so `MD5-sess` computes as
  plain MD5), `response` — is read from the **client's** header, so only
  the shared secret is checked, never the server's own nonce or realm;
  `qop=auth-int` hashes the request body; the RFC 2617 form with
  `nc:cnonce:qop` is selected by **`cnonce` being present**, not by `qop`;
  `-auth_uri` replaces the header's `uri=` in the verifier's HA2 too; a
  non-Digest scheme or an algorithm other than MD5/SHA-256 WARNINGs and
  yields false. The verdict is a boolean variable (`test=` branches on it).
  sipr matches all of this, with one tolerance: the `response` hex is
  compared case-insensitively (SIPp's `strcmp` rejects uppercase hex).
  Verified both ways against real sipp: sipr's `<verifyauth>` accepts and
  rejects sipp's `[authentication]` header, and sipp's accepts and rejects
  sipr's.
- `_unexp.main`, `<jump variable=>`, `<pauserestore>` (M27; verified in
  `scenario.cpp` ~l.1065 and `call.cpp` ~l.5449, ~l.1975, ~l.2315,
  ~l.6003): when a scenario has `<label id="_unexp.main"/>`, an unexpected
  in-call message does not fail the call — SIPp stores the current
  message index in `_unexp.retaddr` and the running pause's absolute
  deadline (`paused_until`, a ms clock tick; 0 when not pausing) in
  `_unexp.pausedaddr` (each only if the scenario mentions the variable),
  cancels the pause, jumps to the label and re-queues the message for the
  handler's `<recv>`. It does **not** count as unexpected in the stats. The
  jump is refused (normal unexpected handling) while `_unexp.retaddr` is
  non-zero — "already in a jump" — and nothing ever resets that variable,
  so one interruption per call unless the scenario zeroes it. The handler
  ends with `<pauserestore variable="_unexp.pausedaddr"/>` and
  `<jump variable="_unexp.retaddr"/>`: `pauserestore` sets `paused_until`
  to the operand (`(int)`, absolute), and `run()` serves a pending
  `paused_until` **before executing the current message** and then
  `next()`s past it — so jumping back to an interrupted `<pause>` waits
  out the original deadline and skips the pause; jumping back to a
  `<recv>` (pausedaddr 0) simply re-arms it. `<jump>` itself is `handle_rhs`
  (`value=` or `variable=`, `msg_index = (int)operand - 1`, a message
  index — labels do not count, see "Message indices" below); an
  out-of-range target is a fatal ERROR. sipr matches all of this (deadlines
  are ms since the run started, like SIPp's clock tick), with two
  divergences: an out-of-range jump fails the call rather than the run,
  and the `_unexp.main` jump is tried before `-aa` auto-answering.
  Verified both ways against real sipp with an INFO during a 3 s pause: the
  BYE after the pause lands ~2.5 s after the INFO, not ~3 s.
- `<closecon/>` (M27; verified in `call.cpp` ~l.5836 `E_AT_CLOSE_CON`,
  `socket.cpp` `SIPpSocket::close` ~l.1045, ~l.1155-1168, `call.cpp`
  ~l.1089, ~l.1481): it is `call_socket->close(); call_socket = nullptr`,
  and `close()` only **decrements a reference count**, freeing the socket
  at zero. Every call holds one reference on the socket it uses and the
  process holds another on the shared ones (`main_socket`,
  `tcp_multiplex`, each accepted server connection), so in the
  mono-socket modes (`u1`, `t1`, `l1` — everything sipr offers) `closecon`
  never closes anything: it drops the call's reference, after which a
  further `<send>` on that call has no socket (`send_raw` asserts unless
  `-rsa`). Only the per-call socket modes (`un`, `tn`, `ln`) actually close
  a connection. sipr accepts the action as a no-op — the same observable
  behavior — and the per-call socket modes remain unimplemented.
- Per-call sockets `-t un|tn|ln` (M28; verified in `sipp.cpp` ~l.1660
  (`multisocket`), `call.cpp` `connect_socket_if_needed` ~l.1419 and its
  call site at the top of `createSendingMessage` ~l.1737, `E_Message_Local_Port`
  ~l.2753, `socket.cpp` `new_sipp_call_socket` ~l.1340 and the call-creation
  branches ~l.1148-1185): `multisocket` only changes the **client** side. A
  call opens its own socket at its first send — "socket port must be known
  before string substitution" — bound to the local IP on a system-chosen
  port for UDP, or dialed to the target for TCP/TLS; `[local_port]` then
  renders that socket's port (`call_port`) instead of `-p`, but only for
  clients (`sendMode != MODE_SERVER`). A server call keeps the socket the
  message arrived on: the main UDP socket under `un`, the accepted
  connection under `tn`/`ln` — so a per-call server is the mono server.
  Past `-max_socket` (default 50000) open call sockets, a new call is handed
  an existing one round-robin (`next_socket`), and a socket closes when the
  last call holding it ends (the reference count `closecon` decrements).
  A per-call TCP/TLS connect failure fails **that call**
  (`E_FAILED_TCP_CONNECT`) when reconnects are allowed, else the run. sipr
  matches all of this — pool sharing, `[local_port]`, server-side
  behavior, closing with the last holder, and `<closecon/>` now really
  closing a per-call socket with the next send opening a fresh one — with
  these divergences: a connect failure always fails only the call (the
  `-max_reconnect`/`-reconnect_*` family, `-rsa` and `-t ui` landed later,
  in M29–M31 — see their notes below); each per-call socket has its own
  receive thread rather than SIPp's single `poll` loop, so very large
  `-max_socket` values cost threads.
- `-rsa host[:port]` (M29; verified in `sipp.cpp` ~l.1827 (parse, default
  port 5060), `call_generation_task.cpp` ~l.152 and `socket.cpp` ~l.1146-1230
  (the call's `call_peer`), `socket.cpp` ~l.2588 and `call.cpp` ~l.1489
  (TCP dials it), `call.cpp` `send_raw` ~l.1570-1600 (`call_remote_socket`),
  `E_Message_Remote_IP/Port` ~l.2741): the remote *sending* address replaces
  where messages go, never what keywords say. A UAC's calls send to it
  instead of the target (mono TCP/TLS dials it; per-call sockets connect to
  it) while `[remote_ip]`/`[remote_port]` — and so the digest `uri=` — keep
  the command-line target. A UAS's calls send to it instead of the
  request's source, and do so from a **socket of their own**
  (`new_sipp_socket`, connected for TCP/TLS, plain for UDP: responses leave
  from an ephemeral port, not `-p`), one shared `main_remote_socket` unless
  the transport is per-call. sipr matches all of this (the UAS-side socket
  is a call socket shared with cap 1 in mono modes), with one divergence:
  `[remote_ip]` on a UAS still renders the request's source, where SIPp
  renders its `remote_ip` global (the command-line remote host, if any).
  Verified against real sipp in both roles, including sipr accepting the
  responses a `-rsa` sipp UAS sends from its extra socket.
- TCP/TLS reconnection `-max_reconnect`/`-reconnect_close`/`-reconnect_sleep`
  (M30; verified in `socket.cpp` `reconnect_allowed` ~l.2257,
  `reset_connection` ~l.2265, the recv/send error paths ~l.1866-1880 and
  ~l.1940-1970, `write_primitive` ~l.2098, `sipp.cpp` ~l.551/~l.635 and
  `docs/transport.rst`): `reset_number` (default **0**: no reconnection;
  -1 unlimited) is a process-wide budget. A **clean** close (read returns
  0) only `invalidate()`s the socket and, with `reset_close` (default
  true), `close_calls()` — every call on it fails with
  `E_FAILED_TCP_CLOSED` ("Closing calls, because of TCP reset or
  close!"); nothing is re-dialed until a send needs the socket: writing to
  an invalid socket is an `EPIPE`, which queues a `reset_connection` — if
  no budget is left that is a fatal `ERROR("Max number of reconnections
  reached")` (exit -1), else the budget is spent, calls are closed again
  under `reset_close`, the main loop **sleeps** `reset_sleep` (default
  1000 ms, blocking everything, `usleep`) and re-dials the same
  destination ("Socket required a reconnection."); a failed re-dial closes
  the calls and leaves the socket invalid for the next attempt. An
  **error** close (`EPIPE` on send, a recv error) queues the reset
  immediately. The **order** matters: `send_raw` deletes the call whose
  write failed (`E_FAILED_CANNOT_SEND_MSG`) *before* the main loop resets
  the socket, so the call that discovers the dead connection always dies;
  `-reconnect_close false` only decides whether the *other* calls on the
  socket live on — and they do send again once someone has re-dialed it
  (the "resurrect the socket" comment). A write on a half-closed socket
  (FIN received, no RST yet) still succeeds, so an ACK queued behind the
  200 that preceded the FIN goes out. sipr matches all of this for the
  mono client connection (`t1`/`l1` as UAC) — the reader only reports the
  end of a connection and the engine forgets it when it processes that
  event, keeping the same ordering — including the synchronous sleep, the
  fatal exit 255, the counters `failed_cannot_send` / `failed_tcp_closed`
  / `failed_tcp_connect`, and the log lines, with these divergences: a
  **server** whose client resets the connection closes that client's calls
  (under `-reconnect_close`) but never re-dials and never exits — SIPp's
  UAS dies on a client's RST with the default budget; a dropped
  **per-call** connection (`tn`/`ln`) fails its call under
  `-reconnect_close` or, without it, simply re-dials at the call's next
  send outside the budget; and a connection failure at start-up stays a
  start-up error (SIPp decrements the budget and carries on without a
  socket). Verified against real sipp both ways by restarting the UAS
  between two calls.
- Pacing start (verified in `call_generation_task.cpp` `set_rate` ~l.228,
  `run` ~l.90-110, `wake` ~l.60): SIPp anchors `last_rate_change_time` at
  start-up and opens `elapsed × rate / rate_period − calls_since` calls per
  run, so with `-r 1 -rp 1000` the **first call comes at t ≈ 1 s**, not at
  t = 0 (`-r 10` → 100 ms, `-r 1 -rp 2000` → 2 s); each rate change (`+`/`-`,
  the control socket) re-anchors the clock and the count. sipr's pacer
  credits `rate × elapsed / rate_period` per tick from the wall clock (a
  tick that arrives late credits the interval it covers, so a loaded host
  never silently runs below the requested rate) and produces the same
  first-call time and the same steady-state spacing; it does not re-anchor
  on a rate change (the fractional carry survives), a sub-interval
  difference.
- `-t ui` / `-ip_field` / `[server_ip]` (M31; verified in `sipp.cpp`
  ~l.316 and ~l.1996 (`peripfield` default 0; `-inf` required; UDP only),
  ~l.1572 (`ip_file` = the first `-inf`), `socket.cpp` `open_connections`
  ~l.2466-2560 and `call.cpp` `connect_socket_if_needed` ~l.1430-1475,
  `E_Message_Server_IP` ~l.2768, `docs/transport.rst`): the main socket is
  bound to the IP in line 0's `-ip_field` column ("on some machines it
  fails to bind to the self computed local IP"), and `map_perip_fd` maps
  IP → socket. A **client** call, at its first send, looks up the IP in
  *its* injection line and uses the mapped socket, creating one bound to
  `ip:local_port` if absent — persistent for the run, never closed (an
  unbindable IP is a fatal "Unable to bind UDP socket"). A **server**
  binds one extra socket per distinct listed IP at start-up and answers
  each request from the socket it arrived on. `[server_ip]` is
  `getsockname` on the call's socket — the IP the call sends from —
  which is how a `ui` scenario writes correct Via/Contact lines
  (`[local_ip]` stays the `-i` / auto-detected address). sipr matches all
  of this — the per-IP sockets share the main socket's port, calls attach
  to the receiving socket on the server, `[server_ip]` renders the socket
  IP, the errors are fatal at the same points — with one divergence: IPs
  must be literal (SIPp resolves host names in the column).
- SCTP `-t s1|sn` (M32; verified in `sipp.cpp` ~l.209-243, `socket.cpp`
  ~l.806-850, ~l.888-905, ~l.1575-1590, ~l.1694-1775, ~l.2076): SIPp uses
  one-to-one `SOCK_STREAM` SCTP sockets, receives with `sctp_recvmsg` —
  **one SCTP message is one SIP message**, no Content-Length framing —
  holds sends until `SCTP_COMM_UP` arrives as an `SCTP_EVENTS`
  notification, sets `SCTP_NODELAY`, and applies `-heartbeat`,
  `-pathmaxret`, `-pmtu`, `-assocmaxret` per peer address
  (`SCTP_PEER_ADDR_PARAMS`), `-multihome` via `sctp_bindx`, `-gracefulclose`
  as SHUTDOWN vs ABORT. A SIPp built without `USE_SCTP` errors "SCTP support
  is not enabled!". sipr (cargo feature `sctp`, off by default; `socket2`)
  matches the socket type, the message-per-message model, `s1`/`sn`, the
  association-up gating (a blocking `connect`), reliability (no
  retransmissions), reconnection and the clear error without support, with
  these divergences: no `SCTP_NODELAY`, no notifications (a peer's SHUTDOWN
  is seen as end-of-stream), and the six SCTP option flags are **rejected**
  rather than applied — socket2 cannot set SCTP-level socket options. Only
  Linux with the `sctp` module has a stack; macOS and Windows report "SCTP
  is not supported on this host". Verified in Linux CI against a sipp built
  with `USE_SCTP`; the development host cannot run it.
- Variable scopes and dynamic users (M35; verified in `variables.cpp`
  ~l.187-210, ~l.284-330, ~l.342-351, `scenario.cpp` ~l.718, ~l.756-790,
  `sipp.cpp` ~l.1449-1450, ~l.1738-1744, ~l.2123-2126, `call.cpp`
  ~l.1100-1115, ~l.1296, `call_generation_task.cpp` ~l.144-145,
  ~l.252-293, `socket.cpp` ~l.289-290): SIPp keeps three chained variable
  tables — the call's own, `userVarMap[userId]` (one per user id, created
  at start-up for 1..N and by `set_users` growth, never freed) and one
  `globalVariables` — and `<User variables="a,b"/>` / `<Global
  variables="c"/>` allocate the names at the user / global level. Both
  levels are process-wide: every scenario (`-sf`, `-oocsf`, `-rxsf`)
  hangs its `allocVars` off the same `userVariables`, so one name is one
  slot across scenarios. A call with a user id parents its table on the
  user's; a call without one (UAS, ooc, rx, plain rate mode) gets a fresh
  private table, so "user" variables are per call there. `-set VAR VALUE`
  seeds a global (fatal "Can not set the global variable VAR, because it
  does not exist." when no scenario declared it — and, in SIPp, when it
  comes *before* `-sf` on the command line, since the scenario loads as
  its flag is parsed). `dump variables` prints the displayed scenario's
  names per level (0 global, 1 user, 2 call) as WARNINGs. User ids: the
  free pool is filled 1..N and served from the **back**, so the first
  call is user N's; a finished call's id goes to the front of the pool
  (behind the still-free ones) — or, when more calls are live than `set
  users` now allows, to `retiredUsers`; the next growth takes retired ids
  back first (oldest first, with their variables), then creates fresh
  ones; a shrink touches no pool.
  sipr matches all of it — scopes resolved at compile time into a
  per-scenario layout over one user table per id and one global table,
  the private user layer for id-less calls, `-set` (checked after all
  scenarios load, so flag order does not matter), `dump variables` into
  the error trace with SIPp's line format, and the exact pool order —
  with these deliberate divergences: (1) a name used *before* its
  `<User>`/`<Global>` declaration is already call-scoped in SIPp
  (`AllocVariableTable::find` checks the scenario's own map first) and the
  declaration silently creates a second, differently scoped variable of
  the same name; sipr scopes every use as declared and **warns** (so
  `--check` fails) naming the earlier use. (2) A name one scenario
  declares `<User>` and another `<Global>` is a start-up error in sipr
  (SIPp: whichever level allocated first wins, silently). (3) Each
  scenario must declare its own scopes — a bare use of `g` in the rx
  scenario does not inherit the main scenario's `<Global>` declaration
  (SIPp resolves it through the shared parent tables; sipr compiles each
  file on its own). (4) On a growth that needs fresh ids SIPp uses
  `users + 1` counting from the *current target*, which after a shrink
  collides with ids still live (e.g. 3 → 1 → 3 while the calls of 2 and 3
  are up hands id 2 out twice and replaces user 2's table); sipr creates
  never-used ids instead (4, 5, …), so an id is live at most once and no
  table is lost. (5) A `<Global>` read but never set in a scenario is no
  diagnostic (its value may come from `-set` or the other scenario); a
  `<User>` one still is the usual error, since only the main scenario's
  own actions could set it. Found on the way: (a) variable value
  semantics, fixed right after M35 (v0.24.0) — see the next note; (b)
  SIPp's scheduler runs one message step per call per turn (`call::run`
  returns after a `<nop>`'s `next()`), sipr runs a call until its first
  blocking step — so two calls started in the same tick interleave their
  action steps differently (both `<nop>`s before either `<send>` in
  SIPp), which only shows through shared (global) variables. Settled as a
  permanent divergence in M44 below; the M35 interop test normalises it.
- Variable value semantics (v0.24.0; verified in `variables.cpp` ~l.33-46
  `CCallVariable::isSet`, `call.cpp` ~l.3968-3978 `E_Message_Variable`,
  ~l.1933 `call::next`, ~l.2241 `condexec`): a variable "is set" when it
  is a string or regexp capture (even empty), a **non-zero** double, or a
  **true** bool. `[$var]` writes nothing for an unset variable, a double
  as `%lf` (`3.000000`, `-2.000000`), a true bool as `true`; so a zero
  counter and a false `<test>` result render empty. `test="var"` on a
  message and `condexec` ask the same `isSet`. sipr now matches all of
  it (it used to print `3`, `false` and `0`, and treated a `"0"`/`"false"`
  string as not set). Not matched on purpose: SIPp's `getString()` of a
  double is `""` (the source calls it a bug), so `strcmp`/`trim`/
  `urlencode` on a numeric variable see nothing there; sipr gives them
  the `%lf` text.
- `<assign>` (verified in `scenario.cpp` ~l.1344-1365 `handle_rhs`,
  ~l.1469; `call.cpp` ~l.5692 `get_rhs`, ~l.5778
  `E_AT_ASSIGN_FROM_VALUE`): it takes `value=` (a double, the form SIPp's
  docs show) or `variable=`, exactly one of them, and stores a **double**
  either way: `variable=` stores the other variable's number, not a copy
  of its value. sipr refused `value=` and copied the value as is, until
  it matched both. Verified against real sipp 3.7.7 by the
  `assign_takes_a_value_or_a_variable_like_real_sipp` interop test.
  **Open:** SIPp's number of a variable (`CCallVariable::getDouble`) is 0
  for anything but a double, so `variable=` naming a string or a bool
  stores 0. sipr's parses a numeric string and reads a true bool as 1, as
  in all its `value=`/`variable=` actions.
- Manual transactions (M36; verified in `scenario.cpp` ~l.343-400
  `get_txn`, ~l.878-931, ~l.588-602 `validate_txn_usage`; `call.cpp`
  ~l.1128, ~l.2110-2116, ~l.4431-4450 `extract_transaction`,
  ~l.4581-4587 `matches_scenario`, ~l.5395-5430, ~l.5502-5504;
  `docs/scenarios/ownscenarios.rst`): `start_txn="n"` on a sent request
  stores the top Via `branch` of the message as sent (up to `;`, `,` or
  whitespace) under `n`; `ack_txn="n"` on a sent ACK records that ACK's
  step; `response_txn="n"` on a `recv response=` matches **only** a
  response whose top Via branch equals the stored one — that check
  replaces both the first-step rule and the CSeq-method guard, and a
  request that names a transaction is left out of the CSeq-method list
  the other recvs use. Placement is strict, with these fatal texts: "An
  ACK message can not start a transaction!", "The ack_txn attribute is
  valid only for ACK messages!", "Responses can not start a transaction",
  "Responses can not ACK a transaction", "response_txn can only be used
  for received messages." (on a send), "… for received responses." (on
  `recv request=`); names obey the variable-name rules ("Variable names
  may not be empty / contain $ or , for start transaction | ack
  transaction | transaction response"); after parsing,
  `validate_txn_usage`: "Transaction n is never started!", "… has no
  responses defined!", "… is an INVITE transaction without an ACK!",
  "… is a non-INVITE transaction with an ACK!". A response for a named
  transaction that arrives once the call has moved past its recv (an
  "old transaction" reply, found by branch anywhere behind the window):
  a 1xx is ignored ("Ignoring provisional `<transport>` message for
  transaction n", a trace line), a final one for an INVITE transaction
  gets the recorded `ack_txn` ACK re-rendered and sent again, and a
  repeat of the final response already taken (same message hash) is
  ignored with a WARNING ("Ignoring final `<transport>` message for
  transaction n (hash …)"); anything else is unexpected as usual. The
  accepted response's hash is stored per transaction. `[branch]` itself
  knows nothing of transactions (`z9hG4bK-pid-number-index`): an
  `ack_txn` ACK carries its own branch. sipr matches all of it (the
  trace/WARNING lines go to the error trace; the hash is over the
  datagram bytes) with one addition: a `<send>` carrying both
  `start_txn` and `ack_txn` is an error (SIPp silently takes
  `start_txn`). Verified against real sipp both ways.
- `exec command=` and `<setdest>` (M37; verified in `scenario.cpp`
  ~l.265-270 `xp_get_string` ("%s is missing the required '%s'
  parameter."), ~l.1596-1600, ~l.1637-1640; `call.cpp` ~l.6144-6178,
  ~l.5841-5935, ~l.2741; `socket.cpp` ~l.2588; `docs/scenarios/actions.rst`):
  `exec command="…"` renders the text like a message (keywords, `[$var]`)
  and runs it through `system()` in a double-forked grandchild — SIPp
  never waits for it and never sees its status, stdio is inherited (the
  `>> file` idiom; output lands on the curses screen too) and a
  `system()` failure is the grandchild's WARNING "system call error for
  %s". sipr matches the contract from one runner thread that spawns `sh
  -c` (`cmd /C` on Windows) with stdin closed and reaps its children as
  they exit — the engine thread never forks or blocks, no zombie
  accumulates under load — and prints the same warning to stderr on a
  spawn failure; commands still running at exit are left to finish, as
  SIPp's grandchildren are. `<setdest host= port= protocol=/>`: all three
  required, all three rendered at run time; the port must be numeric
  ("Invalid port for setdest: %s"), the protocol `udp|tcp|tls|sctp` in
  either case ("Unknown transport for setdest: '%s'") and the run's own
  ("Can not switch protocols during setdest."); TLS is refused ("Changing
  destinations is not supported for TLS."), TCP/SCTP need the per-call
  modes `-t tn|sn` ("Changing destinations for TCP or SCTP requires
  multisocket mode.") and a connection no other call shares ("Can not
  change destinations for a TCP/SCTP socket that has more than one
  user."); the host goes through a **blocking** `getaddrinfo` ("Unknown
  host '%s' for setdest"); UDP then retargets the call's peer, TCP/SCTP
  close the call's connection and dial the new peer, a failure logging
  "Unable to connect a TCP/SCTP/TLS socket" and spending one
  `-max_reconnect` credit ("Max number of reconnections reached" when
  none is left). `[remote_ip]`/`[remote_port]` keep rendering the global
  remote — setdest moves the traffic, not the keywords — and it
  overrides `-rsa` for that call (SIPp copies the sending address into
  `remote_sockaddr` at start-up and setdest overwrites the peer). sipr
  matches every check and its wording, with two deliberate differences:
  (1) each `setdest` error **fails the call, not the run** (the same
  choice as for "Jump statement out of range"), logged as `call … failed:
  setdest: <SIPp text>`; (2) an IP literal costs no I/O, and the first
  host name resolved logs a note that the lookup blocks the engine
  thread. IPv6 literals go bare, as SIPp documents (brackets read as a
  keyword). A call that has not sent yet (per-call modes) is simply
  retargeted; its first send dials the new peer. Verified against real
  sipp both ways. Found on the way: (a) `ereg search_in="body"` and
  `search_in="var" variable="…"` (`scenario.cpp` ~l.1396-1401, `call.cpp`
  ~l.5739-5760: the body, or the variable's text, is the haystack) were
  missing and are now supported — SIPp's setdest idiom needs `var`;
  `case_indep`, `occurrence` and `check_it_inverse` on `ereg` are still
  not. (b) `[next_url]` (`call.cpp` ~l.5570-5580): SIPp copies the
  Contact into `next_req_url` only for a recv with `rrs="true"`;
  otherwise the keyword falls back to the last *received* request's URI,
  which a UAC never has — so the documented setdest example silently
  depends on `rrs="true"` on the `recv response="200"`. sipr renders the
  last received Contact regardless of `rrs` (settled as permanent in
  M44 below: it is what the example intends). (c) `[last_*]` inside the actions of
  the recv that just matched (`call.cpp` ~l.5517 `executeAction` before
  ~l.5641 `last_recv_msg = …`): SIPp still names the *previous* received
  message — empty on a call's first recv — so SIPp's own
  `<exec command="echo [last_From] >> from_list.log"/>` example writes
  blank lines; sipr's `[last_*]` name the message just received (settled
  as permanent in M44 below; the interop test accepts both). (d) The
  example's unquoted From also breaks under any shell (`<`, `>` and `;`
  are redirections and a command separator) — quote it.
- The three divergences M37 and M35 left open, settled (M44). Each was
  "left as is" with no decision recorded; each is now **permanent**, with
  no `--sipr-strict-sipp` flag, and the first two are pinned by
  `next_url_and_last_headers_follow_siprs_reading_not_sipps` in
  `tests/e2e.rs`.
  (1) **`[next_url]` without `rrs`** (`call.cpp` ~l.5570-5580): SIPp fills
  `next_req_url` only on a recv carrying `rrs="true"` and otherwise falls
  back to the last received *request's* URI, which a UAC never has — so its
  own documented `setdest` example depends on an `rrs` nobody writes, and
  the keyword renders **empty** without it. sipr renders the last received
  Contact either way. A scenario written SIPp's way behaves identically in
  both; matching SIPp could only turn a working scenario into one that
  sends to an empty URI, which is no one's test.
  (2) **`[last_*]` inside the matching recv's own actions** (`call.cpp`
  ~l.5517 `executeAction` runs before ~l.5641 `last_recv_msg = …`): SIPp's
  keywords still name the *previous* received message, empty on a call's
  first recv — which is why SIPp's own `echo [last_From]` example logs
  blank lines. Matching it would mean rendering `[last_*]` from the
  previous message while `ereg` in the same action list still searches the
  new one: two different "current messages" in one `<action>` block, for a
  behavior no scenario depends on deliberately.
  (3) **Action-step interleaving** (`call.cpp` `call::run` returns after a
  `<nop>`'s `next()`): SIPp's scheduler runs one message step per call per
  turn, sipr runs a call until its first blocking step, so two calls
  started in the same tick interleave their `<nop>`s differently. Matching
  it means SIPp's one-step-per-turn scheduler, the opposite of the runtime
  model in ARCHITECTURE §3, for a difference observable only through a
  `<Global>` variable two such calls both write.
- sipp frees the socket it is still sending on when a TCP peer resets
  (found M44 while closing the interop gate; `socket.cpp` ~l.2151, the
  `default:` arm of `write_primitive`). After the far end closes a `-t t1`
  connection, sipp 3.7.7 reaches a `SIPpSocket` whose `ss_transport` reads
  back as garbage — the same run logs "Unable to send UDP message" for a
  TCP run, and then dies on the fatal "Internal error, unknown transport
  type 1024" instead of reconnecting. Reproducible on macOS; the mirror
  direction (sipr's UAC reconnecting to a sipp UAS) is unaffected, so this
  is sipp's bookkeeping, not a protocol difference. Nothing sipr can do
  about it — closing the connection is what the test is *for* — so
  `real_sipp_tcp_uac_reconnects_to_sipr` skips **visibly** when sipp's
  error log shows it, alongside the pre-existing "Unable to bind TCP
  socket" guard.
- (append new findings above this line, with a pointer to where in the C++ you
  verified them)
- Statistical pauses and `<sample>` (M38; verified in `scenario.cpp`
  ~l.1112 `parse_distribution`, ~l.965-985 the `<pause>` branch and its
  `sanity_check`, ~l.1522 `sample`; `stat.cpp` ~l.1530-1880 the `CSample`
  classes; `call.cpp` ~l.1956 the pause branch of `call::run`, ~l.6125
  `E_AT_ASSIGN_FROM_SAMPLE`): the distribution is `distribution="<kind>"`
  and its parameters are **separate attributes** with SIPp's names —
  `fixed` `value`; `uniform` `min`/`max`; `normal` and `lognormal`
  `mean`/`stdev` (a lognormal's are the log-space parameters, GSL's
  `zeta`/`sigma`); `exponential` `mean`; `weibull` `lambda` (scale) /`k`
  (shape); `pareto` `k` (shape) /`x_m` (minimum); `gpareto`
  `shape`/`scale`/`location`; `gamma` `k` (shape) /`theta` (scale);
  `negbin` `p`/`n`. There is no `poisson`. A missing parameter is SIPp's
  "`<Kind>` distribution is missing the required '`<name>`' parameter.", an
  unknown kind "Unknown distribution: `<kind>`". Old-style `<pause>` spellings
  are accepted too: `min`/`max` alone mean `uniform`, and a bare
  `normal="…"`/`exponential="…"`/`lognormal`/`weibull`/`pareto`/`gamma`
  flag names that kind. sipr's earlier positional shorthand,
  `distribution="uniform(200,3000)"`, still parses (values in SIPp's
  attribute order) but is a sipr extension. `sanity_check` (default true)
  refuses a distribution whose 99th percentile exceeds `INT_MAX` ms, as
  SIPp does; a negative binomial has no percentile in SIPp and is not
  checked. Sampling (engine `sample.rs`, one draw per pause or action
  from the seeded generator): SIPp uses GSL and is built with these only
  under `USE_GSL` — a GSL-less sipp errors "The distribution '…' is only
  available with GSL" for everything but `fixed` and `uniform`; sipr always
  has them. A pause sample below 1 (the negative tail of a normal) is no
  pause, as SIPp's `if (actualpause < 1) pause = 0`. `<sample>` stores a
  double. Two deliberate divergences: (1) SIPp passes negbin's `n` and `p`
  to GSL swapped (`gsl_ran_negative_binomial(rng, n, p)` against GSL's
  `(rng, p, n)`), so with its own documented `p="0.1" n="2"` GSL gets a
  "probability" of 2 and the pauses are garbage — sipr draws the documented
  meaning, failures before `n` successes at probability `p`; (2) the
  generalized Pareto's `shape="0"` divides by zero in SIPp — sipr uses the
  `shape → 0` limit, `location + Exp(scale)`. Poisson draws past a mean of
  30 (inside negbin) use the normal approximation. The screen/`--check`
  label is SIPp's `textDescr`: `N(mean,stdev)`, `LN(…)`, `Exp(mean)`,
  `Wb(lambda,k)`, `P(k,x_m)`, `P(shape,scale,location)`, `G(k,theta)`,
  `NB(p,n)`, `min/max`, or the fixed value.
- Keyword parity, `-key` and `-tdmmap` (M39; verified in `message.cpp`
  ~l.50-120 the keyword table and ~l.236-372 `SendingMessage`'s dispatch,
  `call.cpp` `createSendingMessage` the `E_Message_*` arms, `sipp.cpp`
  `SIPP_OPTION_KEY`/`SIPP_OPTION_TDMMAP`, `call.cpp` ~l.113 the dynamic-id
  defaults and ~l.281 `get_tdm_map_number`, `stat.cpp` `CStat::formatTime`,
  `time.cpp` `getmicroseconds`): SIPp looks a bracketed name up in its
  keyword table **before** the `last_<Header>` copy, so `[last_message]`
  (the whole last received message, empty without one) and
  `[last_cseq_number]` (the CSeq number of the last received message,
  `sscanf("%d")`, 0 without one, plus a `+N`/`-N` suffix) are keywords,
  not header copies. `[clock_tick]` is milliseconds since the process
  started (SIPp's `clock_tick`, a steady clock). `[date]` is `gmtime` in
  RFC 1123 form, `Mon, 25 Oct 2021 07:20:55 GMT`. `[timestamp]` is the
  log time: `YYYY-MM-DD<TAB>HH:MM:SS.uuuuuu<TAB>ssssssssss.uuuuuu` or, with
  `-rfc3339`, `YYYY-MM-DDTHH:MM:SS.uuuuuu<offset>`; SIPp renders it in
  **local** time — sipr in UTC (offset `Z`), the one deliberate
  divergence, so it needs no timezone dependency. `[sipp_version]` is the
  bare version number (SIPp drops its `v`; sipr renders its own, e.g.
  `0.28.0`). `[dynamic_id]` is one counter for the run, starting at
  `-dynamicStart` (10000), stepping by `-dynamicStep` (4) at **every
  render**, wrapping back to the start once past `-dynamicMax` (18000).
  `[remote_host]` is the target host as typed on the command line,
  unresolved, port and IPv6 brackets stripped. `[fill variable=N
  text="…"]` repeats `text` (default `X`) to the variable's numeric value
  in characters (negative or unset = nothing); `[file name=…]` inserts a
  file's contents, the name itself a template (`[$var]`, `[fieldN]`) —
  sipr reads each name once per run and caches it, and a missing file
  fails the call where SIPp aborts the process. `-key KEYWORD VALUE`
  defines `[KEYWORD]` as the literal VALUE (SIPp's `generic` map, no
  keyword expansion inside the value); the compiler is told the names so
  they do not draw the unknown-keyword warning. `-tdmmap
  {x-x'}{h}{y-y'}{z-z'}` builds `(x'-x+1)·(y'-y+1)·(z'-z+1)` circuits;
  each outgoing call takes a free one at creation and `[tdmmap]` renders
  it as `X.h.Y/Z` (SIPp's formula, `Z` cycling fastest); no free circuit
  is SIPp's warning "Can't create new outgoing call: all tdm_map circuits
  busy" and a failed call. `[tdmmap]` without `-tdmmap` is SIPp's
  "[tdmmap] keyword without -tdmmap parameter on command line", raised at
  start-up rather than at the first render. Divergences from SIPp's
  circuit bookkeeping, deliberate: SIPp marks circuit `n-1` busy and frees
  circuit `n` (an off-by-one that leaks one circuit per call) and picks a
  random start — sipr hands out the lowest free circuit and frees the
  same one. The screen/`--check` dump names each keyword; `[file]` shows
  as `[file name=…]`.
- Statistics files at parity (M40; verified in `stat.cpp` `CStat::dumpData`
  ~l.1230-1400 (the header and row), `sRepartitionHeader`/`sRepartitionInfo`,
  `msToHHMMSS`/`msToHHMMSSus`, `computeRtt`/`dumpDataRtt`, `findRtd`
  (RTD numbering by first mention), `initRtt`/`setFileName` (file names);
  `logger.cpp` `print_count_file`, `print_error_codes_file`,
  `print_screens`; `reporttask.cpp` (`-fd` `stattask` dumps the CSV, the
  counts and the error codes then resets the PL counters; `-f`
  `screentask` refreshes the screen and resets the PD counters);
  `sipp.hpp` the defaults): `-trace_stat` writes
  `<scenario>_<pid>_.csv` (or `-stf`) with SIPp's header — `StartTime`,
  `LastResetTime`, `CurrentTime` (the `formatTime` form, `-rfc3339`
  aware), `ElapsedTime(P|C)` as `hh:mm:ss`, `TargetRate` (the `-users`
  count in users mode), `CallRate(P|C)` with three decimals, the fixed
  counter pairs through `WatchdogMinor`, then `ResponseTime<rtd>(P|C)` and
  `…StDev(P|C)` per RTD as `hh:mm:ss:uuuuuu`, `CallLength(P|C)` and
  `…StDev`, then a repartition block per RTD and for the call length: a
  name column (empty in rows) plus `Name_<b` per bound and `Name_>=last`.
  Every field ends with the delimiter, so the header ends with one. `(P)`
  is since the last dump (SIPp resets its PL counters after each dump;
  sipr diffs against a per-dump baseline), `(C)` since the start. RTDs
  are numbered by first mention in the scenario and named as written
  (`rtd="1"` → `ResponseTime1`, `rtd="setup"` → `ResponseTimesetup`).
  Counters sipr has no source for are always 0: `FailedCallRejected`,
  `FailedCmdNotSent`, `FailedRegexp*`, `FailedOutboundCongestion`,
  `FailedTimeoutOnSend`, `FailedTest*`, `FailedStrcmp*`, `Warnings`,
  `FatalErrors`, `Watchdog*`; `OutOfCallMsgs` counts messages for no
  call, `DeadCallMsgs` those absorbed in timewait. The generic
  `counter=` columns follow `CallLengthStDev(C)`, a `(P)`/`(C)` pair per
  counter (the generic-counters note below). `-fd` defaults to 60 s as SIPp's (it was 1 s) and the final row
  is written at exit regardless; `-f` (default 1 s) paces the screen
  snapshot and the `-bg` line. `-trace_rtt` writes
  `<scenario>_<pid>_rtt.csv`: `Date_ms;response_time_ms;rtd_no`, then
  per `rtd=` close the stop time and the response time — both in
  **seconds** despite the names, as SIPp divides by 1000 — and the RTD
  name, in C++ `ostream` default number form (six significant digits),
  buffered `-rtt_freq` (200) rows between flushes. `-trace_counts` writes
  `<scenario>_<pid>_counts.csv`: `CurrentTime;ElapsedTime` (the latter
  `hh:mm:ss:uuuuuu`) then per visible step `<index>_<name>_Sent`,
  `_Retrans` and, for a send with `retrans=`, `_Timeout`; for a recv
  `_Recv`, `_Retrans`, `_Timeout`, `_Unexp`; for a pause or timewait
  `<index>_Pause_Sessions` (times entered) and `_Pause_Unexp`; for a
  3PCC `sendCmd` `<index>_SendCmd`, for a `recvCmd` `<index>_RecvCmd` and
  `_RecvCmd_Timeout`; nothing for a nop or label — `<name>` the method or
  status code, `<index>` SIPp's message index, which counts pauses and
  nops but not labels (see "Message indices" below). **Open:** real
  SIPp's `print_count_file` gives a nop, `sendCmd` and `recvCmd` the
  `Pause` columns instead — its `else if (pause_distribution ||
  pause_variable)` test is always true there, because `pause_variable`
  defaults to -1 — so its NOP, RecvCmd and SendCmd arms never run. SIPp's `_Lost` columns
  appear only with `-lost` (M42). `-trace_error_codes` writes
  `<scenario>_<pid>_error_codes.csv`: per dump the time, the elapsed
  time and the status codes of the responses that failed a call as
  unexpected since the last dump, comma-terminated, newest first (SIPp
  pops them off the back). `-trace_screen` writes the
  scenario, statistics and repartition screens as text at exit, SIPp's
  `print_screens` order, to `<scenario>_<pid>_screen.log` (or
  `-screen_file`) — SIPp's `screen` log file (`logger.hpp`
  `LOGFILE(screen_lfi, "screen", …)`), not the `_screens.log` its help
  text promises, which sipr copied until the generic-counters interop
  test read real sipp's directory; sipr's screens are its own layout, not a copy of
  SIPp's curses text. `-periodic_rtd` zeroes every repartition table
  (per RTD and call length) at each dump. `-stat_delimiter` applies to
  all four CSV files. Found on the way: an `rtd=` with no matching
  `start_rtd=` measures from the call's creation — SIPp initialises every
  RTD's start time in `call::init`, and its own default UAC has only
  `rtd="true"` on the 200 — where sipr used to record nothing (so its
  `ResponseTime1` stayed 0 for the embedded UAC); `repeat_rtd` then
  restarts that clock at the recording step.
- Message and error logs at parity (M41; verified in `logger.cpp`
  `_trace`/`rotatef`/`_screen_error`/`LOG_MSG`, `socket.cpp` the
  `TRACE_MSG`/`TRACE_SHORTMSG` calls in `process_message` (receive) and
  `write_primitive` (send), `call.cpp` `callDebug`/`_callDebug`, `abort`
  (the dump) and `terminate` (`new deadcall`), `deadcall.cpp`, `sipp.cpp`
  the `SIPP_OPTION_LFNAME`/`LFOVERWRITE` cases and the startup
  `rotate_*f` calls, `sipp.hpp` `DEFAULT_DEADCALL_WAIT`): every log is
  `<scenario>_<pid>_<kind>.log` — `messages`, `errors`, `logs`,
  `shortmessages`, `calldebug`, `screens` — or the `-<kind>_file` name;
  `-<kind>_overwrite false` appends instead of truncating (SIPp also sets
  `fixedname` there, which empties the name when no `-<kind>_file` was
  given — a SIPp bug sipr does not copy). `-trace_msg` frames are SIPp's:
  a 47-dash rule and the time (always the RFC 3339 form there), then
  `<TRANSPORT> message sent|received [<bytes>] bytes:`, a blank line and
  the message — no peer address (sipr used to print one). `-trace_err`
  starts with `The following events occurred:` and each line is `<time>:
  <text>` (`-rfc3339` aware); `<warning>` actions land there. `<log>`
  actions go to `-trace_logs` (`LOG_MSG`, one line each, keyword-expanded)
  and nowhere without it. `-trace_shortmsg` writes per message
  `<time>\tS|R\t<Call-ID>\tCSeq:<value>\t<start line>`; SIPp's receive
  side always uses the default (tab-separated) time form while its send
  side honours `-rfc3339`, so a line has seven tab-separated columns
  except an RFC 3339 send line's five — matched, quirk included.
  `-trace_calldebug` buffers per call SIPp's `callDebug` entries (`<time>
  <text>`): `Starting call`, `Sending <TRANSPORT> message for call <id>
  (index <n>, hash <h>)` with the message, `Processing <n> byte incoming
  message for call-ID <id> (hash <h>)` with the message, `Unexpected …
  message received`, and on abort `Aborting call <id> (index <n>).`; an
  aborted call's buffer is written under `Call debugging information for
  call <id>:` and its rule — a successful call writes nothing, as SIPp's
  `abort` is the only dumper. The hash is sipr's, not SIPp's. Rotation
  (`_trace`): `-ringbuffer_size` bytes written rotates the file — with
  `-ringbuffer_files` N the current file is renamed
  `<scenario>_<pid>_<kind>_<start seconds>.log` (`.<n>.log` when the same
  second repeats) and the oldest beyond N is deleted; without it the file
  is truncated in place — and `-max_log_size` closes the file for good.
  Rotation applies to the messages, errors, logs, shortmessages and
  calldebug files, not the statistics CSVs, as in SIPp. `-deadcall_wait`
  (default 33 s; 0 disables): a finished call's Call-ID is remembered
  with its reason — `successful`, or `aborted at index <n>` — and a late
  message for it is not out-of-call: SIPp's `deadcall` counts
  `DeadCallMsgs`, warns `Dead call <id> (<reason>), received '<msg>'`,
  writes `Dead call <id> received a <TRANSPORT> message:` to the message
  trace and refreshes the expiry; sipr does the same and sweeps expired
  entries once a second (a message absorbed by a call in `<timewait>`
  also counts as `DeadCallMsgs`, M40). `-trace_timeout` is accepted and
  does nothing: SIPp 3.7's implementation is commented out.
- Timer and behavior knobs (M42; verified in `call.cpp` ~l.2252-2320 the
  retransmission block, ~l.2160-2205 the receive timeout, ~l.2445-2520
  `process_unexpected`, ~l.2534-2600 `abortCall`, ~l.6665-6830
  `checkAutomaticResponseMode`/`automaticResponseMode`, ~l.1242
  `matches_cseq`, ~l.1527 `lost`, ~l.4628 the `-pause_msg_ign` check,
  `default_message_strings` ~l.2335; `sipp.cpp` `SIPP_OPTION_DEFAULTS`,
  `timeout_alarm`, the `sleeptime`/`nostdin` setup; `socket.cpp`
  `get_trimmed_call_id`; `call.hpp`/`sipp.hpp` the defaults): SIPp
  retransmits an INVITE up to `-max_invite_retrans` (5) times and any
  other message up to `-max_non_invite_retrans` (9), `-max_retrans` being
  a ceiling on both; the interval doubles from the send's `retrans=` and
  is capped at T2 (4 s) only for non-INVITE transactions — an INVITE keeps
  doubling (500, 1000, 2000, 4000, 8000 ms). sipr used one cap of 5 and
  capped everything at T2; both now match. `-recv_timeout` (default unit
  ms) is the timeout of every recv without its own `timeout=`; the
  timeout fires the same way (`ontimeout` label or a failed call).
  `-timeout_error` makes reaching `-timeout` an error — SIPp's
  `<scenario> timed out after '<s>' seconds`, exit 255. `-lost <percent>`
  is the loss of every send and every recv whose own `lost=` is absent;
  a received message that "loses" is dropped after matching, with a
  `message lost (recv)` call-debug entry. `-pause_msg_ign` drops whatever
  arrives while the call is in a pause before anything is counted.
  `-default_behaviors` is SIPp's list (`all`, `none`, `bye`,
  `abortunexp`, `pingreply`, `cseq`; `-x` removes, `+x`/`x` adds, left to
  right from none; `-nd` = `none`): `abortunexp` off counts an unexpected
  message and continues the call (SIPp's "Continuing call on unexpected
  message"); `bye` on ends an aborted client-side call the way SIPp's
  `abortCall` does — an unestablished INVITE answered 4xx or worse gets an
  ACK, one answered 200 gets ACK then BYE, one answered provisionally gets
  a CANCEL, one never answered gets nothing, any other call that received
  something gets a BYE — using SIPp's own built-in templates (compiled
  with sipr's template engine, hence the new `[last_Request_URI]`
  keyword: the URI in `<…>` of the last received To); `bye` also answers
  an unexpected BYE or CANCEL with a 200 before aborting; `pingreply`
  answers an unexpected `PING` request with a 200 and drops the call,
  neither successful nor failed, as SIPp does; `cseq` makes an ACK match
  only when its CSeq number is the last received INVITE's (SIPp
  `matches_cseq`). A server-side or secondary call never sends abort
  messages (SIPp `creationMode != MODE_SERVER`). Call-IDs: SIPp keys a
  call by the text after the first `///` (its 3PCC twin marker) unless
  `-callid_slash_ign`; sipr used to keep the whole value and now trims
  it the same way. `-sleep <s>` waits before the run, `-nostdin` disables
  the keyboard watcher. `-send_timeout` and `-timer_resol` are accepted
  with a warning: sipr has no send queue that could time out and its
  timers are exact, not polled.
- Message indices: labels are not messages (verified in `scenario.cpp`
  ~l.803-839 and `call.cpp` ~l.1930-1945, ~l.3892-3902, ~l.5449-5458,
  ~l.5991-6002, `logger.cpp` `print_count_file`; confirmed against real
  sipp). SIPp's scenario is a vector of *messages* — `send`, `recv`,
  `pause`, `timewait`, `nop`, `sendCmd`, `recvCmd` — and a `<label>` is
  not one of them: it only records `labelMap[id] = messages.size()`, the
  index of the message after it. Every index a scenario or SIPp's output
  speaks is a message index. `<jump value="N"/>` (and `variable=`) sets
  `msg_index = N - 1` and lets `next()` step to N, with the range
  `0 <= N <= messages`: N equal to the message count runs past the last
  message, and the call ends successfully. `[msg_index]` renders the
  index of the message being sent, and `[branch]` ends in it
  (`z9hG4bK-<pid>-<call>-<index>`). `_unexp.retaddr` receives the
  interrupted message's index. The `-trace_counts` columns are prefixed
  with it, and the call-debug lines ("Sending … (index N", "Unexpected …
  (index N", "Aborting call … (index N)") print it. sipr keeps a label
  as a step of its own (the scenario screen and the lints place it), so
  it used to count labels in all of these. A `<label>` before the target
  sent a jump elsewhere, and a label anywhere earlier shifted
  `[msg_index]`, `[branch]` and the counts columns. Now the compiler
  numbers messages as SIPp does (`Scenario::message_index` and
  `step_of_message`). `jump value=` resolves to the message's step at
  compile time, and `jump variable=` maps its message index at run time,
  so `_unexp.retaddr`, written as a message index, round-trips. The
  range check follows SIPp, including the jump past the end. sipr's own
  outputs number the same way: the `--check` dump and `/scenario`
  (labels unnumbered, `next->`/`ontimeout->` as message indices),
  `dump tasks`, and `/metrics` `step=` (no series for a label).
  Verified against real sipp, which sends the same messages with the
  same `[msg_index]`, `[branch]` and counts prefixes for a UAC whose
  jumps cross labels. It also round-trips `_unexp.retaddr` with a label
  before the interrupted pause. **Open**, found on the way: (1) SIPp
  evaluates `next()` *at message N-1* after a jump, so if message N-1
  has a `next=` (its `test` set, its `chance` won), SIPp follows that
  instead of running N. sipr runs N. (2) A `<jump>` in a mandatory
  `<recv>`'s actions does nothing in SIPp: `process_incoming` then sets
  `msg_index = search_index` and calls `next()`. sipr takes the jump.
  (3) Where SIPp renders with no message index (`P_index` -1: actions
  such as `<log>` and `<assignstr>`, `<sendCmd>`, the `-default_behaviors`
  abort messages), `[msg_index]` prints `-1`, and `[branch]` ends in the
  current message index minus one. sipr renders the current message's
  index in both.
- Receive timeouts (verified in `call.cpp` ~l.2150-2205 `call::run`,
  ~l.5653-5687 `process_incoming`, ~l.1920-1945 `next()`, `task.cpp`
  `add_paused_task`, and `scenario.cpp` ~l.33-39 the `message` defaults,
  ~l.914/948 where `timeout` is read; confirmed against real sipp, the
  `recv_timeouts_arm_like_real_sipp` interop test). The call waits at
  `msg_index`, the recv (or `<recvCmd>`) it reached, and `run()` arms
  *that* message's `timeout=`, else `-recv_timeout`, optional or not;
  zero means none. A recv further into the window plays no part: in
  `<recv request="INFO" optional="true"/>` `<recv request="BYE"
  timeout="1000" ontimeout="x"/>` the BYE's timeout never runs while the
  call waits at the INFO, and with `-recv_timeout` it is the INFO that
  times out and, with no `ontimeout` of its own, fails the call. A
  matched optional recv moves the call on. `process_incoming` keeps
  `msg_index` only when `!optional || (next && test)` is false, but
  `next` defaults to -1, which C reads as set, so every optional match
  without a `test=` does `msg_index = search_index; next()`, and
  `next()` zeroes `recv_timeout`: the recv after it arms its own timeout
  afresh. (The smallest timeout of the recvs ahead, which the "stay"
  branch computes, is thrown away: `setPaused()` reschedules from
  `wake()` alone.) On expiry the waiting message counts the timeout
  (`_Timeout`) and the call goes to its `ontimeout`. With none — or with
  a label past the last message — the call fails as
  `FailedTimeoutOnRecv`, with the `bye` behavior's abort messages. The
  error log gets SIPp's `Call-Id: <id>, receive timeout on message
  <scenario>:<index>, jumping to label <index>`, or `… without label to
  jump to (ontimeout attribute): aborting call`. `<recvCmd>` has no
  `timeout=` (SIPp reads it on `<send>` and `<recv>` only), so
  `-recv_timeout` is its timeout, mandatory or optional. sipr used to arm
  the window's *mandatory* recv's timeout instead: an optional recv's
  `timeout=`/`ontimeout` did nothing, so a trailing `optional
  timeout="1000" ontimeout="end"` recv hung where sipp fails the call
  after 1 s; a mandatory recv's timeout ran while the call still waited
  at the optional one in front of it; an `ontimeout` past the end
  counted as a success; and a `<recvCmd>` never timed out. So a
  `timeout=` on the 200 of `100 optional`, `180 optional`, `200` arms
  only once a provisional has moved the call onto the 200. Until then it
  waits for the 100, as it always did in SIPp. **Open:** SIPp takes
  `ontimeout=` on a `<recvCmd>` (a common attribute); sipr warns it away
  as unknown, so a recvCmd that times out always fails the call. (The
  other item once open here, a matched recv's `next=`/`test=`/`chance=`,
  is fixed since: see the next note.)
- Branching on a matched `<recv>` (verified in `call.cpp` ~l.5653-5687
  `process_incoming`, ~l.1920-1945 `next()`, ~l.1777 `do_bookkeeping`,
  and `scenario.cpp` ~l.1860-1876, which reads `test=` and `chance=` only
  beside a `next=`; confirmed against real sipp, the
  `a_matched_recv_branches_like_real_sipp` interop test). A matched recv
  leaves through `next()`, as a send, pause or nop does: to its `next=`
  when its `test=` variable, if any, is set and its `chance=` draw, if
  any, is won, else to the message after it. The recv's actions run
  first, so an `<ereg assign_to=>` on the recv decides its own `test=`.
  The exception is an optional recv whose `test=` variable is unset:
  `process_incoming` skips `next()`, so `msg_index` stays at the message
  the call waited at — the window's first recv, not the one that matched
  — and the `recv_timeout` running there keeps its deadline (sipr
  re-arms it unchanged). The rest of the match still happens: the
  message counts as received, becomes the `[last_*]` message and stops
  a retransmission, and its RTDs and `counter=` are booked
  (`do_bookkeeping` runs before the branch). A mandatory recv never
  stays, whatever its `test=`, and `test=` without `next=` does nothing.
  sipr used to ignore `next=`, `test=`, `chance=` and `counter=` on a
  recv: it never jumped, and always moved to the message after the
  match. `counter=` now ticks on a recv as on the other steps (reported
  since: the generic-counters note below). **Divergence, on purpose:** SIPp tests `next` there as a
  C boolean (`next && …`), and a `next=` label before the first message
  resolves to index 0, which reads as false. So in SIPp an optional recv
  whose `next=` names message 0 stays where it waited, `test=` or not,
  and never takes the jump (checked by hand against real sipp). sipr
  takes it: silently dropping a `next=` is a SIPp failure mode sipr does
  not inherit.
- Generic counters, `counter=` (verified in `scenario.cpp` ~l.567
  `get_counter` and ~l.1824 `getBookKeeping`; `stat.cpp` ~l.869
  `findCounter`, ~l.999 `E_ADD_GENERIC_COUNTER`, the `RESET_*_COUNTERS`
  macros, ~l.1273 and ~l.1388 in `dumpData`; `screen.cpp` ~l.755
  `draw_stats_screen`; `call.cpp` ~l.1777 `do_bookkeeping` and its call
  sites; `reporttask.cpp`; confirmed against real sipp, the
  `generic_counters_match_real_sipps_statistics` interop test). A
  counter is a scenario-wide statistic, not a per-call one: every step
  that names it adds one, whichever call runs the step, on the stat set
  of the scenario it belongs to (the main, `-oocsf` and `-rxsf`
  scenarios each count their own, as each owns a `CStat`). The
  scenario registers its counters as it loads, in the order it first
  names them, so a counter no call ever reaches is still listed, at 0.
  A name is refused at load when it is empty or holds `$` or `,` — SIPp's
  two checks, compile errors in sipr. **When a step books it**
  (`do_bookkeeping`, which also stops and starts the RTDs): a send
  before its message is built, so a send that fails still counts; a
  pause (and SIPp's timewait) on entry; a nop, and a recvCmd on
  receipt, *before* their actions, so a `<jump>` or a stopped call does
  not undo it; a recv when it matches, whatever branch it then takes
  (the recv-branching note above); a sendCmd once the command is out.
  A retransmission books nothing. **Where it shows:** the statistics
  screen gives each counter a `Counter <name>` row, after the calls
  created and before the successful/failed counts, with a periodic value
  (reset at every screen refresh, SIPp's `PD` counters) and a
  cumulative one; sipr draws the rows on its main (statistics) screen,
  in its own layout, so they also reach `-trace_screen`. `-trace_stat`
  gives each a `<name>(P)` and a `<name>(C)` column after
  `CallLengthStDev(C)` and before the repartition blocks — `(P)` since
  the last dump (`PL`), `(C)` since the start. An all-digit name heads
  its columns `GenericCounter<name>` instead, cut to 19 characters
  because SIPp formats it into a 20-byte buffer: `counter="1234567"` is
  `GenericCounter12345(P)`, and two long numeric names can share a
  column name (sipr follows this, since wrappers read columns by name).
  The screen label is never rewritten: `Counter 1234567`. As with the
  rest of the file, only the main scenario's counters are written.
  sipr additions: `/stats` and `--sipr-stats-json` carry
  `"counters":[{"name","periodic","cumulative"}]` for the displayed
  scenario, and `/metrics` a `sipr_scenario_counter_total{counter=…}`
  series each (docs/CONTROL_API.md). sipr kept a per-call map until
  now, which nothing read; it also booked a nop's and a recvCmd's
  counter only when their actions did not move the call, and a send's
  only after a successful send. **Open:** sipr's `<timewait>` takes
  only `milliseconds` and warns the common attributes away as unknown,
  so `<timewait counter=…>` does not count there, where SIPp books it
  on entry.

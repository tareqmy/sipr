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
| `send` | common⁺, `retrans`, `lost`, `crlf` | CDATA body = message template |
| `recv` | common⁺, `response`, `request`, `optional`, `timeout`, `ontimeout`, `rrs`, `auth`, `lost`, `regexp_match` | |
| `pause` | common⁺, `milliseconds`, `variable`, `distribution`, `sanity_check` | uniform/normal/exp distributions |
| `nop` | common⁺, `display` | carries actions |
| `label` | `id` | jump target; validated at compile |
| `timewait` | `milliseconds` | end-of-call linger |
| `Reference` | `variables` | suppress unused-var warnings |
| `ResponseTimeRepartition` | `value` | ms bucket list |
| `CallLengthRepartition` | `value` | ms bucket list |

⁺ common attrs: `start_rtd`, `rtd`, `repeat_rtd`, `crlf`, `next`, `test`,
`chance`, `condexec`, `condexec_inverse`, `counter`.

### v1 actions (inside `<action>` on recv/nop)

`ereg` (with `assign_to`, `check_it`, `header`, `regexp`, `search_in`,
`start_line`), `log`, `warning`, `error`, `assign`, `assignstr`, `strcmp`,
`test`, `add`, `subtract`, `multiply`, `divide`, `todouble`, `jump`, `trim`,
`gettimeofday`, `urlencode`, `urldecode`,
`exec` with `int_cmd` only (`stop_now`, `stop_gracefully`, `stop_call`).

### v1.x tier (fast follow)

`sample`, `setdest`, `exec command=` (external process),
`start_txn`/`ack_txn`/`response_txn` (manual transaction naming). `index` as a
standalone action stays out — sipr builds the index from `-infindex` at load,
not from a scenario action. Extended 3PCC (`-master`/`-slave`/`-slave_cfg` with
`dest=`/`src=` peer routing) also stays out; classic `-3pcc` is supported.

`-inf` injection + `[fieldN]` and `lookup`/`insert`/`replace` shipped in M7,
classic 3PCC (`sendCmd`/`recvCmd`) in M10 (see §6).

### Media (M14–M15)

Shipped: `exec play_pcap_audio|video|image=` and `<recv ignoresdp>` (M14),
`exec rtp_stream=` (file/pattern/pause/resume) and `exec play_dtmf=` (M15) —
see §6. Still later: `exec rtp_echo=`, `-rtp_echo` global echo, rtpcheck,
SRTP, `verifyauth`, `closecon`, `pauserestore`.

## 2. Keywords (v1)

`[service]` `[remote_ip]` `[remote_port]` `[local_ip]` `[local_ip_type]`
`[local_port]` `[transport]` `[call_id]` `[call_number]` `[userid]` `[users]`
`[cseq]` `[branch]` `[msg_index]` `[pid]` `[routes]` `[next_url]` `[peer_tag_param]`
`[last_*]` (verbatim copy of header(s) from last received message, e.g.
`[last_Via:]`, `[last_From:]`) `[$var]` `[authentication]` (+ `username=`/
`password=` params) `[len]` (Content-Length auto-compute) `[field0..N]` (v1.x,
with injection files) `[date]` `[timestamp]` `[cseq+n]`-style arithmetic if
present in corpus scenarios (verify against C++).

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

Scenario/mode: `-sf <file>` `-sn uac|uas` `-sd` (dump embedded) `--check` (sipr
addition: lint scenario and exit).
Traffic: `-r <rate>` `-rp <ms>` `-l <max concurrent>` `-m <total calls>`
`-d <pause ms default>` `-users` (v1.x closed loop) `-rate_increase <n>`
`-rate_max <n>` `-rate_interval <time>` `-no_rate_quit` `-rate_scale <n>`
(M20 ramps).
Network: `-p <local port>` `-i <local ip>` `-t u1|t1|l1` (UDP / TCP / TLS
mono-socket; `tn`/`ln` accepted as aliases) `-s <service>` (called number)
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
`--sipr-http-token` (docs/CONTROL_API.md).
Tracing/output: `-trace_msg` `-trace_err` `-trace_stat` `-stf <file>`
`-fd <interval s>` `-nd` (no defaults) `-timeout <s>` `-bg` (headless).
Behavior toggles: `-aa` (auto-answer OPTIONS/INFO/UPDATE/NOTIFY in-dialog),
`-base_cseq`, `-cid_str` (Call-ID format), `-max_retrans`, `-nr` (no retrans).

Where sipr needs a flag SIPp lacks, prefix long-form `--sipr-*` to keep the two
namespaces distinct.

`hide="true"` and `display="…"` on any message command (M22): the scenario
screen skips hidden rows while `set hide true` (default) holds, and shows
`display` text instead of the derived label.

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
  address (Via received/rport handling: post-v1).
- `-trace_stat` CSV (M4): a pragmatic subset of SIPp's columns with the
  (P)/(C) periodic/cumulative naming and `;` separators — CurrentTime,
  ElapsedTime, CallRate, Incoming/OutgoingCall, TotalCallCreated,
  CurrentCall, Successful/FailedCall, Retransmissions, AutoAnswered,
  UnexpectedMessage, ResponseTime1 (avg/stddev/max ms), CallLength.
  Full column parity with SIPp is a v1-polish item.
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
  (verify), and CRLF normalization of line endings. `-nd` disables scenario
  defaults behaviors. Record exact findings here.
- Diagnostics policy as implemented (M1): unknown *elements* and *actions*
  are hard errors (skipping a step silently would change call flow); unknown
  *attributes* warn and are ignored; unknown *keywords* warn and pass through
  verbatim (IPv6 literals like `[2001:db8::1]` in URIs depend on this).
  `--check` treats any diagnostic, warnings included, as failure.
- Template CDATA normalization (M1, `template::normalize_cdata`): every line
  left-trimmed, line endings → CRLF, leading/trailing blank lines dropped,
  single trailing CRLF appended; internal blank line (header/body separator)
  preserved. TO VERIFY against `scenario.cpp` message construction at M3
  interop — especially whether SIPp appends CRLFCRLF or CRLF.
- `<pause sanity_check>` only tunes a runtime warning in SIPp; sipr accepts
  and ignores it (comment in `compile_pause`).
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
  `SEQUENTIAL`, `RANDOM`, or `USER` (SIPp also supports `PRINTF=` virtual
  lines; sipr does not yet). Data lines follow; a line beginning `#` is a
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
  standalone `<index>` action is not supported — use `-infindex`. `PRINTF=`
  virtual-line files remain out.
- TCP transport `-t t1` (M8): SIP over TCP is a byte stream, so message
  boundaries come from `Content-Length`, not packet edges (RFC 3261 §7.5). A
  framer reads headers up to the first `\r\n\r\n`, then exactly Content-Length
  body bytes; leading `\r\n` runs (keep-alive pings, RFC 5626) are skipped.
  sipr keeps one connection per peer — the client (`UAC`) dials the target
  once at start-up and the server (`UAS`) accepts, framing each; responses go
  back on the connection the request arrived on (keyed by peer address, like
  SIPp routes by the socket the message came in on). Reliable transports carry
  NO SIP retransmissions (RFC 3261 §18.2), so `retrans=`/`-max_retrans` are
  ignored under `t1`. SIPp's multi-socket `tn` maps onto the same
  connection-per-peer model. Not yet: TLS (`l1`), connection re-dial after a
  drop, and `-t un`/`ui`.
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
  `<recvCmd>` the answer. Not supported: extended master/slave 3PCC, optional
  `recvCmd` fall-through, and twin reconnection.
- `-users N` closed loop (M11, verified in `call_generation_task.cpp`
  `run`/`free_user`/`set_users`, `call.cpp` `init` line assignment and
  `[userid]`/`[users]` keywords, `sipp.cpp` `SIPP_OPTION_USERS`): instead of
  open-loop rate pacing, keep N concurrent calls, each holding a 1-based user
  id drawn from a free pool (1..N). A finished call returns its id and a
  replacement opens immediately (`calls_to_open = users - current_calls`), so
  the population stays constant until `-m` total is reached. `-users` and `-l`
  are mutually exclusive. USER-mode `-inf` files resolve line = userId-1
  (SIPp `nextLine(userId)`); `[userid]` renders the id, `[users]` the count.
  Not supported: per-user persistent variables (SIPp's `userVarMap`) and
  dynamic user-count changes at runtime — sipr's `-users` is a fixed N.
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
  (unsupported link type) — recapture on the wired side. `play_pcap=` (in
  the DTD, never implemented by SIPp) is an error pointing at
  `play_pcap_audio=`. Bracketed `-key` values are not supported yet.
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
  display ooc|rx`, `trace logs|shortmessages`, and `dump variables` warn
  that they are unsupported instead of silently succeeding; (6) `set
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
  (default true, toggled by the `<rtp_echo value=>` action from *any*
  call) is false; counters `rtp_pckts`/`rtp_bytes` (1st stream) and
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
  (2) `exec rtp_echo=` (SRTP) is rejected with a pointer to `-rtp_echo`;
  (3) `<rtp_echo variable=>` is rejected (value only).
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
  RTP instead of `rejectCall()`; (4) `exec rtp_echo=start…` (SIPp as an
  SRTP echo server) is not implemented; (5) payload length is taken from
  the datagram, not configured. Interop verified with sipp's own
  `-srtpcheck_debug` log: it authenticates and decrypts sipr's packets
  (`processIncomingPacket() rc == 0`). Also found: sipp's per-call SRTP
  echo does `sendto()` with an explicit address on a socket it has
  `connect()`ed, which macOS rejects with EISCONN (errno 56) — on macOS a
  sipp SRTP echo server never answers (Linux allows it). Same family as
  the stream-client bind limitation.
- (append new findings above this line, with a pointer to where in the C++ you
  verified them)

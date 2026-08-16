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

`sendCmd`/`recvCmd` + `dest`/`src` (3PCC), `sample`, `setdest`,
`exec command=` (external process), `start_txn`/`ack_txn`/`response_txn`
(manual transaction naming). `index` as a standalone action stays out — sipr
builds the index from `-infindex` at load, not from a scenario action.

`-inf` injection + `[fieldN]` and `lookup`/`insert`/`replace` shipped in M7
(see §6).

### Later / with media & transports

`exec play_pcap*`, `exec rtp_stream`, `rtp_echo`, `verifyauth`, `closecon`,
`pauserestore`, `ignoresdp`.

## 2. Keywords (v1)

`[service]` `[remote_ip]` `[remote_port]` `[local_ip]` `[local_ip_type]`
`[local_port]` `[transport]` `[call_id]` `[call_number]` `[cseq]` `[branch]`
`[msg_index]` `[pid]` `[routes]` `[next_url]` `[peer_tag_param]`
`[last_*]` (verbatim copy of header(s) from last received message, e.g.
`[last_Via:]`, `[last_From:]`) `[$var]` `[authentication]` (+ `username=`/
`password=` params) `[len]` (Content-Length auto-compute) `[field0..N]` (v1.x,
with injection files) `[date]` `[timestamp]` `[cseq+n]`-style arithmetic if
present in corpus scenarios (verify against C++).

Media placeholders `[media_ip]` `[media_port]` `[media_ip_type]` appear in the
default uac/uas scenarios' SDP bodies, so the keyword engine must substitute
them in v1 even though no media flows: SIPp sources them from `-mi`/`-mp`
(defaulting media_ip to the local IP). Pin exact defaults at M3.

Keyword parameters use SIPp syntax `[keyword param=value]`. Unknown keywords:
loud warning + left verbatim in the message (match SIPp behavior — verify in
C++ and record below).

## 3. CLI flags (v1 set, SIPp names)

Scenario/mode: `-sf <file>` `-sn uac|uas` `-sd` (dump embedded) `--check` (sipr
addition: lint scenario and exit).
Traffic: `-r <rate>` `-rp <ms>` `-l <max concurrent>` `-m <total calls>`
`-d <pause ms default>` `-users` (v1.x closed loop).
Network: `-p <local port>` `-i <local ip>` `-t u1` (UDP mono-socket; other modes
later) `-s <service>` (called number) `-mi`/`-mp` reserved (media, later).
Auth: `-au`/`-ap` (username/password defaults for `[authentication]`).
Tracing/output: `-trace_msg` `-trace_err` `-trace_stat` `-stf <file>`
`-fd <interval s>` `-nd` (no defaults) `-timeout <s>` `-bg` (headless).
Behavior toggles: `-aa` (auto-answer OPTIONS/INFO/UPDATE/NOTIFY in-dialog),
`-base_cseq`, `-cid_str` (Call-ID format), `-max_retrans`, `-nr` (no retrans).

Where sipr needs a flag SIPp lacks, prefix long-form `--sipr-*` to keep the two
namespaces distinct.

## 4. Runtime key bindings (TUI)

`+`/`-` rate ±1 (`*`,`/` ±10), `p` pause traffic, `s`..screens cycle, `q` soft
quit (drain), `Q` hard quit. Match SIPp muscle memory exactly.

## 5. Exit codes

0 = all calls successful; 1 = at least one call failed; 97 = exit on internal
command / user abort; 99 = aborted, no calls processed; -1/255 = fatal error.
Verify exact SIPp table before closing M3 and update this line.

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
    its CSeq method equals the nearest preceding request send's method
    (`recv_response_for_cseq_method_list`) — a late 200/INVITE cannot match
    the BYE's 200.
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
  (needs `-users`; without it the fields render empty — sipr warns at load).
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
- (append new findings above this line, with a pointer to where in the C++ you
  verified them)

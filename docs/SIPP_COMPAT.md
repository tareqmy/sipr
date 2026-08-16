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
`test`, `add`, `subtract`, `multiply`, `divide`, `todouble`, `jump`, `insert`,
`replace`, `trim`, `gettimeofday`, `urlencode`, `urldecode`,
`exec` with `int_cmd` only (`stop_now`, `stop_gracefully`, `stop_call`).

### v1.x tier (fast follow)

`sendCmd`/`recvCmd` + `dest`/`src` (3PCC), `lookup` + `-inf` injection files +
`[fieldN]`, `sample`, `setdest`, `exec command=` (external process),
`start_txn`/`ack_txn`/`response_txn` (manual transaction naming).

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

- `optional="true"` recv steps: an inbound message is tried against the current
  pending non-optional recv AND any optional recvs in the window before it;
  optional steps may arrive out of order / not at all. (Verify exact matching
  order in `call.cpp` before implementing M3.)
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
- (append new findings above this line, with a pointer to where in the C++ you
  verified them)

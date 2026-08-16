---
name: sipp-scenarios
description: Use when writing, parsing, or debugging SIPp XML scenario files, when working on sipr-scenario (parser, keyword tokenizer, actions, IR), or when authoring test scenarios for the corpus. Covers the XML format, keyword semantics, execution model, and where reference scenarios live.
---

# SIPp XML scenarios

Grammar source of truth: `../../cprojects/sipp/sipp.dtd`. Implemented surface
and tiers: `docs/SIPP_COMPAT.md` (keep it updated). Reference corpus:
`../../cprojects/sipp/sipp_scenarios/*.xml` (mostly media/SRTP — signaling-only
ones like `mcd_register.xml`, `uc360_register*.xml` are v1-relevant),
`crates/sipr-scenario/tests/corpus/`, and https://sipp.readthedocs.io.

## Shape of a scenario

```xml
<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">
<scenario name="Basic UAC">
  <send retrans="500"><![CDATA[
    INVITE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
    Via: SIP/2.0/UDP [local_ip]:[local_port];branch=[branch]
    From: sipr <sip:sipr@[local_ip]:[local_port]>;tag=[pid]SIPpTag00[call_number]
    To: [service] <sip:[service]@[remote_ip]:[remote_port]>
    Call-ID: [call_id]
    CSeq: 1 INVITE
    Contact: sip:sipr@[local_ip]:[local_port]
    Max-Forwards: 70
    Content-Type: application/sdp
    Content-Length: [len]

    v=0
    o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
    ...
  ]]></send>
  <recv response="100" optional="true"/>
  <recv response="180" optional="true"/>
  <recv response="200" rtd="true"/>
  <send>...ACK...</send>
  <pause milliseconds="3000"/>
  <send retrans="500">...BYE...</send>
  <recv response="200" crlf="true"/>
</scenario>
```

## Execution model (what the IR must preserve)

Steps run strictly in document order ("message index"); jumps (`next`, `label`,
action `jump`) target indices/labels. A UAS scenario starts with a `recv
request=`. `recv` blocks until match or `timeout` (→ `ontimeout` label or call
failure). `optional="true"` recvs form a window before the next mandatory step:
they may match, repeat (e.g. multiple 180s), or never arrive; an inbound is
tested against the window + current mandatory step — anything else is an
"unexpected message" (kills the call unless auto-answered via `-aa`).
Conditionals: `test`/`chance` on a step gate its `next` jump; `condexec` runs a
step only if a variable is set. CDATA line endings are normalized to CRLF;
`crlf="true"` appends an extra blank line after the message.

## Keyword gotchas (bugs live here)

- `[len]` counts the body bytes AFTER keyword substitution; compute last.
- `[last_Via:]` copies the entire header line(s) *verbatim* from the last
  received message, including the header name — commonly used to mirror
  Via/From/To/Call-ID in UAS replies. Multi-value headers copy all instances.
- `[branch]` must differ per transaction: index it by msg_index so retransmits
  reuse it but new transactions don't.
- `[call_number]` is 1-based and monotonic per run; `[pid]` disambiguates
  concurrent sipr instances — both appear inside From/To tags in stock
  scenarios, so tag uniqueness depends on them.
- `[routes]` expands to a `Route:` header set only when `rrs="true"` captured
  Record-Route earlier; empty expansion must produce NO header line, not a
  blank `Route:`.
- `[field0]`/`[fieldN]` come from `-inf` CSV rows (v1.x); `[$var]` reads a call
  variable — undefined var at send time is a scenario error (match SIPp:
  verify whether it aborts call or run, record in SIPP_COMPAT §6).
- Keywords may take params: `[authentication username=joe password=schmo]`,
  `[field0 line=3]`, `[pause distribution=...]`-style attrs are XML attrs, not
  keyword params — don't confuse the two syntaxes.

## Actions quick map

`<action>` hangs off `recv`/`nop`. `ereg` runs a regex over the message
(`search_in="msg|hdr"`, `header="X:"`, `start_line`), assigns capture groups to
`assign_to="1,2,3"` (first var gets whole match; `check_it="true"` makes
no-match a failure). Math (`add/subtract/multiply/divide`), `assign`/
`assignstr`, `strcmp`, `test` (writes boolean var), `jump`, `log`/`warning`/
`error` (keyword-expanded messages), `exec int_cmd="stop_call|
stop_gracefully|stop_now"`. Variables are per-call; `Reference` marks vars as
intentionally unused.

## Authoring rules for the sipr corpus

New test scenarios go in `crates/sipr-scenario/tests/corpus/`; pair every UAC
scenario with a matching UAS counterpart for the interop suite; keep them
signaling-only for v1; unsupported-feature scenarios belong in the negative
corpus with the expected error message. When a scenario exercises folklore
behavior (optional windows, auth retry, routes), link the SIPP_COMPAT §6 note
it verifies.

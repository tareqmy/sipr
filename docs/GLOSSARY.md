# Glossary — SIP and SIPp terms

Read this before touching engine or scenario code if you're not fluent in SIP.
Confusing these terms causes real bugs (especially transaction vs dialog vs call).

## SIP protocol

- **UAC / UAS** — User Agent Client (sends a request) / Server (answers it).
  Roles are *per transaction*: the callee becomes a UAC when it sends BYE.
  In sipp/sipr CLI terms, `uac` = caller scenario, `uas` = callee scenario.
- **Transaction** — one request + its responses (+ retransmissions). INVITE
  transactions end at a final response (ACK for non-2xx is part of it; ACK for
  2xx is a *separate* transaction per RFC 3261). Identified by the Via `branch`.
- **Dialog** — a peer-to-peer relationship spanning transactions, identified by
  Call-ID + local tag + remote tag. Established by INVITE/2xx (or early via 1xx
  with tag). Holds CSeq counters both directions, route set, remote target.
- **Call** — in sipp/sipr: one execution of the scenario (one line in the call
  table), which usually maps to one dialog but needn't (e.g. REGISTER scenarios
  have no dialog).
- **Via / branch** — routing breadcrumb header; `branch` (must start with magic
  cookie `z9hG4bK`) identifies the transaction.
- **CSeq** — per-dialog, per-direction request sequence number + method.
- **Tags** — random tokens in From/To identifying dialog ends. UAS adds the To
  tag; `[peer_tag_param]` in SIPp exposes the remote one.
- **Record-Route / Route / route set** — proxies inserting themselves into the
  dialog path; `rrs="true"` on a recv captures them, `[routes]` replays them.
- **T1 / T2** — RFC 3261 retransmission timers for unreliable transport:
  T1=500ms initial, doubling per retransmit, capped at T2=4s.
- **REGISTER / OPTIONS / INFO / UPDATE / NOTIFY** — non-INVITE methods that show
  up in test scenarios; `-aa` auto-answers the in-dialog ones with 200.
- **Digest auth** — 401 (UAS) / 407 (proxy) challenge → request re-sent with
  Authorization/Proxy-Authorization. RFC 2617 (MD5) / RFC 7616 (SHA-256, qop).
- **SDP** — session description carried as the body of INVITE/200; for
  signaling-only v1 it is opaque template bytes (only `[len]` cares).
- **3PCC** — third-party call control: an external controller coordinates two
  scenario halves; SIPp implements it as `sendCmd`/`recvCmd` between instances.
- **B2BUA** — back-to-back user agent (two dialogs bridged); relevant only as
  the kind of DUT sipr often tests.
- **DUT / SUT** — device/system under test.

## SIPp-specific

- **Scenario** — the XML file: an ordered list of send/recv/pause/nop steps the
  call must follow. Compiled in sipr to a flat step IR ("message index" order).
- **Keyword** — `[call_id]`-style placeholder substituted into message
  templates at send time.
- **Action** — per-step operation (`<action>` on recv/nop): regex capture
  (`ereg`), variable math, branching (`test`+`next`), logging, exec.
- **Call variables** — per-call named values (`[$1]`, `[$name]`) written by
  actions, read by keywords/conditions.
- **Injection file (`-inf`)** — CSV whose rows feed `[field0..N]` keywords;
  sequential/random/user modes. (v1.x)
- **Open loop vs closed loop** — SIPp default is open loop: `-r` new calls per
  period *regardless of completions* (models real traffic, can overload DUT).
  `-users` mode is closed loop: fixed population, new call only when one ends.
- **cps** — calls per second (the `-r` rate).
- **RTD (response time duration)** — stopwatch between `start_rtd` and `rtd`
  markers in the scenario; reported in percentiles/histograms.
- **Repartition** — SIPp's term for histogram bucket tables
  (ResponseTimeRepartition, CallLengthRepartition).
- **Unexpected message** — inbound that matches no pending recv (incl. optional
  window); increments counters and by default kills the call.
- **Retrans** — either the protocol-level UDP retransmission (timer-driven) or
  the `retrans` attribute overriding its base interval. Context matters.
- **Timewait** — post-scenario linger absorbing late retransmissions before the
  call slot is freed (SIPp `timewait` element / deadcall handling).
- **OOC (out-of-call)** — messages not attributable to any live call.
- **PCAP play / rtp_stream** — media features (later; out of v1).

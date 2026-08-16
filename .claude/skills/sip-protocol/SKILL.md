---
name: sip-protocol
description: Use when implementing or reviewing SIP protocol behavior in sipr — message structure, transactions, retransmission timers, dialogs, tags, CSeq, digest auth. A tester-focused RFC 3261 quick reference plus rules for when a test tool should deliberately deviate from the RFC.
---

# SIP protocol reference for sipr

sipr is a *test tool*, not a compliant stack. Two consequences frame everything:
outbound behavior is scenario-driven (the scenario may legally violate the RFC —
that's a feature); inbound handling should be liberal (real devices send garbage).
Full compliance logic (e.g. complete §17 transaction state machines) is
explicitly NOT the goal — match SIPp's behavior, using
`../../cprojects/sipp/src/call.cpp` as the oracle.

## Message anatomy (RFC 3261)

```
INVITE sip:service@10.0.0.2:5060 SIP/2.0          ← request line (or status line)
Via: SIP/2.0/UDP 10.0.0.1:5061;branch=z9hG4bK-1-1-7
From: sipp <sip:sipp@10.0.0.1>;tag=1a2b3c          ← + tag = dialog half-id
To: service <sip:service@10.0.0.2>                 ← UAS adds its tag in replies
Call-ID: 1-12345@10.0.0.1                          ← call/dialog correlation key
CSeq: 1 INVITE                                     ← seq + method
Contact: sip:sipp@10.0.0.1:5061                    ← where to reach me directly
Max-Forwards: 70
Content-Length: 135                                ← [len] computes this
                                                   ← blank line, then body (SDP)
```

Header lines end CRLF; blank CRLF line separates body. Headers can be folded,
have compact forms (`f`=From, `t`=To, `v`=Via, `i`=Call-ID, `m`=Contact,
`l`=Content-Length) — accept them inbound, never emit them.

## Correlation rules (what the router/engine key on)

- Call ↔ inbound message: **Call-ID** (sipr's call table key, same as SIPp).
- Transaction ↔ response: top **Via branch** (+ CSeq method). Branch must be
  unique per transaction and start with magic cookie `z9hG4bK`. sipr generates
  SIPp-shaped branches: cookie + call number + msg index (+ pid discriminator).
- Dialog: Call-ID + From tag + To tag. Callee (UAS role) MUST add a To tag in
  non-100 responses. CSeq increments per in-dialog request per direction; ACK
  and CANCEL reuse the INVITE's CSeq number (method differs).

## Response classes

1xx provisional (100 Trying, 180 Ringing, 183 Progress — often `optional` in
scenarios), 2xx success, 3xx redirect, 4xx client error (401 auth challenge,
407 proxy auth, 486 busy), 5xx server error, 6xx global. Final = ≥200.
ACK rules: non-2xx final → ACK is hop-by-hop, same transaction, same branch;
2xx final → ACK is end-to-end, NEW transaction, new branch, sent to the
Contact/route set. Scenarios usually hand-write the ACK; the engine just needs
correct keyword values for both shapes.

## Retransmission (UDP)

Timer T1 = 500ms, doubles each retransmit, capped at T2 = 4s. SIPp model
(mirror this, not full RFC §17): a sent request retransmits on this schedule
until the recv step it's waiting on matches; `retrans="500"` on `<send>` sets
the base interval; global max-retrans caps attempts; retransmitted *inbound*
messages (same branch/CSeq already seen) increment retrans counters and are
answered by re-sending the last response where applicable, not treated as
unexpected. UAS side: retransmit final responses to INVITE until ACK arrives.

## Digest auth flow (RFC 2617/7616)

401/407 carries `WWW-Authenticate`/`Proxy-Authenticate`: realm, nonce,
qop, algorithm (MD5 | SHA-256), opaque. Client re-sends the request with
incremented CSeq and `Authorization`/`Proxy-Authorization`:
response = H(H(user:realm:pass) : nonce : nc : cnonce : qop : H(method:uri))
(with qop=auth; simpler concat without qop). `stale=true` → retry once with new
nonce, same credentials. Scenario surface: `recv auth="true"` captures the
challenge; `[authentication username=X password=Y]` in the next send emits the
header. Test vectors: RFC 7616 §3.9. Implementation lives in `sipr-auth`.

## Deliberate-deviation rules (do not "fix" these)

- Templates are sent byte-exact (after keyword fill + CRLF normalization). No
  auto-added headers, no reordering, no casing fixes. `[len]` is the only
  computed header, and only when present.
- `lost`/`retrans` attrs simulate network pathology on purpose.
- Malformed inbound must never panic the tool: parse failures on the recv path
  count as errors/unexpected per SIPp semantics and the tool keeps running.
- Strict validation belongs only in `--check` scenario linting, never on the
  wire path.

When unsure whether behavior X should be RFC-correct or SIPp-compatible:
SIPp-compatible wins; document the divergence in `docs/SIPP_COMPAT.md` §6.

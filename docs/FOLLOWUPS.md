# Follow-up tasks

Work found while fixing something else and left out of that change so it
stayed one logical fix. Each entry stands alone and can be handed to an
agent as is. Delete an entry when its fix lands.

- **14** is a flaky interop test, seen again while running the gates for
  the fixes above. It changes only tests, so it replaces steps 1 and 2
  below with the check it describes.
- **15** is a SIPp divergence found while fixing the `_Lost` columns
  (commit `79c22ee`). It needs a decision before a fix.

The SIPp C++ source is at `../../cprojects/sipp/src` (relative to the
repo root). Read it to confirm the behavior, and never copy it (GPL).
Every task follows the same loop:

1. Write a failing test first, preferably an interop test against real
   sipp. `jumps_and_message_indices_skip_labels_like_real_sipp` in
   `tests/interop.rs` shows the UAC-against-a-UDP-sink pattern.
2. Fix it, then update `docs/SIPP_COMPAT.md` §6 (mark the open item
   fixed) and the Unreleased section of `CHANGELOG.md`.
3. Run the gates:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo deny check
   SIPP_BIN=../../cprojects/sipp/sipp cargo test -p sipr --test interop
   ```

4. Commit per `docs/CONVENTIONS.md`, with the scope given below.

## 14. Let `real_sipp_tcp_uac_reconnects_to_sipr` see sipp's hang

Scope: `test(interop)`.

- **The flake:** real sipp's TCP UAC now and then never exits. The test
  waits 20 s, past the UAC's `-timeout 15`, then fails with
  `left: None, right: Some(1)`. It happened in 2 of about 20 full
  interop runs on 2026-09-25, once before `badc816` and once after
  `42ac306`, and never in 15 runs of the test alone. The test skips when
  sipp's `-trace_err` log shows its freed-socket bug
  (`sipp_freed_socket_on_reset` in `tests/interop.rs`: "unknown transport
  type" or "Unable to send UDP message"). These hangs log neither, and
  the assertion prints nothing about what sipp did, so it is unknown
  whether this is the same bug.
- **Done so far:** a failure now prints sipp's stderr and `-trace_err`
  log. Fifteen full interop runs after that, some beside four CPU-bound
  processes, did not reproduce the hang, so there is no evidence yet.
- **Next:** when the test fails again, read what sipp logged. If it is
  sipp's reset-connection bug in another form, widen the skip. Match
  something specific, not a bare "did not exit", which would hide a real
  sipr regression. If sipr is at fault, it becomes a `fix(net)` task.

## 15. Handle a received retransmission as SIPp's `process_incoming` does

Scope: `fix(engine)`. SIPP_COMPAT §6, the M40 statistics-files note,
lists the loss half as open. **Needs a decision first** (see the last
point): matching SIPp exactly makes sipr end calls it copes with today.

- **SIPp** (`call.cpp` ~l.2118-2130 on every send, ~l.4659-4705 on
  receipt; UDP with retransmission enabled only). Every send made after
  something was received records `recv_retrans_hash = last_recv_hash`,
  the last recv's index and its own index, then zeroes
  `last_recv_hash`. So only the *first* send after a recv carries that
  recv's hash, and a second send (180, then 200) overwrites the record
  with hash 0. A received message that equals `recv_retrans_hash` rolls
  the recv's loss (`nb_lost` on a loss, then nothing). Otherwise it books
  `nb_recv_retrans` on the recv, re-renders and resends the recorded
  send (`send_scene`), and books `nb_sent_retrans` on that send. One
  that equals `last_recv_hash` (received, nothing sent since) books
  `nb_recv_retrans` and is dropped. Anything else goes through normal
  matching.
- **Confirmed against sipp 3.7.7** with a UAS scenario of INVITE, 180,
  200, ACK, BYE, 200, driven by a raw UAC that sent the INVITE again after
  the 200. sipp sent nothing back, counted the INVITE as unexpected at
  the ACK recv (`3_ACK_Unexp` = 1) and aborted the call. The counts row
  was `1;0;0;0;1;0;1;0;0;0;0;1;0;0;0;0;0;0;`.
- **sipr:** the `is_dup` branch of the inbound path
  (`crates/sipr-engine/src/engine.rs`, keyed on `last_recv_key`: top Via
  branch, CSeq, method or status) answers any copy of the last received
  message by resending `last_sent`, whatever the transport, and counts
  only the global `retrans_recv` and `retrans_sent`. The same scenario
  under sipr resent the 200 and completed the call, with the counts row
  `1;0;0;0;1;0;1;0;1;0;0;0;1;0;0;0;1;0;`. SIPP_COMPAT §6 ("UAS behaviors
  (M4)") describes sipr's behavior as if it were SIPp's; it was never
  checked.
- **Decide:** mirror SIPp exactly, keeping its hash-per-send
  bookkeeping and the call it aborts, or keep sipr's more forgiving
  resend and adopt only the parts that do not end calls: the per-step
  `_Retrans` bookkeeping, resending the send that answered rather than
  the last one, and the loss roll. Then correct the M4 note.
- **Test:** the UAS above as an interop test with `-trace_counts`,
  compared with real sipp. Add a one-send variant (BYE, 200) to cover
  the resend, and a `lost="100"` variant for the loss.

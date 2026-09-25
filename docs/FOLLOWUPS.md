# Follow-up tasks

Work found while fixing something else and left out of that change so it
stayed one logical fix. Each entry stands alone and can be handed to an
agent as is. Delete an entry when its fix lands.

- **14** is a flaky interop test, seen again while running the gates for
  the fixes above. It changes only tests, so it replaces steps 1 and 2
  below with the check it describes.
- **15-16** are SIPp divergences found while fixing the `_Lost` columns
  (commit `79c22ee`) and pause actions (commit `69319d6`).

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
- **Fix:** when the UAC has not exited, put its stderr (the pair already
  reads it) and its `-trace_err` log into the failure message. Loop the
  test under load until it fails, and read what sipp logged. If it is
  sipp's reset-connection bug in another form, widen the skip. Match
  something specific, not a bare "did not exit", which would hide a real
  sipr regression. If sipr is at fault, it becomes a `fix(net)` task.
- **Verify:** loop the full interop suite, or run the test beside a
  CPU-heavy job, and check that a failure now explains itself.

## 15. Handle a received retransmission as SIPp's `process_incoming` does

Scope: `fix(engine)`. SIPP_COMPAT §6, the M40 statistics-files note,
lists the loss half as open.

- **SIPp** (`call.cpp` ~l.4659-4705, and ~l.2118-2124 where a send
  records the pair): over UDP with retransmission enabled, a send that
  follows a received message remembers that recv
  (`recv_retrans_recv_index`, `recv_retrans_hash`) and itself
  (`recv_retrans_send_index`). When the received message comes again,
  SIPp:
  - rolls the recv's loss (`lost(recv_retrans_recv_index)`). On a loss
    it books `nb_lost` on the recv and stops there.
  - Otherwise it books `nb_recv_retrans` on the recv (its `_Retrans`
    column), sends that send again (`send_scene`), and books
    `nb_sent_retrans` on it.

  A copy of the last received message that nothing answered yet
  (`last_recv_hash`) only books `nb_recv_retrans` on its recv.
- **sipr:** the `is_dup` branch of the inbound path
  (`crates/sipr-engine/src/engine.rs`, the one keyed on
  `last_recv_key`) counts the global `retrans_recv` and `retrans_sent`,
  and resends `last_sent`, whatever the transport. It books nothing per
  step, so a recv's `-trace_counts` `_Retrans` column stays 0 and the
  resent send's does not grow. It rolls no loss. Which message it
  resends can differ too: SIPp resends the send that answered the
  retransmitted message, sipr its last send.
- **Fix:** remember the recv step and the answering send per call, as
  SIPp does, then book, roll the loss and resend by them. Check the
  transport and `-nr` conditions, and what sipr's TCP paths should do.
- **Test:** an interop UAS whose peer (the test) retransmits its INVITE
  after the 200, with `-trace_counts`, comparing the `_Retrans` columns
  with real sipp. Add a `lost="100"` variant for the loss.

## 16. Run a `<sendCmd>`'s actions

Scope: `fix(scenario)`, then `fix(engine)`.

- **SIPp:** a `<sendCmd>` takes `<action>` like any message
  (`getCommonAttributes`). Its branch of `executeMessage` (`call.cpp`
  ~l.1989-2006) sends the command, books `M_nbCmdSent` and
  `do_bookkeeping`, runs the actions, then calls `next()`. A `<jump>`
  among them lands as a nop's does (SIPP_COMPAT §6, "Where a `<jump>`
  lands").
- **sipr:** `compile_send_cmd` (`crates/sipr-scenario/src/compile.rs`)
  refuses any child but the CDATA: "unexpected <action> inside
  <sendCmd>". A SIPp scenario with one does not load. `Step::SendCmd`
  has no `actions`.
- **Fix:** give `Step::SendCmd` actions, parsed as a nop's are, and add
  them to `Step::actions()`/`actions_mut()`. Run them in the engine's
  `Step::SendCmd` arm after the command is sent and booked, landing a
  jump through `step_after_jump` as the `Step::Nop` arm does. The lint
  then follows those jumps without change.
- **Test:** a 3PCC interop controller, as in
  `msg_index_and_branch_in_a_send_cmd_render_like_real_sipp`, whose
  `<sendCmd>` logs through `-trace_logs` and jumps, compared with real
  sipp.

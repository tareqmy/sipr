# Follow-up tasks

SIPp divergences found while fixing message indices (commit `5d28c1c`,
"count messages, not labels, in jumps and indices") and left out of that
change so it stayed one logical fix. Each entry stands alone and can be
handed to an agent as is. Delete an entry when its fix lands.

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

## 1. Accept SIPp's `<assign value=>` form

Scope: `fix(scenario)`.

- **SIPp:** `assign` is compiled by `handle_arithmetic` → `handle_rhs`
  (`scenario.cpp` ~l.1344-1365, ~l.1469). It takes `value=` (a double)
  or `variable=`, which are mutually exclusive, and errors on neither or
  both. `<assign assign_to="x" value="7"/>` runs in sipp 3.7.7.
- **sipr:** the `"assign"` arm of the action compiler in
  `crates/sipr-scenario/src/compile.rs` requires `variable=` and warns
  that `value` is an unknown attribute. The scenario is refused with
  "`<assign>` needs a 'variable' attribute".
- **Fix:** make `Action::Assign` take an `Operand`, as `pauserestore` and
  the arithmetic actions already do through `parse_operand`, with SIPp's
  errors for neither or both. Update the action runner in
  `crates/sipr-engine/src/actions.rs` and the compile tests.

## 2. Match SIPp's jump semantics after the jump

Scope: `fix(engine)`. SIPP_COMPAT §6, "Message indices", open items (1)
and (2).

- **Resuming after a jump.** SIPp's `E_AT_JUMP` (`call.cpp`
  ~l.5991-6002) sets `msg_index = N - 1`. The caller's `next()`
  (~l.1930-1945) then reads `messages[N-1]->next`/`test`/`chance`. So if
  message N-1 has a `next=` (its test set, its chance won), SIPp
  continues at that label instead of running message N. sipr's
  `jump_to_step` in `crates/sipr-engine/src/engine.rs` goes straight
  to N.
- **A jump inside a mandatory `<recv>`.** It does nothing in SIPp. After
  `executeAction`, `process_incoming` sets `msg_index = search_index`
  and calls `next()` (~l.5650-5660), which overwrites the jump. Read
  that branch for optional recvs too, which behave differently. sipr
  takes the jump: see the `ActionOutcome::Jump`/`JumpToMessage` arms in
  the engine's action-outcome loop.
- **Also check:** SIPp's fatal "jumps to itself" check
  (`msg_index == operand`), which sipr lacks.
- **Also update:** the `unreachable` lint's `successors` in
  `crates/sipr-scenario/src/lint.rs`, which models jumps and may need
  the same semantics.

## 3. Render `[msg_index]` and `[branch]` like SIPp when there is no message index

Scope: `fix(engine)`. SIPP_COMPAT §6, "Message indices", open item (3).

- **SIPp:** `createSendingMessage` takes a `P_index` that defaults to
  -1 whenever it is not rendering a scenario `<send>`:
  - action messages: `<log>`, `<warning>`, `<error>`, `<assignstr>`,
    `exec command=` (`call.cpp` ~l.6128-6145)
  - `<sendCmd>` bodies (~l.2625)
  - the `-default_behaviors` abort messages, built from
    `get_default_message("bye"/"ack"/"cancel")` (~l.2554-2582)

  With `P_index` -1, `[msg_index]` (`E_Message_Index`, ~l.3900) prints
  `-1`. `[branch]` (`E_Message_Branch`, ~l.3892-3898) ends in
  `msg_index - 1 + offset`, the call's current message index minus one.
- **sipr:** renders the current message's index for both. See the
  `RenderCtx` built for actions and `render_call_template` (sendCmd and
  default messages) in `crates/sipr-engine/src/engine.rs`.
  `RenderCtx::msg_index` in `crates/sipr-engine/src/render.rs` is a
  `usize`, so it cannot hold -1.
- **Fix:** confirm against real sipp first, e.g. with
  `<log message="[msg_index] [branch]"/>` in a nop and in a sendCmd body,
  compared through `-trace_logs` or the twin socket. Then model "no
  message index" in `RenderCtx` and match SIPp's output, including the
  branch offset if sipr supports `[branch-N]`.

## 4. Give nops and 3PCC commands SIPp's `-trace_counts` columns

Scope: `fix(stats)`. SIPP_COMPAT §6, the M40 statistics-files note.

- **SIPp:** `print_count_file` (`logger.cpp` ~l.60-190) tests, in order:
  a send, a `recv_response`, a `recv_request`, then
  `else if (pause_distribution || pause_variable)`. `pause_variable`
  defaults to -1 (`scenario.cpp` l.46), which is truthy, so every other
  message (nop, `sendCmd`, `recvCmd`) gets
  `<index>_Pause_Sessions;<index>_Pause_Unexp`. Its NOP, RecvCmd and
  SendCmd arms never run. Confirmed against sipp 3.7.7: a UAC with nops
  at messages 0 and 4 wrote `0_Pause_Sessions;0_Pause_Unexp;…;4_Pause_Sessions;4_Pause_Unexp`.
- **sipr:** `counts_header`/`counts_row` in
  `crates/sipr-stats/src/lib.rs` write nothing for a nop, and their own
  columns for sendCmd and recvCmd. The `counts_file_follows_sipps_columns`
  unit test pins that behavior.
- **Fix:** match SIPp's header and rows. The row values are `sessions`
  and `unexpected`; check what SIPp counts in `sessions` for a nop.
  Labels still get no columns and no index.
- **Then widen the interop test:** it compares only the `_OPTIONS_`
  columns because of this divergence
  (`jumps_and_message_indices_skip_labels_like_real_sipp` in
  `tests/interop.rs`). Make it compare the full header.

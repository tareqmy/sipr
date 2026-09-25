# Follow-up tasks

Work found while fixing something else and left out of that change so it
stayed one logical fix. Each entry stands alone and can be handed to an
agent as is. Delete an entry when its fix lands.

- **1-4** are SIPp divergences found while fixing message indices (commit
  `5d28c1c`, "count messages, not labels, in jumps and indices").
- **5-6** are test-harness problems found while fixing the interop
  port-probe race (commit `4ff94ca`). They change only tests, so each one
  replaces steps 1 and 2 below with the check it describes.
- **7-8** are SIPp divergences that `docs/SIPP_COMPAT.md` §6 already
  listed as open, with no fix picked up yet.

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

## 5. Stop e2e children inheriting port-probe sockets

Scope: `test(e2e)`.

- **The race:** macOS has no `SOCK_CLOEXEC`, so std sets `FD_CLOEXEC` on
  a new socket a moment after `socket()`. A child spawned from another
  test thread in that gap inherits a `free_port()` probe socket. It then
  keeps the probed port bound for as long as it lives, and the sipr the
  port is handed to exits with "Address already in use".
  `docs/TESTING.md` §4 has the details.
- **Fixed in interop** (commit `4ff94ca`): in `tests/interop.rs`, probes
  hold `PORT_PROBES` exclusively through `probing()`. Every child starts
  through `spawn_outside_probes()` or `output_outside_probes()`, which
  hold it shared. That took `recv_timeouts_arm_like_real_sipp` from 5/35
  failed runs to 0/55.
- **Still open in e2e:** `tests/e2e.rs` has its own `free_port()` and
  `free_port_block()` and 19 unguarded spawn sites (8 `.spawn()`, 11
  `.output()`). cargo runs its tests in parallel threads, and each one
  probes and spawns, so any of them can inherit another's probe socket.
- **Fix:** port the interop guard, or move both copies into a shared
  `tests/common/mod.rs`. Keep `output_outside_probes()`'s shape: it
  spawns under the lock and waits outside it. Most e2e `.output()` calls
  run sipr to completion, so holding the lock across the wait would
  stall every other test's probes.
- **Verify:** loop the e2e suite about 10 times before and after the
  fix. The tests need sockets, so run them outside the sandbox.

## 6. Pass `-nostdin` to every sipp the interop suite starts

Scope: `test(interop)`.

- **The spin:** a sipp whose stdin is `/dev/null` busy-polls it: `poll()`
  returns at once, forever, so each sipp burns a full core, mostly in
  the kernel. `-bg` does not help, because its forked child points stdin
  at `/dev/null` too. Measured on macOS: a sipp UAS runs at 99.6% CPU,
  and at 1.5% with `-nostdin`. Five full interop runs used ~405 s of
  system CPU in ~117 s of wall time.
- **Done so far:** only `run_recv_timeout_uas` passes `-nostdin` (commit
  `4ff94ca`). That took one run of `recv_timeouts_arm_like_real_sipp`
  from ~14 s of CPU to ~0.4 s.
- **Fix:** pass `-nostdin` to every sipp that `tests/interop.rs` starts.
  Pass it to sipr too where the two share an argument list: sipr accepts
  the flag (`src/cli.rs`). A helper would give new tests the flag by
  default.
- **Verify:** time the interop test binary before and after, and loop
  the full suite a few times. Also check whether
  `real_sipp_tcp_uac_reconnects_to_sipr` is steadier with the load gone.
  It failed once in 13 full runs after `4ff94ca`: sipp hit its known
  freed-socket bug and hung past `-timeout`, without logging the text
  the test's skip looks for.

## 7. Take `ontimeout=` on `<send>` and `<recvCmd>`

Scope: `fix(engine)`. SIPP_COMPAT §6, the receive-timeouts note lists
the `<recvCmd>` half as open. The `<send>` half is not recorded yet.

- **SIPp:** `ontimeout` is a common attribute, parsed for every message
  by `getCommonAttributes` (`scenario.cpp` ~l.1878; only `<timewait>`
  refuses it). Two places use it:
  - A `<recv>` or `<recvCmd>` whose receive timeout expires
    (`call.cpp` ~l.2150-2190). `<recvCmd>` has no `timeout=` of its own
    (its branch in `scenario.cpp` ~l.997 reads none), so only
    `-recv_timeout` arms it.
  - A `<send>` whose UDP retransmissions run out (`call.cpp`
    ~l.2262-2285). SIPp warns "timeout on max UDP retrans for message
    <n>, jumping to label <m>" and jumps. A label past the last message
    fails the call as `E_FAILED_MAX_UDP_RETRANS`. Without `ontimeout`
    the call fails as before.

  `<pause>`, `<nop>` and `<sendCmd>` also accept `ontimeout`, and
  nothing reads it there.
- **sipr:** `<send>` and `<recvCmd>` warn `ontimeout` away ("unknown
  attribute 'ontimeout' … — ignored", confirmed on `master`). Only
  `RecvStep` has an `ontimeout` field (`crates/sipr-scenario/src/model.rs`).
  So a send whose retransmissions run out always fails the call
  (`fail_call(…, "retransmissions exhausted")` in `on_retrans_timer`,
  `crates/sipr-engine/src/engine.rs`), and so does a timed-out recvCmd
  (`on_recv_timeout`).
- **Fix:** resolve `ontimeout` for `<send>` and `<recvCmd>` the way
  `<recv>`'s is resolved (a pending label in `compile.rs`, checked in
  `finish()`). Then follow it on retransmission exhaustion and on a
  recvCmd timeout, with SIPp's warnings and failure counters. Decide
  what `ontimeout` on `<pause>`, `<nop>` and `<sendCmd>` should do.
  SIPp accepts it and ignores it, and AGENTS.md says sipr must not
  ignore scenario input silently, so a specific warning is likely
  right.
- **Also update:** the `unreachable` lint's `successors`
  (`crates/sipr-scenario/src/lint.rs`), which follows only a recv's
  `ontimeout`, and the `--check` dump, which prints `ontimeout->` for
  recvs only.
- **Test:** an interop test with a UAC whose `<send retrans=…
  ontimeout=…>` goes to a silent sink, and a 3PCC pair where a
  `<recvCmd ontimeout=…>` waits out `-recv_timeout`. Compare the
  messages sent, the exit code and the warning with real sipp.

## 8. Log 3PCC twin commands in `-trace_msg` and `-trace_shortmsg`

Scope: `fix(engine)`. SIPP_COMPAT §6, the 3PCC note, says "Still open:
`-trace_msg` does not log twin commands".

- **SIPp:** its socket layer logs every write and read, twin sockets
  included, and marks the twin ones `control`:
  - `-trace_msg` frames read `<transport> control message sent [<n>]
    bytes:` and `… received …` (`socket.cpp` ~l.1132-1138 and
    ~l.2211-2217).
  - `-trace_shortmsg` gets its `S`/`R` lines from the same paths
    (~l.1127 and ~l.2219-2224).
  - A twin command for no call, or one the call did not expect, logs
    "Unexpected control message received …" in `-trace_msg` and the
    call debug (`call.cpp` ~l.4274 and ~l.4318).

  Check whether the logged text and byte count include the ESC delimiter
  SIPp appends to a command on the wire.
- **sipr:** `trace_send`/`trace_recv` (`crates/sipr-engine/src/engine.rs`)
  are called for SIP messages only. The `Step::SendCmd` arm's twin send,
  `send_twin_abort` and `on_twin_cmd` log nothing. `sipp_message_frame`
  (`crates/sipr-stats/src/lib.rs`) has no `control` tag.
- **Fix:** give the frame a control flag and log twin commands from the
  send and receive paths, the unexpected-command lines included. Add
  short-message lines if real sipp writes them.
- **Test:** run a 3PCC pair under `-trace_msg` and `-trace_shortmsg` on
  both sides and compare the entries' shapes with real sipp's, as
  `short_message_log_matches_real_sipps` does for SIP. The classic and
  extended 3PCC tests in `tests/interop.rs` show how to start the pair.

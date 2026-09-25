# Follow-up tasks

Work found while fixing something else and left out of that change so it
stayed one logical fix. Each entry stands alone and can be handed to an
agent as is. Delete an entry when its fix lands.

- **6** is a test-harness problem found while fixing the interop
  port-probe race (commit `4ff94ca`). It changes only tests, so it
  replaces steps 1 and 2 below with the check it describes.
- **7-8** are SIPp divergences that `docs/SIPP_COMPAT.md` §6 already
  listed as open, with no fix picked up yet.
- **9-10** are SIPp divergences in how variables read and render, found
  while fixing `<assign value=>` (commit `86b9505`). Both were confirmed
  against sipp 3.7.7.
- **11** breaks the rule that sipr never ignores scenario input silently.
  It was found while fixing jump semantics (commit `5b29b65`).
- **12** is a gap in SIPp's documented keywords, found while adding
  `[branch±N]` (commit `bffa0e8`).
- **13** is a SIPp divergence in the `-trace_counts` columns, found while
  fixing the nop and 3PCC columns (commit `532133a`).

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

## 9. Read a variable's number the way SIPp's `getDouble()` does

Scope: `fix(engine)`. SIPP_COMPAT §6, the `<assign>` note, lists it as
open.

- **SIPp:** `CCallVariable::getDouble` (`variables.cpp` ~l.94) returns
  the double of a double variable and 0 for anything else: a string, a
  regexp capture, a bool (true included) or an unset variable. Every
  numeric read goes through it:
  - `get_rhs` (`call.cpp` ~l.5692): `variable=` on `assign`, `add`,
    `subtract`, `multiply`, `divide`, `jump` and `pauserestore`
  - the arithmetic actions' own left-hand side (~l.6006-6025)
  - `CAction::compare` (`actions.cpp` ~l.69), for `<test>`
  - `<pause variable=>` (~l.1970), `[fill variable=]` (~l.3989) and the
    `_unexp.retaddr` check (~l.5452)

  Only `<todouble>` converts: `CCallVariable::toDouble` (~l.121) parses
  a string or capture with `strtod` and requires all of it to parse,
  reads a bool as 0 or 1, and otherwise leaves the target alone with a
  "Invalid double conversion" warning (`call.cpp` ~l.6117-6124).
- **Confirmed against sipp 3.7.7**, in a UAC nop rendering into an
  OPTIONS: `<assignstr assign_to="t" value="5"/><add assign_to="t"
  value="1"/>` makes `[$t]` `1.000000`. `<assign variable=>` naming the
  string `"5"`, or a true `<test>` result, renders empty (a zero double).
- **sipr:** `Value::as_num` (`crates/sipr-engine/src/actions.rs`)
  parses a numeric string and reads a true bool as 1. It serves all the
  reads above (see its callers in `actions.rs`, `render.rs` and
  `engine.rs`), so the same scenario sends `6.000000`, `5.000000` and
  `1.000000`. `ToDouble` uses it too, so an unparsable string writes 0
  with no warning.
- **Fix:** give `Value` SIPp's strict number and use it for every read
  above, and move `as_num`'s parsing into `ToDouble` with SIPp's
  whole-string check and warning. Check each caller against SIPp before
  switching it: `[fieldN line=[$v]]` is not in the list above. The
  `value_coercions` unit test pins the current coercions.
- **Test:** extend `assign_takes_a_value_or_a_variable_like_real_sipp`
  in `tests/interop.rs` with string and bool sources and an `<add>` on
  a string, or write a sibling test that also covers `<todouble>`.

## 10. Render a false bool as `false`

Scope: `fix(engine)`. The "Variable value semantics" note in
SIPP_COMPAT §6 says the opposite and needs correcting.

- **SIPp:** `E_Message_Variable` (`call.cpp` ~l.3966-3981) writes
  `true` for a set (true) bool, and its `else if (var->isBool())` branch
  writes `false` for an unset (false) one. Confirmed against sipp 3.7.7:
  `[$no]` after `<test assign_to="no" variable="seven" compare="equal"
  value="8"/>` renders `false`.
- **sipr:** `Value::as_str` (`crates/sipr-engine/src/actions.rs`)
  renders `Bool(false)` as nothing. The `value_coercions` unit test pins
  that, and the §6 note says "a false `<test>` result render[s] empty"
  and that sipr "used to print … `false`". So an earlier change moved
  sipr away from SIPp here.
- **Fix:** render `Bool(false)` as `false` in the message template path.
  Keep `is_set` false for it, since `test=` and `condexec` ask `isSet`.
  Check the other users of `as_str` (`strcmp`, `trim`, `urlencode`,
  `ereg search_in="var"`), where SIPp calls `getString()`, which is `""`
  for a bool.
- **Test:** an interop test rendering `[$yes]` and `[$no]` from two
  `<test>` results, compared with real sipp.

## 11. Run a `<pause>`'s and a `<timewait>`'s actions

Scope: `fix(scenario)`, then `fix(engine)`. SIPP_COMPAT §6, "Where a
`<jump>` lands", lists it as open.

- **SIPp:** `<pause>` and `<timewait>` are messages like any other, so
  `getCommonAttributes` (`scenario.cpp` ~l.1829) reads their `<action>`
  (~l.1783 `getActionForThisMessage`). `executeMessage`'s pause branch
  (`call.cpp` ~l.1956-1990) runs them with `executeAction` when the
  pause starts, right after `do_bookkeeping`. A `<jump>` among them sets
  `msg_index = N - 1`. When the pause ends, `run()` serves
  `paused_until` and calls `next()` from there, so the call goes on at
  N, or at message N-1's `next=`.
- **sipr:** `compile_pause` and `compile_timewait`
  (`crates/sipr-scenario/src/compile.rs`) never look at the element's
  children. `<pause milliseconds="10"><action><log message="x"/></action>
  </pause>` compiles clean under `--check`, and the log never runs. Any
  other child element vanishes the same way, which the "unknown elements
  are hard errors" rule in AGENTS.md forbids. `Step::Pause` and
  `Step::Timewait` have no `actions` field.
- **Fix:** compile `<action>` on both, and refuse other children as
  `compile_nop` does ("unexpected <x> inside <pause>"). Run the actions
  in the engine's `Step::Pause` arm when the pause starts, after
  `book_counter`. Apply a jump as `step_after_jump` does when the pause
  ends, and add the actions to `Scenario::all_actions`. Check whether
  SIPp's `<timewait>` runs them the same way. It shares the pause branch,
  with `timewait` set.
- **Test:** an interop UAC whose pause logs through `-trace_logs` and
  jumps, compared with real sipp. Add a compile test that an unknown
  child of `<pause>` is an error.

## 12. Take SIPp's `+N`/`-N` offset on every keyword

Scope: `fix(scenario)`, and `fix(engine)` for the rendering.

- **SIPp:** `SendingMessage` (`message.cpp` ~l.242-250) strips a `+N`
  or `-N` (a sign, then a digit) from any keyword but `authentication`
  and `tdmmap`, and keeps it as the component's `offset`. These
  keywords add it: `[remote_port]` (`call.cpp` ~l.2748),
  `[local_port]` (~l.2760), `[media_port]` (~l.2791), the
  `[rtpstream_*_port]`s (~l.2832-2856), the crypto keywords, `[cseq]`
  (~l.3884), `[branch]` (~l.3892), `[len]` (~l.3915) and
  `[last_cseq_number]` (~l.4083). Every other keyword drops it:
  `[call_number+1]` renders the call number. SIPp's
  `docs/scenarios/keywords.rst` documents `[remote_port+3]`,
  `[local_port+3]`, `[len+3]` and `[cseq+1]`.
- **sipr:** `classify` in `crates/sipr-scenario/src/template.rs` takes
  offsets only on the media and rtpstream ports, the crypto keywords,
  `[last_cseq_number]` and `[branch]`. `[cseq+1]`, `[len+3]`,
  `[remote_port+3]` and `[local_port+3]` warn "unknown keyword … passed
  through verbatim", so the brackets go out in the message. So does an
  offset on any other keyword.
- **Fix:** give `Cseq`, `Len`, `RemotePort` and `LocalPort` an `offset`
  like `Branch { offset }`, parsed with `parse_offset`, and add it where
  `render.rs` writes them. `[len]` fills a width-5 placeholder after
  the body is known, so check that the offset reaches that
  computation. For the keywords SIPp parses an offset on and drops it,
  decide between matching SIPp and a specific warning. Dropping it
  silently is what AGENTS.md forbids.
- **Test:** an interop UAC rendering each offset form into an OPTIONS
  to a UDP sink, compared with real sipp.

## 13. Count and report simulated losses per message

Scope: `fix(stats)`. SIPP_COMPAT §6, the M40 statistics-files note,
lists it as open.

- **SIPp:** `lose_packets` goes on with `-lost` (`sipp.cpp` ~l.2010)
  or with any message's `lost=` (`scenario.cpp` ~l.1838). Each
  simulated loss adds one to that message's `nb_lost`: a send dropped
  in `send_raw` (`call.cpp` ~l.1564), a received message dropped after
  matching (~l.5497), and a dropped retransmission of the last received
  message (~l.4672). With `lose_packets` on, `print_count_file`
  (`logger.cpp` ~l.102-152) gives every send and recv a
  `<index>_<name>_Lost` column after its others. The scenario screen
  (`screen.cpp` ~l.477-545) adds a `Lost` column too.
- **sipr:** `-lost` and `lost=` drop messages (the M42 note in §6), but
  `StepStats` (`crates/sipr-stats/src/snapshot.rs`) has no lost counter.
  `counts_header`/`counts_row` (`crates/sipr-stats/src/lib.rs`) write no
  `_Lost` column, so with loss on sipr's header is shorter than sipp's.
- **Fix:** count each simulated loss on the step it belongs to, in the
  three places SIPp does. Tell the stat set whether loss is on (`-lost`
  or any step's `lost=`), and add the column to the counts file and to
  the scenario screen when it is. Check how SIPp spells the header of a
  retransmission-dropped recv.
- **Test:** widen `statistics_file_headers_match_real_sipps` in
  `tests/interop.rs`, or add a sibling that runs with `-lost 50` and
  compares the counts header with real sipp's.

# Follow-up tasks

Work found while fixing something else and left out of that change so it
stayed one logical fix. Each entry stands alone and can be handed to an
agent as is. Delete an entry when its fix lands.

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

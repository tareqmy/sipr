# Follow-up tasks

Work found while fixing something else and left out of that change so it
stayed one logical fix. Each entry stands alone and can be handed to an
agent as is. Delete an entry when its fix lands.

- **12** is a gap in SIPp's documented keywords, found while adding
  `[branch±N]` (commit `bffa0e8`).
- **13** is a SIPp divergence in the `-trace_counts` columns, found while
  fixing the nop and 3PCC columns (commit `532133a`).
- **14** is a flaky interop test, seen again while running the gates for
  the fixes above. It changes only tests, so it replaces steps 1 and 2
  below with the check it describes.

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

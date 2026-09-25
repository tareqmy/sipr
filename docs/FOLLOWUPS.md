# Follow-up tasks

Work found while fixing something else and left out of that change so it
stayed one logical fix. Each entry stands alone and can be handed to an
agent as is. Delete an entry when its fix lands.

- **14** is a flaky interop test, seen again while running the gates for
  the fixes above. It changes only tests, so it replaces steps 1 and 2
  below with the check it describes.
- **17** is a race in the HTTP control API, seen once on a loaded CI
  runner (run 36123832128, macOS).

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

## 17. Answer `POST /quit` in full before sipr exits

Scope: `fix(control)`.

- **The failure:** `http_api_reports_stats_and_controls_the_run` in
  `tests/e2e.rs` got a `202` for `POST /quit` with an empty body
  (`assert!(body.contains("\"quitting\":\"soft\""))`) on a loaded
  macOS CI runner, where the e2e suite took 280 s. It passed on the
  previous run and has not failed locally.
- **Likely cause:** `crates/sipr-control/src/http.rs` writes a response
  in two calls, the head and then the body (~l.150-151). The `/quit`
  handler only replies after the engine has taken the quit (`ask(link,
  ControlCmd::Quit …)` in `api.rs`). With few calls to drain, a soft quit
  can finish and the process exit while the HTTP thread sits between the
  two writes, so the client reads the head and then EOF.
- **Fix:** write head and body in one call, which closes the gap between
  the writes. Then make sure the process cannot exit before an accepted
  `/quit` reply is written, for example by having the engine wait for the
  HTTP thread to finish its response, or by answering before the engine
  acts on the quit.
- **Test:** loop the e2e test beside CPU-bound processes. A unit test
  can drive the handler with a quit whose engine side has already
  finished.

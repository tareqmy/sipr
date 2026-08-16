# AGENTS.md — operating instructions for AI agents working on sipr

sipr is a SIPp-like SIP testing tool and traffic generator written in Rust. It plays
call flows described in SIPp's XML scenario format, as UAC or UAS, at a controlled
rate, and reports live (TUI) and aggregate statistics.

**Current state: pre-M0.** No code exists yet. `PLAN.md` is the master plan; work
proceeds milestone by milestone against `docs/MILESTONES.md`.

## Read this first

1. `PLAN.md` — architecture decisions, milestones, rationale. Do not contradict it;
   if a decision needs revisiting, say so explicitly and ask rather than silently
   diverging.
2. `docs/MILESTONES.md` — what to build next and the acceptance criteria for "done".
3. The doc relevant to your task:
   - `docs/ARCHITECTURE.md` — crate map, runtime model, data flow, hot-path rules
   - `docs/SIPP_COMPAT.md` — the exact SIPp XML/keyword/CLI surface we implement
   - `docs/CONVENTIONS.md` — code style, error handling, logging, commit rules
   - `docs/TESTING.md` — test layers and how to run them, incl. interop with real SIPp
   - `docs/GLOSSARY.md` — SIP/SIPp domain terms; read it if you are unsure what a
     transaction vs dialog vs call is, or what RTD/repartition/3PCC mean

Repo-local skills exist under `.claude/skills/` (sip-protocol, sipp-scenarios,
interop-testing). Use them when implementing protocol behavior, touching scenario
parsing, or writing/running interop tests.

## Reference material

- The original SIPp C++ source is expected as a sibling checkout at
  `../../cprojects/sipp` (i.e. `~/development/cprojects/sipp`). It is the behavioral
  oracle: **when SIPp's documented behavior is ambiguous, read the C++**
  (`src/call.cpp`, `src/scenario.cpp`, `src/socket.cpp`) rather than guessing.
  Never copy C++ code verbatim (GPL); learn the behavior, implement independently.
- `../../cprojects/sipp/sipp.dtd` — the scenario XML grammar.
- `../../cprojects/sipp/sipp_scenarios/*.xml` and `docs/` there — golden corpus.
- SIPp docs: https://sipp.readthedocs.io — RFC 3261 (SIP), RFC 7616 (digest auth).

## Build, test, lint

Standard cargo workspace. Before considering any change complete, all of these must
pass from the repo root:

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

From milestone M3 onward, also run the interop suite when touching engine, net, or
scenario code: `cargo test -p sipr --test interop` (requires a built `sipp` binary;
see `docs/TESTING.md`). Never mark a milestone item done with failing or skipped
acceptance tests.

## Hard rules

- **Compatibility is the product.** Anything in the v1 tier of `docs/SIPP_COMPAT.md`
  must behave like SIPp. New CLI flags must use SIPp's names where an equivalent
  exists (`-sf`, `-r`, `-l`, `-m`, ...). Do not invent alternative names for things
  SIPp already has a name for.
- **Never silently ignore scenario input.** Unknown XML elements, attributes, or
  keywords produce a loud warning with file:line context (or a hard error in
  `--check` mode). Silent skips are the worst SIPp failure mode; we do not inherit it.
- **Hot path discipline** (per-message send/recv code): no allocations beyond
  template slot filling, no locks held across `.await`, no synchronous I/O, no
  regex compilation. Message templates are pre-tokenized at scenario load; if you
  find yourself scanning strings per-send, stop and re-read `docs/ARCHITECTURE.md` §3.
- **The TUI never touches the engine.** It reads 1-second stat snapshots only.
- **`unsafe` is forbidden** in this workspace (`#![forbid(unsafe_code)]` in every
  crate). If you believe an exception is warranted, ask; do not just add it.
- **No `unwrap()`/`expect()`/`panic!` in library crates** outside tests. Errors are
  typed per crate (`thiserror`) and bubble to the binary (`anyhow`) — see
  `docs/CONVENTIONS.md`.
- **A test tool must be able to misbehave on purpose.** Do not "fix" scenario
  behavior into RFC compliance: `lost`, `retrans`, malformed templates, and
  rule-breaking scenarios are features. Strictness belongs on the *inbound* parse
  side, and even there be tolerant (real devices send garbage).
- **Do not add dependencies casually.** The sanctioned set is in
  `docs/CONVENTIONS.md` §Dependencies. Adding a new crate requires a stated reason
  in the PR/commit description.

## Workflow

- Work in small, compilable increments; keep `main` green.
- Update `docs/MILESTONES.md` checkboxes in the same change that completes them.
- If you learn a non-obvious SIPp behavior from the C++ source, record it in
  `docs/SIPP_COMPAT.md` §Behavior notes so the next agent doesn't re-derive it.
- Commit messages follow Conventional Commits (`feat(scenario): ...`,
  `fix(net): ...`) — scope = crate short name. See `docs/CONVENTIONS.md`.

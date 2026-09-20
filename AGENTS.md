# AGENTS.md — operating instructions for AI agents working on sipr

sipr is a SIPp-like SIP testing tool and traffic generator written in Rust. It plays
call flows described in SIPp's XML scenario format, as UAC or UAS, at a controlled
rate, and reports live (TUI) and aggregate statistics.

**Current state: v1 shipped, M0–M37 complete** (UDP/TCP/TLS transports incl. per-call and per-IP sockets, SCTP behind the `sctp` feature, `-rsa`, reconnection, UAC/UAS, out-of-call scenarios (`-oocsf`/`-oocsn`), mixed mode (`-rxsf`/`-rxsn`, `-rxinf`),
stats + TUI, the full SIPp action set incl. `_unexp.main`, `exec command=` and `<setdest>`, manual transactions (`start_txn`/`ack_txn`/`response_txn`), `<User>`/`<Global>` variable scopes, auth incl. IMS AKA + AUTS resync + `verifyauth`, `-inf` injection, 3PCC, `-users`, IPv6,
pcap replay, RTP streaming + DTMF, RTP echo + rtpcheck, SRTP + SRTP echo server, SIPp
control socket + HTTP API). `PLAN.md` is the
master plan (its dependency choices were superseded by in-tree implementations —
`docs/MILESTONES.md` notes record each swap); the post-v1 backlog at the bottom of
`docs/MILESTONES.md` (the second backlog, M38+) is what comes next.

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
cargo deny check      # dependency licenses, advisories, sources (deny.toml)
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
- **Never silently ignore scenario input.** Unknown XML *elements and actions*
  are hard errors (silently skipping a step would change the call flow);
  unknown *attributes and keywords* produce a loud warning with file:line
  context; `--check` treats any diagnostic, warnings included, as failure.
  Silent skips are a SIPp failure mode we deliberately do not inherit.
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

## Engineering principles

- **Prioritize readability over cleverness.** Write code that clearly
  communicates intent. Code is read far more often than it is written: use
  descriptive names, keep functions small and single-purposed, and follow the
  project's style conventions instead of writing dense one-liners.
- **Write automated tests early.** Cover core logic and edge cases with unit
  and integration tests as the code lands, not after. Tests reduce regressions,
  act as living documentation, and buy the confidence to refactor aggressively
  (see `docs/TESTING.md` for the required layers per crate).
- **Practice strict version-control hygiene.** Small, atomic commits with
  clear, imperative messages explaining the *why*, not just the *what*
  (Conventional Commits, per `docs/CONVENTIONS.md`). Keep branches short-lived
  and review changes thoroughly before they reach `main`.
- **Avoid premature optimization (YAGNI).** Build what is needed for the
  current milestone rather than engineering for hypothetical futures. Implement
  the simplest solution that works, profile actual bottlenecks with data
  (criterion benches, M3+), and optimize only when necessary. The documented
  hot-path rules in `docs/ARCHITECTURE.md` §3 are the *measured-by-design*
  exception, not a license to micro-optimize elsewhere.
- **Design defensively and fail gracefully.** Never trust external input —
  inbound datagrams, scenario files, injection CSVs, CLI values. Validate at
  the boundaries, use structured error handling (typed errors, no swallowed
  failures), log actionable context, and fail without leaking internals.
  Remember the test-tool nuance: *outbound* scenario traffic may deliberately
  violate the SIP RFCs; defensiveness applies to what we *accept*, not what
  scenarios choose to send.

Core refactoring strategies:

- **Extract method.** If a block inside a function needs a comment to explain
  *what* it does, extract it into a helper named after that intent.
- **Use guard clauses.** Return early on invalid input and edge cases instead
  of nesting the happy path inside `if` pyramids.
- **Favor composition over inheritance.** In Rust terms: no god-objects or
  deep trait hierarchies — inject small, focused types (services, strategies)
  to handle specific behaviors, and keep trait bounds narrow. SIPp's `call.cpp`
  absorbed most concerns over the years; the crate boundaries exist so that
  does not happen here.

## Workflow

- Work in small, compilable increments; keep `main` green.
- Update `docs/MILESTONES.md` checkboxes in the same change that completes them.
- If you learn a non-obvious SIPp behavior from the C++ source, record it in
  `docs/SIPP_COMPAT.md` §Behavior notes so the next agent doesn't re-derive it.
- Commit messages follow Conventional Commits (`feat(scenario): ...`,
  `fix(net): ...`) — scope = crate short name. See `docs/CONVENTIONS.md`.

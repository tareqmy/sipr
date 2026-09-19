# Conventions

## Rust

- Edition 2024, MSRV = 1.85 (`rust-version` in the root Cargo.toml). Unsafe
  code is forbidden workspace-wide (`[workspace.lints.rust] unsafe_code =
  "forbid"`; every crate sets `[lints] workspace = true`).
- `rustfmt` with default settings — no local style debates. `cargo clippy
  --workspace --all-targets -- -D warnings` must pass; `#[allow]` requires an
  adjacent comment justifying it.
- Public items in library crates get doc comments. Doc examples must compile
  (`cargo test` runs them).

## Errors

- Library crates: typed errors with `thiserror`, one error enum per crate
  (`ScenarioError`, `NetError`, ...). Include position context in scenario
  errors (file, line, element) — scenario authors debug with these.
- Binary: `anyhow` at the top level; user-facing messages must be actionable
  ("unknown attribute 'retrnas' on <send> at uac.xml:41 — did you mean
  'retrans'?"), not debug dumps.
- No `unwrap()`/`expect()`/`panic!` in library code outside tests and truly
  unreachable states (`unreachable!` with a comment). In tests, unwrap freely.

## Logging and tracing

- `tracing` everywhere; no `println!`/`eprintln!` outside the TUI crate and CLI
  output paths. Levels: `error` = call/tool integrity, `warn` = compat surprises
  (unknown keyword, unexpected message), `info` = lifecycle, `debug` = per-call,
  `trace` = per-message. Per-message logging must be zero-cost when disabled
  (guard with `tracing::enabled!` where formatting is expensive).
- SIPp-style file outputs (`-trace_msg`, `-trace_err`, `-trace_stat`) are product
  features, implemented as dedicated writers — not routed through `tracing`.

## Async

- Tokio only. No blocking calls on the runtime (file I/O for traces goes through
  a dedicated writer task or `spawn_blocking`).
- Prefer channels + ownership over `Mutex`. If a lock is unavoidable it must
  never be held across `.await` (clippy's `await_holding_lock` is promoted to
  deny).

## Dependencies

Sanctioned: `tokio`, `tokio-util`, `rsip`, `quick-xml`, `ratatui`,
`crossterm`, `regex`, `hdrhistogram`, `thiserror`, `anyhow`, `tracing`,
`tracing-subscriber`, `rand`, `md-5`, `sha2`, `dashmap`, `arc-swap`, `bytes`,
`rustls`, `rustls-pki-types` (PEM parsing; replaced the unmaintained `rustls-pemfile`), `socket2` (only behind the `sctp` cargo feature:
std has no SCTP, and socket2 is the safe way to open `SOCK_STREAM`/
`IPPROTO_SCTP` sockets — decision recorded in MILESTONES.md M32),
and for tests `proptest`, `criterion`, `assert_cmd`, `tempfile`, `rcgen`. Add them to
`[workspace.dependencies]` when a milestone first needs them. The CLI is a
deliberate exception: `src/cli.rs` is a bespoke table-driven parser (not clap)
because SIPp's single-dash multi-char flags don't fit clap's model — extend
the `FLAGS` table there rather than introducing clap.
Anything else: state the reason in the commit/PR description. Prefer std over a
crate for trivial needs. No crates with native/C dependencies without discussion
(portability is a selling point vs SIPp's build).

TLS note (M13): `rustls` is used with `default-features = false` and the
`ring` provider — NOT the default `aws-lc-rs`, whose C build can require
cmake. `ring` vendors its own C/asm but builds with `cc` alone, keeping
`cargo build` dependency-free at the system level (no OpenSSL headers — the
exact pain point of building SIPp with TLS). `rcgen` (dev-only, `ring`
feature) generates test certificates at test time so no expiring PEM
fixtures are checked in.

## Testing (summary — full detail in TESTING.md)

- Every bugfix lands with a regression test.
- Scenario parser changes: extend the golden corpus.
- Engine/net changes from M3 on: interop suite must pass.
- New public API: at least one doc example.

## Commits

Conventional Commits: `type(scope): summary` where scope is the crate short name
(`scenario`, `net`, `engine`, `auth`, `stats`, `tui`, `cli`, `docs`). Types:
`feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`, `build`. Imperative
mood, ≤72-char subject. Body explains *why* when non-obvious. One logical change
per commit; keep the tree building at every commit.

## Documentation upkeep

Docs are part of the change, not a follow-up: structural changes update
`ARCHITECTURE.md`; discovered SIPp behaviors go to `SIPP_COMPAT.md` §Behavior
notes; completed criteria get checked in `MILESTONES.md` in the same commit.

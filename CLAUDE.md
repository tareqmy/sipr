# CLAUDE.md

@AGENTS.md

Quick commands (details in AGENTS.md and docs/TESTING.md):

```
cargo fmt --all -- --check                       # formatting gate
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                           # unit + golden tests
cargo deny check                                 # dependency licenses + advisories
cargo test -p sipr --test interop                # vs real sipp (M3+)
```

Master plan: `PLAN.md`. Next work + acceptance criteria: `docs/MILESTONES.md`.
Project skills live in `.claude/skills/` (sip-protocol, sipp-scenarios,
interop-testing) — use them.

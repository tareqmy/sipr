# Contributing to sipr

Thanks for your interest. sipr aims to run existing SIPp scenarios unchanged,
so compatibility with SIPp's documented behavior is the bar for every change.

## Before you start

- Read `AGENTS.md`. It is written for AI coding agents but it is the
  project's operating manual for people too: the hard rules, the docs to
  read for each area, and where SIPp's C++ is used as the behavioral
  reference (learn the behavior, never copy the code; SIPp is GPL and sipr
  is MIT).
- Check `docs/MILESTONES.md` and `docs/SIPP_COMPAT.md` before proposing a
  feature. Some gaps are deliberate and listed in the README.

## Documentation

The site at https://tareqmy.github.io/sipr/ is built with
[mdBook](https://rust-lang.github.io/mdBook/) from `docs/` (`book.toml` at
the root) and deployed by `.github/workflows/docs.yml` on every push to
`master`. A new page must be listed in `docs/SUMMARY.md` or it will not be
rendered. `make book` serves it locally (`cargo install mdbook`).

## Pull requests

All of these must pass from the repo root; CI runs the same commands:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check      # dependency licenses, advisories, sources (cargo install cargo-deny)
```

Changes to engine, net, or scenario code also need the interop suite against
a real SIPp binary (`cargo test -p sipr --test interop`; see `docs/TESTING.md`
for building SIPp). If you cannot run it locally, say so in the PR and CI
will.

- Keep PRs small and focused; one behavior per PR.
- Add tests with the change: unit tests in the crate, an e2e or interop
  test when the behavior is visible on the wire.
- Commit messages follow Conventional Commits with the crate short name as
  scope (`feat(scenario): …`, `fix(net): …`), explaining the *why*.
- If you learned a non-obvious SIPp behavior while working, record it in
  `docs/SIPP_COMPAT.md` §6 so the next person does not re-derive it.

AI-assisted contributions are welcome and held to the same bar. Please
review what the tool produced before opening the PR.

## Reporting bugs

A minimal scenario file plus the exact `sipr` and `sipp` command lines, and
`-trace_msg` output from both sides where relevant, makes most bugs
reproducible in minutes. Security issues go through `SECURITY.md`, not the
issue tracker.

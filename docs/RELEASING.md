# Releasing sipr

A short, repeatable checklist for cutting a release. sipr is a Cargo
workspace of eight library crates plus the `sipr` binary; publishing to
crates.io means publishing each crate in dependency order.

## 1. Pre-flight

Everything must be green (this is exactly what CI runs):

```sh
make check            # fmt-check + clippy -D warnings + tests
```

Then run the one gate CI can't fully cover without a SIPp binary — the
interop suite against real SIPp, both directions:

```sh
make interop          # uses SIPP_BIN (defaults to ~/development/cprojects/sipp/sipp)
# or: SIPP_BIN=$(command -v sipp) cargo test --test interop -- --nocapture
```

Expect all four flows green: sipr-UAC ↔ sipp-UAS, sipp-UAC ↔ sipr-UAS.

## 2. Version + changelog

1. Bump `version` in the root `Cargo.toml` `[workspace.package]` and the
   internal-dependency versions in `[workspace.dependencies]` (they must
   match — they're pinned so the crates are publishable).
2. Move the `[Unreleased]` items in `CHANGELOG.md` under a new dated
   version heading; update the compare/tag links at the bottom.
3. Commit: `git commit -am "release: v0.1.0"`.

## 3. Tag

```sh
git tag -a v0.1.0 -m "sipr v0.1.0"
git push origin master --tags
```

## 4. Publish to crates.io (optional)

Publishing is optional — the binary builds fine from source without it.
If you do publish, the crates must go up in dependency order, because
each depends on the previous ones already being on the registry:

```
sipr-auth        # no internal deps
sipr-net         # no internal deps
sipr-scenario    # no internal deps
sipr-stats       # no internal deps
sipr-media       # depends on auth
sipr-control     # depends on stats
sipr-tui         # depends on stats
sipr-engine      # depends on scenario, net, auth, stats, media, control
sipr             # the binary — depends on all
```

Dry-run each first (requires network / a crates.io token):

```sh
cargo publish -p sipr-auth --dry-run
cargo publish -p sipr-auth
# ...repeat down the list, waiting for each to index before the next...
cargo publish            # the binary, from the workspace root
```

Offline sanity check that a crate packages cleanly (no registry needed
for the zero-dependency leaf crates):

```sh
cargo package -p sipr-auth --allow-dirty
```

Note: the crate names must be available on crates.io. If `sipr` or any
`sipr-*` name is taken, rename before publishing (a repo-wide find/replace
on the crate name plus its `[workspace.dependencies]` key).

## 5. Binary artifacts (optional)

For a GitHub release, attach a stripped release binary:

```sh
cargo build --release
strip target/release/sipr        # optional, smaller binary
# upload target/release/sipr to the GitHub release for v0.1.0
```

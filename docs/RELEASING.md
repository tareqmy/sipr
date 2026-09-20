# Releasing sipr

Releases are cut by pushing a `vX.Y.Z` tag. The `CD` workflow
(`.github/workflows/cd.yml`) then builds the binaries, publishes the GitHub
release, and pushes to crates.io, the Homebrew tap and Chocolatey. The manual
part is the pre-flight, the version bump, and the tag.

## 1. Pre-flight

Everything must be green (this is what CI runs on every push):

```sh
make check            # fmt-check + clippy -D warnings + tests
make deny             # cargo-deny: dependency licenses, advisories, sources
```

Then the gate CI can only run with a SIPp binary, both directions:

```sh
make interop          # SIPP_BIN defaults to ~/development/cprojects/sipp/sipp
```

If SIPp is not built locally, push to master first and wait for the `interop`
and `sctp` CI jobs; the tag must not go on a commit CI has not validated.

Optionally confirm that every crate still packages cleanly (no network
writes, but it builds each crate):

```sh
make publish-dry-run
```

## 2. Version + changelog

The version lives in four places; they must agree:

1. `version` in the root `Cargo.toml` `[workspace.package]`, and the pinned
   internal-dependency versions in `[workspace.dependencies]` (they are
   pinned so the crates are publishable).
2. `.version` — the plain version without `v`, no trailing newline. The
   install scripts read it from `master` to find the latest release.
3. `Formula/sipr.rb` and `dist/chocolatey/sipr.nuspec` +
   `tools/chocolateyinstall.ps1` — reference copies; CD rewrites the live
   ones with real checksums, but keep these on the same version.
4. `CHANGELOG.md`: move the `[Unreleased]` items under a new dated heading
   and add the compare link at the bottom.

Then:

```sh
git commit -am "release: v0.27.0"
git tag -a v0.27.0 -m "sipr v0.27.0"
git push origin master --tags
```

## 3. What CD does on the tag

1. Creates a draft GitHub release.
2. Builds `sipr` for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`
   (static), `x86_64-apple-darwin`, `aarch64-apple-darwin`, and
   `x86_64-pc-windows-msvc`, and uploads
   `sipr-vX.Y.Z-<target>.tar.gz` (`.zip` on Windows) to the draft.
3. Publishes the release once every asset is up.
4. In parallel, `scripts/publish-crates.sh` pushes the nine crates to
   crates.io in dependency order, skipping any version already there — only
   when `CARGO_REGISTRY_TOKEN` is set.
5. After the release is public, rewrites `Formula/sipr.rb` in
   `tareqmy/homebrew-tap` with the new version and checksums — only when
   `TAP_GITHUB_TOKEN` is set.
6. Packs and pushes the Chocolatey package — only when `CHOCO_API_KEY` is set.

Each publish step skips with a workflow warning when its secret is missing,
so a release without them still produces the GitHub release and binaries.

## 4. One-time setup (repository secrets)

Settings → Secrets and variables → Actions:

| Secret | Used for | Where to get it |
|---|---|---|
| `CARGO_REGISTRY_TOKEN` | crates.io publish | crates.io → Account Settings → API Tokens, scope `publish-new` + `publish-update` |
| `TAP_GITHUB_TOKEN` | pushing the formula to `tareqmy/homebrew-tap` | a fine-grained PAT with *Contents: write* on the tap repo only |
| `CHOCO_API_KEY` | Chocolatey push | chocolatey.org → account → API key |

The crate names `sipr` and `sipr-*` must be free on crates.io at first
publish (they were, as of 2026-09-19). The Homebrew tap already exists and
serves other formulas; CD adds `Formula/sipr.rb` next to them.

### If the crates.io step fails part-way

crates.io rate-limits brand-new crate names (five per ten minutes), and the
tag's workflow file cannot be edited after the fact. Run the **Publish
crates** workflow from `master` with the tag name; it checks out the tag's
sources and publishes only the crates still missing:

```sh
gh workflow run publish-crates.yml -f tag=v0.27.0
```

The same script works locally after `cargo login`: `make publish` from a
checkout of the tag.

## 5. After the workflow

- Check the release page: five assets, notes pointing at the changelog.
- `brew update && brew upgrade sipr` on a Mac, and the shell installer on a
  Linux box, should both land the new version.
- If a step failed, fix it and re-run the job from the Actions tab; the
  workflow is idempotent (existing release and assets are reused or
  overwritten with `--clobber`).

#!/bin/sh
# Publish the workspace crates to crates.io, in dependency order, skipping any
# crate whose version is already there.
#
# Safe to rerun after a partial failure: crates.io rate-limits brand-new crate
# names (five per ten minutes at the time of writing), and `cargo publish
# --workspace` refuses to continue once any member already exists, so a
# resumable per-crate loop is the only shape that survives a first release.
#
# Run from the repository root (or a checkout of the release tag). The token
# comes from `cargo login` or the CARGO_REGISTRY_TOKEN environment variable,
# which cargo reads on its own.
set -eu

version=$(tr -d '[:space:]' < .version)
crates="sipr-auth sipr-net sipr-scenario sipr-stats sipr-media sipr-control sipr-engine sipr-tui sipr"
user_agent="sipr-release (https://github.com/tareqmy/sipr)"

for crate in $crates; do
  status=$(curl -sS -o /dev/null -w '%{http_code}' -A "$user_agent" \
    "https://crates.io/api/v1/crates/$crate/$version")
  case "$status" in
    200) echo "skip: $crate $version is already on crates.io"; continue ;;
    404) ;;
    *) echo "error: crates.io answered HTTP $status for $crate $version" >&2; exit 1 ;;
  esac
  echo "publish: $crate $version"
  cargo publish -p "$crate" --locked
done

echo "done: every crate is at $version on crates.io"

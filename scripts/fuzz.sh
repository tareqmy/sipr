#!/bin/sh
# Run the fuzz targets for a fixed time each (docs/TESTING.md §6): the
# nightly-only step that the four stable gates cannot cover.
#
# libFuzzer writes every input that widened coverage into the first corpus
# directory it is given, so each target gets a scratch directory to grow in
# and reads the checked-in seeds from `fuzz/corpus/<target>` read-only.
# A crash, a panic, or an input that runs past TIMEOUT seconds stops the
# run with a non-zero exit; the reproducer lands in `fuzz/artifacts/<target>/`
# and cargo-fuzz prints the command to replay it.
#
# Usage:  scripts/fuzz.sh [SECONDS_PER_TARGET] [TARGET...]
# Environment: TIMEOUT (seconds one input may take; default 10)
#              FUZZ_WORK (scratch corpus root; default under $TMPDIR)
set -eu

cd "$(dirname "$0")/../fuzz"

secs=${1:-30}
[ $# -gt 0 ] && shift
if [ $# -gt 0 ]; then
    targets=$*
else
    targets=$(cargo +nightly fuzz list)
fi
timeout=${TIMEOUT:-10}
work=${FUZZ_WORK:-${TMPDIR:-/tmp}/sipr-fuzz}
mkdir -p "$work"
log="$work/run.log"

cargo +nightly fuzz build

for target in $targets; do
    mkdir -p "$work/$target"
    echo "==> $target: ${secs}s (scratch corpus $work/$target)"
    if cargo +nightly fuzz run "$target" "$work/$target" "corpus/$target" -- \
        -max_total_time="$secs" -timeout="$timeout" -print_final_stats=1 >"$log" 2>&1
    then
        # The one-line summary: executions, corpus size, coverage edges.
        grep -E '^#[0-9]+\s+DONE' "$log" || tail -3 "$log"
    else
        # The finding: sanitizer report, the panic message, and the replay
        # command cargo-fuzz prints.
        grep -vE '^(#[0-9]+\s+(NEW|REDUCE|pulse|INITED)|MS: )' "$log" | tail -40
        echo "!! $target: reproducer in fuzz/artifacts/$target" >&2
        exit 1
    fi
done
echo "fuzz: every target ran ${secs}s without a finding"

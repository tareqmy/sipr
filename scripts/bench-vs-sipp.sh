#!/bin/sh
# Side-by-side load comparison: sipr against real sipp, same host, same call
# flow, same rates. Prints a Markdown table for docs/PERFORMANCE.md.
#
# Both tools run the embedded `uac`/`uas` scenarios, so the call flow is
# identical, and both are measured the same way:
#
#   * CPU and peak RSS come from /usr/bin/time around each process (BSD `-l`
#     on macOS, GNU `-v` on Linux). Neither tool is given a background flag:
#     sipp's `-bg` forks and the parent exits at once, which would leave
#     nothing to measure, and sipr skips its TUI on its own when stdout is
#     not a terminal. So both run in the foreground with output redirected.
#   * Calls, retransmissions and peak concurrency come from each tool's own
#     `-trace_stat` CSV. sipr writes SIPp's columns byte-for-byte (M40), so
#     one parser reads both.
#
# Each rate runs for a fixed WINDOW of seconds rather than a fixed call
# count, so every rate gets the same time under load.
#
# Usage:  scripts/bench-vs-sipp.sh [-o docs/PERFORMANCE.md]
# Environment: SIPR_BIN SIPP_BIN RATES WINDOW PAUSE_MS
set -eu

SIPR_BIN=${SIPR_BIN:-./target/release/sipr}
SIPP_BIN=${SIPP_BIN:-$HOME/development/cprojects/sipp/sipp}
RATES=${RATES:-"500 2000 5000"}
WINDOW=${WINDOW:-10}
PAUSE_MS=${PAUSE_MS:-10}

for bin in "$SIPR_BIN" "$SIPP_BIN"; do
  [ -x "$bin" ] || { echo "error: no executable at $bin" >&2; exit 1; }
done
# Each run works in its own directory, so the binaries need absolute paths.
SIPR_BIN=$(cd "$(dirname "$SIPR_BIN")" && pwd)/$(basename "$SIPR_BIN")
SIPP_BIN=$(cd "$(dirname "$SIPP_BIN")" && pwd)/$(basename "$SIPP_BIN")

case $(uname -s) in
  Darwin|*BSD) time_flag=-l ;;
  *)           time_flag=-v ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

# Three free UDP ports (SIP, and one control port per side), chosen together
# so they cannot collide with each other.
free_udp_ports() {
  python3 - <<'PY'
import socket
held = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3)]
for s in held:
    s.bind(("127.0.0.1", 0))
print(" ".join(str(s.getsockname()[1]) for s in held))
for s in held:
    s.close()
PY
}

# Block until something holds `$1`, which for UDP means trying to bind it
# ourselves: while the bind succeeds the UAS is not up yet.
wait_for_listener() {
  python3 - "$1" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
deadline = time.time() + 10
while time.time() < deadline:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError:
        sys.exit(0)
    finally:
        probe.close()
    time.sleep(0.02)
sys.exit(1)
PY
}

# CPU seconds (user+sys) from a /usr/bin/time report.
cpu_of() {
  if [ "$time_flag" = -l ]; then
    awk '/real/ { print $3 + $5; exit }' "$1"
  else
    awk '/User time/ { u=$NF } /System time/ { s=$NF } END { print u + s }' "$1"
  fi
}

# Peak resident set in MiB from a /usr/bin/time report (BSD reports bytes,
# GNU kibibytes).
rss_mib_of() {
  if [ "$time_flag" = -l ]; then
    awk '/maximum resident set size/ { printf "%.1f", $1 / 1048576; exit }' "$1"
  else
    awk '/Maximum resident set size/ { printf "%.1f", $NF / 1024; exit }' "$1"
  fi
}

# One column of a -trace_stat CSV, by header name. `max` takes the largest
# value in the column, anything else the last row's.
stat_of() {
  csv=$1 column=$2 mode=${3:-last}
  [ -f "$csv" ] || { echo "-"; return; }
  awk -F';' -v want="$column" -v mode="$mode" '
    NR == 1 { for (i = 1; i <= NF; i++) if ($i == want) col = i; next }
    col && $col != "" {
      if (mode == "max") { if ($col + 0 > best) best = $col + 0 }
      else best = $col + 0
    }
    END { printf "%d", best }
  ' "$csv"
}

# The one *_.csv a run wrote (both tools name it <scenario>_<pid>_.csv).
csv_in() { ls "$1"/*_.csv 2>/dev/null | head -1; }

# Run one tool against itself for one rate; echo a Markdown table row.
run_pair() {
  tool=$1 bin=$2 rate=$3
  calls=$((rate * WINDOW))
  dir="$work/$tool-$rate"
  mkdir -p "$dir/uas" "$dir/uac"
  # shellcheck disable=SC2046
  set -- $(free_udp_ports)
  port=$1 uas_cp=$2 uac_cp=$3

  (cd "$dir/uas" && /usr/bin/time $time_flag -o "$dir/uas.time" \
      "$bin" -sn uas -i 127.0.0.1 -p "$port" -cp "$uas_cp" \
        -m "$calls" -timeout 300 -trace_stat -fd 1 \
      >/dev/null 2>"$dir/uas.err") &
  uas=$!
  wait_for_listener "$port" || {
    echo "error: $tool UAS never bound $port" >&2
    cat "$dir/uas.err" >&2
    exit 1
  }

  (cd "$dir/uac" && /usr/bin/time $time_flag -o "$dir/uac.time" \
      "$bin" -sn uac -i 127.0.0.1 -r "$rate" -m "$calls" -d "$PAUSE_MS" \
        -cp "$uac_cp" -timeout 300 -trace_stat -fd 1 "127.0.0.1:$port" \
      >/dev/null 2>"$dir/uac.err") || true
  wait "$uas" 2>/dev/null || true

  uac_csv=$(csv_in "$dir/uac")
  created=$(stat_of "$uac_csv" TotalCallCreated)
  ok=$(stat_of "$uac_csv" 'SuccessfulCall(C)')
  failed=$(stat_of "$uac_csv" 'FailedCall(C)')
  retrans=$(stat_of "$uac_csv" 'Retransmissions(C)')
  # UAC-side concurrency only: on the UAS side both tools keep finished
  # calls counted for a while (dead-call retention), so that figure measures
  # retention, not live dialogs. Verified identical in sipr and sipp.
  peak=$(stat_of "$uac_csv" CurrentCall max)
  printf '| %s | %s | %s | %s | %s | %s | %s s | %s s | %s | %s | %s |\n' \
    "$tool" "$rate" "$created" "$ok" "$failed" "$retrans" \
    "$(cpu_of "$dir/uac.time")" "$(cpu_of "$dir/uas.time")" \
    "$(rss_mib_of "$dir/uac.time")" "$(rss_mib_of "$dir/uas.time")" "$peak"
}

echo "host: $(uname -srm), $WINDOW s per rate, -d $PAUSE_MS, embedded uac/uas"
echo "sipr: $("$SIPR_BIN" -v | head -1)"
echo "sipp: $("$SIPP_BIN" -v 2>&1 | sed -n 's/^ *\(SIPp .*\)$/\1/p' | head -1)"
echo
echo '| Tool | Rate (cps) | Created | OK | Failed | Retrans | CPU UAC | CPU UAS | RSS UAC (MiB) | RSS UAS (MiB) | Peak concurrent |'
echo '|---|---|---|---|---|---|---|---|---|---|---|'
for rate in $RATES; do
  run_pair sipr "$SIPR_BIN" "$rate"
  run_pair sipp "$SIPP_BIN" "$rate"
done

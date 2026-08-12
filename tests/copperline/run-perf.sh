#!/bin/sh
# run-perf.sh -- Phase 1's performance gate (implementation-plan.md:
# "10k-file unchanged run under a minute on emulated 68030 without
# archive-bit help").
#
# Boots a minimal (no-Workbench) 68030/50 from ./boot-perf. The boot
# script (boot-perf/S/Startup-Sequence) runs: C:bulkstage (creates
# 10,000 small, distinct-content files directly under Source:), a first
# AmiSnap SNAPSHOT (populates the repository -- not timed, this is the
# "before" state), then a second AmiSnap SNAPSHOT over the *unchanged*
# tree wrapped in C:timeit (which brackets it with DateStamp() reads and
# logs the elapsed emulated time -- accurate regardless of host wall-
# clock/warp-speed pacing, since Copperline's core is cycle-accurate).
# AmiSnap has no archive-bit change-detection wired into cmd_snapshot
# yet (implementation-plan.md's index.c module exists but isn't called
# from the CLI) -- this run is exactly the "without archive-bit help"
# case the gate describes: a full re-scan/re-hash/re-write of every
# file, relying only on repo.c's own content-addressed dedup to skip
# redundant object uploads.
#
# Prereqs: same as run.sh (copperline + a staged Kickstart ROM), plus
# the bulkstage/timeit fixtures (`make copperline-fixtures`).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

COPPERLINE=${COPPERLINE:-copperline}
KICK=${KICK:-$ROOT/nondistribution/roms/a1200-kick31-40.68.rom}
BENCH=${BENCH:-300}
GATE_SECONDS=${GATE_SECONDS:-60}

AMISNAP_BIN="$ROOT/build/AmiSnap"
BULKSTAGE_BIN="$ROOT/build/copperline-fixtures/bulkstage"
TIMEIT_BIN="$ROOT/build/copperline-fixtures/timeit"

if [ ! -e "$KICK" ]; then
    echo "SKIP: no Kickstart ROM at $KICK (see nondistribution/README.md) -- not an asset CI has"
    exit 0
fi
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
[ -e "$AMISNAP_BIN" ] || { echo "FAIL: missing $AMISNAP_BIN (run: make m68k)" >&2; exit 2; }
[ -e "$BULKSTAGE_BIN" ] || { echo "FAIL: missing $BULKSTAGE_BIN (run: make copperline-fixtures)" >&2; exit 2; }
[ -e "$TIMEIT_BIN" ] || { echo "FAIL: missing $TIMEIT_BIN (run: make copperline-fixtures)" >&2; exit 2; }

echo "ROM: $KICK"

for d in source-perf repo-perf results-perf; do
    rm -rf "$HERE/$d"
    mkdir -p "$HERE/$d"
done
mkdir -p "$HERE/boot-perf/C" "$HERE/boot-perf/S"
cp "$AMISNAP_BIN" "$HERE/boot-perf/C/AmiSnap"
cp "$BULKSTAGE_BIN" "$HERE/boot-perf/C/bulkstage"
cp "$TIMEIT_BIN" "$HERE/boot-perf/C/timeit"

OUT=$(mktemp)
cleanup() { rm -f "$OUT"; }
trap cleanup EXIT INT TERM

set +e
( cd "$HERE" && "$COPPERLINE" --config machine-perf.toml --model A4000 --cpu 68030 --noaudio \
    --benchmark-until "$BENCH" "$KICK" ) >"$OUT" 2>&1
CL_RC=$?
set -e

echo "----- copperline output -----"
tail -20 "$OUT"
echo "------------------------------"
[ "$CL_RC" -eq 0 ] || { echo "FAIL: $COPPERLINE exited $CL_RC"; cat "$OUT"; exit 3; }

fail=0
check_log() {
    name=$1; pattern=$2
    path="$HERE/results-perf/$name"
    if [ ! -e "$path" ]; then
        echo "FAIL: missing $name (command never completed -- BENCH=$BENCH too short?)"
        fail=1
        return
    fi
    echo "--- $name ---"; cat "$path"
    if ! grep -q "$pattern" "$path"; then
        echo "FAIL: $name does not contain expected pattern: $pattern"
        fail=1
    fi
}

check_log bulkstage.log "^bulkstage: done"
check_log snapshot1.log "^Snapshot "
check_log timeit.log "^timeit: elapsed_ticks="
check_log snapshot2.log "^Snapshot "
check_log list.log " entries"

if [ "$fail" -eq 0 ]; then
    ticks=$(grep '^timeit: elapsed_ticks=' "$HERE/results-perf/timeit.log" | sed 's/.*=//')
    seconds=$((ticks / 50))
    echo "unchanged 10k-file SNAPSHOT took ${ticks} ticks (~${seconds}s emulated 68030/50), gate is ${GATE_SECONDS}s"
    if [ "$seconds" -ge "$GATE_SECONDS" ]; then
        echo "FAIL: gate missed -- ${seconds}s >= ${GATE_SECONDS}s"
        fail=1
    fi
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: one or more checks failed"
    exit 1
fi
echo "PASS"

#!/bin/sh
# run.sh -- headless Copperline on-target smoke test for AmiSnap
# (implementation-plan.md Phase 1 item 8).
#
# Boots a minimal (no-Workbench) A1200/68020 from ./boot (a host
# directory Copperline mounts live -- see machine.toml). The boot
# script (boot/S/Startup-Sequence) runs: C:stage (creates a small
# source tree with deliberately non-default metadata), AmiSnap
# SNAPSHOT/LIST/VERIFY/RESTORE (each via LOG=<path> to its own file on
# the Results: mount, not Shell redirection), then C:readback
# (Examine()s the restored tree, an independent verification channel
# from AmiSnap's own reporting). Every host-mounted directory is
# staged before launch and read back after -- implementation-plan.md's
# item 8 scope.
#
# Prereqs:
#   - copperline on PATH (brew install copperline)
#   - a Kickstart 3.1 A1200 ROM staged at nondistribution/roms/ (see
#     that directory's own README) -- KICK= overrides the default path.
#     Skips cleanly (exit 0, not a false pass) if absent, since CI has
#     no such asset.
#   - the cross-built AmiSnap binary and the stage/readback fixtures
#     (`make m68k copperline-fixtures`)
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

COPPERLINE=${COPPERLINE:-copperline}
KICK=${KICK:-$ROOT/nondistribution/roms/a1200-kick31-40.68.rom}
BENCH=${BENCH:-60}

AMISNAP_BIN="$ROOT/build/AmiSnap"
STAGE_BIN="$ROOT/build/copperline-fixtures/stage"
READBACK_BIN="$ROOT/build/copperline-fixtures/readback"

if [ ! -e "$KICK" ]; then
    echo "SKIP: no Kickstart ROM at $KICK (see nondistribution/README.md) -- not an asset CI has"
    exit 0
fi
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
[ -e "$AMISNAP_BIN" ] || { echo "FAIL: missing $AMISNAP_BIN (run: make m68k)" >&2; exit 2; }
[ -e "$STAGE_BIN" ] || { echo "FAIL: missing $STAGE_BIN (run: make copperline-fixtures)" >&2; exit 2; }
[ -e "$READBACK_BIN" ] || { echo "FAIL: missing $READBACK_BIN (run: make copperline-fixtures)" >&2; exit 2; }

echo "ROM: $KICK"

# --- reset every host-mounted directory to a known, empty state ------------
# (except boot/, which we're about to (re)populate) -- a previous local run
# must never leak into this one.
for d in source repo restored results; do
    rm -rf "$HERE/$d"
    mkdir -p "$HERE/$d"
done
mkdir -p "$HERE/boot/C" "$HERE/boot/S"
cp "$AMISNAP_BIN" "$HERE/boot/C/AmiSnap"
cp "$STAGE_BIN" "$HERE/boot/C/stage"
cp "$READBACK_BIN" "$HERE/boot/C/readback"

# --- boot windowless; --benchmark-until runs with no window until the
# given emulated time, then exits (amiauth/copperline-bridgeboard-plugin's
# own pattern -- no JSON-RPC control server needed since nothing here
# needs indefinite runtime or live interaction). cd so `path = "boot"`
# etc. in machine.toml resolve relative to this directory. --cpu 68020
# explicit even though machine.toml already sets it (AmiPilot's own
# documented lesson: don't rely on a single implicit source for this).
OUT=$(mktemp)
cleanup() { rm -f "$OUT"; }
trap cleanup EXIT INT TERM

set +e
( cd "$HERE" && "$COPPERLINE" --config machine.toml --cpu 68020 --noaudio \
    --benchmark-until "$BENCH" "$KICK" ) >"$OUT" 2>&1
CL_RC=$?
set -e

echo "----- copperline output -----"
cat "$OUT"
echo "------------------------------"
[ "$CL_RC" -eq 0 ] || { echo "FAIL: $COPPERLINE exited $CL_RC"; exit 3; }

# --- read results back off the host-mounted directories --------------------
fail=0
check_log() {
    name=$1; pattern=$2
    path="$HERE/results/$name"
    if [ ! -e "$path" ]; then
        echo "FAIL: missing $name (command never completed?)"
        fail=1
        return
    fi
    echo "--- $name ---"; cat "$path"
    if ! grep -q "$pattern" "$path"; then
        echo "FAIL: $name does not contain expected pattern: $pattern"
        fail=1
    fi
}

check_log stage.log "^stage: done$"
check_log snapshot.log "^Snapshot "
check_log list.log " entries"
check_log verify.log "^Verify .*0 missing, 0 corrupt$"
check_log restore.log "^Restored "
check_log readback.log "^readback: end$"

# --- content fidelity: the restored files must match what stage.c wrote ----
if [ -f "$HERE/restored/root.txt" ]; then
    if ! grep -q "^root file content$" "$HERE/restored/root.txt"; then
        echo "FAIL: restored/root.txt content mismatch"
        fail=1
    fi
else
    echo "FAIL: restored/root.txt does not exist"
    fail=1
fi
if [ -f "$HERE/restored/Sub/nested.txt" ]; then
    if ! grep -q "^nested content here$" "$HERE/restored/Sub/nested.txt"; then
        echo "FAIL: restored/Sub/nested.txt content mismatch"
        fail=1
    fi
else
    echo "FAIL: restored/Sub/nested.txt does not exist"
    fail=1
fi

# --- .uaem sidecar inspection (secondary, independent channel) -------------
# Format per Amiberry's own wiki (Host-Directory-Filesystem-Metadata),
# empirically confirmed for Copperline specifically right here, not
# assumed from a different emulator's docs alone -- see
# implementation-plan.md's item 8 scope for why this needed checking.
echo "--- .uaem sidecars found under restored/ ---"
find "$HERE/restored" -name '*.uaem' -exec sh -c 'echo "$1:"; cat "$1"' _ {} \;

if [ "$fail" -ne 0 ]; then
    echo "FAIL: one or more checks failed"
    exit 1
fi
echo "PASS"

#!/bin/sh
# tests/cross/run.sh -- Phase 2's CI cross-implementation check
# (implementation-plan.md / docs/format.md's own opening line: "the C
# implementation and the host-side reference reader both cite it, and
# CI asserts they agree").
#
# Builds a small, deterministic repository with the real portable C
# write path (build/gen_sample_repo, host-buildable -- see that file's
# own header), then drives tools/amisnap_reader.py (stdlib-only Python,
# completely independent of src/core/) against it: list, verify --full,
# and restore, asserting each against known-correct values. Finally
# corrupts one real object byte and confirms the Python reader's own
# --full verify independently detects it -- proving the reader's
# BLAKE2s-256 check is real, not a rubber stamp.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

GEN="$ROOT/build/gen_sample_repo"
READER="$ROOT/tools/amisnap_reader.py"
REPO="$ROOT/build/cross-check-repo"
DEST="$ROOT/build/cross-check-restored"

[ -e "$GEN" ] || { echo "FAIL: missing $GEN (run: make cross-check)" >&2; exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }

rm -rf "$REPO" "$DEST"
SNAPID=$("$GEN" "$REPO")
echo "generated snapshot: $SNAPID"

fail=0

echo "--- list ---"
python3 "$READER" list "$REPO"
if ! python3 "$READER" list "$REPO" | grep -q "^$SNAPID  5 entries\$"; then
    echo "FAIL: list output mismatch (want '$SNAPID  5 entries')"
    fail=1
fi

echo "--- verify --full ---"
VERIFY_OUT=$(python3 "$READER" verify "$REPO" --full)
echo "$VERIFY_OUT"
if ! echo "$VERIFY_OUT" | grep -q "^Verify $SNAPID (FULL): 2 objects checked, 0 missing, 0 corrupt\$"; then
    echo "FAIL: verify output mismatch"
    fail=1
fi

echo "--- restore ---"
python3 "$READER" restore "$REPO" "$DEST"

if [ ! -f "$DEST/readme.txt" ] || ! grep -q "^Hello from AmiSnap\$" "$DEST/readme.txt"; then
    echo "FAIL: readme.txt content mismatch"
    fail=1
fi
if [ ! -f "$DEST/Docs/notes.txt" ] || ! grep -q "^notes\$" "$DEST/Docs/notes.txt"; then
    echo "FAIL: Docs/notes.txt content mismatch"
    fail=1
fi
if [ ! -f "$DEST/empty.dat" ] || [ -s "$DEST/empty.dat" ]; then
    echo "FAIL: empty.dat missing or non-empty"
    fail=1
fi

echo "--- corrupt an object, confirm --full independently catches it ---"
OBJ=$(find "$REPO/objects" -type f | head -1)
echo "corrupting $OBJ"
printf 'X' >> "$OBJ"
set +e
CORRUPT_OUT=$(python3 "$READER" verify "$REPO" --full 2>&1)
CORRUPT_RC=$?
set -e
echo "$CORRUPT_OUT"
if [ "$CORRUPT_RC" -eq 0 ]; then
    echo "FAIL: verify --full should have failed on a corrupted object"
    fail=1
fi
if ! echo "$CORRUPT_OUT" | grep -q "CORRUPT"; then
    echo "FAIL: expected a CORRUPT report"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: cross-implementation check failed"
    exit 1
fi
echo "PASS"

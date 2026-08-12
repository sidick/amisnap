#!/bin/sh
# run-bigfile.sh -- proves the fixed-size chunking feature end to end on
# real AmigaOS: a file well over AMISNAP_DEFAULT_CHUNK_SIZE (repo.h)
# backs up, verifies, and restores without ever needing to hold the
# whole file in memory at once, on either side.
#
# This exists because chunking's own memory-bounding purpose was
# initially only half-delivered: amisnap_repo_writer_file_chunked()
# (repo.c) made SNAPSHOT's write path bounded, but restore.c's
# restore_file() still accumulated the whole reconstructed file into
# one buffer before writing it out, so RESTORE failed with
# AMISNAP_ERR_NOMEM on exactly the large files chunking exists for --
# confirmed live, on this same fixture, before restore.c was changed to
# stream each chunk straight to the destination via backend.h's new
# put_begin/put_append/put_finish. This script is the regression that
# keeps that fixed.
#
# bigfile.c (fixture/) writes a file just over the chunk-size threshold
# with deterministic, non-repeating content (a byte value that
# increments once per 64KB block), so a corrupted/misordered chunk on
# restore is detectable by content, not just by size.
#
# Deliberately run at a constrained fast_ram (2M, matching run.sh's own
# default) -- a large chunk-buffer or whole-file accumulation that
# regresses back to needing the full file's worth of RAM will fail here
# exactly as it did during development, not just in principle.
#
# Prereqs: same as run.sh (copperline, a staged Kickstart ROM, the
# cross-built AmiSnap binary and copperline-fixtures):
# `make m68k copperline-fixtures`.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

COPPERLINE=${COPPERLINE:-copperline}
KICK=${KICK:-$ROOT/nondistribution/roms/a1200-kick31-40.68.rom}
BENCH=${BENCH:-600}

AMISNAP_BIN="$ROOT/build/AmiSnap"
BIGFILE_BIN="$ROOT/build/copperline-fixtures/bigfile"

if [ ! -e "$KICK" ]; then
    echo "SKIP: no Kickstart ROM at $KICK (see nondistribution/README.md) -- not an asset CI has"
    exit 0
fi
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }
[ -e "$AMISNAP_BIN" ] || { echo "FAIL: missing $AMISNAP_BIN (run: make m68k)" >&2; exit 2; }
[ -e "$BIGFILE_BIN" ] || { echo "FAIL: missing $BIGFILE_BIN (run: make copperline-fixtures)" >&2; exit 2; }

echo "ROM: $KICK"

WORK="$HERE/bigfile-work"
rm -rf "$WORK"
mkdir -p "$WORK/boot/C" "$WORK/boot/S" "$WORK/source" "$WORK/repo" "$WORK/restored" "$WORK/results"

cp "$AMISNAP_BIN" "$WORK/boot/C/AmiSnap"
cp "$BIGFILE_BIN" "$WORK/boot/C/bigfile"
cat > "$WORK/boot/S/Startup-Sequence" <<'EOF'
FailAt 21
bigfile
AmiSnap ACTION=SNAPSHOT SOURCE=Source: REPO=Repo: LOG=Results:snapshot.log
AmiSnap ACTION=LIST REPO=Repo: LOG=Results:list.log
AmiSnap ACTION=VERIFY REPO=Repo: FULL LOG=Results:verify.log
AmiSnap ACTION=RESTORE REPO=Repo: DEST=Restored: LOG=Results:restore.log
EOF

cat > "$WORK/machine.toml" <<EOF
[cpu]
model = "68020"

[memory]
chip = "1M"
fast = "2M"

[[filesys]]
path = "$WORK/boot"
volume = "AmiSnapBoot"
bootpri = 10

[[filesys]]
path = "$WORK/source"
volume = "Source"
bootpri = -128

[[filesys]]
path = "$WORK/repo"
volume = "Repo"
bootpri = -128

[[filesys]]
path = "$WORK/restored"
volume = "Restored"
bootpri = -128

[[filesys]]
path = "$WORK/results"
volume = "Results"
bootpri = -128

[emulation]
power_on = true
warp_speed = "max"
EOF

OUT=$(mktemp)
cleanup() { rm -f "$OUT"; }
trap cleanup EXIT INT TERM

set +e
"$COPPERLINE" --config "$WORK/machine.toml" --cpu 68020 --noaudio \
    --benchmark-until "$BENCH" "$KICK" >"$OUT" 2>&1
CL_RC=$?
set -e

echo "----- copperline output -----"
tail -20 "$OUT"
echo "------------------------------"
[ "$CL_RC" -eq 0 ] || { echo "FAIL: $COPPERLINE exited $CL_RC"; cat "$OUT"; exit 3; }

fail=0
check_log() {
    name=$1; pattern=$2
    path="$WORK/results/$name"
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

check_log snapshot.log "^Snapshot .*1 files (0 unchanged, 0 failed)"
check_log list.log " entries"
# 8*1024*1024 + 300*1024 bytes at the 256 KiB default chunk size -> 34 chunks.
check_log verify.log "^Verify .*34 objects checked, 0 missing, 0 corrupt$"
check_log restore.log "^Restored .*(8695808 bytes)"

set +e
python3 - "$WORK/restored/bigfile.dat" <<'PYEOF'
import sys

BLOCK_SIZE = 64 * 1024
TOTAL_SIZE = 8 * 1024 * 1024 + 300 * 1024

path = sys.argv[1]
try:
    with open(path, "rb") as f:
        data = f.read()
except FileNotFoundError:
    print("FAIL: restored/bigfile.dat does not exist")
    sys.exit(1)

if len(data) != TOTAL_SIZE:
    print("FAIL: restored/bigfile.dat size %d != expected %d" % (len(data), TOTAL_SIZE))
    sys.exit(1)

for i in range(0, len(data), BLOCK_SIZE):
    blocknum = i // BLOCK_SIZE
    expected = blocknum & 0xFF
    block = data[i:i + BLOCK_SIZE]
    if any(b != expected for b in block):
        print("FAIL: restored/bigfile.dat content mismatch in block %d" % blocknum)
        sys.exit(1)

print("bigfile content verified byte-for-byte (%d bytes, %d blocks)" % (len(data), (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE))
PYEOF
[ $? -eq 0 ] || fail=1
set -e

if [ "$fail" -ne 0 ]; then
    echo "FAIL: one or more checks failed"
    exit 1
fi
echo "PASS"

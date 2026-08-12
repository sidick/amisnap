#!/bin/sh
# run-uaem.sh -- proves the .uaem round trip end to end, across all
# three pieces built for it: the C repository writer, the Python
# reference reader's `restore --uaem`, and AmiSnap's own ACTION=
# APPLYUAEM (src/amiga/applyuaem.c). Real disaster-recovery scenario
# this exists for: a repository restored on a bare PC (no Amiga, no
# AmiSnap binary -- tools/amisnap_reader.py alone) can't apply AmigaDOS
# metadata itself, so it writes .uaem sidecars instead; this is what
# turns those sidecars into a real, bit-perfect restore once the tree
# reaches a real Amiga (or copies onto real AmigaDOS media).
#
# Deliberately run against a REAL FFS floppy (xdftool, same mechanism
# as run-ffs.sh), not Copperline's own HOSTFS pass-through: HOSTFS
# already interprets .uaem sidecars natively (the whole reason run.sh's
# own harness can inspect them at all), which would make ApplyUAEM's
# own effect unobservable -- confirmed the hard way while building
# this script: an identical HOSTFS-mounted run reported "0 applied" yet
# still showed correct metadata, because Copperline's own HOSTFS driver
# had already synthesized it from the sidecars before ApplyUAEM ever
# got a chance to run. A real FFS floppy has no such native awareness,
# so metadata only ends up correct if AmiSnap's own SetProtection/
# SetComment/SetFileDate calls actually did it.
#
# Prereqs: same as run-ffs.sh (copperline, a staged Kickstart ROM,
# amitools' xdftool), plus `make cross-check` having produced
# build/gen_sample_repo and tools/amisnap_reader.py's own restore
# path (stdlib Python, no extra install).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

COPPERLINE=${COPPERLINE:-copperline}
XDFTOOL=${XDFTOOL:-xdftool}
KICK=${KICK:-$ROOT/nondistribution/roms/a1200-kick31-40.68.rom}
BENCH=${BENCH:-60}

AMISNAP_BIN="$ROOT/build/AmiSnap"
CHECKUAEM_BIN="$ROOT/build/copperline-fixtures/checkuaem"
GEN_BIN="$ROOT/build/gen_sample_repo"
READER="$ROOT/tools/amisnap_reader.py"

if [ ! -e "$KICK" ]; then
    echo "SKIP: no Kickstart ROM at $KICK (see nondistribution/README.md) -- not an asset CI has"
    exit 0
fi
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
if ! command -v "$XDFTOOL" >/dev/null; then
    echo "SKIP: $XDFTOOL not found (pip3/pipx install amitools) -- .uaem round trip needs it"
    exit 0
fi
command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }
[ -e "$AMISNAP_BIN" ] || { echo "FAIL: missing $AMISNAP_BIN (run: make m68k)" >&2; exit 2; }
[ -e "$CHECKUAEM_BIN" ] || { echo "FAIL: missing $CHECKUAEM_BIN (run: make copperline-fixtures)" >&2; exit 2; }
[ -e "$GEN_BIN" ] || { echo "FAIL: missing $GEN_BIN (run: make cross-check)" >&2; exit 2; }

echo "ROM: $KICK"

WORK="$HERE/uaem-work"
rm -rf "$WORK"
mkdir -p "$WORK/boot/C" "$WORK/boot/S" "$WORK/results"

cp "$AMISNAP_BIN" "$WORK/boot/C/AmiSnap"
cp "$CHECKUAEM_BIN" "$WORK/boot/C/checkuaem"
cat > "$WORK/boot/S/Startup-Sequence" <<'EOF'
FailAt 21
AmiSnap ACTION=APPLYUAEM SOURCE=Source: LOG=Results:applyuaem.log
checkuaem
EOF

# --- generate the known-content sample repo (same one make cross-check
# uses) and restore it with --uaem to a host staging directory. -------
SAMPLE_REPO="$WORK/sample-repo"
STAGE_DIR="$WORK/staged"
rm -rf "$SAMPLE_REPO" "$STAGE_DIR"
"$GEN_BIN" "$SAMPLE_REPO" >/dev/null
python3 "$READER" restore "$SAMPLE_REPO" "$STAGE_DIR" --uaem >/dev/null

# --- format a real 880K FFS floppy and write the staged tree (content
# + .uaem sidecars) onto it via xdftool, matching run-ffs.sh's own
# create-then-format-as-two-calls convention (chaining them in one
# xdftool invocation was confirmed there to leave the boot block
# unwritten). Files land at default (unset) protection/date/comment --
# ApplyUAEM is what's expected to fix that, not xdftool's own write. --
SOURCE_ADF="$WORK/Source.adf"
rm -f "$SOURCE_ADF"
"$XDFTOOL" "$SOURCE_ADF" create >/dev/null
"$XDFTOOL" "$SOURCE_ADF" format Source ffs >/dev/null
"$XDFTOOL" "$SOURCE_ADF" write "$STAGE_DIR/readme.txt" readme.txt >/dev/null
"$XDFTOOL" "$SOURCE_ADF" write "$STAGE_DIR/readme.txt.uaem" readme.txt.uaem >/dev/null
"$XDFTOOL" "$SOURCE_ADF" makedir Docs >/dev/null
"$XDFTOOL" "$SOURCE_ADF" write "$STAGE_DIR/Docs.uaem" Docs.uaem >/dev/null
"$XDFTOOL" "$SOURCE_ADF" write "$STAGE_DIR/Docs/notes.txt" Docs/notes.txt >/dev/null
"$XDFTOOL" "$SOURCE_ADF" write "$STAGE_DIR/Docs/notes.txt.uaem" Docs/notes.txt.uaem >/dev/null
"$XDFTOOL" "$SOURCE_ADF" write "$STAGE_DIR/empty.dat" empty.dat >/dev/null
"$XDFTOOL" "$SOURCE_ADF" write "$STAGE_DIR/empty.dat.uaem" empty.dat.uaem >/dev/null

cat > "$WORK/machine.toml" <<EOF
[cpu]
model = "68020"

[memory]
chip = "1M"
fast = "2M"

[floppy]
drives = 1
speed = 800

[floppy.df0]
path = "$SOURCE_ADF"
write_protected = false

[[filesys]]
path = "$WORK/boot"
volume = "AmiSnapBoot"
bootpri = 10

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

check_log applyuaem.log "^ApplyUAEM Source:: 4 applied, 0 failed\$"
check_log checkuaem.log "^Source:readme.txt: prot=00000010 comment=\"a readme\" date=17000.10.20\$"
check_log checkuaem.log "^Source:Docs: prot=00000000 comment=\"\" date=17000.0.0\$"
check_log checkuaem.log "^Source:Docs/notes.txt: prot=00000000 comment=\"\" date=17000.5.5\$"
check_log checkuaem.log "^Source:empty.dat: prot=00000010 comment=\"\" date=17000.0.0\$"

if [ "$fail" -ne 0 ]; then
    echo "FAIL: one or more checks failed"
    exit 1
fi
echo "PASS"

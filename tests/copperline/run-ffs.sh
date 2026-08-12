#!/bin/sh
# run-ffs.sh -- real-FFS-floppy variant of run.sh (implementation-plan.md
# Phase 1 item 8's "noted for later" follow-up).
#
# run.sh exercises Copperline's own custom HOSTFS handler (host directories
# passed through, not a real Amiga filesystem). This script instead formats
# genuine AmigaDOS floppy images (via amitools' xdftool) with each real
# on-disk filesystem AmigaOS 3.1 actually ships -- OFS (DOS0), FFS (DOS1),
# FFS+International (DOS3), FFS+International+DirCache (DOS5) -- and mounts
# them as DF0/DF1/DF2 for Source:/Repo:/Restored:, to catch any semantic gap
# between HOSTFS and real AmigaDOS filesystem behaviour that run.sh alone
# can't see. Boot (AmiSnap/stage/readback binaries) and Results: (LOG=
# output) stay on the same HOSTFS mounts run.sh uses -- only the volumes
# under test move to real floppies. stage.c/readback.c/AmiSnap are reused
# completely unmodified: SOURCE=/REPO=/DEST= already just name volumes.
#
# Prereqs (same as run.sh, plus):
#   - xdftool on PATH (amitools -- already pinned in ghcr.io/sidick/
#     amiga-dev's Dockerfile, `pip3 install amitools[vamos]`; `pipx install
#     amitools` locally). Skips cleanly (exit 0) if absent.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

COPPERLINE=${COPPERLINE:-copperline}
XDFTOOL=${XDFTOOL:-xdftool}
KICK=${KICK:-$ROOT/nondistribution/roms/a1200-kick31-40.68.rom}
BENCH=${BENCH:-60}

AMISNAP_BIN="$ROOT/build/AmiSnap"
STAGE_BIN="$ROOT/build/copperline-fixtures/stage"
READBACK_BIN="$ROOT/build/copperline-fixtures/readback"

# xdftool's own `format` command needs a separate invocation from `create`
# -- chaining them in one `xdftool img.adf create format ...` call left the
# boot block's dos_type/checksum unwritten in the tested amitools release
# (0.8.1), a real cross-command-flush quirk, not a usage mistake; confirmed
# empirically here rather than assumed. Two calls per image sidesteps it.
#
# DOS5 (ffs+intl+dc, FFS+International+DirCache) deliberately excluded --
# tried it empirically first (house rule 6), confirmed real and not a
# harness bug: the boot hangs before Copperline's own HOSTFS handlers even
# start (no "HOSTFS0: handler started" log line, blank screen the whole
# run), consistent with Kickstart 3.1's ROM-resident FastFileSystem having
# no DirCache support -- real hardware shows the same "clicking drive" boot
# hang for an unrecognized dostype with no L:FastFileSystem present to load
# it from. A minimal (no-Workbench, no L:) boot has nowhere to load a
# DirCache-capable FFS module from. Revisit only if a future phase adds a
# Workbench/L: asset to the boot volume.
DOSTYPES="ofs ffs ffs+intl"

if [ ! -e "$KICK" ]; then
    echo "SKIP: no Kickstart ROM at $KICK (see nondistribution/README.md) -- not an asset CI has"
    exit 0
fi
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
if ! command -v "$XDFTOOL" >/dev/null; then
    echo "SKIP: $XDFTOOL not found (pip3/pipx install amitools) -- real-FFS variant needs it"
    exit 0
fi
[ -e "$AMISNAP_BIN" ] || { echo "FAIL: missing $AMISNAP_BIN (run: make m68k)" >&2; exit 2; }
[ -e "$STAGE_BIN" ] || { echo "FAIL: missing $STAGE_BIN (run: make copperline-fixtures)" >&2; exit 2; }
[ -e "$READBACK_BIN" ] || { echo "FAIL: missing $READBACK_BIN (run: make copperline-fixtures)" >&2; exit 2; }

echo "ROM: $KICK"

mkdir -p "$HERE/boot/C" "$HERE/boot/S"
cp "$AMISNAP_BIN" "$HERE/boot/C/AmiSnap"
cp "$STAGE_BIN" "$HERE/boot/C/stage"
cp "$READBACK_BIN" "$HERE/boot/C/readback"

FFS_WORK="$HERE/ffs"
rm -rf "$FFS_WORK"
mkdir -p "$FFS_WORK"

overall_fail=0
summary=""

for DOSTYPE in $DOSTYPES; do
    label=$(echo "$DOSTYPE" | tr '+' '_')
    work="$FFS_WORK/$label"
    mkdir -p "$work"

    rm -rf "$HERE/results"
    mkdir -p "$HERE/results"

    # --- format one 880K DD floppy per volume, real AmigaDOS filesystem
    # structures (boot block, root block, bitmap) via xdftool -- create then
    # format as two separate invocations (see the header comment above).
    for vol in Source Repo Restored; do
        adf="$work/$vol.adf"
        rm -f "$adf"
        "$XDFTOOL" "$adf" create >/dev/null
        "$XDFTOOL" "$adf" format "$vol" "$DOSTYPE" >/dev/null
    done

    cat > "$work/machine.toml" <<EOF
[cpu]
model = "68020"

[memory]
chip = "1M"
fast = "2M"

[floppy]
drives = 3
speed = 800   # bit-identical faster-than-real DMA, not 0/turbo (0 skips
              # real disk-transfer timing, per Copperline's own docs a
              # "compatibility trade-off" some software depends on --
              # not a valid test of real filesystem behavior)

[floppy.df0]
path = "$work/Source.adf"
write_protected = false

[floppy.df1]
path = "$work/Repo.adf"
write_protected = false

[floppy.df2]
path = "$work/Restored.adf"
write_protected = false

[[filesys]]
path = "boot"
volume = "AmiSnapBoot"
bootpri = 10

[[filesys]]
path = "results"
volume = "Results"
bootpri = -128

[emulation]
power_on = true
warp_speed = "max"
EOF

    echo "=== dostype: $DOSTYPE ==="

    OUT=$(mktemp)
    set +e
    ( cd "$HERE" && "$COPPERLINE" --config "$work/machine.toml" --cpu 68020 --noaudio \
        --benchmark-until "$BENCH" "$KICK" ) >"$OUT" 2>&1
    CL_RC=$?
    set -e

    if [ "$CL_RC" -ne 0 ]; then
        echo "----- copperline output -----"; cat "$OUT"; echo "------------------------------"
        echo "FAIL ($DOSTYPE): $COPPERLINE exited $CL_RC"
        summary="$summary\n$DOSTYPE: FAIL (copperline exit $CL_RC)"
        overall_fail=1
        rm -f "$OUT"
        continue
    fi
    rm -f "$OUT"

    fail=0
    check_log() {
        name=$1; pattern=$2
        path="$HERE/results/$name"
        if [ ! -e "$path" ]; then
            echo "FAIL ($DOSTYPE): missing $name (command never completed?)"
            fail=1
            return
        fi
        echo "--- $name ---"; cat "$path"
        if ! grep -q "$pattern" "$path"; then
            echo "FAIL ($DOSTYPE): $name does not contain expected pattern: $pattern"
            fail=1
        fi
    }

    check_log stage.log "^stage: done$"
    check_log snapshot.log "^Snapshot "
    check_log list.log " entries"
    check_log verify.log "^Verify .*0 missing, 0 corrupt$"
    check_log restore.log "^Restored "
    check_log readback.log "^readback: end$"

    # --- content fidelity: extract the restored floppy back to the host via
    # xdftool unpack (there's no HOSTFS-style live host directory for a real
    # floppy image) and check restored bytes match what stage.c wrote.
    extract="$work/extracted"
    rm -rf "$extract"; mkdir -p "$extract"
    "$XDFTOOL" "$work/Restored.adf" unpack "$extract" >/dev/null

    if [ -f "$extract/Restored/root.txt" ]; then
        if ! grep -q "^root file content$" "$extract/Restored/root.txt"; then
            echo "FAIL ($DOSTYPE): restored root.txt content mismatch"
            fail=1
        fi
    else
        echo "FAIL ($DOSTYPE): restored root.txt does not exist"
        fail=1
    fi
    if [ -f "$extract/Restored/Sub/nested.txt" ]; then
        if ! grep -q "^nested content here$" "$extract/Restored/Sub/nested.txt"; then
            echo "FAIL ($DOSTYPE): restored Sub/nested.txt content mismatch"
            fail=1
        fi
    else
        echo "FAIL ($DOSTYPE): restored Sub/nested.txt does not exist"
        fail=1
    fi

    if [ "$fail" -ne 0 ]; then
        summary="$summary\n$DOSTYPE: FAIL"
        overall_fail=1
    else
        summary="$summary\n$DOSTYPE: PASS"
    fi
done

echo "=== summary ==="
printf '%b\n' "$summary"

if [ "$overall_fail" -ne 0 ]; then
    echo "FAIL: one or more dostypes failed"
    exit 1
fi
echo "PASS"

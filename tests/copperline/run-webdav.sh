#!/bin/sh
# run-webdav.sh -- real on-target exercise of the WebDAV backend
# (implementation-plan.md Phase 3 item 3's own remaining gap): boots a
# real AmigaOS guest under Copperline with --hostsocket-net host (a
# Zorro board that installs bsdsocket.library into the guest with ZERO
# guest-side setup -- no TCP/IP stack to boot, confirmed against
# Copperline's own source and sibling amipilot's tests/copperline/
# tcp-host-test.py, which validated this exact mechanism first), then
# runs a real SNAPSHOT/LIST/VERIFY/RESTORE cycle with REPO= pointing at
# a real WebDAV server (tests/webdav/mini_webdav_server.py -- the same
# independent, non-mock server Phase 3 item 5's host-CI check already
# uses) reachable over a real TCP connection out of the guest, back to
# the host's own loopback address.
#
# This is the genuine end-to-end proof host-CI (item 5, a host binary
# built with cc against a POSIX transport) and the m68k cross-build
# (item 3's own host-tested-only-so-far webdav.c) couldn't give on
# their own: real bsdsocket.library LVO calls, real bsdsocket.library
# HostSocket-board plumbing, real bidirectional guest<->host loopback
# traffic, all under real 68020 execution.
#
# Prereqs: same as run.sh (copperline, a staged Kickstart ROM, the
# cross-built AmiSnap binary, copperline-fixtures for stage/readback),
# plus python3 (tests/webdav/mini_webdav_server.py, stdlib-only).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

COPPERLINE=${COPPERLINE:-copperline}
KICK=${KICK:-$ROOT/nondistribution/roms/a1200-kick31-40.68.rom}
BENCH=${BENCH:-120}
# Fixed, not auto-selected: the port has to be known before Copperline
# boots, since it's baked into the guest's own Startup-Sequence (a
# static text file staged before launch, unlike host-CI's own
# run-after-the-fact port discovery in tests/webdav/run.sh).
PORT=${PORT:-18790}

AMISNAP_BIN="$ROOT/build/AmiSnap"
STAGE_BIN="$ROOT/build/copperline-fixtures/stage"
READBACK_BIN="$ROOT/build/copperline-fixtures/readback"

if [ ! -e "$KICK" ]; then
    echo "SKIP: no Kickstart ROM at $KICK (see nondistribution/README.md) -- not an asset CI has"
    exit 0
fi
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }
[ -e "$AMISNAP_BIN" ] || { echo "FAIL: missing $AMISNAP_BIN (run: make m68k)" >&2; exit 2; }
[ -e "$STAGE_BIN" ] || { echo "FAIL: missing $STAGE_BIN (run: make copperline-fixtures)" >&2; exit 2; }
[ -e "$READBACK_BIN" ] || { echo "FAIL: missing $READBACK_BIN (run: make copperline-fixtures)" >&2; exit 2; }

echo "ROM: $KICK"

WORK="$HERE/webdav-work"
rm -rf "$WORK"
mkdir -p "$WORK/boot/C" "$WORK/boot/S" "$WORK/source" "$WORK/restored" "$WORK/results" "$WORK/server-root"

cp "$AMISNAP_BIN" "$WORK/boot/C/AmiSnap"
cp "$STAGE_BIN" "$WORK/boot/C/stage"
cp "$READBACK_BIN" "$WORK/boot/C/readback"

REPO_URL="http://127.0.0.1:$PORT/repo"
cat > "$WORK/boot/S/Startup-Sequence" <<EOF
FailAt 21
stage
AmiSnap ACTION=SNAPSHOT SOURCE=Source: REPO=$REPO_URL LOG=Results:snapshot.log
AmiSnap ACTION=LIST REPO=$REPO_URL LOG=Results:list.log
AmiSnap ACTION=VERIFY REPO=$REPO_URL FULL LOG=Results:verify.log
AmiSnap ACTION=RESTORE REPO=$REPO_URL DEST=Restored: LOG=Results:restore.log
readback
EOF

cat > "$WORK/machine.toml" <<EOF
[cpu]
model = "68020"

[memory]
chip = "1M"
fast = "2M"

[floppy]
drives = 1

[[filesys]]
path = "$WORK/boot"
volume = "AmiSnapBoot"
bootpri = 10

[[filesys]]
path = "$WORK/source"
volume = "Source"
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

# --- start the real (non-mock) WebDAV server the guest will connect out
# to over --hostsocket-net host's loopback passthrough -- same server
# Phase 3 item 5's host-CI check (tests/webdav/run.sh) uses. -----------
SERVER_LOG="$WORK/server.log"
python3 "$ROOT/tests/webdav/mini_webdav_server.py" "$WORK/server-root" "$PORT" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

OUT=$(mktemp)
cleanup() {
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    rm -f "$OUT"
}
trap cleanup EXIT INT TERM

i=0
READY=0
while [ $i -lt 50 ]; do
    if grep -q "^READY" "$SERVER_LOG" 2>/dev/null; then READY=1; break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: mini_webdav_server.py exited early:" >&2
        cat "$SERVER_LOG" >&2
        exit 3
    fi
    i=$((i + 1))
    sleep 0.1
done
[ "$READY" -eq 1 ] || { echo "FAIL: server never became ready" >&2; cat "$SERVER_LOG" >&2; exit 3; }

set +e
"$COPPERLINE" --config "$WORK/machine.toml" --cpu 68020 --noaudio --hostsocket-net host \
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

check_log stage.log "^stage: done$"
check_log snapshot.log "^Snapshot .*(0 unchanged, 0 failed)"
check_log list.log " entries"
check_log verify.log "^Verify .*0 missing, 0 corrupt$"
check_log restore.log "^Restored "
check_log readback.log "^readback: end$"

# --- content fidelity: same host-side check run.sh already does, just
# against a WebDAV-backed repository instead of a mounted-volume one. --
if [ -f "$WORK/restored/root.txt" ]; then
    if ! grep -q "^root file content$" "$WORK/restored/root.txt"; then
        echo "FAIL: restored/root.txt content mismatch"
        fail=1
    fi
else
    echo "FAIL: restored/root.txt does not exist"
    fail=1
fi
if [ -f "$WORK/restored/Sub/nested.txt" ]; then
    if ! grep -q "^nested content here$" "$WORK/restored/Sub/nested.txt"; then
        echo "FAIL: restored/Sub/nested.txt content mismatch"
        fail=1
    fi
else
    echo "FAIL: restored/Sub/nested.txt does not exist"
    fail=1
fi

# --- independent confirmation: the objects really did land on the
# server's own backing directory via real HTTP PUT/MKCOL requests from
# the guest, not just that AmiSnap's own log claims success. -----------
OBJECT_COUNT=$(find "$WORK/server-root/repo/objects" -type f 2>/dev/null | wc -l | tr -d ' ')
echo "--- WebDAV server backing store: $OBJECT_COUNT object(s) under repo/objects ---"
if [ "$OBJECT_COUNT" -lt 1 ]; then
    echo "FAIL: no objects found on the WebDAV server's own backing store"
    fail=1
fi
if [ ! -e "$WORK/server-root/repo/snapshots" ]; then
    echo "FAIL: no snapshots/ collection found on the WebDAV server's own backing store"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: one or more checks failed"
    exit 1
fi
echo "PASS"

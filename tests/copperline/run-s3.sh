#!/bin/sh
# run-s3.sh -- real on-target exercise of the S3 backend
# (implementation-plan.md Phase 5 item 6): boots a real AmigaOS guest
# under Copperline with --hostsocket-net host (same HostSocket
# bsdsocket.library board run-webdav.sh already uses -- zero guest-side
# TCP/IP stack setup), then runs a real SNAPSHOT/LIST/VERIFY/RESTORE
# cycle with REPO= pointing at a real S3-compatible server
# (tests/s3/mini_s3_server.py -- the same independent, from-scratch,
# signature-verifying server Phase 5 item 5's host-CI check already
# uses) reachable over a real TCP connection out of the guest, back to
# the host's own loopback address.
#
# This is the genuine end-to-end proof host-CI (item 5, a host binary
# built with cc against a POSIX transport) and the m68k cross-build
# (item 3's own host-tested-only-so-far s3.c) couldn't give on their
# own: real bsdsocket.library LVO calls, real SigV4 signing against a
# real wall-clock timestamp on real m68k hardware timing, real
# HostSocket-board plumbing, and (unlike WebDAV) a server that actually
# verifies the Authorization header's signature from scratch -- so a
# PASS here proves the on-target signer, not just the host-built one,
# produces signatures an independent implementation accepts.
#
# Prereqs: same as run-webdav.sh, plus python3 (tests/s3/
# mini_s3_server.py, stdlib-only).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

COPPERLINE=${COPPERLINE:-copperline}
KICK=${KICK:-$ROOT/nondistribution/roms/a1200-kick31-40.68.rom}
BENCH=${BENCH:-120}
# Fixed, not auto-selected: the port has to be known before Copperline
# boots, since it's baked into the guest's own Startup-Sequence (a
# static text file staged before launch) -- same reasoning
# run-webdav.sh's own PORT gives.
PORT=${PORT:-18791}

BUCKET="amisnap-test-bucket"
ACCESS_KEY="AKIDEXAMPLE"
SECRET_KEY="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
REGION="us-east-1"

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

WORK="$HERE/s3-work"
rm -rf "$WORK"
mkdir -p "$WORK/boot/C" "$WORK/boot/S" "$WORK/source" "$WORK/restored" "$WORK/results" "$WORK/server-root"

cp "$AMISNAP_BIN" "$WORK/boot/C/AmiSnap"
cp "$STAGE_BIN" "$WORK/boot/C/stage"
cp "$READBACK_BIN" "$WORK/boot/C/readback"

# No "?region=" query: deliberately omitted, not just to keep the line
# short. AmigaDOS ReadItem()'s own documented rule (amigados-rkrm's
# "Shell" chapter) is that an UNQUOTED argument is delimited by the
# first space, tab, semicolon, OR EQUALS SIGN it meets, full stop -- not
# just the "KEY=" one ReadArgs itself consumes. A REPO value containing
# a second, embedded '=' (from "?region=us-east-1") confirmed live on
# Copperline: ReadArgs split the argument there and rejected the whole
# line as "bad arguments" on every single AmiSnap invocation. Quoting
# the value (REPO="...") does not fix this either -- also confirmed
# live: a quote immediately following the '=' that ReadArgs already
# consumed for the REPO keyword is not "at the start of the line or
# preceded by a blank/tab" (the RKRM's own precise quote-recognition
# rule), so it is not treated as opening a quoted string; the literal
# quote character then breaks s3.c's own "s3://" prefix check in
# open_backend(), falling through to the mounted-volume backend, which
# tried to Lock() the raw string and produced a real "Please insert
# volume s3 in any drive" requester. us-east-1 is already
# amisnap_s3_parse_url()'s own built-in default region (s3.c), so
# simply never appending the query avoids the whole class of problem
# rather than fighting AmigaDOS quoting edge cases for it.
REPO_URL="s3://$ACCESS_KEY:$SECRET_KEY@127.0.0.1:$PORT/$BUCKET/repo"
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

# --- start the real (non-mock, signature-verifying) S3 server the
# guest will connect out to over --hostsocket-net host's loopback
# passthrough -- same server Phase 5 item 5's host-CI check
# (tests/s3/run.sh) uses. Port 0 = auto-select there; here it's fixed
# up front for the same reason PORT above is fixed. ---------------
SERVER_LOG="$WORK/server.log"
python3 "$ROOT/tests/s3/mini_s3_server.py" "$WORK/server-root" "$BUCKET" \
    "$ACCESS_KEY" "$SECRET_KEY" "$REGION" "$PORT" >"$SERVER_LOG" 2>&1 &
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
        echo "FAIL: mini_s3_server.py exited early:" >&2
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

echo "--- S3 server log ---"
cat "$SERVER_LOG"

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

# --- content fidelity: same host-side check run-webdav.sh already
# does, just against an S3-backed repository instead of WebDAV. -------
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

# --- independent confirmation: the objects really did land on the S3
# server's own backing directory via real, signature-verified PUT
# requests from the guest, not just that AmiSnap's own log claims
# success (mini_s3_server.py would have 403'd a bad signature). -------
OBJECT_COUNT=$(find "$WORK/server-root" -type f 2>/dev/null | wc -l | tr -d ' ')
echo "--- S3 server backing store: $OBJECT_COUNT object(s) ---"
if [ "$OBJECT_COUNT" -lt 1 ]; then
    echo "FAIL: no objects found on the S3 server's own backing store"
    fail=1
fi

kill "$SERVER_PID" >/dev/null 2>&1 || true

# --- second pass: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_REGION
# env-var credential fallback, no credentials in REPO= at all -- same
# standard names/precedence the AWS CLI and SDKs use everywhere else,
# so this REPO= URL never has to carry secrets in plaintext in a
# Startup-Sequence script, shell history, or `ps` output
# (amisnap_s3_parse_url()'s own has_credentials/has_region fields,
# src/cli/main.c's open_backend()). `Set` (a Shell-resident built-in
# needing no C: binary and no ENV: assign) rather than `SetEnv`: this
# minimal boot's C: has only the 4 binaries run.sh itself stages, so
# MakeDir/Assign/List (needed to set up ENV: for a true global/
# SetEnv-style variable) are "Unknown command" here -- confirmed live.
# `Set` defines a *local* shell variable instead, which GetVar()'s own
# documented local-before-global lookup order finds through exactly
# the same code path, without needing ENV: to exist. ---------------
PORT2=$((PORT + 1))
WORK2="$HERE/s3-work-envcreds"
rm -rf "$WORK2"
mkdir -p "$WORK2/boot/C" "$WORK2/boot/S" "$WORK2/source" "$WORK2/results" "$WORK2/server-root"
cp "$AMISNAP_BIN" "$WORK2/boot/C/AmiSnap"
cp "$STAGE_BIN" "$WORK2/boot/C/stage"

REPO_URL2="s3://127.0.0.1:$PORT2/$BUCKET/repo"
cat > "$WORK2/boot/S/Startup-Sequence" <<EOF
FailAt 21
Set AWS_ACCESS_KEY_ID $ACCESS_KEY
Set AWS_SECRET_ACCESS_KEY $SECRET_KEY
Set AWS_REGION $REGION
stage
AmiSnap ACTION=SNAPSHOT SOURCE=Source: REPO=$REPO_URL2 LOG=Results:snapshot.log
AmiSnap ACTION=LIST REPO=$REPO_URL2 LOG=Results:list.log
EOF

cat > "$WORK2/machine.toml" <<EOF
[cpu]
model = "68020"

[memory]
chip = "1M"
fast = "2M"

[floppy]
drives = 1

[[filesys]]
path = "$WORK2/boot"
volume = "AmiSnapBoot"
bootpri = 10

[[filesys]]
path = "$WORK2/source"
volume = "Source"
bootpri = -128

[[filesys]]
path = "$WORK2/results"
volume = "Results"
bootpri = -128

[emulation]
power_on = true
warp_speed = "max"
EOF

SERVER_LOG2="$WORK2/server.log"
python3 "$ROOT/tests/s3/mini_s3_server.py" "$WORK2/server-root" "$BUCKET" \
    "$ACCESS_KEY" "$SECRET_KEY" "$REGION" "$PORT2" >"$SERVER_LOG2" 2>&1 &
SERVER_PID2=$!
cleanup2() { kill "$SERVER_PID2" >/dev/null 2>&1 || true; }
trap cleanup2 EXIT INT TERM

i=0
READY2=0
while [ $i -lt 50 ]; do
    if grep -q "^READY" "$SERVER_LOG2" 2>/dev/null; then READY2=1; break; fi
    if ! kill -0 "$SERVER_PID2" 2>/dev/null; then
        echo "FAIL: mini_s3_server.py (env-creds pass) exited early:" >&2
        cat "$SERVER_LOG2" >&2
        exit 3
    fi
    i=$((i + 1))
    sleep 0.1
done
[ "$READY2" -eq 1 ] || { echo "FAIL: server (env-creds pass) never became ready" >&2; cat "$SERVER_LOG2" >&2; exit 3; }

set +e
"$COPPERLINE" --config "$WORK2/machine.toml" --cpu 68020 --noaudio --hostsocket-net host \
    --benchmark-until "$BENCH" "$KICK" >"$OUT" 2>&1
CL_RC2=$?
set -e
kill "$SERVER_PID2" >/dev/null 2>&1 || true

echo "----- copperline output (env-creds pass) -----"
tail -20 "$OUT"
echo "------------------------------"
[ "$CL_RC2" -eq 0 ] || { echo "FAIL: $COPPERLINE (env-creds pass) exited $CL_RC2"; cat "$OUT"; exit 3; }

check_log2() {
    name=$1; pattern=$2
    path="$WORK2/results/$name"
    if [ ! -e "$path" ]; then
        echo "FAIL: (env-creds pass) missing $name (command never completed?)"
        fail=1
        return
    fi
    echo "--- (env-creds pass) $name ---"; cat "$path"
    if ! grep -q "$pattern" "$path"; then
        echo "FAIL: (env-creds pass) $name does not contain expected pattern: $pattern"
        fail=1
    fi
}
check_log2 stage.log "^stage: done$"
check_log2 snapshot.log "^Snapshot .*(0 unchanged, 0 failed)"
check_log2 list.log " entries"

OBJECT_COUNT2=$(find "$WORK2/server-root" -type f 2>/dev/null | wc -l | tr -d ' ')
echo "--- (env-creds pass) S3 server backing store: $OBJECT_COUNT2 object(s) ---"
if [ "$OBJECT_COUNT2" -lt 1 ]; then
    echo "FAIL: (env-creds pass) no objects found on the S3 server's own backing store"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: one or more checks failed"
    exit 1
fi
echo "PASS"

#!/bin/sh
# run-webdav-tls.sh -- real on-target exercise of the re-enabled
# https:// WebDAV path (implementation-plan.md Phase 3 item 4's
# 2026-08-17 re-enable): the strongest test available -- the real,
# unmodified production AmiSnap CLI and webdav.c/tls.c, a real TLS
# session with real certificate-chain AND hostname verification
# (SSL_VERIFY_PEER against AmiSSL:Certs, exactly as
# amisnap_tls_lib_open() runs in production, never SSL_VERIFY_NONE the
# way tests/copperline/tlsbench.c's own earlier diagnostic
# deliberately narrowed its scope to), and a full real
# SNAPSHOT/LIST/VERIFY/RESTORE cycle over the negotiated session, not
# just a bare handshake.
#
# Boots the same real Workbench 3.2 + AmiSSL install run-tls-bench.sh
# uses (sibling AmiAuth's own known-good clone) -- a from-scratch
# minimal boot doesn't get AmiSSL to a working state at all
# (implementation-plan.md's own finding) -- against
# tests/webdav/mini_webdav_server.py's new optional TLS mode (a real,
# independent TLS implementation: Python's stdlib ssl module, not
# AmiSSL's own code tested against itself) wrapping the same WebDAV
# server host-CI's own webdav-check already uses.
#
# A throwaway local CA + server cert is generated fresh each run and
# its hash installed into the CLONED WB's own AmiSSL/Certs/ (never the
# real WB image -- same copy-on-write clone run-tls-bench.sh uses) so
# SSL_CTX_load_verify_locations("AmiSSL:Certs") genuinely has to walk a
# real chain to a real (if locally-minted) trust root, not skip
# verification the way the narrower tlsbench.c diagnostic did.
#
# TLS13=1 runs the same cycle with the TLS13 switch set (opt into TLS
# 1.3) instead of the TLS 1.2 default -- pass it to test that path too.
#
# Prereqs: same as run-tls-bench.sh (copperline, a real WB clone with
# AmiSSL installed, openssl, docker for the cross-build) plus python3
# (mini_webdav_server.py, stdlib-only).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

AMIAUTH_ENV="$ROOT/../amiauth/tests/gui/.env"
if [ -f "$AMIAUTH_ENV" ]; then
    # shellcheck disable=SC1090
    . "$AMIAUTH_ENV"
fi

COPPERLINE=${COPPERLINE:-copperline}
KICK=${KICK:-${AMIAUTH_ROM:-}}
WB=${WB:-${AMIAUTH_WB_HDD:-}}
BENCH=${BENCH:-120}
PORT=${PORT:-18794}
TLS13=${TLS13:-0}

AMISNAP_BIN="$ROOT/build/AmiSnap"
STAGE_BIN="$ROOT/build/copperline-fixtures/stage"
READBACK_BIN="$ROOT/build/copperline-fixtures/readback"

[ -n "$KICK" ] && [ -e "$KICK" ] || { echo "FAIL: Kickstart ROM missing (KICK=, or AMIAUTH_ROM via $AMIAUTH_ENV): '$KICK'" >&2; exit 2; }
[ -n "$WB" ] && [ -d "$WB" ] || { echo "FAIL: Workbench dir missing (WB=, or AMIAUTH_WB_HDD via $AMIAUTH_ENV): '$WB'" >&2; exit 2; }
[ -f "$WB/S/User-Startup" ] || { echo "FAIL: $WB/S/User-Startup missing (need the real AmiSSL assign it sets up)" >&2; exit 2; }
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
command -v openssl >/dev/null || { echo "FAIL: openssl not found" >&2; exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }
[ -e "$AMISNAP_BIN" ] || { echo "FAIL: missing $AMISNAP_BIN (run: make m68k)" >&2; exit 2; }
[ -e "$STAGE_BIN" ] || { echo "FAIL: missing $STAGE_BIN (run: make copperline-fixtures)" >&2; exit 2; }
[ -e "$READBACK_BIN" ] || { echo "FAIL: missing $READBACK_BIN (run: make copperline-fixtures)" >&2; exit 2; }

echo "ROM: $KICK"
echo "WB:  $WB"
echo "TLS13: $TLS13"

T=$(mktemp -d)
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1 || true
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

# --- throwaway local CA + server cert, fresh every run -- never the
# real AmiSSL:Certs trust store, only this run's own clone's copy.
# -not_before/-not_after (not -days, which is notAfter-relative-to-
# host-now only): this WB clone's guest RTC is not synced to real
# wall-clock time (confirmed live -- X509_V_ERR_CERT_NOT_YET_VALID,
# "certificate is not yet valid or the system clock is incorrect",
# against a -days-2 cert whose notBefore was the host's real "now"),
# so a validity window has to cover whatever the guest's own default
# clock happens to be, not just the host's. ------------------------
PKI="$T/pki"
mkdir -p "$PKI"
openssl genrsa -out "$PKI/ca-key.pem" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$PKI/ca-key.pem" -sha256 \
    -not_before 19700101000000Z -not_after 20991231235959Z \
    -out "$PKI/ca-cert.pem" -subj "/CN=AmiSnap Test CA" >/dev/null 2>&1
openssl genrsa -out "$PKI/server-key.pem" 2048 >/dev/null 2>&1
openssl req -new -key "$PKI/server-key.pem" -out "$PKI/server.csr" \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1
echo "subjectAltName = IP:127.0.0.1" > "$PKI/ext.cnf"
openssl x509 -req -in "$PKI/server.csr" -CA "$PKI/ca-cert.pem" -CAkey "$PKI/ca-key.pem" \
    -CAcreateserial -out "$PKI/server-cert.pem" -sha256 \
    -not_before 19700101000000Z -not_after 20991231235959Z \
    -extfile "$PKI/ext.cnf" >/dev/null 2>&1
CA_HASH=$(openssl x509 -noout -hash -in "$PKI/ca-cert.pem")

# --- clone the WB (copy-on-write), install the CA hash into the
# clone's own AmiSSL:Certs (AmiSSL: -> SYS:AmiSSL per its own
# S:User-Startup), stage AmiSnap + fixtures + results mount. ----------
cp -Rc "$WB" "$T/boot" 2>/dev/null || cp -R "$WB" "$T/boot"
CERTS_DIR="$T/boot/AmiSSL/Certs"
[ -d "$CERTS_DIR" ] || { echo "FAIL: $WB/AmiSSL/Certs missing -- AmiSSL not actually installed on this WB?" >&2; exit 2; }
cp "$PKI/ca-cert.pem" "$CERTS_DIR/$CA_HASH.0"

mkdir -p "$T/source" "$T/restored" "$T/results" "$T/server-root"
cp "$AMISNAP_BIN" "$T/boot/AmiSnap"
cp "$STAGE_BIN" "$T/boot/stage"
cp "$READBACK_BIN" "$T/boot/readback"

REPO_URL="https://127.0.0.1:$PORT/repo"
TLS13_ARG=""
[ "$TLS13" = "1" ] && TLS13_ARG=" TLS13"

SEQ="$T/boot/S/Startup-Sequence"
awk -v repo="$REPO_URL" -v tls13="$TLS13_ARG" '
/^LoadWB/ {
    print "Assign Source: AmiSnapSource:"
    print "Assign Restored: AmiSnapRestored:"
    print "Assign Results: AmiSnapResults:"
    print "SYS:stage"
    print "SYS:AmiSnap ACTION=SNAPSHOT SOURCE=Source: REPO=" repo tls13 " LOG=Results:snapshot.log"
    print "SYS:AmiSnap ACTION=LIST REPO=" repo tls13 " LOG=Results:list.log"
    print "SYS:AmiSnap ACTION=VERIFY REPO=" repo tls13 " FULL LOG=Results:verify.log"
    print "SYS:AmiSnap ACTION=RESTORE REPO=" repo tls13 " DEST=Restored: LOG=Results:restore.log"
    print "SYS:readback"
}
{ print }
' "$SEQ" > "$SEQ.new" && mv "$SEQ.new" "$SEQ"
grep -q '^SYS:AmiSnap ACTION=SNAPSHOT' "$SEQ" || { echo "FAIL: could not patch Startup-Sequence (no LoadWB line?)" >&2; exit 1; }

cat > "$T/cfg.toml" <<EOF
[cpu]
model = "68020"

[memory]
fast = "8M"

[[filesys]]
path = "$T/boot"
volume = "Workbench"
bootpri = 10

[[filesys]]
path = "$T/source"
volume = "AmiSnapSource"
bootpri = -128

[[filesys]]
path = "$T/restored"
volume = "AmiSnapRestored"
bootpri = -128

[[filesys]]
path = "$T/results"
volume = "AmiSnapResults"
bootpri = -128

[emulation]
power_on = true
warp_speed = "max"
EOF

# --- start the real (TLS-wrapped) WebDAV server -- Python's own
# independent ssl module doing real TLS termination, same server
# host-CI's own webdav-check uses underneath. --------------------
python3 "$ROOT/tests/webdav/mini_webdav_server.py" "$T/server-root" "$PORT" \
    "$PKI/server-cert.pem" "$PKI/server-key.pem" >"$T/server.log" 2>&1 &
SERVER_PID=$!
i=0
READY=0
while [ $i -lt 50 ]; do
    if grep -q "^READY" "$T/server.log" 2>/dev/null; then READY=1; break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: mini_webdav_server.py exited early:" >&2
        cat "$T/server.log" >&2
        exit 3
    fi
    i=$((i + 1))
    sleep 0.1
done
[ "$READY" -eq 1 ] || { echo "FAIL: server never became ready" >&2; cat "$T/server.log" >&2; exit 3; }

OUT=$(mktemp)
set +e
"$COPPERLINE" --config "$T/cfg.toml" --cpu 68020 --noaudio --hostsocket-net host \
    --benchmark-until "$BENCH" "$KICK" >"$OUT" 2>&1
CL_RC=$?
set -e
kill "$SERVER_PID" >/dev/null 2>&1 || true

echo "----- copperline output (tail) -----"
tail -20 "$OUT"
echo "-------------------------------------"
rm -f "$OUT"
[ "$CL_RC" -eq 0 ] || { echo "FAIL: $COPPERLINE exited $CL_RC"; exit 3; }

fail=0
check_log() {
    name=$1; pattern=$2
    path="$T/results/$name"
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

if [ -f "$T/restored/root.txt" ]; then
    if ! grep -q "^root file content$" "$T/restored/root.txt"; then
        echo "FAIL: restored/root.txt content mismatch"
        fail=1
    fi
else
    echo "FAIL: restored/root.txt does not exist"
    fail=1
fi
if [ -f "$T/restored/Sub/nested.txt" ]; then
    if ! grep -q "^nested content here$" "$T/restored/Sub/nested.txt"; then
        echo "FAIL: restored/Sub/nested.txt content mismatch"
        fail=1
    fi
else
    echo "FAIL: restored/Sub/nested.txt does not exist"
    fail=1
fi

OBJECT_COUNT=$(find "$T/server-root/repo/objects" -type f 2>/dev/null | wc -l | tr -d ' ')
echo "--- WebDAV(TLS) server backing store: $OBJECT_COUNT object(s) under repo/objects ---"
if [ "$OBJECT_COUNT" -lt 1 ]; then
    echo "FAIL: no objects found on the WebDAV server's own backing store"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: one or more checks failed"
    exit 1
fi
echo "PASS"

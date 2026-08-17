#!/bin/sh
# run-cipherconndiag.sh -- dev-only harness for cipherconndiag.c
# (implementation-plan.md Phase 3 item 4's still-open CIPHERS=
# corruption finding). Runs 4 rounds of real TLS connect+handshake+
# echo (cipher_list set, insecure verification so no AmiSSL:Certs
# setup is needed) against tests/copperline/tls_echo_server.py, in ONE
# process, testing Lock() after every round.
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
BENCH=${BENCH:-60}
PORT=${PORT:-18831}
CIPHER=${CIPHER:-ECDHE-RSA-AES128-GCM-SHA256}
INSECURE=${INSECURE:-1}

[ -n "$KICK" ] && [ -e "$KICK" ] || { echo "FAIL: Kickstart ROM missing" >&2; exit 2; }
[ -n "$WB" ] && [ -d "$WB" ] || { echo "FAIL: Workbench dir missing" >&2; exit 2; }
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
command -v openssl >/dev/null || { echo "FAIL: openssl not found" >&2; exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }

BIN="$ROOT/build/cipherconndiag"
LOCKBIN="$ROOT/build/lockchecker"
[ -e "$BIN" ] || { echo "FAIL: missing $BIN -- cross-build it first" >&2; exit 2; }
[ -e "$LOCKBIN" ] || { echo "FAIL: missing $LOCKBIN -- cross-build it first" >&2; exit 2; }

echo "CIPHER: ${CIPHER:-(none)}  INSECURE: $INSECURE"

T=$(mktemp -d)
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1 || true
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

PKI="$T/pki"
mkdir -p "$PKI"
openssl genrsa -out "$PKI/key.pem" 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$PKI/key.pem" -sha256 \
    -not_before 19700101000000Z -not_after 20991231235959Z \
    -out "$PKI/cert.pem" -subj "/CN=127.0.0.1" >/dev/null 2>&1

cp -Rc "$WB" "$T/boot" 2>/dev/null || cp -R "$WB" "$T/boot"
cp "$BIN" "$T/boot/diag"
cp "$LOCKBIN" "$T/boot/lockchecker"
mkdir -p "$T/results"

SEQ="$T/boot/S/Startup-Sequence"
awk -v cipher="$CIPHER" -v port="$PORT" -v insecure="$INSECURE" '
/^CPU CHECKINSTALL/ { next }
/^LoadWB/ {
    print "Assign Results: AmiSnapResults:"
    print "SYS:diag 127.0.0.1 " port " " cipher " " insecure " 1 1 >Results:diag1.log"
    print "SYS:diag 127.0.0.1 " port " " cipher " " insecure " 2 1 >Results:diag2.log"
    print "SYS:diag 127.0.0.1 " port " " cipher " " insecure " 3 1 >Results:diag3.log"
    print "SYS:diag 127.0.0.1 " port " " cipher " " insecure " 4 1 >Results:diag4.log"
    print "SYS:lockchecker AmiSnapResults:scratch1.dat AmiSnapResults:scratch2.dat AmiSnapResults:scratch3.dat AmiSnapResults:scratch4.dat >Results:lockchecker.log"
}
{ print }
' "$SEQ" > "$SEQ.new" && mv "$SEQ.new" "$SEQ"
grep -q '^SYS:diag ' "$SEQ" || { echo "FAIL: could not patch Startup-Sequence" >&2; exit 1; }

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
path = "$T/results"
volume = "AmiSnapResults"
bootpri = -128

[emulation]
power_on = true
warp_speed = "max"
EOF

python3 "$HERE/tls_echo_server.py" "$PORT" "$PKI/cert.pem" "$PKI/key.pem" >"$T/server.log" 2>&1 &
SERVER_PID=$!
i=0
READY=0
while [ $i -lt 50 ]; do
    if grep -q "^READY" "$T/server.log" 2>/dev/null; then READY=1; break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: tls_echo_server.py exited early:" >&2
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
echo "--- server.log ---"
cat "$T/server.log"
echo "-------------------"
[ "$CL_RC" -eq 0 ] || { echo "FAIL: $COPPERLINE exited $CL_RC"; exit 3; }

for n in 1 2 3 4; do
    if [ -e "$T/results/diag$n.log" ]; then
        echo "--- diag$n.log ---"
        cat "$T/results/diag$n.log"
    else
        echo "FAIL: missing diag$n.log (command never completed?)"
        exit 1
    fi
done

if [ -e "$T/results/lockchecker.log" ]; then
    echo "--- lockchecker.log (separate process) ---"
    cat "$T/results/lockchecker.log"
else
    echo "FAIL: missing lockchecker.log (command never completed?)"
    exit 1
fi

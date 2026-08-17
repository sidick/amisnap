#!/bin/sh
# run-tls-cipher-bench.sh -- dev-only bulk-cipher throughput benchmark
# (not wired into test-target, needs the real WB+AmiSSL clone CI has no
# way to provide, same status as run-tls-bench.sh) for the follow-up
# question implementation-plan.md Phase 3 item 4 raised once the real
# TLS hang was fixed: is a cipher override worth adding for CPU budget
# on slower Amigas (proposal.md's own "CPU budget" principle), not
# security/interop (TLSINSECURE already covers untrusted certs)?
#
# Runs tests/copperline/tlsthroughput.c against tests/copperline/
# tls_echo_server.py (a real, independent TLS echo server -- Python's
# own ssl module, not AmiSSL tested against itself) over
# --hostsocket-net host, once per cipher in the list below, each
# sending+receiving TOTAL_KB of data and reporting real EClock-timed
# throughput. PSK ciphers (no certificate, no asymmetric crypto at
# all) isolate bulk-cipher cost specifically -- what this benchmark
# exists to measure -- from key-exchange/certificate-verification
# cost, which tests/copperline/tlsbench.c already covers separately.
#
# Prereqs: same as run-tls-bench.sh (copperline, a real WB clone with
# AmiSSL installed, docker for the cross-build) plus python3.
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
BENCH=${BENCH:-180}
PORT=${PORT:-18820}
TOTAL_KB=${TOTAL_KB:-128}
PSK_HEX=${PSK_HEX:-1a2b3c4d5e6f708192a3b4c5d6e7f809}
# CPU_MODEL/CPU_CLOCK: override the emulated CPU, e.g.
# CPU_MODEL=68030 CPU_CLOCK=50 for a real (not extrapolated) number on
# a common accelerated-Amiga target instead of the 14MHz 68020 stock
# baseline. Passed straight to copperline's own --cpu/--cpu-clock
# flags below, same "don't rely on a single implicit source" reasoning
# tests/copperline/machine.toml's own header comment already gives for
# always passing --cpu explicitly on the command line.
CPU_MODEL=${CPU_MODEL:-68020}
CPU_CLOCK=${CPU_CLOCK:-}

[ -n "$KICK" ] && [ -e "$KICK" ] || { echo "FAIL: Kickstart ROM missing (KICK=, or AMIAUTH_ROM via $AMIAUTH_ENV): '$KICK'" >&2; exit 2; }
[ -n "$WB" ] && [ -d "$WB" ] || { echo "FAIL: Workbench dir missing (WB=, or AMIAUTH_WB_HDD via $AMIAUTH_ENV): '$WB'" >&2; exit 2; }
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }

BIN="$ROOT/build/tlsthroughput"
[ -e "$BIN" ] || { echo "FAIL: missing $BIN -- cross-build it first" >&2; exit 2; }

echo "ROM: $KICK"
echo "WB:  $WB"
echo "TOTAL_KB per cipher: $TOTAL_KB"
echo "CPU: $CPU_MODEL${CPU_CLOCK:+ @ ${CPU_CLOCK}MHz}"

# --- PSK ciphers: isolate bulk-cipher cost, no certificate/key
# exchange overhead at all. One AES-CBC (the classic, oldest-style
# cipher), two AES-GCM (AEAD, the realistic modern default), and
# ChaCha20-Poly1305 (AEAD, the cipher this whole benchmark exists to
# check against AES on a CPU with no AES acceleration -- every 68k). -
CIPHERS="PSK-AES128-CBC-SHA PSK-AES256-CBC-SHA PSK-AES128-GCM-SHA256 PSK-AES256-GCM-SHA384 PSK-CHACHA20-POLY1305"

T=$(mktemp -d)
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1 || true
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

cp -Rc "$WB" "$T/boot" 2>/dev/null || cp -R "$WB" "$T/boot"
cp "$BIN" "$T/boot/bench"
mkdir -p "$T/results"

SEQ="$T/boot/S/Startup-Sequence"
{
    echo "Assign Results: AmiSnapResults:"
    n=0
    for c in $CIPHERS; do
        n=$((n + 1))
        echo "SYS:bench 127.0.0.1 $PORT $c $PSK_HEX $TOTAL_KB >Results:cipher$n.log"
    done
} > "$T/cipher-commands.txt"
# "CPU CHECKINSTALL" (this WB's own real Startup-Sequence) blocks on a
# real "press RETURN to resume booting" prompt under any --cpu other
# than what the WB was originally installed for (68030/68040/etc. with
# no matching *.library present) -- confirmed live, headless, no way
# to press a key. This diagnostic never calls a CPU-specific library
# itself, so the check is simply skipped in THIS throwaway clone's own
# copy (never the real WB image) rather than sourcing/vendoring a real
# 68030.library into LIBS: just to satisfy a check nothing here needs.
awk -v cmdfile="$T/cipher-commands.txt" '
/^CPU CHECKINSTALL/ { next }
/^LoadWB/ {
    while ((getline line < cmdfile) > 0) print line
}
{ print }
' "$SEQ" > "$SEQ.new" && mv "$SEQ.new" "$SEQ"
grep -q '^SYS:bench ' "$SEQ" || { echo "FAIL: could not patch Startup-Sequence (no LoadWB line?)" >&2; exit 1; }

cat > "$T/cfg.toml" <<EOF
[cpu]
model = "$CPU_MODEL"

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

python3 "$HERE/tls_echo_server.py" "$PORT" - - "$PSK_HEX" >"$T/server.log" 2>&1 &
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

CPU_CLOCK_ARGS=""
[ -n "$CPU_CLOCK" ] && CPU_CLOCK_ARGS="--cpu-clock $CPU_CLOCK"

OUT=$(mktemp)
set +e
# shellcheck disable=SC2086
"$COPPERLINE" --config "$T/cfg.toml" --cpu "$CPU_MODEL" $CPU_CLOCK_ARGS --noaudio --hostsocket-net host \
    --benchmark-until "$BENCH" "$KICK" >"$OUT" 2>&1
CL_RC=$?
set -e
kill "$SERVER_PID" >/dev/null 2>&1 || true

echo "----- copperline output (tail) -----"
tail -10 "$OUT"
echo "-------------------------------------"
rm -f "$OUT"
[ "$CL_RC" -eq 0 ] || { echo "FAIL: $COPPERLINE exited $CL_RC"; exit 3; }

FOUND=0
for f in "$T/results"/cipher*.log; do
    [ -e "$f" ] || continue
    FOUND=1
    echo "--- $(basename "$f") ---"
    cat "$f"
done
[ "$FOUND" -eq 1 ] || { echo "FAIL: no results files -- benchmark never started"; exit 1; }

echo "--- summary (KB/s per cipher) ---"
grep -h '^tlsthroughput: RESULT' "$T/results"/cipher*.log 2>/dev/null || echo "(no RESULT lines -- see full log above for failures)"

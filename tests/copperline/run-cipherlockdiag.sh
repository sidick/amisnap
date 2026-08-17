#!/bin/sh
# run-cipherlockdiag.sh -- dev-only harness for cipherlockdiag.c
# (implementation-plan.md Phase 3 item 4's still-open CIPHERS=
# corruption finding). Boots the real WB+AmiSSL clone (same as
# run-tls-bench.sh) and runs cipherlockdiag once, no network needed --
# it never calls tls_connect(), only amisnap_tls_lib_open() with a
# cipher_list and repeated Lock() calls in the SAME process, to check
# whether the corruption already exists before any TLS handshake or
# process-boundary crossing happens at all.
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
CIPHER=${CIPHER:-ECDHE-RSA-AES128-GCM-SHA256}

[ -n "$KICK" ] && [ -e "$KICK" ] || { echo "FAIL: Kickstart ROM missing" >&2; exit 2; }
[ -n "$WB" ] && [ -d "$WB" ] || { echo "FAIL: Workbench dir missing" >&2; exit 2; }
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }

BIN="$ROOT/build/cipherlockdiag"
[ -e "$BIN" ] || { echo "FAIL: missing $BIN -- cross-build it first" >&2; exit 2; }

echo "CIPHER: ${CIPHER:-(none)}"

T=$(mktemp -d)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT INT TERM

cp -Rc "$WB" "$T/boot" 2>/dev/null || cp -R "$WB" "$T/boot"
cp "$BIN" "$T/boot/diag"
mkdir -p "$T/results"

SEQ="$T/boot/S/Startup-Sequence"
awk -v cipher="$CIPHER" '
/^CPU CHECKINSTALL/ { next }
/^LoadWB/ {
    print "Assign Results: AmiSnapResults:"
    print "SYS:diag " cipher " >Results:diag.log"
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

OUT=$(mktemp)
set +e
"$COPPERLINE" --config "$T/cfg.toml" --cpu 68020 --noaudio --hostsocket-net host \
    --benchmark-until "$BENCH" "$KICK" >"$OUT" 2>&1
CL_RC=$?
set -e

echo "----- copperline output (tail) -----"
tail -20 "$OUT"
echo "-------------------------------------"
rm -f "$OUT"
[ "$CL_RC" -eq 0 ] || { echo "FAIL: $COPPERLINE exited $CL_RC"; exit 3; }

if [ -e "$T/results/diag.log" ]; then
    echo "--- diag.log ---"
    cat "$T/results/diag.log"
else
    echo "FAIL: missing diag.log (command never completed?)"
    exit 1
fi

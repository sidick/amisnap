#!/bin/sh
# run-tls-bench.sh -- dev-only diagnostic (not wired into `test-target`,
# needs a real Workbench install with AmiSSL genuinely installed that
# CI has no way to provide -- same "not shipped, informs a decision"
# status as sibling AmiAuth's own amissl-bench.sh) for
# implementation-plan.md Phase 3 item 4's open TLS question: does the
# blocking SSL_set_fd()+SSL_connect() design in src/amiga/tls.c
# (confirmed hanging against a real example.com:443 -- a known,
# independently-documented AmiSSL fragility "under the Amiga's slow
# handshakes", per micropython/ports/amiga/modssl.c's own header
# comment) also hang against a LOCAL server with the cheapest possible
# real TLS cipher, removing both suspected contributors to "slow" --
# real internet RTT and handshake compute cost -- at once?
#
# Runs tests/copperline/tlsbench.c (a standalone diagnostic that
# reimplements tls.c's own soft-load sequence directly rather than
# modifying/linking tls.c itself, see that file's own header) against a
# local `openssl s_server` reachable over Copperline's
# --hostsocket-net host loopback passthrough, booting from a real
# Workbench install that already has AmiSSL installed via its own
# installer (a from-scratch minimal boot doesn't get AmiSSL to a
# working state at all -- implementation-plan.md's own finding).
#
# Prereqs:
#   - copperline, a Kickstart ROM matching the WB clone's own OS
#     version, and a bootable WB directory with AmiSSL installed and
#     its S:User-Startup already wired up (AmiSSL: assign + LIBS:) --
#     none of these are committed (copyrighted / machine-specific).
#     Reuses sibling AmiAuth's own known-good WB 3.2 clone by default
#     (tests/gui/.env there) since implementation-plan.md's own item 4
#     work already established that's a real, working AmiSSL install;
#     override with WB=/KICK= for a different one.
#   - openssl (for the local s_server) and python3 are NOT needed here
#     (s_server is real openssl, no bespoke server this time -- the
#     whole point is testing against something this project didn't
#     write).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

# Reuse AmiAuth's own known-good WB 3.2 + AmiSSL clone by default --
# implementation-plan.md Phase 3 item 4 already validated this exact
# image gets OpenAmiSSLTags() all the way to a working state, the
# question this script answers picks up from exactly that point.
AMIAUTH_ENV="$ROOT/../amiauth/tests/gui/.env"
if [ -f "$AMIAUTH_ENV" ]; then
    # shellcheck disable=SC1090
    . "$AMIAUTH_ENV"
fi

COPPERLINE=${COPPERLINE:-copperline}
KICK=${KICK:-${AMIAUTH_ROM:-}}
WB=${WB:-${AMIAUTH_WB_HDD:-}}
BENCH=${BENCH:-120}
PORT=${PORT:-18793}
# Cheapest-that-actually-works-first: PSK-NULL-SHA (no asymmetric key
# exchange, no certificate exchange, no bulk encryption at all -- "TLS"
# in name only) is rejected outright by this AmiSSL build with "no
# ciphers available" -- confirmed to be OPENSSL_NO_WEAK_SSL_CIPHERS in
# its own opensslconf.h, not a hang or a real bug, NULL-encryption
# suites are deliberately excluded. PSK-AES128-CBC-SHA is the next
# cheapest real option (still no asymmetric key exchange or
# certificate exchange, just a single AES-128 op) and is what this
# defaults to. Pass CIPHER= to try a more realistic (and more
# expensive) one once the cheap end is proven to work, e.g.
# CIPHER=ECDHE-RSA-AES128-GCM-SHA256 (needs a real cert on the server
# side too -- see the CERT=/KEY= handling below).
CIPHER=${CIPHER:-PSK-AES128-CBC-SHA}
PSK_HEX=${PSK_HEX:-1a2b3c4d5e6f708192a3b4c5d6e7f809}
# CERT=/KEY= for a real certificate-authenticated cipher (e.g.
# ECDHE-RSA-AES128-GCM-SHA256) -- the closest local equivalent to the
# real example.com:443 scenario implementation-plan.md's own Phase 3
# item 4 diagnosis hung against, minus real internet RTT/jitter. Auto-
# generates a throwaway self-signed cert into $T below if CIPHER=
# doesn't start with "PSK" and neither is set -- tlsbench.c always
# runs with SSL_VERIFY_NONE (a deliberate diagnostic scope narrowing,
# see its own header comment), so a self-signed cert with no real CA
# chain is fine here even though it's never how amisnap_tls_lib_open()
# itself verifies in production.
CERT=${CERT:-}
KEY=${KEY:-}

[ -n "$KICK" ] && [ -e "$KICK" ] || { echo "FAIL: Kickstart ROM missing (KICK=, or AMIAUTH_ROM via $AMIAUTH_ENV): '$KICK'" >&2; exit 2; }
[ -n "$WB" ] && [ -d "$WB" ] || { echo "FAIL: Workbench dir missing (WB=, or AMIAUTH_WB_HDD via $AMIAUTH_ENV): '$WB'" >&2; exit 2; }
[ -f "$WB/S/User-Startup" ] || { echo "FAIL: $WB/S/User-Startup missing (need the real AmiSSL assign it sets up)" >&2; exit 2; }
command -v "$COPPERLINE" >/dev/null || { echo "FAIL: $COPPERLINE not found" >&2; exit 2; }
command -v openssl >/dev/null || { echo "FAIL: openssl not found (need it for the local s_server)" >&2; exit 2; }

echo "ROM: $KICK"
echo "WB:  $WB"
echo "cipher: $CIPHER"

sdk_out=$(AMISSL_CACHE_DIR="$ROOT/.amissl-cache" sh "$ROOT/scripts/fetch-amissl-sdk.sh")
SDK_DEV=$(echo "$sdk_out" | sed -n 1p)
[ -d "$SDK_DEV" ] || { echo "FAIL: fetch-amissl-sdk.sh did not return a valid SDK path" >&2; exit 1; }

BIN="$ROOT/build/tlsbench"
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
    -v "$ROOT":/work -v "$SDK_DEV":/amissl-sdk -w /work ghcr.io/sidick/amiga-dev:1 sh -lc \
    'PATH=/opt/amiga/bin:$PATH m68k-amigaos-gcc -std=c99 -O2 -Wall -Wextra -m68020 -msoft-float -noixemul \
     -Isrc/core -Isrc/amiga -I/amissl-sdk/include \
     src/core/tlv.c src/amiga/socket.c tests/copperline/tlsbench.c \
     -L/amissl-sdk/lib/AmigaOS3 -lamisslstubs \
     -o build/tlsbench'
[ -e "$BIN" ] || { echo "FAIL: build/tlsbench missing after cross-build" >&2; exit 1; }

T=$(mktemp -d)
OUT=$(mktemp)
SERVER_PID=""
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1 || true
    rm -rf "$T" "$OUT"
}
trap cleanup EXIT INT TERM

# --- clone the WB (copy-on-write) and stage the bench binary, results
# mount -- same shape as sibling AmiAuth's amissl-bench.sh, never
# mutating the real WB install itself. ------------------------------
cp -Rc "$WB" "$T/boot" 2>/dev/null || cp -R "$WB" "$T/boot"
cp "$BIN" "$T/boot/bench"
mkdir -p "$T/results"

# Run right after S:User-Startup (which sets up the AmiSSL:/LIBS:
# assigns) and before LoadWB -- no Workbench screen needed for a CLI
# diagnostic, so skip the time it'd take to load one. Output goes to
# the real dos.library Results: mount below via plain `>` redirection
# (bench itself just uses stdio) -- readable from the host even if a
# later step genuinely hangs, unlike relying on the process's own exit.
SEQ="$T/boot/S/Startup-Sequence"
awk -v port="$PORT" -v cipher="$CIPHER" \
    '/^LoadWB/ { print "Assign Results: AmiSnapResults:"; print "SYS:bench 127.0.0.1 " port " " cipher " >Results:tlsbench.log" } { print }' \
    "$SEQ" > "$SEQ.new" && mv "$SEQ.new" "$SEQ"
grep -q '^SYS:bench ' "$SEQ" || { echo "FAIL: could not patch Startup-Sequence (no LoadWB line?)" >&2; exit 1; }

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

# --- start the local TLS server -- real openssl, not a mock, same
# "independent implementation" reasoning every other host-CI check in
# this tree uses, just running the server-side role here instead of
# the client-side. -www answers any request with a canned HTML status
# page, giving a genuine bidirectional data check post-handshake with
# no bespoke protocol needed on either side. -----------------------
case "$CIPHER" in
PSK*)
    # PSK ciphers authenticate via the shared key -- no certificate
    # exchanged at all.
    AUTH_ARGS="-nocert -psk $PSK_HEX"
    ;;
*)
    if [ -z "$CERT" ] || [ -z "$KEY" ]; then
        CERT="$T/cert.pem"
        KEY="$T/key.pem"
        openssl req -x509 -newkey rsa:2048 -keyout "$KEY" -out "$CERT" \
            -days 1 -nodes -subj "/CN=127.0.0.1" >/dev/null 2>&1
    fi
    AUTH_ARGS="-cert $CERT -key $KEY"
    ;;
esac
# shellcheck disable=SC2086
openssl s_server -accept "$PORT" $AUTH_ARGS -cipher "$CIPHER" \
    -tls1_2 -www -quiet </dev/null >"$T/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || { echo "FAIL: openssl s_server exited early:" >&2; cat "$T/server.log" >&2; exit 3; }

set +e
"$COPPERLINE" --config "$T/cfg.toml" --cpu 68020 --noaudio --hostsocket-net host \
    --benchmark-until "$BENCH" "$KICK" >"$OUT" 2>&1
CL_RC=$?
set -e

echo "----- copperline output (tail) -----"
tail -20 "$OUT"
echo "-------------------------------------"
[ "$CL_RC" -eq 0 ] || { echo "FAIL: $COPPERLINE exited $CL_RC"; cat "$OUT"; exit 3; }

echo "--- server log ---"
cat "$T/server.log"

if [ ! -e "$T/results/tlsbench.log" ]; then
    echo "FAIL: no tlsbench.log -- bench never even started (Startup-Sequence patch or boot issue)"
    exit 1
fi

echo "--- tlsbench.log ---"
cat "$T/results/tlsbench.log"

if grep -q '^tlsbench: PASS$' "$T/results/tlsbench.log"; then
    echo "PASS ($CIPHER handshake + data exchange completed)"
else
    echo "FAIL: tlsbench did not report PASS (see log above -- a truncated log with no FAIL line "
    echo "      either means it genuinely hung mid-call, same signature as the known SSL_connect() issue)"
    exit 1
fi

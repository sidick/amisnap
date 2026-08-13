#!/bin/sh
# run.sh -- Phase 5's own host-CI check (implementation-plan.md):
# builds live_test against the real POSIX transport
# (tests/webdav/posix_transport.c, reused as-is -- see live_test.c's
# own header comment for why) and the portable s3.c/sigv4.c/http.c,
# starts mini_s3_server.py (a minimal, stdlib-only, INDEPENDENT S3
# server implementation with its own from-scratch SigV4 verification
# -- not this project's own in-memory mock, tests/test_s3.c, which
# shares this project's own assumptions about both the wire format and
# the signing math), runs live_test against it over a real TCP loopback
# connection, then cleans up.
#
# Prereqs: cc (or $CC) and python3 on PATH -- both already required
# elsewhere in this repo's own test/build tooling, no new dependency
# introduced here (deliberately not a real MinIO binary/container --
# same reasoning tests/webdav/run.sh's own header comment gives for
# preferring a genuinely independent from-scratch implementation over
# a heavier external dependency).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
WEBDAV_DIR="$ROOT/tests/webdav"
CC=${CC:-cc}

command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }

WORK=$(mktemp -d)
BIN="$WORK/live_test"
SERVER_ROOT="$WORK/server-root"
SERVER_OUT="$WORK/server.out"
SERVER_PID=""

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -I"$ROOT/src/core" -I"$WEBDAV_DIR" \
    "$ROOT/src/core/tlv.c" "$ROOT/src/core/http.c" "$ROOT/src/core/sha256.c" \
    "$ROOT/src/core/hmac_sha256.c" "$ROOT/src/core/sigv4.c" "$ROOT/src/core/s3.c" \
    "$WEBDAV_DIR/posix_transport.c" "$HERE/live_test.c" \
    -o "$BIN"

mkdir -p "$SERVER_ROOT"
python3 "$HERE/mini_s3_server.py" "$SERVER_ROOT" amisnap-test-bucket AKIDEXAMPLE \
    'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' us-east-1 0 >"$SERVER_OUT" 2>&1 &
SERVER_PID=$!

PORT=""
i=0
while [ $i -lt 50 ]; do
    if [ -s "$SERVER_OUT" ]; then
        PORT=$(awk '/^READY /{print $2}' "$SERVER_OUT")
        [ -n "$PORT" ] && break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: mini_s3_server.py exited early:" >&2
        cat "$SERVER_OUT" >&2
        exit 3
    fi
    i=$((i + 1))
    sleep 0.1
done
[ -n "$PORT" ] || { echo "FAIL: server never printed READY <port>" >&2; cat "$SERVER_OUT" >&2; exit 3; }

"$BIN" "$PORT"

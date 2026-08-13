#!/bin/sh
# run.sh -- Phase 3 item 5's own host-CI check (implementation-plan.md):
# builds live_test against the real POSIX transport (posix_transport.c)
# and the portable webdav.c/http.c, starts mini_webdav_server.py (a
# minimal, stdlib-only, INDEPENDENT WebDAV server implementation -- not
# this project's own in-memory mock, tests/test_webdav.c, which shares
# this project's own assumptions about the wire format), runs live_test
# against it over a real TCP loopback connection, then cleans up.
#
# Prereqs: cc (or $CC) and python3 on PATH -- both already required
# elsewhere in this repo's own test/build tooling (make test,
# tools/amisnap_reader.py), no new dependency introduced here.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
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

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -I"$ROOT/src/core" -I"$HERE" \
    "$ROOT/src/core/tlv.c" "$ROOT/src/core/http.c" "$ROOT/src/core/base64.c" \
    "$ROOT/src/core/webdav.c" "$HERE/posix_transport.c" "$HERE/live_test.c" \
    -o "$BIN"

mkdir -p "$SERVER_ROOT"
python3 "$HERE/mini_webdav_server.py" "$SERVER_ROOT" 0 >"$SERVER_OUT" 2>&1 &
SERVER_PID=$!

PORT=""
i=0
while [ $i -lt 50 ]; do
    if [ -s "$SERVER_OUT" ]; then
        PORT=$(awk '/^READY /{print $2}' "$SERVER_OUT")
        [ -n "$PORT" ] && break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "FAIL: mini_webdav_server.py exited early:" >&2
        cat "$SERVER_OUT" >&2
        exit 3
    fi
    i=$((i + 1))
    sleep 0.1
done
[ -n "$PORT" ] || { echo "FAIL: server never printed READY <port>" >&2; cat "$SERVER_OUT" >&2; exit 3; }

"$BIN" "$PORT"

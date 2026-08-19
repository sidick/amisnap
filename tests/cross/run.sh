#!/bin/sh
# tests/cross/run.sh -- Phase 2's CI cross-implementation check
# (implementation-plan.md / docs/format.md's own opening line: "the C
# implementation and the host-side reference reader both cite it, and
# CI asserts they agree").
#
# Builds a small, deterministic repository with the real portable C
# write path (build/gen_sample_repo, host-buildable -- see that file's
# own header), then drives tools/amisnap_reader.py (stdlib-only Python,
# completely independent of src/core/) against it: list, verify --full,
# and restore, asserting each against known-correct values. Finally
# corrupts one real object byte and confirms the Python reader's own
# --full verify independently detects it -- proving the reader's
# BLAKE2s-256 check is real, not a rubber stamp.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

GEN="$ROOT/build/gen_sample_repo"
READER="$ROOT/tools/amisnap_reader.py"
REPO="$ROOT/build/cross-check-repo"
DEST="$ROOT/build/cross-check-restored"
UAEM_DEST="$ROOT/build/cross-check-restored-uaem"

[ -e "$GEN" ] || { echo "FAIL: missing $GEN (run: make cross-check)" >&2; exit 2; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found" >&2; exit 2; }

rm -rf "$REPO" "$DEST" "$UAEM_DEST"
SNAPID=$("$GEN" "$REPO")
echo "generated snapshot: $SNAPID"

fail=0

echo "--- list ---"
python3 "$READER" list "$REPO"
if ! python3 "$READER" list "$REPO" | grep -q "^$SNAPID  5 entries\$"; then
    echo "FAIL: list output mismatch (want '$SNAPID  5 entries')"
    fail=1
fi

echo "--- verify --full ---"
VERIFY_OUT=$(python3 "$READER" verify "$REPO" --full)
echo "$VERIFY_OUT"
if ! echo "$VERIFY_OUT" | grep -q "^Verify $SNAPID (FULL): 2 objects checked, 0 missing, 0 corrupt\$"; then
    echo "FAIL: verify output mismatch"
    fail=1
fi

echo "--- restore ---"
python3 "$READER" restore "$REPO" "$DEST"

if [ ! -f "$DEST/readme.txt" ] || ! grep -q "^Hello from AmiSnap\$" "$DEST/readme.txt"; then
    echo "FAIL: readme.txt content mismatch"
    fail=1
fi
if [ ! -f "$DEST/Docs/notes.txt" ] || ! grep -q "^notes\$" "$DEST/Docs/notes.txt"; then
    echo "FAIL: Docs/notes.txt content mismatch"
    fail=1
fi
if [ ! -f "$DEST/empty.dat" ] || [ -s "$DEST/empty.dat" ]; then
    echo "FAIL: empty.dat missing or non-empty"
    fail=1
fi

echo "--- restore --uaem ---"
python3 "$READER" restore "$REPO" "$UAEM_DEST" --uaem > /dev/null

# Values transcribed straight from tests/cross/gen_sample_repo.c's own
# fixture data -- prot/date/comment for readme.txt (archive bit,
# comment, owner -- owner has no .uaem field at all, a real, documented
# limit of the format itself, not this check's problem) and Docs (no
# comment at all -- E_COMMENT absent, so no trailing text, not even an
# empty one).
if [ ! -f "$UAEM_DEST/readme.txt.uaem" ] || \
   ! grep -q "^---arwed 2024-07-18 00:10:00.40 a readme\$" "$UAEM_DEST/readme.txt.uaem"; then
    echo "FAIL: readme.txt.uaem content mismatch"
    fail=1
fi
if [ ! -f "$UAEM_DEST/Docs.uaem" ] || \
   ! grep -q "^----rwed 2024-07-18 00:00:00.00\$" "$UAEM_DEST/Docs.uaem"; then
    echo "FAIL: Docs.uaem content mismatch"
    fail=1
fi
echo "--- corrupt an object, confirm --full independently catches it ---"
OBJ=$(find "$REPO/objects" -type f | head -1)
echo "corrupting $OBJ"
printf 'X' >> "$OBJ"
set +e
CORRUPT_OUT=$(python3 "$READER" verify "$REPO" --full 2>&1)
CORRUPT_RC=$?
set -e
echo "$CORRUPT_OUT"
if [ "$CORRUPT_RC" -eq 0 ]; then
    echo "FAIL: verify --full should have failed on a corrupted object"
    fail=1
fi
if ! echo "$CORRUPT_OUT" | grep -q "CORRUPT"; then
    echo "FAIL: expected a CORRUPT report"
    fail=1
fi

echo "--- compressed (OBJCOMP=1) repository ---"
# Same fixture plus one genuinely compressible file (big.txt), written
# framed with LZ4 preference: proves the Python reader's pure-stdlib
# frame decoding (including its own LZ4 block decoder) against objects
# the vendored upstream LZ4 wrote, and that the small files' stored-
# fallback frames round-trip too.
C_REPO="$ROOT/build/cross-check-repo-compressed"
C_DEST="$ROOT/build/cross-check-restored-compressed"

rm -rf "$C_REPO" "$C_DEST"
C_SNAPID=$("$GEN" "$C_REPO" --compress)
echo "generated compressed snapshot: $C_SNAPID"

C_LIST_OUT=$(python3 "$READER" list "$C_REPO")
echo "$C_LIST_OUT"
if ! echo "$C_LIST_OUT" | grep -q "^$C_SNAPID  6 entries\$"; then
    echo "FAIL: compressed list output mismatch (want '$C_SNAPID  6 entries')"
    fail=1
fi

C_VERIFY_OUT=$(python3 "$READER" verify "$C_REPO" --full)
echo "$C_VERIFY_OUT"
if ! echo "$C_VERIFY_OUT" | grep -q "^Verify $C_SNAPID (FULL): 3 objects checked, 0 missing, 0 corrupt\$"; then
    echo "FAIL: compressed verify output mismatch"
    fail=1
fi

# At least one stored object really is an LZ4 frame (first frame byte
# 0x01), and it is genuinely smaller than its 4352-byte content --
# otherwise this section would silently only ever test the stored
# fallback.
if ! python3 -c '
import glob, os, sys
for f in glob.glob(sys.argv[1] + "/objects/*/*"):
    with open(f, "rb") as fh:
        if fh.read(1) == b"\x01" and os.path.getsize(f) < 4352:
            sys.exit(0)
sys.exit(1)' "$C_REPO"; then
    echo "FAIL: no object is actually LZ4-compressed"
    fail=1
fi

python3 "$READER" restore "$C_REPO" "$C_DEST" >/dev/null
if [ ! -f "$C_DEST/readme.txt" ] || ! grep -q "^Hello from AmiSnap\$" "$C_DEST/readme.txt"; then
    echo "FAIL: compressed readme.txt content mismatch"
    fail=1
fi
python3 -c 'import sys; sys.stdout.write("AmigaOS forever! " * 256)' > "$ROOT/build/cross-check-big-expected"
if ! cmp -s "$C_DEST/big.txt" "$ROOT/build/cross-check-big-expected"; then
    echo "FAIL: compressed big.txt did not round-trip bit-for-bit"
    fail=1
fi

# Corrupt one byte inside a frame payload: the reader must call it
# corrupt (decompression failure or hash mismatch, never silence).
C_OBJ=$(find "$C_REPO/objects" -type f | head -1)
printf 'X' >> "$C_OBJ"
set +e
C_CORRUPT_OUT=$(python3 "$READER" verify "$C_REPO" --full 2>&1)
C_CORRUPT_RC=$?
set -e
if [ "$C_CORRUPT_RC" -eq 0 ] || ! echo "$C_CORRUPT_OUT" | grep -q "CORRUPT"; then
    echo "FAIL: corrupted framed object not reported"
    fail=1
fi

echo "--- compressed + encrypted repository ---"
CE_REPO="$ROOT/build/cross-check-repo-comp-enc"
CE_DEST="$ROOT/build/cross-check-restored-comp-enc"
PASSPHRASE="correct horse battery staple"
rm -rf "$CE_REPO" "$CE_DEST"
CE_SNAPID=$("$GEN" "$CE_REPO" --compress "$PASSPHRASE")
echo "generated compressed+encrypted snapshot: $CE_SNAPID"

CE_VERIFY_OUT=$(printf '%s\n' "$PASSPHRASE" | python3 "$READER" verify "$CE_REPO" --full 2>/dev/null)
echo "$CE_VERIFY_OUT"
if ! echo "$CE_VERIFY_OUT" | grep -q "^Verify $CE_SNAPID (FULL): 3 objects checked, 0 missing, 0 corrupt\$"; then
    echo "FAIL: compressed+encrypted verify output mismatch"
    fail=1
fi
printf '%s\n' "$PASSPHRASE" | python3 "$READER" restore "$CE_REPO" "$CE_DEST" >/dev/null 2>&1
if ! cmp -s "$CE_DEST/big.txt" "$ROOT/build/cross-check-big-expected"; then
    echo "FAIL: compressed+encrypted big.txt did not round-trip bit-for-bit"
    fail=1
fi

echo "--- encrypted (CIPHER=1) repository ---"
# implementation-plan.md Phase 4 item 6: same fixture, same assertions,
# but generated with a passphrase (gen_sample_repo.c's own optional
# argv[2]) so this exercises the *encrypted* write path (repo_crypto.c/
# repo_header.c) against the Python reader's own independent ChaCha20/
# PBKDF2/keyed-BLAKE2s reimplementation -- not just the CIPHER=0 path
# above. getpass.getpass() falls back to reading a plain (echoed)
# stdin line when it isn't a real tty, which is exactly what piping the
# passphrase in below does -- its own stderr warning about that is
# expected here, not a real problem.
ENC_REPO="$ROOT/build/cross-check-repo-encrypted"
ENC_DEST="$ROOT/build/cross-check-restored-encrypted"
PASSPHRASE="correct horse battery staple"

rm -rf "$ENC_REPO" "$ENC_DEST"
ENC_SNAPID=$("$GEN" "$ENC_REPO" "$PASSPHRASE")
echo "generated encrypted snapshot: $ENC_SNAPID"

ENC_LIST_OUT=$(printf '%s\n' "$PASSPHRASE" | python3 "$READER" list "$ENC_REPO" 2>/dev/null)
echo "$ENC_LIST_OUT"
if ! echo "$ENC_LIST_OUT" | grep -q "^$ENC_SNAPID  5 entries\$"; then
    echo "FAIL: encrypted list output mismatch (want '$ENC_SNAPID  5 entries')"
    fail=1
fi

ENC_VERIFY_OUT=$(printf '%s\n' "$PASSPHRASE" | python3 "$READER" verify "$ENC_REPO" --full 2>/dev/null)
echo "$ENC_VERIFY_OUT"
if ! echo "$ENC_VERIFY_OUT" | grep -q "^Verify $ENC_SNAPID (FULL): 2 objects checked, 0 missing, 0 corrupt\$"; then
    echo "FAIL: encrypted verify output mismatch"
    fail=1
fi

printf '%s\n' "$PASSPHRASE" | python3 "$READER" restore "$ENC_REPO" "$ENC_DEST" >/dev/null 2>&1
if [ ! -f "$ENC_DEST/readme.txt" ] || ! grep -q "^Hello from AmiSnap\$" "$ENC_DEST/readme.txt"; then
    echo "FAIL: encrypted readme.txt content mismatch (decrypt didn't round-trip)"
    fail=1
fi
if [ ! -f "$ENC_DEST/Docs/notes.txt" ] || ! grep -q "^notes\$" "$ENC_DEST/Docs/notes.txt"; then
    echo "FAIL: encrypted Docs/notes.txt content mismatch"
    fail=1
fi

# Wrong passphrase must fail closed (a real error), never silently
# produce garbage or fall through to plaintext access.
set +e
WRONG_OUT=$(printf 'not the passphrase\n' | python3 "$READER" list "$ENC_REPO" 2>&1)
WRONG_RC=$?
set -e
if [ "$WRONG_RC" -eq 0 ]; then
    echo "FAIL: wrong passphrase should not succeed"
    fail=1
fi
if ! echo "$WRONG_OUT" | grep -qi "wrong passphrase"; then
    echo "FAIL: wrong passphrase should report a clear error, got: $WRONG_OUT"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "FAIL: cross-implementation check failed"
    exit 1
fi
echo "PASS"

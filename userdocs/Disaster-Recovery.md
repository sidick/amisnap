# Disaster Recovery

The whole point of AmiSnap's repository format being documented and
versioned (`docs/format.md` in the source tree) is that you are never
dependent on a working Amiga, or even AmiSnap itself, to get your files
back. `tools/amisnap_reader.py` is a from-scratch, stdlib-only Python 3
reader -- no third-party dependency, not even for the BLAKE2s-256
integrity check (Python's own `hashlib` has had BLAKE2s since 3.6) --
that can list, verify, and restore a repository's content on any
ordinary PC.

This is deliberately an *independent* implementation, not a thin wrapper
around AmiSnap's own C code: every tag value and field layout was
transcribed from `docs/format.md` and cross-checked against the C
encoder/decoder, and the project's own CI runs both implementations
against the same generated repository and confirms they agree --
including a real, deliberately-corrupted object, to confirm the
reader's own from-scratch hash check actually catches it rather than
rubber-stamping whatever it's given.

## Requirements

- Python 3.6 or later. No `pip install` needed.
- The repository's raw files, reachable as a normal directory on the PC
  running the reader -- either because the repository lives on a
  mounted volume/network share the PC can also see directly (the common
  case for a Tier 1 mounted-volume destination), or because you've
  copied the repository's directory tree off wherever it was stored.
  The reader operates on the repository as a plain host filesystem
  directory; it does not itself speak WebDAV or S3 to fetch a remote
  repository's content for you.

## Listing what's in a repository

```
$ python3 tools/amisnap_reader.py list /path/to/MyRepo
20260812153044  318 entries
20260813091200  320 entries
```

## Verifying a snapshot

```
$ python3 tools/amisnap_reader.py verify /path/to/MyRepo --full
```

`--full` re-hashes every object's content against its recorded
BLAKE2s-256 (the same check `VERIFY FULL` does on the Amiga side, run
here entirely independently). Without `--snapid`, the most recent
snapshot is checked.

## Restoring content to the PC

```
$ python3 tools/amisnap_reader.py restore /path/to/MyRepo /path/to/output
```

Add `--snapid=<id>` to pick a specific snapshot (default: the most
recent), `--subtree=<path>` to restore only one directory, or `--uaem`
to also write a `.uaem` metadata sidecar next to each restored file --
see below. Content restoration is complete and independently verified: every
object is checked against its own BLAKE2s-256 before being written, the
same as the Amiga-side restore path, implemented from scratch rather
than sharing code with it.

## The honest limit: metadata on a PC

A bare POSIX host has no `fib_Protection` concept, no per-file
FileNote/comment field, and no shared owner/group namespace with the
source Amiga -- there is nowhere on a plain PC filesystem to actually
*apply* AmiSnap's captured metadata. Rather than attempt a doomed,
lossy mapping onto `chmod`/extended attributes, the reader reports every
field's real value for every entry (visible in its output as it
restores) instead of pretending to apply it. **This is why disaster
recovery gets your file content back reliably, but not automatically
your protection bits/comments/datestamps as real Amiga metadata --
unless you also use `--uaem`:**

```
$ python3 tools/amisnap_reader.py restore /path/to/MyRepo /path/to/output --uaem
```

writes a `<name>.uaem` plain-text sidecar next to each restored entry --
the same convention FS-UAE/Amiberry/Copperline already use for
host-directory metadata (one line: protection flags, datestamp, an
optional comment). A tree restored this way can be mounted directly into
an emulator's host-directory filesystem with its metadata intact, or
applied for real on an actual Amiga afterward with
`AmiSnap ACTION=APPLYUAEM SOURCE=<path>` (see
[CLI Reference](CLI-Reference.md)).

## Encrypted repositories

If the repository was created with `INIT ... PASSPHRASE` (see
[Encryption](Encryption.md)), the reader detects this from
`amisnap.repo` automatically and prompts for the passphrase
(no-echo, via Python's `getpass`) before doing anything else -- the
same fail-closed behavior as the Amiga CLI: a wrong passphrase is
rejected outright, never silently produces garbage output. The reader's
own ChaCha20/PBKDF2/keyed-BLAKE2s implementation is, again, entirely
independent of the C side -- written directly from RFC 8439 and the
format spec, not adapted from `src/core/`.

## A repository with no `amisnap.repo` at all

`docs/format.md`'s reader guidance says to parse `amisnap.repo` first
and refuse an unknown version/cipher. In practice, a plain (unencrypted)
repository may not have an `amisnap.repo` file at all yet -- the file is
only ever written once a repository is initialized for encryption. The
reader tolerates this: no `amisnap.repo` is treated as `CIPHER=0`
(the only value a repository without one can actually have), with a
note on stderr, rather than refusing to read an otherwise perfectly
normal repository.

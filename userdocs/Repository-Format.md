# Repository Format

You don't need to know AmiSnap's on-disk format to use it -- this page
exists for the confidence that it's real, documented, and not a black
box, and to point you at the full specification if you ever need it
(writing a third-party tool, recovering from something unusual, or just
curiosity).

The complete, normative specification lives in
[`docs/format.md`](https://github.com/sidick/amisnap/blob/main/docs/format.md)
in the source tree. It is the single source of truth: both the Amiga-
side C implementation and the independent Python reference reader (see
[Disaster Recovery](Disaster-Recovery.md)) are written from it, and the
project's own CI checks that the two agree on real generated
repositories. Anything below is a summary, not a substitute for it.

## The shape of a repository

- A repository is a directory tree (on whichever destination you chose
  -- see [Destinations](Backends.md)): `objects/` (content, addressed
  by hash), `snapshots/` (one manifest file per snapshot), `tmp/`
  (staging area for atomic writes), and optionally `amisnap.repo`
  (present only if the repository is encrypted).
- Every structured file is built from simple, extensible
  tag-length-value fields -- a reader that doesn't understand a
  particular optional field can skip it and still read everything else,
  and new fields can be added without breaking old repositories.
- Filenames, comments, and other strings are stored as the exact bytes
  the filesystem returned (Latin-1 on classic AmigaOS) -- no
  length-107 assumption anywhere, no silent character-set conversion.
- Datestamps are stored as the native AmigaOS `struct DateStamp` triple
  (days/minutes/ticks) -- no lossy conversion to Unix time.

## Content addressing and deduplication

Every file's content is stored as one or more objects named by their own
BLAKE2s-256 hash. Two files with identical bytes -- in the same
snapshot, or across different snapshots -- are stored exactly once.
This is also how `RESTORE` verifies content: it re-hashes every object
before writing it out and aborts on a mismatch, so silently restoring
corrupted content is not possible.

## Snapshots are atomic

A snapshot's manifest is written into place last, only after every
object it references has already been written successfully. A crash or
power loss at any point during `SNAPSHOT` leaves the previous, already-
completed snapshot untouched and still fully usable -- the interrupted
one simply never becomes visible (its manifest was never renamed into
`snapshots/`), and a later `PRUNE` cleans up whatever partial objects it
left behind.

## Compression is per-object, chosen at INIT

A repository created with `INIT ... COMPRESS=LZ4|DEFLATE` stores every
object inside a small self-describing frame naming its own algorithm
(LZ4, deflate, or stored-raw where compression didn't shrink the
content). Object names and dedup are always based on the
*uncompressed* bytes, so compression changes nothing about content
addressing, and `VERIFY FULL` always re-hashes the decompressed
content. A repository without that INIT choice stores objects as the
raw content bytes -- recoverable with nothing but a hash tool.

## Encryption is a per-object frame, not a whole-repository wrapper

When a repository is encrypted (see [Encryption](Encryption.md)), each
object and manifest is individually encrypted and MAC-checked -- object
*names* stay the plaintext content hash either way, since
content-addressing depends on it and a hash reveals nothing about the
underlying bytes.

## What isn't captured yet

- Soft and hard link *targets* aren't captured or restored yet (links
  are detected and counted as skipped, never silently dropped or
  treated as plain files) -- creating a real link on restore needs
  Amiga-specific work (`MakeLink()`) not yet done.
- Owner/group (`ED_OWNER`) needs AmigaOS V39+ and a filesystem that
  supports it; on an older system or filesystem it's captured as
  unsupported, not guessed at.

Both are honest, tracked gaps in the format's current implementation,
not silent data loss -- restore reports exactly what it could and
couldn't do.

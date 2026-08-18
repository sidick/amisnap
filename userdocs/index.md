# AmiSnap

AmiSnap is a snapshot-based backup tool for classic AmigaOS. It backs up
to modern destinations -- a mounted volume (any DOS device, including an
`smbfs`/NFS mount of a LAN NAS), a WebDAV server, or an S3-compatible
object store -- with incremental snapshots, retention pruning, verified
restore, and bit-perfect round-trip of Amiga filesystem metadata.

What a generic copy-to-a-share approach silently loses, AmiSnap
round-trips exactly: the full 32-bit protection mask (not just
HSPARWED), file comments, original datestamps at ticks precision, owner
where the filesystem and OS version provide it, and long filenames on
long-name FFS/SFS/PFS3.

## Why AmiSnap, not a plain copy

- **Metadata is the product.** A plain `Copy ALL` (or a Samba/NFS drag
  copy from Workbench) keeps file bytes, but drops protection bits,
  comments, and precise datestamps the moment the destination isn't a
  real AmigaDOS filesystem. AmiSnap captures everything `ExAll()`
  reports and restores it in the same order it was captured.
- **Incremental by default.** After the first full snapshot, later
  snapshots only re-read files whose metadata (or, in `PARANOID` mode,
  content hash) says they've actually changed -- the archive bit is
  used as corroborating evidence, never sole evidence, so a bit that
  merely happens to be set is not enough to skip a file on its own.
- **Verified, not assumed.** `VERIFY` checks that a snapshot's manifest
  is structurally sound and, in `FULL` mode, that every stored object
  still hashes to what the manifest says it should. A repository is
  never left in a state where a crash mid-`SNAPSHOT` corrupts the
  previous, already-completed one.
- **Recoverable even if the Amiga is gone.** The on-disk format
  (`docs/format.md` in the source tree) is documented and versioned,
  and `tools/amisnap_reader.py` is a from-scratch, stdlib-only Python
  reader that can list/verify/restore a repository's content on any
  POSIX machine -- see [Disaster Recovery](Disaster-Recovery.md).
- **The CPU budget is respected.** Change detection is metadata-first;
  integrity hashing (BLAKE2s-256) happens once per new or changed file,
  not on every run; encryption and TLS are per-destination opt-ins that
  default off, so a trusted LAN NAS runs at wire speed.

## Where to start

- [Installation](Installation.md) -- getting the binary onto your Amiga.
- [Getting Started](Getting-Started.md) -- your first snapshot and restore.
- [CLI Reference](CLI-Reference.md) -- every `ACTION` and keyword.
- [Destinations (Backends)](Backends.md) -- mounted volumes, WebDAV, S3.

## A note on where AmiSnap is today

AmiSnap is beta software. The engine (snapshot/restore/verify/prune),
metadata capture and restore, mounted-volume/WebDAV/S3 destinations, and
optional repository encryption are all implemented and tested -- host
unit tests, a from-scratch cross-implementation Python reader, and
on-target runs against real emulated AmigaOS (Copperline) with real
filesystems (FFS, "international" FFS, real floppy images) and real
independent WebDAV/S3 server implementations. What it has **not** yet
had is a full release cycle on real, non-emulated hardware. Run it
**alongside your existing backup method for a while**, not as its sole
replacement, until it has a track record on your specific setup.

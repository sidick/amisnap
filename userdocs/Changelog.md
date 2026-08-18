# Changelog

AmiSnap has not had a tagged release yet -- see
[the index page](index.md)'s note on beta status. This page tracks
major milestones during development; once the first release ships, it
will follow the project's usual `VERSION.REVISION` scheme
(`version.mk`).

## Unreleased (0.1, in development)

- **Core engine**: repository format v1 (draft), content-addressed
  objects (BLAKE2s-256), atomic manifest commit, metadata-first
  incremental change detection (archive bit as corroboration, never
  sole evidence), full/subtree restore with content verification,
  structural and `FULL` (re-hashing) verify, mark-and-sweep prune
  (`KEEP_LAST=<n>` and single-`SNAPID=` forms).
- **Amiga metadata**: `ExAll()`-based capture and `SetProtection()`/
  `SetComment()`/`SetFileDate()`/`SetOwner()` restore, with honest,
  counted gaps for link targets (not yet captured) and owner (needs
  AmigaOS V39+).
- **Destinations**: mounted volume (Tier 1), WebDAV (`http://`/
  `https://`, real TLS via AmiSSL), and S3-compatible object storage
  (`s3://`, SigV4 signing, real multipart upload for large objects).
- **Encryption**: optional, per-repository (`INIT ... PASSPHRASE`),
  ChaCha20 + keyed-BLAKE2s framing, PBKDF2 key derivation calibrated to
  the machine running it, `REKEY` without re-encrypting existing
  content.
- **Large files**: fixed-size chunking (256KiB default) so neither
  `SNAPSHOT` nor `RESTORE` needs to hold a whole large file in memory.
- **Exclude lists**: `EXCLUDE=<path>` skips named files/directories
  before they're ever examined -- see [Exclude Lists](Exclude-Lists.md).
- **Disaster recovery**: an independent, stdlib-only Python 3 reference
  reader (`tools/amisnap_reader.py`) that lists/verifies/restores a
  repository without any Amiga or AmiSnap's own code involved, plus
  `.uaem` sidecar export/import for metadata a bare PC can't apply
  directly.
- **Testing**: host unit/vector tests, a C/Python cross-implementation
  check in CI, and on-target verification against real emulated
  AmigaOS (Copperline) -- including real FFS/OFS/international-FFS
  floppy images, a real independent WebDAV server, and a real
  independent S3 server implementation.

Not yet implemented: calendar-bucketed (daily/weekly/monthly) prune
retention beyond `KEEP_LAST=<n>`, soft/hard link restoration, snapshot
spanning across fixed-capacity removable media, TLS for `s3://`
destinations, and user documentation/release packaging beyond this page
(in progress).

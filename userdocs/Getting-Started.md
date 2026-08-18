# Getting Started

This walks through the smallest useful AmiSnap session: back up a
directory to a second volume, list what's there, and restore it
somewhere else to confirm it round-trips. It assumes AmiSnap is on your
`PATH` (see [Installation](Installation.md)).

Every example uses a plain mounted-volume destination (any real
AmigaDOS device or DOS-mountable network share, e.g. an `smbfs` mount
of a NAS) -- see [Destinations](Backends.md) for WebDAV/S3 syntax, and
[CLI Reference](CLI-Reference.md) for every keyword used below.

## 1. Take a first snapshot

```
1.C:> AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo COMMENT="first backup"
AmiSnap 0.1 (12.08.2026)
Snapshot 0000000000000605: 42 dirs, 318 files (0 unchanged, 0 failed), 0 links skipped, 0 dirs and 0 files excluded
```

`REPO=` doesn't need to exist beforehand -- the first `SNAPSHOT` creates
whatever structure it needs under `Backup:MyRepo`. The snapshot id
printed (`0000000000000605` here) is a 16-hex-digit id -- the snapshot's
real AmigaDOS timestamp (days since 1978-01-01, minutes, ticks) packed
into hex, not a human-readable date string -- you can refer to later
with `SNAPID=`.

`SOURCE=` and `REPO=` must not overlap (the same volume, or one nested
inside the other) -- AmiSnap refuses to back a volume up onto itself
rather than guess what you meant.

## 2. Take a second, incremental snapshot

Run the exact same command again (perhaps after editing a file or two
under `Work:`):

```
1.C:> AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo COMMENT="second backup"
AmiSnap 0.1 (12.08.2026)
Snapshot 0000000000000616: 42 dirs, 318 files (316 unchanged, 0 failed), 0 links skipped, 0 dirs and 0 files excluded
```

Files whose metadata (protection, datestamp, comment, size, owner) is
identical to the previous snapshot's record, AND whose archive bit is
currently set, are reused without being re-read -- only genuinely
changed files cost real I/O and hashing. This is why the archive bit
matters to AmiSnap: it never trusts an already-clear bit as proof of
"unchanged" (a bit can be clear for reasons unrelated to AmiSnap), but
it does require the bit to be set as one of several conditions before
skipping a file.

## 3. See what's in the repository

```
1.C:> AmiSnap ACTION=LIST REPO=Backup:MyRepo
AmiSnap 0.1 (12.08.2026)
0000000000000605  360 entries  "first backup"
0000000000000616  360 entries  "second backup"
```

(`entries` counts every manifest record -- directories and files
together -- not a separate dir/file breakdown; `SNAPSHOT`'s own summary
line above is the one that splits them out.)

## 4. Verify a snapshot

```
1.C:> AmiSnap ACTION=VERIFY REPO=Backup:MyRepo
AmiSnap 0.1 (12.08.2026)
Verify 0000000000000616 (structural): 318 objects checked, 0 missing, 0 corrupt
```

With no `SNAPID=`, `VERIFY` (like `RESTORE`) targets the most recent
snapshot. Structural verify is fast (it checks the manifest and object
presence, not content); add `FULL` to also re-hash every stored object
against its recorded BLAKE2s-256:

```
1.C:> AmiSnap ACTION=VERIFY REPO=Backup:MyRepo FULL
```

## 5. Restore to an alternate location

Restore never writes back over `SOURCE=` by default -- give `DEST=` an
alternate path to prove the round trip without touching the original:

```
1.C:> AmiSnap ACTION=RESTORE REPO=Backup:MyRepo DEST=RAM:Restored
AmiSnap 0.1 (12.08.2026)
Restored 0000000000000616: 42 dirs, 318 files (2861440 bytes), 0 links skipped, 0 entries outside the subtree filter
Metadata: protection 360/360, comment 12/360, date 360/360, owner 0/360 ok
```

The second line is `RESTORE`'s own metadata report: how many entries
got each field applied successfully, out of how many entries actually
had that field to apply (`comment` is naturally low here -- most files
simply have no comment set; `owner` reads 0/360 on a system with no
`multiuser.library` or pre-V39 `dos.library`, since owner capture and
restore both degrade honestly rather than guessing).

Compare `RAM:Restored` against `Work:` (protection bits, comments,
datestamps included, not just file contents) to see the full metadata
round trip for yourself. `SUBTREE=<path>` restores only one directory
of the snapshot rather than the whole thing; see
[CLI Reference](CLI-Reference.md) for the exact syntax.

## 6. Keep only the last N snapshots

```
1.C:> AmiSnap ACTION=PRUNE REPO=Backup:MyRepo KEEP_LAST=7
```

Deletes every snapshot except the 7 most recent, then reclaims any
content object no longer referenced by anything that's left. See
[CLI Reference](CLI-Reference.md) for `PRUNE`'s other form
(`SNAPID=<id>`, delete exactly one snapshot).

## Where to go next

- [CLI Reference](CLI-Reference.md) for every `ACTION` and keyword,
  including `PARANOID`, `EXCLUDE=`, and the encryption/TLS options.
- [Exclude Lists](Exclude-Lists.md) to skip files/directories you never
  want backed up.
- [Encryption](Encryption.md) to protect a repository with a passphrase.
- [Disaster Recovery](Disaster-Recovery.md) for restoring from a PC if
  the Amiga itself is unavailable.

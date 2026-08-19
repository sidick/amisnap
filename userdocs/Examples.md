# Examples

A quick-reference cookbook of real AmiSnap invocations, covering the
variety of ways it's meant to be used. For a guided first run with real
verified output, see [Getting Started](Getting-Started.md); for every
keyword's full contract, see [CLI Reference](CLI-Reference.md).

## Mounted volume, the common case

```
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo COMMENT="nightly"
AmiSnap ACTION=LIST REPO=Backup:MyRepo
AmiSnap ACTION=VERIFY REPO=Backup:MyRepo
AmiSnap ACTION=RESTORE REPO=Backup:MyRepo DEST=RAM:Restored
```

No `INIT` step needed for a plain, unencrypted, uncompressed
repository -- the first `SNAPSHOT` creates whatever it needs. This is
Tier 1 (see [Destinations](Backends.md)): a local partition or a
network share mounted as a real DOS device (`smbfs`, `AmiNFS`), the
fastest tier and the primary recommendation for stock-speed hardware.

## WebDAV

```
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=http://nas.lan/dav/backups
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=https://nas.lan/dav/backups TLS13
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=https://nas.lan/dav/backups TLSINSECURE
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=https://user:pass@nas.lan/dav/backups
```

Plain `http://` on a trusted home LAN has no TLS overhead at all --
see [Performance](Performance.md) for why `https://` is not recommended
on stock-speed hardware. `TLSINSECURE` is for a self-signed certificate
on a home-lab server (an explicit, deliberate opt-out, never a
default); credentials can be embedded in the URL or left out (WebDAV
servers that don't require auth).

## S3-compatible object storage

```
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=s3://key:secret@minio.lan:9000/backups
```

Or, with credentials from the environment instead of the URL:

```
1.C:> Setenv AWS_ACCESS_KEY_ID <key>
1.C:> Setenv AWS_SECRET_ACCESS_KEY <secret>
1.C:> AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=s3://minio.lan:9000/backups
```

See [Destinations](Backends.md) for the region caveat (`?region=`
can't currently be passed safely on the command line -- use
`AWS_REGION` instead).

## An encrypted repository

```
1.C:> AmiSnap ACTION=INIT REPO=Backup:MyRepo PASSPHRASE
AmiSnap passphrase: ********
Confirm passphrase: ********
1.C:> AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo
AmiSnap passphrase: ********
```

One-time `INIT ... PASSPHRASE` before the first snapshot; every command
against an encrypted repository afterward prompts for the passphrase.
See [Encryption](Encryption.md), including `REKEY` for changing the
passphrase without re-encrypting existing content.

## A compressed repository

```
AmiSnap ACTION=INIT REPO=Backup:MyRepo COMPRESS=LZ4
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo
```

`COMPRESS=` at `INIT` is fixed for the repository's lifetime and picks
the default algorithm; override it per run with `SNAPSHOT ...
COMPRESS=DEFLATE` (harder compression, more CPU -- the right trade for
a slow uplink) or `COMPRESS=NONE` (skip compression for this run's new
objects without leaving the repository's own setting). Not sure which
algorithm suits your machine and destination? See `BENCHMARK` below.
`PASSPHRASE` and `COMPRESS=` compose freely on the same `INIT`.

## Excluding files from a snapshot

```
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo EXCLUDE=S:amisnap-exclude.txt
```

Where `S:amisnap-exclude.txt` is a plain-text pattern file -- see
[Exclude Lists](Exclude-Lists.md) for the wildcard/anchoring rules.

## Paranoid mode

```
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo PARANOID
```

Re-checks small "unchanged" files' actual content hash rather than
trusting metadata alone -- catches a file whose bytes changed while
every other piece of metadata (including the archive bit) happens to
still match. Costs real I/O on every run; see
[Performance](Performance.md).

## Restoring a specific snapshot, or just part of one

```
AmiSnap ACTION=RESTORE REPO=Backup:MyRepo DEST=RAM:Restored SNAPID=0000000000000605
AmiSnap ACTION=RESTORE REPO=Backup:MyRepo DEST=RAM:Restored SUBTREE=Projects/Amiga
```

`SNAPID=` defaults to the latest snapshot if omitted. `SUBTREE=`
restores only that path (and everything under it), preserving the full
relative path under `DEST=` rather than flattening it.

## Retention

```
AmiSnap ACTION=PRUNE REPO=Backup:MyRepo KEEP_LAST=7
AmiSnap ACTION=PRUNE REPO=Backup:MyRepo SNAPID=0000000000000605
```

`KEEP_LAST=<n>` keeps the `n` most recent snapshots and deletes the
rest; `SNAPID=` deletes exactly one, named snapshot instead.

## Verifying integrity

```
AmiSnap ACTION=VERIFY REPO=Backup:MyRepo
AmiSnap ACTION=VERIFY REPO=Backup:MyRepo FULL
```

Structural (default) confirms every object a snapshot's manifest
references actually exists at the right size -- fast, no content read.
`FULL` additionally re-reads and re-hashes every object's real bytes
against its declared hash, catching bit-rot a structural check can't.

## Benchmarking compression and a destination together

```
AmiSnap ACTION=BENCHMARK REPO=Backup:MyRepo
AmiSnap ACTION=BENCHMARK REPO=Backup:MyRepo SOURCE=Work: SIZE=1048576
```

The first samples synthetic mixed data; the second samples up to 1MiB
of real content from `Work:` instead, more representative of your
actual data. Reports measured LZ4/DEFLATE compression speed against
this destination's real write throughput and recommends a `COMPRESS=`
choice -- see [CLI Reference](CLI-Reference.md#benchmark). To compare
`CIPHERS=` choices for an `https://` destination, re-run with each
candidate:

```
AmiSnap ACTION=BENCHMARK REPO=https://nas.lan/dav/backups CIPHERS=AES128-SHA
AmiSnap ACTION=BENCHMARK REPO=https://nas.lan/dav/backups CIPHERS=ECDHE-RSA-AES128-GCM-SHA256
```

## Logging a run

```
AmiSnap ACTION=SNAPSHOT SOURCE=Work: REPO=Backup:MyRepo LOG=RAM:snapshot.log
```

`LOG=` works with every `ACTION` -- writes every diagnostic/summary
line to the given file (opened unbuffered, so a hang or crash never
leaves behind a misleadingly-empty log) in addition to the Shell.
Useful from a scheduled/unattended run.

## Recovering metadata that couldn't be restored directly

```
AmiSnap ACTION=APPLYUAEM SOURCE=Work:RestoredFromReader
```

Applies `.uaem` sidecar files -- written by
`tools/amisnap_reader.py restore ... --uaem` (the Python reference
reader) on a PC that has no real Amiga to apply metadata directly to,
or produced by an emulator's own host-directory mount (FS-UAE/
Amiberry/Copperline) -- once that directory reaches a real Amiga. See
[Disaster Recovery](Disaster-Recovery.md).

## Getting help

```
AmiSnap ACTION=HELP
AmiSnap --help
AmiSnap -h
AmiSnap ?
```

The first three all print the same usage text non-interactively and
exit cleanly; `AmiSnap ?` is the native AmigaDOS `ReadArgs()` prompt
(answer `?` again at that prompt for the same per-action detail).

# CLI Reference

AmiSnap is a single Shell command, `AmiSnap`, dispatched by a required
positional `ACTION` and a set of `KEY=value` (`/K`) or switch (`/S`)
arguments -- standard `ReadArgs()` keyword syntax, so quoting rules are
the usual AmigaDOS ones (wrap a value containing spaces in double
quotes). The full template, verbatim from the binary itself:

```
ACTION/A,SOURCE/K,REPO/K,DEST/K,SNAPID/K,SUBTREE/K,COMMENT/K,FULL/S,
LOG/K,KEEP_LAST/K/N,PARANOID/S,PASSPHRASE/S,COMPRESS/K,TLS13/S,
TLSINSECURE/S,CIPHERS/K,EXCLUDE/K,SIZE/K/N
```

`ACTION` is one of `SNAPSHOT`, `RESTORE`, `LIST`, `VERIFY`, `PRUNE`,
`APPLYUAEM`, `INIT`, `REKEY`, `BENCHMARK`, `HELP` (case-insensitive).
Each keyword below only does something for the actions it's listed
under; giving it elsewhere is silently ignored, not an error, since one
shared template covers every action (see "Why one template" at the end
of this page).

Two ways to get usage help: `AmiSnap ?` is the native AmigaDOS
convention (ReadArgs' own interactive prompt; answer `?` again at that
prompt for the same per-action detail `HELP` prints). `AmiSnap
ACTION=HELP` -- or, since a bare `--help`/`-h`/`-?` parses as the
`ACTION` value directly, `AmiSnap --help` / `AmiSnap -h` / `AmiSnap
-?` -- print the same text non-interactively and exit `RETURN_OK`, for
anyone coming from a Unix background or invoking it from a script.

## Return codes

Every AmigaDOS-standard value, checkable from a script with `IF WARN`
etc.:

| RC | Meaning |
|----|---------|
| 0 (`RETURN_OK`) | Full success. |
| 5 (`RETURN_WARN`) | Completed, but something was degraded or skipped -- reported in the summary line, not fatal. E.g. some files failed to read, some links were skipped, some objects were missing on verify. |
| 10 (`RETURN_ERROR`) | A usage/argument problem -- e.g. a required keyword missing, or `PRUNE` given both `SNAPID=` and `KEEP_LAST=`. |
| 20 (`RETURN_FAIL`) | The operation could not run at all -- repository unreachable, out of memory, a corrupt/missing manifest, a wrong passphrase. |

## SNAPSHOT

```
AmiSnap ACTION=SNAPSHOT SOURCE=<path> REPO=<path> [COMMENT=<text>]
                        [PARANOID] [EXCLUDE=<path>] [COMPRESS=LZ4|DEFLATE|NONE]
```

Creates a new snapshot of `SOURCE=` (an AmigaDOS path -- a volume,
assign, or subdirectory) inside `REPO=` (see
[Destinations](Backends.md) for what `REPO=` may be). `SOURCE=` and
`REPO=` must not overlap.

- `COMMENT=<text>` -- free-text note stored with the snapshot, shown by
  `LIST`.
- `PARANOID` -- for files at or under the chunk-size threshold, don't
  just trust a metadata match against the previous snapshot: re-read the
  file and cross-check its xxHash32 (recorded on every snapshot,
  paranoid or not) before skipping it. Catches a file whose bytes
  changed while every other piece of metadata (including the archive
  bit) happens to still match. A mismatch is reported separately from
  the ordinary "changed" count. Large (chunked) files skip this check --
  see [Performance](Performance.md).
- `EXCLUDE=<path>` -- a plain-text pattern file naming entries to skip
  entirely (never scanned, never emitted). See
  [Exclude Lists](Exclude-Lists.md) for the file format.
- `COMPRESS=LZ4|DEFLATE|NONE` -- only valid against a repository that
  was created with `INIT ... COMPRESS=` (compression is a repository
  property, fixed at init): overrides that repository's default
  algorithm for this run's new objects. `NONE` stores this run's new
  objects uncompressed (zero CPU cost) while the repository stays a
  compressed one; already-stored objects are never rewritten either
  way. On an uncompressed repository this keyword is an error, not a
  silent no-op.

The summary line reports dirs/files seen, how many files were unchanged
(reused without reading), how many failed to read, how many soft/hard
links were skipped (link restoration isn't implemented yet -- see
[the repository format doc](Repository-Format.md)), and how many
dirs/files an `EXCLUDE=` list matched.

## RESTORE

```
AmiSnap ACTION=RESTORE REPO=<path> DEST=<path> [SNAPID=<id>]
                       [SUBTREE=<path>]
```

Restores content and metadata from a snapshot into `DEST=`. Without
`SNAPID=`, the most recent snapshot is used. Without `SUBTREE=`, the
whole tree is restored; with it, only the entry at that exact path plus
everything under it (a real path-component match, not a string prefix
-- `SUBTREE=Work` does not also match `Workbench`). Full relative paths
are always preserved under `DEST=`, even for a subtree restore --
restoring `SUBTREE=Work/Projects` into `DEST=RAM:Recovered` produces
`RAM:Recovered/Work/Projects/...`, not a flattened copy.

Every restored file's content is verified against its recorded
BLAKE2s-256 hash before being written; restore aborts immediately on a
hash mismatch or a missing object rather than writing unverified
content. Metadata (protection, comment, datestamp, owner where
supported) is applied last, after content, so a restrictive protection
mask never blocks the restore of the file's own content first.

## LIST

```
AmiSnap ACTION=LIST REPO=<path>
```

Prints every snapshot in the repository: id, dir/file counts, and
comment.

## VERIFY

```
AmiSnap ACTION=VERIFY REPO=<path> [SNAPID=<id>] [FULL]
```

Without `SNAPID=`, verifies the most recent snapshot. Structural verify
(the default) checks the manifest decodes and every referenced object
exists; `FULL` additionally re-reads and re-hashes every object's
content against its recorded BLAKE2s-256. `VERIFY` never aborts early on
finding a problem -- its whole point is a complete report, so a run
always finishes and tells you exactly how many objects are missing or
corrupt.

## PRUNE

```
AmiSnap ACTION=PRUNE REPO=<path> SNAPID=<id>
AmiSnap ACTION=PRUNE REPO=<path> KEEP_LAST=<n>
```

Exactly one of `SNAPID=` or `KEEP_LAST=` must be given -- combining them
or giving neither is a usage error, not a guess at what you meant.
`SNAPID=<id>` deletes exactly that one snapshot. `KEEP_LAST=<n>` keeps
the `n` most recent snapshots and deletes every older one. Either way,
pruning deletes the target snapshot's manifest(s) first, then sweeps any
content object no longer referenced by any surviving snapshot -- a
crash partway through a `PRUNE` never corrupts a snapshot that wasn't
being deleted.

Calendar-bucketed retention (daily/weekly/monthly, beyond plain
"keep the last N") is not implemented yet.

## APPLYUAEM

```
AmiSnap ACTION=APPLYUAEM SOURCE=<path>
```

Walks `SOURCE=` looking for `.uaem` sidecar files (the FS-UAE/Amiberry/
Copperline host-directory-metadata convention: one plain-text line per
entry recording protection flags, datestamp, and an optional comment)
and applies each one to its corresponding real file via `SetComment()`/
`SetFileDate()`/`SetProtection()`. This is for metadata that arrived via
that convention -- e.g. a tree prepared on a PC and mounted into an
emulator's host-directory filesystem -- not part of AmiSnap's own
`SNAPSHOT`/`RESTORE` cycle, which applies metadata directly and never
needs `.uaem` sidecars for itself.

## INIT

```
AmiSnap ACTION=INIT REPO=<path> [PASSPHRASE] [COMPRESS=LZ4|DEFLATE]
```

One-time setup for an encrypted and/or compressed repository. Refuses
to run against a repository that's already initialized.

- `PASSPHRASE` -- make the repository encrypted; see
  [Encryption](Encryption.md) for the full picture.
- `COMPRESS=LZ4|DEFLATE` -- make the repository compressed: every
  content object is stored inside a compression frame, with the chosen
  algorithm as the default for every future `SNAPSHOT` (overridable
  per run -- see `SNAPSHOT`'s own `COMPRESS=`). `LZ4` is the
  CPU-budget choice (fast on a 68030, modest ratios); `DEFLATE`
  compresses harder and costs more CPU -- the right trade for a slow
  uplink. Files that don't shrink (LhA archives, ADFs, mods) are
  detected and stored raw inside their frame automatically, so
  compression is never a net loss. This choice is fixed for the
  repository's lifetime.

The two options compose. `INIT` with neither is a usage error: a
plain, uncompressed repository needs no `INIT` step at all -- just
`SNAPSHOT` straight to `REPO=`.

## REKEY

```
AmiSnap ACTION=REKEY REPO=<path>
```

Changes an encrypted repository's passphrase without touching the
repository key itself, so every already-written object and manifest
stays readable. Prompts for the current passphrase (failing closed on a
wrong one) and then the new one, twice.

## BENCHMARK

```
AmiSnap ACTION=BENCHMARK REPO=<path> [SOURCE=<path>] [SIZE=<bytes>]
```

Measures this machine and this destination together, so the
`COMPRESS=` choice at `INIT` (see above) can be a real answer instead
of a guess -- the right choice depends on the ratio of *this* CPU's
compression speed to *this* destination's real write throughput, and
that ratio varies enormously across the Amiga install base (a bare
68020 to an accelerated 060; a mounted local volume to WebDAV over
home broadband).

- Builds a sample: if `SOURCE=` is given, real file content read from
  it (up to `SIZE=`, default 512KiB) -- more representative of your
  actual data than a synthetic guess. Without `SOURCE=`, a synthetic
  50/50 mix of compressible and incompressible data, standing in for
  the realistic blend a real volume holds (text/structured data next
  to already-packed archives and tracker modules).
- Writes and reads that sample back from `REPO=` to measure real
  destination throughput (under `tmp/`, removed afterward; a later
  `PRUNE` sweeps it up even if removal itself fails).
- Times LZ4 and DEFLATE compressing the same sample.
- Reports each measurement, an estimated effective throughput for
  `NONE`/`LZ4`/`DEFLATE` (compress time plus write time at the
  measured rates), and which one to pass to `INIT ... COMPRESS=`.

To compare `CIPHERS=` choices for an `https://` destination, re-run
`BENCHMARK` once per candidate value and compare the "Destination
write" line -- see [Performance](Performance.md). `BENCHMARK`
deliberately doesn't loop over ciphers itself: AmiSSL has a real,
documented history of handshake fragility on this platform (see
`docs/implementation-plan.md`'s TLS section), and reopening it
repeatedly inside a shipped command is exactly the kind of thing that
provoked it before.

## HELP

```
AmiSnap ACTION=HELP
```

Prints the template plus the per-action detail above and exits
`RETURN_OK`. `--help`, `-h`, and `-?` are recognized as aliases (a
bare `AmiSnap --help` parses `--help` straight into the positional
`ACTION` value, so no special argument handling was needed beyond
recognizing those strings alongside the other action names).

## Cross-action keywords

- `LOG=<path>` -- also write every diagnostic/summary line to this file
  (opened unbuffered, so a crash or hang never leaves behind a
  misleadingly-empty log). Independent of `ACTION`.
- `TLS13` -- allow TLS 1.3 for this run's `https://` destinations (the
  default sticks to TLS 1.2; see [Destinations](Backends.md)).
- `TLSINSECURE` -- disable certificate verification entirely for this
  run's `https://` destinations. An explicit, deliberate opt-out --
  useful for a self-signed certificate on a home-lab NAS/WebDAV server,
  never a default.
- `CIPHERS=<list>` -- force a specific TLS cipher/list (a CPU-budget
  lever on accelerated hardware, not a security setting -- see
  [Performance](Performance.md)).

## Why one template

AmiSnap uses a single combined `ReadArgs()` template with `ACTION` as
the one required positional field, rather than a separate template per
action. `ReadArgs()`'s own `/A` (required) can't be made conditional on
another field's value, so each action validates its own required
keywords itself after parsing (e.g. `SNAPSHOT` without `SOURCE=`/`REPO=`
is a normal `RETURN_ERROR`, not a template-level rejection).

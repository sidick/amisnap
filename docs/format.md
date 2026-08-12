# AmiSnap repository format, version 1 (DRAFT)

This document is **normative**: the C implementation (`src/core/`) and
the host-side reference reader (`tools/amisnap_reader.py`) both cite
it, and CI asserts they agree. Any change to on-disk structures happens
here first, in the same commit as the code. Design constraints it
serves are in [implementation-plan.md](implementation-plan.md) and
[proposal.md](proposal.md): bit-perfect Amiga metadata, no filename
length assumptions, tag-extensible records, recoverable on a PC with
nothing but this document, cheap to read and write on a 68030.

Status: **draft** until the first repository written by shipped code
exists; field layout may still change. Once v0.x ships a repository to
a real user, v1 is frozen — additions happen only via new tags, and
incompatible changes require a format-version bump.

## Conventions

- All multi-byte integers are **big-endian, unsigned** unless stated
  otherwise. (Native for the 68k writer; trivial everywhere else.)
- `u8`/`u16`/`u32`/`u64` are unsigned integers of that byte width.
- **Strings** are a `u16` byte count followed by that many bytes — no
  NUL terminator, no length ceiling below 65535, and **no character-set
  conversion**: filenames, comments, and volume names are stored as the
  exact byte sequence the filesystem returned (in practice Latin-1 on
  classic AmigaOS). Fidelity over prettiness; presentation-layer
  transcoding is a reader's problem.
- **Hashes** are BLAKE2s-256: 32 bytes. Hex encodings (object names)
  are lower-case.
- **Datestamps** are the native AmigaOS `struct DateStamp`, stored as
  three `u32`s: days since 1978-01-01, minutes past midnight, ticks
  (1/50 s) past the minute. No conversion to Unix time anywhere in the
  format — conversion loses the platform's native precision and epoch,
  and it's the reader's job if wanted.

## TLV encoding

Every structured file is a sequence of **records**; every record is a
sequence of **fields**. Both levels use one primitive:

```
tag     u16
length  u32     byte length of value (0 permitted)
value   length bytes
```

Rules:

- Fields within a record may appear in any order unless stated; a tag
  MUST NOT appear twice in one record unless the field is explicitly
  repeatable.
- **Unknown non-critical tags are skipped** (that's what the length is
  for). Tags with the **high bit set (0x8000) are critical**: a reader
  encountering an unknown critical tag MUST NOT claim a complete read
  of that record — it fails, or reports the record as partially
  understood, but never silently drops it. Writers use critical tags
  only for fields whose omission would corrupt a restore.
- Integers inside a value use the smallest declared width; a field's
  layout is fixed by its tag definition below, not self-describing.

## Limits (explicit, not implied)

The format's only structural limits are inherited from the encoding
primitives; they are stated here so writers can enforce them loudly
rather than anyone discovering them by truncation:

- **Any single string: 65,535 bytes** (u16 byte count). Real
  filesystem ceilings — 107-byte filenames on long-name FFS/SFS/PFS3,
  79-byte FileNotes on FFS — sit far below this; no string a classic
  filesystem can produce comes near it.
- **A full E_PATH: 65,535 bytes total**, since it is one string. This
  is the format's one real ceiling: a path ~600 maximum-length
  components deep would exceed it. **A writer encountering a path that
  does not fit MUST fail that entry with a logged error — never
  truncate, never silently skip** (the "degrades explicitly" rule).
  The snapshot as a whole may continue and MUST report the failure in
  its summary and RC.
- Non-limits, for the record: directory *depth* is unconstrained
  except through the path total (entries are a flat list, nothing
  compounds); TLV values are u32-length (4GB); entries per manifest
  u32 (~4.3 billion); file sizes u64.

## Common file header

Every structured repository file (repository header, manifest — not
content objects) begins:

```
magic    4 bytes   "ASNP"
ftype    u8        1 = repository header, 2 = manifest
version  u8        format version, = 1
flags    u16       reserved, = 0; readers ignore unknown bits
```

A reader MUST refuse a file whose `version` it does not implement.

## Repository layout

Expressed as backend paths (the backend API maps them to a directory
tree, WebDAV collection, or S3 key prefix identically; `/` is the
separator at this layer and never appears in stored Amiga filenames):

```
amisnap.repo                     repository header
snapshots/<snapid>.mf            one manifest per snapshot
objects/<hh>/<hex64>             content objects, by BLAKE2s-256 hex
                                 (<hh> = first two hex chars, fan-out)
```

`<snapid>` is 16 lower-case hex characters: the snapshot's creation
`DateStamp` packed as `days:u32 . mins:u16 . ticks:u16`, so
lexicographic order is chronological order. If that exact id already
exists (two snapshots in the same tick), the writer increments ticks
until free — ids are identifiers, not authoritative times; the
authoritative creation time is inside the manifest.

## Repository header (`amisnap.repo`)

Common header (`ftype`=1), then records:

**REC_REPO (tag 0x8001, critical)** — exactly one. Fields:

| tag    | name        | value |
|--------|-------------|-------|
| 0x8010 | REPO_ID     | 16 random bytes, fixed at init; lets a client detect that a destination was re-initialized out from under its cached index |
| 0x8011 | CIPHER      | u8: 0 = none, 1 = ChaCha20 + keyed-BLAKE2s-256 MAC (see Encryption) |
| 0x0012 | CHUNK_SIZE  | u32: fixed chunk split threshold/size in bytes (default 8388608); informational — refs are self-describing |
| 0x8013 | KDF         | present iff CIPHER != 0: `kdfid:u8` (1 = PBKDF2-HMAC-SHA256) `iters:u32` `salt: string` |
| 0x8014 | WRAPPED_KEY | present iff CIPHER != 0: the 32-byte repository key encrypted with the KDF-derived key (layout per Encryption section) |
| 0x0015 | FORMAT_APP  | string, e.g. `"AmiSnap"`: stamped once at repository init, purely for self-identification — someone who finds a stray `amisnap.repo` with no other context and runs `strings` on it (magic `"ASNP"` plus this) learns what wrote it without needing a parser. Informational only; a reader MUST NOT branch on its value (that's what `ftype`/`version`/`CIPHER` are for) — it names the tool, not a contract. |

A reader that does not implement the stated CIPHER MUST refuse the
repository (critical tags make this automatic for future ciphers).

## Content objects (`objects/<hh>/<hex64>`)

The object name is the BLAKE2s-256 of the object's **plaintext**
content — dedup and `verify` always operate on plaintext identity,
independent of encryption.

- **Plain repository (CIPHER 0):** the object file IS the raw content
  bytes. No header, no framing — `b2sum`-equivalent tooling can verify
  a repository with no AmiSnap code at all, and disaster recovery is
  `cat`.
- **Encrypted repository (CIPHER != 0):** see Encryption below.

An object holds either a whole file's content or one chunk of a large
file; the object itself doesn't know which — manifests do.

## Manifest (`snapshots/<snapid>.mf`)

Common header (`ftype`=2), then records in this order:

1. exactly one **REC_SNAP**
2. one **REC_VOLUME** per source volume, each followed immediately by
   the REC_ENTRY records belonging to it
3. REC_ENTRY records, **depth-first, directories before their
   contents** (so a restore can create structure in read order)
4. exactly one **REC_END**, last

### REC_SNAP (tag 0x8002, critical)

| tag    | name       | value |
|--------|------------|-------|
| 0x8020 | CREATED    | DateStamp (3×u32): authoritative snapshot creation time |
| 0x0021 | HOSTNAME   | string: user-configured machine label, may be absent |
| 0x0022 | TOOLVER    | string: e.g. "AmiSnap 0.1" — forensic, never parsed |
| 0x0023 | COMMENT    | string: user-supplied snapshot note |

### REC_VOLUME (tag 0x8003, critical)

Forensic identity + restore-time compatibility data for one source
volume (proposal, "Repository format"):

| tag    | name          | value |
|--------|---------------|-------|
| 0x8030 | VOL_ROOT      | string: the source path this volume section was snapshotted from, e.g. "Work:" or "Work:Projects" |
| 0x0031 | VOL_NAME      | string: volume name |
| 0x0032 | VOL_DOSTYPE   | u32: e.g. 0x444F5303 "DOS\3", 0x444F5307 "DOS\7", "PFS\3", "SFS\0" |
| 0x0033 | VOL_CREATED   | DateStamp: volume creation date |
| 0x0034 | VOL_CAPS      | probed capabilities, not inferred from DosType: `maxnamelen:u16` `flags:u16` (bit 0: owner support observed, bit 1: FileNote support observed; rest reserved 0) |

### REC_ENTRY (tag 0x8004, critical) — one per path

| tag    | name       | value |
|--------|------------|-------|
| 0x8040 | E_PATH     | string: path relative to VOL_ROOT, components joined with `/` (illegal in Amiga filenames, so unambiguous). Empty = the root itself (carries the root dir's metadata). |
| 0x8041 | E_TYPE     | u8: 1 file, 2 directory, 3 softlink, 4 hardlink |
| 0x8042 | E_PROT     | u32: the **full 32-bit protection mask, verbatim** (`fib_Protection` semantics: low nibble RWED active-low, HSPA). Verbatim means field-blind: the MultiUser (muFS) group/other RWED bits, its setuid bit, and any bit a future filesystem defines all round-trip untouched, because the mask is never re-encoded field by field. |
| 0x8043 | E_DATE     | DateStamp (3×u32), ticks precision |
| 0x0044 | E_COMMENT  | string: the FileNote, byte-exact; absent = no comment (readers MUST distinguish absent from empty) |
| 0x0045 | E_OWNER    | `uid:u16` `gid:u16` (ExAll ED_OWNER — what muFS exposes); absent = filesystem had none. **Numeric IDs verbatim**: the muFS passwd database (name↔ID mapping) is deliberately not stored — restoring onto a system whose user database assigns the IDs differently applies the numbers as-is, an honest documented limit, and restore reports owner application skipped where the target has no owner support at all. |
| 0x8046 | E_SIZE     | u64: file byte size. Required for E_TYPE 1; absent otherwise. (u64, not u32: the format outlives 4GB even if OS 3.x sources can't produce it) |
| 0x8047 | E_CONTENT  | repeatable, ordered: one per content ref, `hash:32 bytes` `size:u64`. Concatenation of refs in record order reconstructs the file; ref sizes MUST sum to E_SIZE. One ref = whole file; several = fixed-size chunks. Required for E_TYPE 1 with E_SIZE > 0. |
| 0x8048 | E_LINK     | string, required for E_TYPE 3/4: link target. Softlink: target path verbatim as stored by the filesystem. Hardlink: the E_PATH of the entry (same volume section, earlier in the manifest) this links to. |
| 0x0049 | E_XHASH    | u32: xxHash32(content, seed 0) — advisory accelerator for the paranoid-verify and dedup fast paths; readers never trust it for integrity |

### REC_END (tag 0x8005, critical) — exactly one, final record

| tag    | name       | value |
|--------|------------|-------|
| 0x8050 | END_COUNT  | u32: number of REC_ENTRY records — truncation tripwire |
| 0x8051 | END_HASH   | 32 bytes: BLAKE2s-256 over every manifest byte from `magic` up to (not including) this REC_END record — manifests aren't content-addressed, so they carry their own integrity check |

A manifest without a valid REC_END is not a snapshot (see Commit
protocol) — readers MUST treat it as absent/corrupt, never as "best
effort".

## Snapshot commit protocol (normative for writers)

1. Write all content objects. An object write is: put to
   `tmp/<hex64>`, finalize (rename) to `objects/<hh>/<hex64>`.
   Finalize-onto-existing is a no-op (dedup). Objects already present
   are never rewritten.
2. Write the manifest to `tmp/<snapid>.mf`, REC_END last.
3. Finalize (rename) to `snapshots/<snapid>.mf`. **This rename is the
   commit.** Before it, the repository is exactly the previous set of
   snapshots plus unreferenced garbage in `tmp/` and possibly some
   pre-deduplicated objects — all harmless, all reclaimed by prune's
   sweep.

Backends MUST provide atomic-on-success finalize (POSIX/AmigaDOS
rename; S3: a single PUT of the full manifest serves as both steps).

## Prune (normative for writers)

1. Delete the target snapshot's manifest. The snapshot ceases to exist
   atomically.
2. Mark: read every remaining manifest, collect referenced hashes.
3. Sweep: delete unreferenced objects, then stale `tmp/` files.

Interruption anywhere leaves only harmless garbage (sweep re-run
collects it), never a manifest referencing a deleted object — because
deletion order is always manifest-first, objects-second.

## Encryption (CIPHER 1) — framing fixed now, activated phase 4

Fixed in v1 so the format never breaks when encryption lands:

- The 32-byte **repository key** is random at init, stored KDF-wrapped
  in the repository header (WRAPPED_KEY), and never changes — so
  losing/changing the passphrase re-wraps one header field, not the
  repository.
- **Objects:** `nonce:12 bytes` `ciphertext` `mac:16 bytes`, where
  ciphertext = ChaCha20(key, nonce, plaintext) and mac = first 16
  bytes of keyed-BLAKE2s-256(key=MAC subkey, nonce ‖ ciphertext).
  Object *names* remain the plaintext hash (dedup works; accepted
  trade-off: an attacker with the repository learns plaintext equality
  and sizes, documented honestly).
- **Manifests:** same framing, applied to the whole file after the
  common header; `flags` bit 0 of the common header set = body is
  encrypted.
- Subkey derivation, WRAPPED_KEY layout, and nonce discipline are
  specified precisely in phase 4 alongside the vendored AmiAuth
  crypto; until then CIPHER MUST be 0 and readers refuse otherwise.
  These details may be refined while draft status lasts, but the
  record/tag structure above is fixed.

## Local index cache

The Amiga-side per-repository index (fast incremental change
detection) is **explicitly outside this specification**: it is a
disposable cache derived from the latest manifest, self-healing by
re-fetch, and its layout may change in any release without a format
bump. It never travels to a destination. (It is documented in a code
comment, not here, precisely so nobody mistakes it for interchange.)

## What a reader needs for disaster recovery

By design, a from-scratch reader (the Python reference reader, or a
human with this document): parse `amisnap.repo` (refuse unknown
version/cipher), list `snapshots/`, pick a manifest, check END_HASH,
then for each entry concatenate its E_CONTENT objects (verifying each
against its name) and apply metadata as far as the target system
allows, reporting what it couldn't apply. No index, no AmiSnap
binaries, no Amiga required.

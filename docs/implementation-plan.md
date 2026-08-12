# AmiSnap implementation plan

This is the working plan for building AmiSnap in this repository. The
design document of record is [proposal.md](proposal.md) — this file
turns it into concrete modules, work order, and release gates, and
records design decisions made since the proposal was written. Where the
two disagree, this file wins (each divergence is called out explicitly).

## Design principles (binding)

1. **A data-losing bug is fatal.** Every skip decision must be provably
   safe; every destructive operation (prune, restore-over) is
   mark-and-sweep or staged, never in-place. A crashed run leaves the
   previous snapshot fully intact: content objects are written first,
   the manifest commit is the atomic last step.
2. **The CPU budget is a 68030** (proposal, "CPU budget"). SHA-256 is
   never mandatory. xxHash32 may be used freely; BLAKE2s once per
   new/changed file; ChaCha20/TLS are per-destination opt-ins
   defaulting to off.
3. **Metadata is the product.** Full 32-bit protection mask, FileNotes,
   ticks-precision datestamps, owner/group where present, long
   filenames — captured via `ExAll()`/`Examine()` only, no filesystem
   internals. Restore degrades explicitly, never silently.
4. **Portable core, thin Amiga rind.** Everything that can be host-built
   lives in `src/core/` and is exercised by host CI on every push. Code
   in `src/amiga/` is limited to OS calls: metadata capture/restore,
   DOS I/O, and (later) bsdsocket transports.
5. **The repository format is a contract.** Documented, versioned,
   tag-extensible; the host-side Python reference reader is updated in
   the same change as any format change, and CI cross-checks the two
   implementations against each other.
6. **Real functions, not guessed heuristics** (house rule): behavior
   comes from documented contracts (autodocs, RKRM, RFC, the xxHash/
   BLAKE2 specs) and is verified against reference implementations or
   a real emulator, never assumed from compilation.

## Decisions since the proposal

### The archive bit is corroboration, never sole evidence (2026-08-12)

The proposal's parenthetical has the semantics inverted; the real
contract (dos.library `FIBF_ARCHIVE`) is: **the filesystem clears the
bit when a file is written; backup software sets it.** Beyond that
correction, the bit is weaker than the proposal implies:

- Any `SetProtection()` with a full mask stomps it (`Copy CLONE`,
  `Protect`, LhA extraction, installers) — a set bit can appear on a
  file we never backed up, and trusting it would silently skip changed
  data.
- It is one shared bit with no owner: another backup tool — or a second
  AmiSnap repository — corrupts its meaning for everyone else.
- It is blind to metadata-only changes (`SetComment()`/
  `SetProtection()` don't clear it), and FileNotes are user data here.
- It arrives in the same `ExAll()` record as size/datestamp/comment, so
  reading it costs the same directory scan as full metadata comparison
  — the "fast path" speed win comes from `ExAll()` itself, not the bit.

Policy, replacing the proposal's:

- **Skip a file only when metadata matches the index AND the archive
  bit is set.** Either signal alone saying "dirty" means examine. The
  bit's clear state catches the one case metadata comparison misses (a
  writer that restores the datestamp); metadata comparison catches
  everything a stomped bit misses. The combined failure (restored
  datestamp + externally set bit) is paranoid mode's job.
- **A set bit means nothing when the index has no entry** (first run,
  fresh index): examine.
- **AmiSnap does not set the bit by default.** Setting it mutates the
  source volume mid-backup and sabotages other tools and our own
  multi-repository story; the index carries the real state. A
  per-source `SETARCHIVE` option exists for users who want the bit
  maintained for other tools' benefit — the skip rule above degrades
  gracefully either way (bit never set by us → the AND simply requires
  a metadata match plus a bit some earlier archiver set; with no
  set bit the file is examined, which is safe, just slower).

Consequence: on a source where nothing maintains the bit, incremental
runs are pure metadata-compare — that alone must meet the 10k-files/
under-a-minute success criterion, and the Phase 1 benchmark verifies it
without relying on the bit.

## Minimum requirements

- **68020, AmigaOS 3.0 (V39), no FPU** (`-m68020 -msoft-float
  -noixemul`). V39 supplies `SetOwner()`; the network-backup audience
  skews accelerated/emulated. Check the NDK autodocs before using
  anything newer than V39, and gate it at runtime if used.
- RAM target: comfortable on 4MB fast for ~50k files (index streamed/
  windowed, never fully resident); the encrypted/TLS cloud tier may
  document 8MB+.

## Architecture and module map

```
src/core/           portable engine (host CI runs all of it)
  xxhash32.[ch]       change-detection hash              [done]
  blake2s.[ch]        integrity hash (RFC 7693)          [phase 1]
  meta.[ch]           metadata record model: the tag-based, extensible
                      per-path record (protection, comment, datestamp,
                      owner, links) + encode/decode       [phase 1]
  manifest.[ch]       snapshot manifest: paths + metadata + content
                      refs; serialize/parse               [phase 1]
  index.[ch]          local snapshot index: streamed compare of an
                      ExAll-shaped walk against the last snapshot;
                      the skip rule lives here            [phase 1]
  repo.[ch]           repository layout + operations over a backend:
                      content-addressed objects, snapshot commit
                      (atomic last), verify, prune        [phase 1-2]
  backend.h           the backend API: open/put/get/list/delete/close
                                                          [phase 1]
  backend_dir.c       portable directory backend — on Amiga this IS
                      Tier 1 (any mounted volume); on the host it is
                      the CI test backend                 [phase 1]
  chunk.[ch]          fixed-size split for files > threshold (8MB
                      default)                            [phase 2]
  chacha20/pbkdf2/hmac  vendored from AmiAuth v1.0        [phase 4]
  webdav.c, s3.c      protocol clients over a socket abstraction
                                                          [phase 3/5]

src/amiga/          m68k build only
  scan.c              ExAll()/Examine() volume walk producing the
                      core's neutral entry records; long-name + ED_OWNER
                      sized buffers; per-volume capability probe
                      (DosType, name length, owner support) [phase 1]
  restore_meta.c      SetProtection/SetComment/SetFileDate/SetOwner,
                      applied metadata-last; degradation policy
                      (fail/skip/truncate+log)             [phase 1]
  dosio.c             DOS I/O for backend_dir on real volumes [phase 1]
  socket.c            bsdsocket glue for webdav/s3         [phase 3]
  tls.c               soft-loaded AmiSSL, per-destination  [phase 3]

src/cli/            AmiSnap front-end: ReadArgs templates per command,
                    RC codes, logging (summary line + optional verbose
                    file)                                  [phase 1]

tools/
  amisnap_reader.py   host-side reference reader — parses manifests/
                      indexes/objects independently of the C code;
                      grows into the disaster-recovery extractor
                                                           [phase 2]

tests/              host vector/unit tests (test.h harness) + CI
                    round-trip suite + Copperline/Amiberry on-target
                    harnesses
```

Dependency direction: `cli → repo → (index, manifest, backend)`,
`index → meta`, everything → hashes. `src/amiga/` implements interfaces
`src/core/` declares (scan entries, backend I/O); core never includes
Amiga headers.

## Repository format work (phase 1, before code that writes it)

Format design is its own deliverable, written down in
`docs/format.md` *before* the serializers exist, because v1 mistakes
are permanent (proposal: no 30-char name assumption, tag-based records,
full superset metadata):

- Content objects stored under BLAKE2s-256 hash; whole-file at first
  (chunking is phase 2, but the manifest's content-ref record is
  designed to reference either from day one).
- Manifest: per-snapshot, listing every path with its full metadata
  record and content refs; plus per-volume identification (DosType,
  volume name/creation date, probed capability set).
- All multi-byte integers big-endian, all records length-prefixed and
  tagged; unknown tags skippable. Format version in every file header.
- Local index: a cache derived from the latest manifest, self-healing
  (re-fetch if missing/stale) — its format may change freely; the
  manifest format may not.
- `docs/format.md` is normative; both the C implementation and
  `amisnap_reader.py` cite it, and a CI test asserts a repository
  written by the C code is fully parsed by the Python reader,
  bit-for-bit metadata equal.

## Phases

Each phase ends green on all five CI verbs and gets committed per
section as it goes; a phase's release gate is a working, honest
deliverable, not scaffolding.

**Phase 1 — Engine + Tier 1 (the product's core).**
Order of work within the phase:

1. `blake2s` with RFC 7693 vectors (reference-verified, like xxhash32).
2. `docs/format.md` v1 draft + `meta` encode/decode with round-trip
   property tests (random metadata records survive encode→decode
   bit-for-bit; host CI).
3. `manifest` + `backend.h` + portable `backend_dir` + `repo` write
   path: `snapshot` against a host directory tree works under CI.
4. `index` + change detection implementing the archive-bit policy
   above; `list`.
5. `restore` (full/subtree, alternate path, metadata-last) + `verify`
   (structural; `FULL` re-hashes) against the directory backend.
6. Amiga side: `scan.c`, `restore_meta.c`, `dosio.c`, capability probe;
   CLI with ReadArgs templates and RC codes.
7. On-target harness: Copperline job snapshots a guest tree, host
   asserts metadata fidelity via `.uaem` sidecars; Amiberry smoke test
   against a Samba share for the real-NAS path.

Gate: snapshot → wipe → restore on FFS is metadata-bit-perfect in the
emulator harness; 10k-file unchanged run under a minute on emulated
68030 without archive-bit help.

**Phase 2 — Prune + hardening + reference reader.**
Retention pruning (`keep last N/daily/weekly/monthly`, mark-and-sweep),
interrupted-run recovery (resumable writes, atomic manifest commit),
paranoid verify mode (xxHash re-check of "unchanged" files), fixed-size
chunking for large files, `tools/amisnap_reader.py` + the CI
cross-implementation check. Gate: kill -9 mid-snapshot at any point
leaves a repository `verify` passes on; Python reader restores a
snapshot's full tree+metadata with the C code uninvolved.

**Phase 3 — WebDAV.** HTTP/1.1 client (PUT/GET/MKCOL/PROPFIND,
keep-alive, resumable) over `src/amiga/socket.c`; per-destination
`TLS=YES` via soft-loaded AmiSSL (absent library + TLS requested =
clear failure, plaintext destinations never touch it). Host CI runs the
protocol code against a local WebDAV container.

**Phase 4 — Encryption.** Vendor ChaCha20/PBKDF2/HMAC from AmiAuth
v1.0; key file with optional passphrase wrap; BLAKE2s joins AmiAuth's
vector + OpenSSL-differential-fuzz regime. Format already carries the
encryption tags from day one (designed in phase 1, unused until here).

**Phase 5 — S3.** SigV4 with `UNSIGNED-PAYLOAD`, large objects, tested
against MinIO in CI and B2 manually.

**Phase 6 — Release.** AmigaGuide + MkDocs user docs (add `userdocs/` +
`make guide` following the siblings), honest per-tier performance
guide, disaster-recovery walkthrough using the reference reader, beta
period framed as "run alongside your existing method", Aminet release
via the existing tag-driven pipeline. At 1.0: at least one full user
backup rotation reported from real hardware.

Post-1.0 (proposal "Future goals", unchanged): `amisnap-tool` host
client growing out of the reference reader, commodity scheduler,
ClassAct GUI + ARexx, repository mirroring.

## Testing strategy

- **Host CI (every push):** vector tests for every primitive
  (reference-verified before recording — house rule), round-trip
  property tests on metadata encoding, full
  snapshot/restore/prune/verify cycle against the directory backend,
  C↔Python cross-implementation check, and (from phase 3/5) container
  services (WebDAV, MinIO).
- **On-target (Copperline):** deterministic boot, snapshot inside the
  guest, assert `.uaem` sidecar metadata on the host; deterministic
  `rtc_time` makes "byte-identical repository given identical input" a
  testable property. Skips honestly (like today's `run.sh`) when local
  ROM/Workbench config is absent.
- **On-target (Amiberry):** smoke test against a real Samba mount,
  muFS owner round-trip.
- **Benchmarks as tests where they gate design:** the 10k-file
  incremental target and hash throughput get a repeatable harness
  before any 68k asm optimization is considered (proposal's asm plans
  are strictly post-correctness).

## Risks being actively managed

Carried from the proposal, with plan-level mitigations: trust/data loss
(atomic commit + verify-first-class + kill-mid-run tests), filesystem
variance (capability probe per volume, FFS/long-FFS/PFS3 matrix),
index memory (streamed compare, 4MB target), archive-bit ambiguity
(resolved — see Decisions above).

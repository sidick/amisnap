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

### OS floor is V37, not V39 — later APIs are runtime-gated (2026-08-12)

The CPU floor (68020) and the OS floor are separate decisions; the
original 68020+V39 bundling in "Minimum requirements" set the OS floor
higher than anything actually in use requires. AmigaOS 2.04 (V37) is
the real floor now, matched opportunistically at runtime with anything
newer that a given system provides — the same pattern this project
already uses for AmiSSL (soft-loaded, absent = plaintext fallback, not
a hard dependency) and per-volume filesystem capability probing
(`VOL_CAPS`, "observed" not assumed from `DosType`), just applied to
the OS version axis too.

**Why this is safe to do, and why it's not just "call it and see":**
Amiga library calls resolve through a jump table sized to what that
copy of the library actually implements. Calling an offset a V39+-only
function occupies, against a V37 library, is not a clean "function not
found" — it is a call into whatever happens to sit past the end of the
real table on that system. So every call to a function newer than V37
**must** be preceded by an explicit runtime version check (e.g.
`((struct Library *)DOSBase)->lib_Version >= 39`), never a bare call
guarded only by a compile-time `#if` or a hopeful try. This is the
house rule for any such call, present or future — the checklist to run
through when adding one: (1) confirm the real minimum version against
the NDK autodocs (house rule 6: verify, don't assume) rather than a
version number half-remembered from documentation prose; (2) gate the
call behind a runtime check of the *specific* library's version, not a
global "is this a modern Kickstart" guess; (3) define and honor an
explicit fallback for the V37 case — normally the same "capability not
supported, report it, don't fail the operation" pattern restore
already commits to for cross-filesystem degradation.

**Currently known instance:** `SetOwner()` (restore-side ownership
application) is V39+; on V37 it is simply unavailable, and restore's
already-planned "owner applied where supported, reported as skipped
where not" behavior covers this for free once the version check
exists — no new degradation path needed, just gating the call.
**Open, to verify when `scan.c` is actually written (not assumed
now):** whether `ExAll()`'s `ED_OWNER` tag (the *read* side, capturing
ownership into a snapshot) is available on V37, or is itself gated
later — the NDK autodocs are the source of truth here, not this
document's memory of them.

## Minimum requirements

- **68020, AmigaOS 2.04 (V37), no FPU** (`-m68020 -msoft-float
  -noixemul`). CPU floor: the network-backup audience skews
  accelerated/emulated. OS floor: V37, with newer APIs (e.g. V39's
  `SetOwner()`) used opportunistically and runtime-gated per the
  decision above — check the NDK autodocs before using anything newer
  than V37, and never call it without a version guard.
- RAM target: comfortable on 4MB fast for ~50k files (index streamed/
  windowed, never fully resident); the encrypted/TLS cloud tier may
  document 8MB+.

## Stack management (StackSwap)

The Shell's default stack (as little as 4000-8000 bytes depending on the
caller's `STACK` setting) and a Workbench icon's default stack tooltype
are both far too small for this program, and an Amiga stack overflow is
silent corruption, not a clean crash -- unacceptable under principle 1
(a data-losing bug is fatal). AmiSnap does real recursion and deep call
chains from day one: `scan.c`'s directory walk, BLAKE2s/manifest
encoding call depth, and (later) chunking/crypto layered on top of I/O.

Policy: **`main()` swaps to an explicitly allocated, generously sized
stack via `StackSwap()` before any real work runs**, unconditionally,
regardless of what stack it was launched with. Sized well above any
measured watermark (start at 32KB, revisit once `scan.c`'s real
recursion depth against a deep test tree is measured -- see below), one
`AllocMem()`/`FreeMem()` pair per process lifetime, restored via a
second `StackSwap()` before exit so DOS gets its own stack back on the
way out. This lands with the Phase 1 CLI skeleton
(`src/amiga/stackswap.c`/`.h`), not deferred to "later hardening" --
every subsequent phase's code runs on top of it from the start rather
than being retrofitted once something actually overflows.

**Testing (host CI, not just on-target):** the CI container
(`ghcr.io/sidick/amiga-dev`) already has `vamos` (amitools' m68k
emulator, confirmed available there; already how sibling AmiAuth runs
its asm crypto tests under `make test-host`). vamos can launch the
cross-built `AmiSnap` binary directly with a deliberately tiny stack, so
`test-host` gets a real regression test: run a deep-recursion operation
(e.g. `scan` against a fixture tree many directories deep) under vamos
first with the *unswapped* default stack size to confirm it fails
predictably (or is skipped as N/A pre-StackSwap-landing), then with
`StackSwap()` in place to confirm the same operation succeeds -- proving
the swap actually happens and is sized adequately, without needing
Copperline/Amiberry for this specific property.

## Architecture and module map

```
src/core/           portable engine (host CI runs all of it)
  xxhash32.[ch]       change-detection hash              [done]
  blake2s.[ch]        integrity hash (RFC 7693)          [done]
  tlv.[ch]            shared big-endian TLV framing (write buffer,
                      read cursor, scalar/string codecs, the
                      critical-tag rule) -- format.md "TLV encoding"
                      and "Conventions"; meta.c and (later) manifest.c
                      both build on this                  [done]
  meta.[ch]           metadata record model: REC_ENTRY, the tag-based,
                      extensible per-path record (protection, comment,
                      datestamp, owner, links) + encode/decode; 500-case
                      random round-trip property test      [done]
  manifest.[ch]       snapshot manifest: REC_SNAP/REC_VOLUME/REC_END +
                      the REC_ENTRY sequence meta.c encodes/decodes;
                      streaming writer, visitor-based reader enforcing
                      record order, END_COUNT, and the END_HASH
                      self-check                            [done]
  index.[ch]          local snapshot index: builds a lookup from a
                      decoded manifest (amisnap_index_build/lookup,
                      O(n) linear scan for now -- flagged as the
                      candidate to optimise if the 50k-file benchmark
                      needs it, not assumed in advance) and implements
                      the archive-bit skip rule
                      (amisnap_index_unchanged)                [done]
  repo.[ch]           repository layout + operations over a backend:
                      write path done (content-addressed objects with
                      exists()-gated dedup, snapshot commit atomic
                      last, snapid collision handling); verify/prune
                      land in phase 2                [write path done]
  backend.h           the backend API: put/get/exists/list/remove/
                      close, one vtable + opaque ctx        [done]
  backend_dir.c       portable directory backend — on Amiga this IS
                      Tier 1 (any mounted volume); on the host it is
                      the CI test backend. Built on stdio/mkdir/
                      opendir/readdir/rename, no #ifdefs; confirmed
                      compiling AND linking clean under m68k-amigaos-
                      gcc -noixemul (libnix genuinely provides these,
                      not just headers) -- the module map's "portable
                      core, not src/amiga/" assumption held. Real
                      on-target *execution* of it is still unverified
                      (no CLI wiring yet to exercise it on real
                      hardware) -- confirm when item 6/7 lands; if it
                      turns out wrong, dosio.c's src/amiga/ split is
                      the documented fallback              [done]
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
  stackswap.[ch]      StackSwap() to a generously sized allocated
                      stack at process start -- see "Stack management"
                      above; every other Amiga-side module runs on top
                      of this from the start                [phase 1]
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
                    round-trip suite + vamos m68k-binary runs (stack
                    swap, asm) + Copperline/Amiberry on-target
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
   **Done.** Independently-verified round trip (writer's output read
   back via a fresh backend_get + manifest_decode, not the writer's
   own state), dedup confirmed to actually skip the second write (not
   just overwrite-with-identical-bytes), snapid collision handling
   exercised. amisnap.repo/REC_REPO (repository-level metadata: REPO_ID,
   CIPHER, CHUNK_SIZE, FORMAT_APP) deliberately deferred -- nothing in
   this gate needed it, since repo.c assumes CIPHER=0 -- lands with
   whichever later item first needs to read it back.
4. `index` + change detection implementing the archive-bit policy
   above; `list`. **Done.** `amisnap_index_build()` decodes a manifest
   into an owned, path-lookupable array (each entry's own content-ref
   copy preserved, not just borrowed -- future snapshot writes can
   reuse an unchanged file's content ref without re-reading it);
   `amisnap_index_unchanged()` implements the policy exactly (archive
   bit masked out of the protection-equality check, then required SET
   on the live side as an independent condition -- confirmed by test
   that a stored record already having the bit set changes nothing,
   and that clearing it on the live side forces "examine" even with
   every other field identical). `amisnap_repo_list_snapshots()`
   enumerates `snapshots/` leniently (non-conforming names skipped,
   not treated as corruption).
5. `restore` (full/subtree, alternate path, metadata-last) + `verify`
   (structural; `FULL` re-hashes) against the directory backend.
   Restore's report includes a long-path advisory: entries whose full
   restored path exceeds ~255 bytes are restored anyway (AmigaDOS
   creates/traverses component-wise, so it works) but flagged, since
   stock shells/utilities with ~255-byte and BSTR-limited buffers may
   misbehave on them. Advisory only, never a refusal — and the exact
   threshold gets verified against the autodocs before the message is
   written, not taken from folklore.
6. Amiga side: `stackswap.c` first (see "Stack management" above --
   every module below runs on top of it, not the other way round),
   then `scan.c`, `restore_meta.c`, `dosio.c`, capability probe; CLI
   with ReadArgs templates and RC codes.
7. vamos regression test (`test-host`) proving the stack swap actually
   happens and covers `scan.c`'s real recursion depth against a deep
   fixture tree, before any on-target work.
8. On-target harness: Copperline job snapshots a guest tree, host
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
- **Host CI, m68k binaries via vamos:** the cross-built `AmiSnap`
  binary runs directly under amitools' vamos (already in
  `ghcr.io/sidick/amiga-dev`, same tool sibling AmiAuth uses for its
  asm crypto tests) with a controlled stack size -- the stack-swap
  regression test above, and later the 68k asm crypto paths (phase
  4's optimisation work) the same way AmiAuth validates theirs.
- **On-target (Copperline):** deterministic boot, snapshot inside the
  guest, assert `.uaem` sidecar metadata on the host; deterministic
  `rtc_time` makes "byte-identical repository given identical input" a
  testable property. Skips honestly (like today's `run.sh`) when local
  ROM/Workbench config is absent.
- **On-target (Amiberry):** smoke test against a real Samba mount,
  muFS owner round-trip.
- **Exotic-source cases in the matrix:** a FAT95-mounted image as a
  source volume — its VFAT long names (up to 255 bytes) exceed the
  107-byte ceiling of every native filesystem, making it the live
  proof that no 107-char assumption crept in anywhere (capture, format,
  restore reporting); and a PFS3 partition with a non-default
  `setfnsize`, proving `maxnamelen` really is probed per volume rather
  than derived from DosType (two PFS\3 volumes can differ).
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

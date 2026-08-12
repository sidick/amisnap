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
**Resolved when `scan.c` was written (2026-08-12), confirmed against
the real NDK, not assumed:** `ExAll()`'s `ED_OWNER` tag is V39
(`dos/exall.h`: `ed_OwnerUID`/`ed_OwnerGID` are explicitly commented
"new for V39", and the header states outright that V37 dos.library/
filesystems return `ERROR_BAD_NUMBER` for it). But this is a
**different, simpler case than a version-gated function call**:
`ExAll()` itself exists at V37 and is just rejecting an unsupported
parameter value at runtime — a normal, self-describing error, not a
call past the end of a V37 jump table. `dos/exall.h` documents the
exact sanctioned fallback itself: request `ED_OWNER`; on
`ERROR_BAD_NUMBER`, retry the *whole* call with `ED_COMMENT`. `scan.c`
implements exactly that (once per volume, not per entry) rather than a
version check — a second, distinct pattern worth keeping alongside the
version-check one above: **"function may not exist -> check the
library version before calling" vs. "function exists but may reject
this parameter -> check the documented return code and retry."** Both
are real, and picking the right one matters.

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
its asm crypto tests under `make test-host`) -- confirmed working for
real by running the cross-built `AmiSnap` binary under `vamos -C 020`
(the `-C <cpu>` flag is required; vamos's default CPU model alerts and
aborts even a bare "hello world"). **Revised after actually trying
this against `scan.c` (2026-08-12):** vamos's own Python dos.library
emulation does NOT implement `AllocDosObject(DOS_EXALLCONTROL,...)` or
`Info()` (confirmed via vamos's own diagnostic messages -- "unsupported
type=1/DOS_EXALLCONTROL" -- not a guess), so `ExAll()`-based directory
walking, and therefore this section's original plan to exercise
`scan.c`'s real recursion depth under vamos, cannot run there at all.
`Lock()`/`Examine()`/`Open()`/`Write()`/`Close()` DO work under vamos
(confirmed via real execution), so vamos remains useful for testing
simpler dos.library call sequences and for `stackswap.c`'s own
mechanism (allocate/swap/run/swap-back, verifiable without any
ExAll-shaped operation at all) -- but the deep-recursion-against-a-
real-scan regression test originally envisioned here moves to item 7's
Copperline/Amiberry harness, which runs the real ROM and has no
stub-coverage gaps to work around.

**Considered and declined:** vamos has a real, documented `amiga` mode
(`.vamosrc`) that loads and executes a real extracted library binary's
native code in place of its Python reimplementation for a given
library -- but vamos's own docs explicitly say not to do this for
`exec` or `dos`, since vamos's whole emulation model depends on
intercepting those two in Python. `dos.library` is exactly where our
gap is, so this wouldn't have helped even setting aside that bundling
an extracted, copyrighted Kickstart/Workbench library binary into this
repo or its CI image is its own separate problem. Patching vamos
itself to add real `ExAll`/`Info`/`AllocDosObject(DOS_EXALLCONTROL)`
support was also considered and declined -- a real upstream
contribution, not a small one, for a gap the Copperline/Amiberry route
(item 8) closes properly anyway. Decision: go straight to Copperline
when this needs real on-target verification, not before.

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
                      write path (content-addressed objects with
                      exists()-gated dedup, snapshot commit atomic
                      last, snapid collision handling), list_snapshots,
                      and verify (structural + FULL re-hash, checks
                      every content-ref occurrence, never aborts
                      early) all done; prune lands in phase 2
                                                    [write+list+verify done]
  restore.[ch]        portable content-restore: reconstructs files/
                      dirs from a manifest into a destination backend,
                      verifying every object against its declared hash
                      before writing (aborts immediately on mismatch/
                      missing -- principle 1); subtree selection
                      (component-boundary correct, preserves full
                      relative paths, no flattening); an optional
                      per-entry callback hook for metadata application
                      (Amiga-only, item 6). Links counted as an honest,
                      explicit gap (no backend.h link concept yet), not
                      silently dropped                          [done]
  backend.h           the backend API: put/get/exists/list/remove/
                      mkcol/close, one vtable + opaque ctx      [done]
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
  scan.c              ExAll()/Examine()/Info()/Lock() volume walk
                      producing meta.h's entry records, depth-first
                      directories-before-contents (matching the
                      manifest's own required order). Every struct
                      field/constant/version floor verified against
                      the real NDK before writing code (not memory) --
                      including a genuine 68k signedness bug
                      (STRPTR/TEXT* are unsigned char* on this target;
                      libnix's strlen() wants char*) that only the
                      cross-build's -Werror caught, invisible from a
                      host build. Verification status, precisely:
                      compiles+links clean; Lock()/Examine() confirmed
                      via REAL execution under `vamos -C 020` against
                      RAM:; Info()/AllocDosObject(DOS_EXALLCONTROL)/
                      ExAll() are NOT supported by vamos's own Python
                      dos.library emulation (confirmed via vamos's own
                      diagnostic messages, not a bug in this code) --
                      so the actual directory-walk logic remains
                      cross-build-verified only, pending item 7's
                      Copperline/Amiberry harness (real ROM execution,
                      no stub-coverage gaps) for genuine confirmation.
                      Two explicit, tracked gaps, not silent: (1)
                      soft/hard links are detected (ST_SOFTLINK/
                      ST_LINKDIR/ST_LINKFILE, verified against
                      dos/dosextens.h -- note ST_SOFTLINK=3 is
                      *positive*, "looks like dir, but may point to a
                      file!", so naive type>0-means-directory logic
                      would have silently misclassified it) but not
                      captured as entries -- ReadLink()'s msgport-level
                      packet contract and hard-link source resolution
                      aren't implemented; counted via
                      result->links_skipped, symmetric with restore.c's
                      own gap. (2) The root directory's own owner
                      fields are never populated, even on a volume that
                      supports ownership -- the ED_OWNER/ED_COMMENT
                      capability negotiation happens inside the
                      recursive walk, after the root's own entry is
                      already emitted; fixing this cleanly needs a
                      small interface change (thread a pre-negotiated
                      type into the walk, or negotiate before emitting
                      root) deferred rather than rushed here.
                      maxnamelen is deliberately observational (the
                      longest name actually seen this scan), not an
                      invasive probe that writes a test file to the
                      volume being backed up -- a backup tool must
                      never mutate its source.                [done]
  restore_meta.c      SetProtection/SetComment/SetFileDate/SetOwner,
                      wired as restore.h's on_entry_restored hook --
                      metadata-last (protection applied last of the
                      four too, so a restrictive mask can't block a
                      later SetComment/SetFileDate/SetOwner on the
                      same object). Every field independently best-
                      effort, accumulated into running ok/failed
                      counts, never fatal to the restore. All four
                      functions/version floors verified against the
                      real NDK first: SetComment/SetProtection have no
                      version label (pre-2.0); SetFileDate is V36
                      (documented expected failure: OFS/FFS refuses it
                      on the root directory); SetOwner's own autodoc
                      has a genuinely useful nuance beyond its "(V39)"
                      label -- the call slot exists from V37 and
                      simply returns FALSE pre-V39, so it's safe to
                      call unconditionally with no version check, a
                      documented exception to the general V39+ policy.
                      This module is inherently coupled to a real
                      AmigaDOS path (not amisnap_backend's
                      abstraction, which has no filesystem-path
                      concept by design) -- its on_entry_restored
                      adapter takes the destination root explicitly.
                      Real execution under `vamos -C 020` against
                      RAM: (not just cross-build): SetOwner's
                      documented pre-V39 FALSE-return behavior
                      confirmed exactly -- vamos's own stub returns
                      d0=0 and amisnap_restore_meta_apply() correctly
                      recorded owner_failed, exactly the intended
                      degrade-gracefully path, real proof the contract
                      works end to end. SetComment/SetProtection
                      reported success but a follow-up Examine()
                      readback showed the comment empty and protection
                      0 -- vamos's own RAM: handler stubs for these
                      two don't actually persist changes (a further,
                      distinct vamos coverage gap, confirmed by vamos
                      itself logging "SetComment: not implemented"),
                      not evidence of a bug in this module, but also
                      not proof of correctness -- genuine verification
                      of SetComment/SetProtection/SetFileDate's real
                      effect needs item 8's Copperline/Amiberry
                      harness, same as scan.c's ExAll() gap.    [done]
  dosio.c             LIKELY NOT NEEDED, pending on-target
                      confirmation: backend_dir.c already builds
                      *and links* clean against libnix's stdio/mkdir/
                      opendir/readdir under m68k-amigaos-gcc -noixemul
                      (see backend_dir.c's own entry above) -- strong
                      evidence it can be the DOS I/O layer directly,
                      with no separate indirection needed. Link-time
                      symbol resolution isn't proof of correct runtime
                      behavior, though (house rule 6) -- item 7's
                      on-target harness, actually exercising
                      backend_dir.c's put/get/list/mkcol against a
                      real Amiga filesystem, is what turns "likely" into
                      "confirmed". Keep this entry until that happens;
                      only then delete it outright.
  stackswap.[ch]      StackSwap() to a generously sized allocated
                      stack at process start -- see "Stack management"
                      above; every other Amiga-side module runs on top
                      of this from the start. Struct fields (stk_Lower:
                      APTR, stk_Upper: ULONG -- not APTR, the one easy
                      field to get wrong from memory -- stk_Pointer:
                      APTR) and the V36 minimum verified against the
                      real NDK headers in ghcr.io/sidick/amiga-dev
                      (exec/tasks.h; exec_lib.sfd's "==version 36"
                      grouping) before writing any code, not assumed.
                      Wired into src/cli/main.c as real_main()'s
                      wrapper, establishing the pattern immediately.
                      Verified with a REAL execution, not just a
                      cross-build: `vamos -C 020 build/AmiSnap` runs
                      the actual binary under emulation and gets the
                      expected output/RC -- the `-C <cpu>` flag turned
                      out to be required (vamos's default CPU model
                      alerts and aborts with RC 20 on a plain "hello
                      world" too, confirmed not specific to this code)
                      and is now on record for item 7's own vamos
                      regression test to reuse.               [done]
  socket.c            bsdsocket glue for webdav/s3         [phase 3]
  tls.c               soft-loaded AmiSSL, per-destination  [phase 3]

src/cli/            AmiSnap front-end: one ReadArgs template
                    ("ACTION/A,SOURCE/K,REPO/K,DEST/K,SNAPID/K,
                    SUBTREE/K,COMMENT/K,FULL/S") with ACTION as the one
                    positional field and everything else keyword-only
                    -- deliberately not per-verb templates (would need
                    a second ReadArgs pass over a CSource-wrapped
                    remainder), since a single shared template makes a
                    field's position not verb-aware; each verb
                    validates its own required fields manually since
                    ReadArgs' /A can't be conditional on ACTION.
                    RETURN_OK/WARN/ERROR/FAIL used per dos/dos.h,
                    confirmed via the NDK (WARN = completed with some
                    entries degraded, never used for a usage error).
                    SNAPSHOT does two directory walks (a caps-only pass
                    to get complete VOL_CAPS before any REC_ENTRY can
                    be written -- format.md's required record order
                    means VOL_CAPS can't be patched in afterward -- then
                    the real content-reading pass); a documented
                    efficiency trade-off (extra ExAll traffic, not
                    extra file-content reads), not silently accepted.
                    RESTORE/VERIFY resolve an omitted SNAPID to the
                    lexicographically-latest (= chronologically latest,
                    per format.md's snapid design) snapshot, capped at
                    1024 listed snapshots -- a real, documented limit
                    pending phase 2's prune.
                    Verification: cross-build clean. Real execution
                    under `vamos -C 020`: argument dispatch/validation
                    confirmed for real (bad args, unknown ACTION,
                    missing required fields all produce the right
                    stderr message and RC). A single-process combined
                    test (build a repo with real repo_writer calls,
                    fetch its manifest via real backend_get, call the
                    real amisnap_verify_manifest and
                    amisnap_restore_manifest, read the restored file
                    back) confirmed the full content pipeline for real
                    on m68k: verify found 0 missing/corrupt, restore
                    wrote the right byte count, and the restored
                    file's content read back byte-for-byte correct --
                    genuine end-to-end proof, not just unit tests.
                    restore_meta's SetOwner correctly failed and was
                    correctly recorded as failed (vamos's V37-style
                    stub, exactly as designed).
                    **New, distinct vamos gap found while testing
                    this:** libnix's own opendir()/readdir() are
                    themselves implemented via ExAll() internally
                    (visible in vamos's own call trace) -- so
                    backend_dir.c's list() inherits the same ExAll
                    gap scan.c already has, meaning LIST and any
                    SNAPID-omitted RESTORE/VERIFY cannot be verified
                    under vamos at all, only with an explicit SNAPID
                    (which sidesteps listing). Also could not test the
                    actual AmiSnap binary across a build-then-read
                    sequence at all: vamos does not persist RAM: state
                    between separate process launches, only within one
                    process's lifetime -- a test-methodology limit
                    (hence the single-process combined test above),
                    not a code issue. Full CLI verification, including
                    LIST and multi-invocation workflows, needs item 8's
                    Copperline/Amiberry harness.                [done]

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
   **Content-restore/verify done** (`src/core/restore.[ch]`,
   `amisnap_verify_manifest` in `repo.[ch]`); metadata application is
   Amiga-only and lands with item 6 below. Subtree selection preserves
   full relative paths under the destination rather than flattening
   (restoring "Work/Projects" into an alternate root produces
   ".../Work/Projects/...", matching restic/borg-style tools and
   avoiding a family of path-stripping edge cases) — a deliberate
   interpretation of the proposal's "full or subtree" wording, recorded
   here since the proposal itself doesn't specify it. Every content
   object is verified against its declared BLAKE2s-256 before being
   written out and restore aborts immediately on a hash mismatch or
   missing object (principle 1: silently writing unverified content is
   exactly the fatal case that principle exists to prevent) — this
   required extending `manifest.h`'s visitor callbacks to be abort-
   capable (return 0 to continue, nonzero to stop decode and propagate
   that value), since the original void-returning callbacks had no way
   to stop decode from processing further entries after a fatal error.
   `verify`, by contrast, deliberately never aborts early (its whole
   point is a complete report even after finding corruption).
   `backend.h` gained `mkcol` (idempotent "ensure this container
   exists") so an empty directory entry — no file content to `put`,
   nothing else would ever create it — still gets restored; documented
   as a real no-op for a future S3 backend (no directory concept) and a
   real WebDAV MKCOL for that tier. Soft/hard link restoration is an
   explicit, counted gap (`links_skipped`) — `backend.h` has no link
   concept and real link creation is Amiga-only (`MakeLink()`); not
   silently dropped, not attempted as a plain file.
   Restore's eventual CLI-level report should include a long-path
   advisory: entries whose full restored path exceeds ~255 bytes are
   restored anyway (AmigaDOS creates/traverses component-wise, so it
   works) but flagged, since stock shells/utilities with ~255-byte and
   BSTR-limited buffers may misbehave on them. Advisory only, never a
   refusal — the exact threshold gets verified against the autodocs
   before the message is written, not taken from folklore. Not yet
   implemented (no CLI exists yet to report anything to) — tracked here
   so it isn't forgotten when item 6's CLI wiring lands.
6. Amiga side: `stackswap.c` first (see "Stack management" above --
   every module below runs on top of it, not the other way round).
   **`stackswap.c` done** -- struct layout and V36 minimum verified
   against the real NDK headers before writing any code (not assumed
   from memory), wired into `src/cli/main.c` as `real_main()`'s
   wrapper, and confirmed with a genuine execution under `vamos -C
   020` (not just a cross-build) -- the expected output and RC came
   back from the actual emulated binary. `dosio.c` looks unnecessary
   (see its own module-map entry) but stays pending item 7's on-target
   confirmation. Remaining: `scan.c`, `restore_meta.c`, capability
   probe; CLI with ReadArgs templates and RC codes.
   **`scan.c` done** (the walk itself; capability-probe caveats and two
   explicit gaps recorded in its own module-map entry above). A real,
   if partial, execution-verification milestone along the way: trying
   to run it under vamos (rather than assuming the earlier-planned
   vamos regression test would just work) surfaced that vamos's own
   dos.library emulation doesn't implement `ExAll()`'s prerequisites at
   all -- see the "Stack management" testing section above for what
   this changes.
   **`restore_meta.c` done** (see its own module-map entry for the
   verified version floors -- SetOwner's genuinely useful "safe to call
   unconditionally, returns FALSE pre-V39" nuance in particular -- and
   what real vamos execution did and didn't confirm).
   **CLI wiring done** (see src/cli/'s own module-map entry above for
   the template design, RC conventions, and what real vamos execution
   confirmed -- including a new, distinct vamos gap it surfaced:
   libnix's opendir()/readdir() are themselves ExAll()-based, so
   backend_dir.c's list() has the same coverage gap as scan.c).
   **Item 6 is now complete.** The one deferred, non-blocking item:
   capability-probe refinement (the scan.c root-owner gap).
7. vamos regression test (`test-host`) covering `stackswap.c`'s own
   mechanism against a deep (but safely bounded -- see "Stack
   management" above on why deliberately triggering a real overflow is
   unsafe to test) recursive operation that doesn't depend on
   `ExAll()`, since vamos can't run that. `scan.c`'s own real recursion
   depth is verified on-target instead (item 8), not under vamos.
   **Done.** `tests/vamos/stackswap_test.c`: recurses 40 levels with a
   256-byte touched buffer per frame (~10KB, comfortably inside the
   32KB swapped stack, nowhere near overflowing it) inside
   `amisnap_stackswap_run()`, capturing the deepest stack pointer
   reached; compares it against the caller's own stack pointer
   captured before the swap. `AllocMem()`'s returned block has no
   proximity guarantee to the task's own stack region, so a large gap
   (threshold 4096 bytes; observed in practice ~39KB) is a reliable,
   always-safe positive signal -- never an attempt to trigger or
   detect a real overflow. Confirmed this isn't a tautology by running
   the *identical* recursion without the swap, live: it genuinely
   crashed vamos's CPU emulation with an invalid memory access (a real
   stack overflow, not a clean assertion failure) -- concrete proof
   both that the danger this mechanism guards against is real, and
   exactly why deliberately provoking it in an automated test would be
   unsafe rather than a valid test technique. Wired into `make
   test-host` (`stackswap-vamos-test`, depends on both
   `m68k-amigaos-gcc` and `vamos` being on PATH together, same
   assumption sibling AmiAuth's own vamos-based test-host step makes)
   and confirmed running end to end inside the real CI container image
   after clearing a stale build/ directory left over from local,
   wrong-architecture host builds (a testing-workflow gotcha, not a
   Makefile bug: never reuse one `build/` directory across a host
   build and a containerized one without `make clean` between them).
8. On-target harness: **Copperline, not Amiberry** -- decided
   explicitly (2026-08-12): easier to automate (its own JSON-RPC
   control protocol vs. Amiberry's more interactive MCP surface),
   matching how this plan already treats Copperline as the primary
   harness elsewhere and Amiberry as the interactive fallback. This is
   where `scan.c`'s actual directory-walk logic (`ExAll`/`Info`/
   `AllocDosObject(DOS_EXALLCONTROL)`, none exercisable under vamos --
   confirmed scan.c *and* backend_dir.c's `list()`, which turned out to
   depend on `ExAll` too via libnix's opendir/readdir) and
   `backend_dir.c`'s real filesystem I/O get their first genuine
   execution confirmation, not just a cross-build. Amiberry smoke test
   against a real Samba share (the actual Tier-1 NAS scenario) stays a
   secondary, interactive check, not the primary automated path.

   **Scope, decided 2026-08-12** (researched against all four sibling
   repos' existing, working Copperline harnesses -- `amipilot`,
   `amiauth`, `amirfb`, `copperline-bridgeboard-plugin` -- before
   designing anything new, per house rule 6):

   - **Minimal boot, no Workbench** -- following `amiauth`'s exact
     pattern (`tests/copperline/sys/`: just `C/` + `S/Startup-Sequence`,
     confirmed live in its own `machine.toml`/`run.sh`), not
     `amipilot`'s full-Workbench one. Nothing this phase touches needs
     a real Workbench install (no ReAction, no AmiSSL, no Workbench-
     resident library) -- ROM-resident `dos.library`/`exec.library` is
     everything the target binary needs. `[cpu] model = "68020"`
     explicit (our real floor); no `--model A1200` (sidesteps
     `amipilot`'s own documented EC020/Zorro-autoconfig-crowding
     gotcha, since we never touch that flag at all).
   - **Host-mounted `[[filesys]]` directories**, staged before launch
     and read after (per user guidance), each its own mount: `boot/`
     (the minimal boot volume: `C/AmiSnap`, `C/stage`, `C/readback`,
     `S/Startup-Sequence`), `source/` (pre-staged test tree),
     `repo/` (backup destination), `restored/` (restore destination).
     Confirmed (via Copperline's own installed README) that 0.12+
     makes these live, writable pass-throughs by default, not the
     throwaway/snapshot behavior implied by a stale comment in
     `amiauth`'s own `machine.toml` (predates that repo's Copperline
     upgrade) -- verify this empirically before relying on it, don't
     just trust the doc.
   - **Test data staging without any Workbench C: commands**: a small
     dedicated `stage` helper binary (test-only, never shipped --
     same convention as AmiPilot's own `fixtures/`) creates the source
     tree directly via `Open`/`Write`/`Close`/`SetProtection`/
     `SetComment`/`SetFileDate` calls, since `C:Protect`/`C:SetComment`
     aren't available in a minimal boot. Gives deliberately non-default
     metadata (specific protection bits, comments, dates) to round-trip
     -- exercising the real capture/restore path, not just defaults.
   - **Verification: Amiga-side readback, not `.uaem` parsing.** The
     `.uaem` sidecar's internal format is genuinely undocumented --
     confirmed by checking all four sibling repos plus Copperline's own
     installed README, which only describes the *capability*
     ("protection bits/comments/datestamps in `.uaem` sidecars"), never
     the byte format; no sibling repo has ever needed to parse one.
     **Revised (2026-08-13):** the Amiberry project's own wiki
     ("Host-Directory-Filesystem-Metadata") documents the `.uaem`
     format precisely, and it's simple enough to change the plan --
     one per-file, **plain-text** sidecar (`<name>.uaem`), one line:
     `----rwed 2024-03-15 14:30:22.50 optional file comment` -- an
     8-character HSPARWED-style protection flag string (`-` for unset),
     a `YYYY-MM-DD HH:MM:SS.CC` (centisecond) timestamp, then a
     free-form comment to end of line. No magic number, no binary
     layout, no owner/UID field. Documented as the FS-UAE-originated
     convention Amiberry adopted for interop ("host directory trees
     prepared for FS-UAE... should work directly when mounted in
     Amiberry"), matching this plan's own earlier claim that WinUAE/
     Amiberry/Copperline converged on the same `.uaem` naming -- almost
     certainly the same text format for the same interop reason, though
     that's still an inference about Copperline specifically (the wiki
     documents Amiberry, not Copperline) and needs empirical
     confirmation against a real Copperline-written `.uaem` file before
     any parser is trusted, not assumed correct from a different tool's
     docs alone (house rule 6). Checked WinUAE's own source
     (`~/src/WinUAE/fsdb.cpp`) too, on the chance it would shortcut
     this further: its classic mechanism is a genuinely different,
     older design -- `_UAEFSDB.___`, one shared *binary* database per
     directory (not per-file), a documented 600-byte fixed record
     (`valid` + `mode` + `aname` + `nname` + `comment`, no datestamp
     field at all -- WinUAE reads that from the host file's own mtime
     instead). Useful only as background (confirms protection+comment
     are the two fields with no native host equivalent across every
     variant of this idea); not what Copperline actually uses.

     **Given the format is this simple, run both checks as primary,
     not one deferred behind the other** (per explicit direction): the
     `readback` helper (`Examine()`-based, printed to a host-mount
     results file) and direct `.uaem` parsing are complementary, not
     redundant -- `.uaem` is a genuinely independent verification
     channel outside AmiSnap's own reporting (catches a bug where
     AmiSnap's restore_meta.c *thinks* it succeeded but didn't, the
     exact class of gap vamos's own incomplete SetComment/SetProtection
     stubs already surfaced once), while `readback` is the only path to
     owner/UID-GID fidelity (`.uaem` has no such field per the
     documented format) and exercises the real `Examine()` call AmiSnap
     itself depends on. A plain-text one-line format is cheap to parse
     from the host side (`awk`/a few lines of Python), so there's no
     real cost to keeping both.
   - **AmiSnap output capture: `LOG=<path>` CLI option** (decided over
     relying on Startup-Sequence `>` redirection, which is probably
     fine for a minimal boot -- the one sibling-repo gotcha found
     (`amiauth`'s README) was specifically about `AUX:`/`SER:` device
     handlers, not plain file redirection -- but untested, and this
     sidesteps the question entirely while adding a real feature the
     proposal already planned ("optional verbose log to a file").
     AmiSnap opens and writes its own log file directly via `Open`/
     `Write` when `LOG=` is given.
   - **Config convention**: `copperline.example.toml` (committed) +
     `copperline.local.toml` (gitignored, machine-specific ROM/host
     paths) -- `amipilot`/`amirfb`'s established pattern -- with
     `run.sh` skipping cleanly (exit 0, not a false pass) when the
     local file is absent, so CI without the ROM asset still passes.
     ROMs live in `nondistribution/roms/` (already staged, gitignored).
   - **Orchestration**: `--cpu 68020` explicit, `--noaudio`,
     `--benchmark-until <seconds>` (the simpler fixed-emulated-time
     mode `amiauth`/`copperline-bridgeboard-plugin` use, no JSON-RPC
     control server needed since nothing here requires indefinite
     runtime or live interaction) -- boot, run `stage` → `AmiSnap
     SNAPSHOT` → `LIST` → `VERIFY FULL` → `RESTORE` → `readback`, each
     via `LOG=` to its own file on a host mount, then exit. Host script
     reads every log back off the host-mounted directories and asserts
     against expected content/counts/metadata -- no in-guest
     interaction, no screen-scraping, matching `amipilot`'s own
     established "read results straight off the host filesystem"
     pattern.
   - **Known gotchas already on record from sibling repos**, to apply
     rather than rediscover: CRLF-strip serial output if any is used;
     `--control` alone leaves the machine paused (not relevant here
     since `--benchmark-until` is used instead); pin Copperline >=0.14.0
     if a real 68000 target is ever added (a `[[filesys]]` hang on
     68000/68010 was fixed upstream in 0.14.0); a file still
     `LoadSeg`-resident when the host overwrites it live is silently a
     no-op -- always stage files before Copperline starts, never
     mid-session.

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
  asm crypto tests, and confirmed to need `-C <cpu>` explicitly) with
  a controlled stack size -- the stack-swap regression test above, and
  later the 68k asm crypto paths (phase 4's optimisation work) the
  same way AmiAuth validates theirs. Confirmed working: `Lock()`/
  `Examine()`/`Open()`/`Write()`/`Close()`. Confirmed NOT implemented
  by vamos's own dos.library emulation, so anything needing them is
  cross-build-verified only until item 8's real on-target harness:
  `Info()`, `AllocDosObject(DOS_EXALLCONTROL,...)`, `ExAll()`.
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

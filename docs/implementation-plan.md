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
  webdav.c            backend_ops over http.c + transport.h -- CLI
                      wiring/on-target execution still pending, see
                      Phase 3 item 3                              [done]
  transport.h         abstract connect/send/recv/close vtable webdav.c
                      (and s3.c later) build against, portable        [done]
  base64.[ch]         RFC 4648 encoding, for WebDAV Basic auth        [done]
  s3.c                protocol client over transport.h            [phase 5]

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
  socket.c            bsdsocket glue for webdav/s3, cross-build-
                      verified only so far -- real on-target coverage
                      is unblocked (Copperline 0.15+ --hostsocket-net
                      host, confirmed via sibling amirfb), just not
                      wired into a harness until item 3 needs it
                      (see Phase 3 item 2)                    [done]
  tls.c               soft-loaded AmiSSL, real cert+hostname
                      verification -- cross-build-verified against the
                      real SDK, on-target execution still open, see
                      Phase 3 item 4                              [done]

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

   **Result (2026-08-12): full pipeline passes end to end on real
   Copperline** (`sh tests/copperline/run.sh`, `a1200-kick31-40.68.rom`,
   68020) -- `stage` → `SNAPSHOT` → `LIST` → `VERIFY FULL` → `RESTORE` →
   `readback` all succeed, both `readback.log` and the `.uaem` sidecars
   independently confirm restored protection/comment/date match the
   staged tree (owner is the one expected 0/4 -- no multiuser.library in
   a minimal boot, `restore_meta.c` already treats it as best-effort).
   Getting there found two real bugs neither host tests nor vamos could
   ever have caught, both genuine path-joining defects, not vamos/
   Copperline artifacts:
   - **Relative, not absolute, child-directory `Lock()`.** `scan.c`'s
     recursive descent locked the manifest-relative path directly (e.g.
     `"Sub"`) instead of resolving it against the volume being scanned,
     so it resolved against the process's own current directory instead
     -- failed with `IoErr 209`. Fixed by threading the real root path
     through `scan_dir()`/`process_entry()`.
   - **A root ending in `:` must not get an extra `/` inserted before
     the next path component.** `"Source:/Sub"` is rejected by real
     AmigaDOS/Copperline (`Lock()` fails, `IoErr 209`) -- only
     `"Source:Sub"` resolves; a bare volume/assign's trailing `:` already
     *is* the separator, the same role `/` plays after a directory name.
     This exact wrong assumption (never previously verified against real
     AmigaDOS, only assumed) was duplicated in four places: `scan.c`'s
     child-lock path, `main.c`'s own join helper, `restore_meta.c`'s
     inline join, and `backend_dir.c`'s `join_path()` (plus a second,
     separate copy of the same bug in `dir_put()`'s `tmp_dir`
     construction). Fixed once for the three Amiga-side call sites via a
     new shared `src/amiga/amipath.c` (`amisnap_join_amiga_path()`), and
     directly inside `backend_dir.c`'s own `join_path()` (checking for a
     trailing `:` or `/` before inserting a separator -- harmless on
     host, since no host root ever ends in `:`).
   Debugging method: plain `printf`/`fprintf(stderr,...)` produces no
   visible output at all in a minimal, no-Workbench, no-console boot --
   temporary `fopen("Results:...", "a")` diagnostics at each candidate
   failure point (added, rebuilt, rerun, then removed once understood)
   were what actually localized both bugs to a specific `Lock()`/
   `Examine()` call and its `IoErr()` value.
   **Item 8 is now complete.**

   **Real-FFS floppy variant (2026-08-12): done** --
   `tests/copperline/run-ffs.sh`, wired into `test-target` alongside
   `run.sh`. Same pipeline (`stage` -> `SNAPSHOT` -> `LIST` -> `VERIFY
   FULL` -> `RESTORE` -> `readback`), same binaries, same
   `Source:`/`Repo:`/`Restored:` volume names -- only the backing volumes
   move from Copperline's HOSTFS pass-through to genuine 880K AmigaDOS
   floppy images, one freshly formatted per dostype via amitools' `xdftool`
   (already pinned in `ghcr.io/sidick/amiga-dev`'s Dockerfile), mounted as
   `[floppy.df0-2]`; boot/results stay on the existing HOSTFS mounts.
   Passes for **OFS (DOS0), FFS (DOS1), FFS+International (DOS3)**.
   Getting there found real, on-record findings, not harness bugs:
   - `xdftool`'s own `create`+`format` must be two separate invocations --
     chaining them in one call leaves the boot block's dos_type/checksum
     unwritten (tested amitools 0.8.1).
   - Floppy mounts default to `write_protected = true` (unlike
     `[[filesys]]` HOSTFS mounts); a write to a write-protected real
     AmigaDOS floppy pops a blocking system requester instead of a clean
     DOS error, hanging the whole run silently until the benchmark timeout
     -- `write_protected = false` must be set explicitly per floppy.
   - `[floppy] speed = 800` (Copperline's own bit-identical faster-than-
     real DMA option, not `0`/turbo -- Copperline's own docs call `0` "a
     compatibility trade-off" that skips real transfer timing, not a
     valid test of real filesystem behavior) speeds up each dostype's
     iteration; motor/seek mechanics still run at real speed regardless
     (confirmed empirically -- a 30s benchmark window still isn't enough
     even at `speed = 800`), so `BENCH` stays at run.sh's own 60s default.
   - **DOS5 (FFS+International+DirCache) is excluded from the default
     loop, confirmed real via empirical isolation, not assumed**: the boot
     hangs before Copperline's own HOSTFS handlers even start (no
     "HOSTFS0: handler started" line, blank screen the whole run) --
     consistent with Kickstart 3.1's ROM-resident FastFileSystem having no
     DirCache support, the same "clicking drive" boot hang real hardware
     shows for a dostype with no matching handler and no `L:` to load one
     from in a minimal, no-Workbench boot. Worth retrying only if a future
     phase adds an `L:FastFileSystem` asset to the boot volume.
   - **A genuine metadata gap this harness exists to catch, found on its
     first real run -- root-caused and fixed (2026-08-12)**: the `Sub`
     directory's own protection (archive bit) and datestamp came back
     wrong after restore on every real FFS dostype tested, confirmed
     independently by three channels (AmiSnap's own restore report
     undercounting at 4/5, `readback.c`'s live `Examine()`, and `xdftool
     unpack`'s own metadata dump). Root cause, confirmed via a series of
     minimal isolated reproductions run directly against a real FFS
     floppy (house rule 6 -- verified empirically at each step, not
     assumed): **creating a new entry inside a directory resets that
     directory's own protection bits and datestamp on real AmigaDOS
     FFS.** Two independent places had exactly this ordering flaw:
     - `restore.c` applied a directory's own metadata immediately after
       its `mkcol()`, before descending into its children -- fixed by
       collecting the whole manifest and applying every entry's metadata
       in a *second* pass, in *reverse* manifest order (children before
       their parent; manifest entries are the scanner's own pre-order
       DFS, so reversing it is a post-order walk with no tree
       reconstruction needed). Two intermediate orderings were tried and
       both still failed empirically before landing on reverse order --
       see `restore.c`'s own `apply_metadata_reverse` comment for the
       full trail.
     - `tests/copperline/fixture/stage.c` (the test fixture that stages
       the source tree) had the *identical* flaw: it stamped `Source:Sub`
       immediately after `CreateDir()`, then created `Sub/nested.txt` and
       `Sub/empty.txt` afterward -- silently corrupting `Sub`'s metadata
       in the *source* tree before `SNAPSHOT` ever scanned it. This is
       why the bug persisted even after the `restore.c` fix landed:
       restore was faithfully reproducing already-corrupted source data,
       not corrupting correct data itself. Fixed by reordering `stage.c`
       to create and stamp both children before stamping `Sub` itself.
     Both fixes were necessary; neither alone was sufficient to make the
     harness pass. Confirmed clean on OFS/FFS/FFS+International after
     both landed: `Sub`'s protection and datestamp round-trip correctly
     end to end.

Gate: snapshot → wipe → restore on FFS is metadata-bit-perfect in the
emulator harness; 10k-file unchanged run under a minute on emulated
68030 without archive-bit help. **Both halves met, Phase 1 done
(2026-08-12).** The performance half: `tests/copperline/run-perf.sh`
(new) -- boots a real 68030/50 (`--model A4000 --cpu 68030`; bare
`--cpu 68030` with no `--model` hangs before boot on this ROM's default
chipset profile, confirmed empirically up to a 180s window, not a
timing issue -- `--model A4000` is a real historical 68030 Amiga and
boots cleanly), stages 10,000 small distinct-content files under
`Source:` (`bulkstage`, new fixture), runs a first `SNAPSHOT` to
populate the repository, then times a second `SNAPSHOT` over the
*unchanged* tree via a `timeit` fixture that brackets `SystemTagList()`
with `DateStamp()` reads. AmiSnap has no archive-bit change-detection
wired into `cmd_snapshot` yet (`index.c`'s module exists, `amisnap_
index_unchanged()` is tested standalone, but nothing in `src/cli/
main.c` calls it) -- this run *is* the gate's own "without archive-bit
help" case: a full re-scan/re-hash/re-write of all 10,000 files, with
only `repo.c`'s existing content-addressed dedup avoiding redundant
object uploads. **Result: ~33.6s (1682 ticks), comfortably under the
60s budget, stable across four consecutive runs.** Wiring the archive-
bit fast path into `cmd_snapshot` remains real, valuable future work
(near-instant "nothing changed" runs per the proposal's own CPU-budget
section) but isn't required to meet this specific gate.

Getting a reliable timing measurement took two real, on-record
findings, not guesswork:
- `DateStamp()`'s `ds_Tick` field is ticks elapsed in the *current
  minute* (0-2999 at `TICKS_PER_SECOND`=50, i.e. `60 *
  TICKS_PER_SECOND`), not ticks-per-second as a first reading of its
  own autodoc suggested -- `timeit.c` initially multiplied the
  `ds_Minute` delta by `TICKS_PER_SECOND` instead of `60 *
  TICKS_PER_SECOND`, silently producing a nonsensical *negative*
  elapsed time the moment a real run crossed a one-minute boundary (a
  10,000-file `SNAPSHOT` reliably does). A dedicated isolation fixture
  (since removed) confirmed the clock itself was never unreliable --
  `ds_Days`/`ds_Minute`/`ds_Tick` are fully consistent and monotonic
  across process boundaries in this minimal boot; the bug was purely
  the wrong conversion constant.
- Wall-clock pacing (`warp_speed`) doesn't need to be turned off for a
  timing gate like this: Copperline's core is cycle-accurate and
  deterministic regardless of `warp_speed`, which only skips host-side
  real-time/vsync pacing -- confirmed by running the harness four times
  back to back and getting the identical 1682-tick result every time.

**Self-backup guard (2026-08-12, done, not gated -- landed opportunistically
alongside the performance gate work above).** `cmd_snapshot` now refuses a
SNAPSHOT whose `REPO=` is the same object as, nested inside, or an ancestor
of `SOURCE=` (`main.c`'s `snapshot_source_repo_overlap`/`lock_is_ancestor_
or_self`, checked both directions via `Lock()`/`SameLock()`/`ParentDir()`
walks, not string-prefix path comparison -- assigns/soft-links can alias
the same volume two different ways a naive string check would miss).
Without this, writing new repository objects into a directory that's also
being scanned would feed the scan its own output on any later run, silently
corrupting or endlessly growing the backup -- exactly principle 1's "must
never happen quietly." Confirmed live on Copperline: `SOURCE=Source: REPO=
Source:Sub` and the reverse both refuse with a clear `RETURN_ERROR`
message; unrelated volumes (`SOURCE=Source: REPO=Repo:`) proceed normally.

**Phase 2 — Prune + hardening + reference reader.**
Retention pruning (`keep last N/daily/weekly/monthly`, mark-and-sweep),
interrupted-run recovery (resumable writes, atomic manifest commit),
paranoid verify mode (xxHash re-check of "unchanged" files), fixed-size
chunking for large files, `tools/amisnap_reader.py` + the CI
cross-implementation check. Gate: kill -9 mid-snapshot at any point
leaves a repository `verify` passes on; Python reader restores a
snapshot's full tree+metadata with the C code uninvolved. **Both
halves of the gate met (2026-08-12)** -- crash-safety was item 2
above; the reader half is item 5 below, with one honest caveat on
"+metadata": see that item for why a POSIX host reader reports every
Amiga-specific metadata field rather than literally applying it.

1. Mark-and-sweep prune engine + `keep last N` retention, wired to
   `ACTION=PRUNE`. **Done (2026-08-12).** `src/core/prune.[ch]`
   implements format.md's "Prune" section exactly as specified --
   delete target manifest(s) first (always manifest-first, never
   objects-first, so interruption anywhere leaves only harmless garbage
   for the next run to collect), then one mark pass (decode every
   surviving manifest, collect every referenced object hash into a
   sorted set) and one sweep pass (delete every `objects/<hh>/<hex64>`
   not in that set, then everything under `tmp/` -- nothing
   legitimately persists there between normally-completed operations).
   Deliberately policy-agnostic (principle 4, portable core/thin rind):
   `amisnap_prune_execute()` just deletes whichever snapshot ids it's
   handed: `PRUNE SNAPID=<id>` (format.md's raw single-snapshot
   primitive, verbatim) or `PRUNE KEEP_LAST=<n>` (the CLI's own
   retention-policy layer -- keep the N most recent by
   `list_all_snapshots`'s existing ascending lexicographic order,
   format.md's own note that this equals chronological order; delete
   every older one). Host-tested (`tests/test_prune.c`: two snapshots
   sharing one deduplicated object plus one unique object each, plus a
   stray `tmp/` leftover simulating an interrupted run -- confirms
   exactly the referenced objects survive, the stray tmp/ entry is
   swept, and pruning the same already-gone id twice is a harmless no-
   op, not an error) and confirmed live on Copperline (three snapshots,
   `KEEP_LAST=2` correctly drops only the oldest, `VERIFY FULL` still
   passes clean on what remains, both no-op cases -- `KEEP_LAST=` above
   the actual count and `SNAPID=` of a nonexistent id -- correctly do
   nothing rather than error).

   **Daily/weekly/monthly retention is a deliberately separate,
   not-yet-started follow-up**: unlike `keep last N` (pure snapid
   lexicographic ordering, no calendar math needed), bucketing by
   calendar day/week/month requires converting a snapid's embedded
   days-since-Jan-1-1978 count into a real Gregorian calendar date
   (year/month/day/weekday) from scratch -- AmigaDOS's own DateStamp
   has no calendar library behind it, just a raw day counter. A well-
   known, portable, floating-point-free algorithm exists for this
   (Howard Hinnant's public-domain `civil_from_days`) and should be
   used rather than hand-rolled leap-year logic -- scoped as its own
   item, not bundled into this one.

2. Interrupted-run recovery gate ("kill -9 mid-snapshot at any point
   leaves a repository `verify` passes on"). **Done (2026-08-12) --
   and, on inspection, already true of the existing commit protocol
   rather than new mechanism this item had to add.** `backend_dir.c`'s
   `dir_put()` (every object AND the manifest itself go through it) was
   already write-to-`tmp/`-then-atomic-`rename()` from Phase 1; content
   objects are already dedup-checked by hash before writing; the
   manifest is already renamed into `snapshots/` last, after every
   object. Together these already imply exactly the gate's guarantee --
   this item turned out to be about *proving* that empirically rather
   than building something new, matching house rule 6.
   `tests/test_crash_safety.c` does that proof for real: forks a child
   that starts writing a second snapshot into a repository that already
   has one committed, sends the child a real `SIGKILL` (deterministic
   on file count, not a timing-based `sleep()` -- doesn't flake under a
   loaded CI runner) partway through, then from the parent confirms the
   prior snapshot still lists and verifies clean, the partial one is
   invisible to `list_snapshots` (its manifest was never renamed), a
   no-op `PRUNE` sweeps whatever `tmp/` litter the kill left behind
   without touching anything real, and the repository is still
   perfectly usable for a brand new snapshot afterward. Confirmed
   stable across five consecutive runs and clean under ASan/UBSan.
   `backend_dir.c` is the same portable code AmigaOS itself uses, so
   this is a real proof of the guarantee on the actual code path, not a
   host-only approximation of it.

3. Wire the archive-bit change-detection policy into `cmd_snapshot`
   itself. **Done (2026-08-12) -- a real gap closed, not originally its
   own numbered item.** `index.c`'s change-detection module and policy
   have been "done" since item 4 of Phase 1's own work order, but
   nothing in `src/cli/main.c` ever actually called it -- every real
   `SNAPSHOT` run, including the Phase 1 performance gate's own
   "unchanged" measurement, always fully re-read and re-hashed every
   file regardless of whether it had changed. Discovered while
   answering "what's next" and re-examining that gate's own result.
   Now: `cmd_snapshot` loads the previous snapshot's manifest into an
   `amisnap_index` (gracefully degrading to a full scan, not aborting,
   if there is no previous snapshot or its manifest fails to read/
   decode -- losing the speed-up isn't the class of problem principle 1
   is about), and `snapshot_on_entry()` looks up each scanned file
   there: if `amisnap_index_unchanged()` says it's provably identical,
   it reuses the previous entry's content refs verbatim instead of
   reading and re-hashing bytes that haven't changed, and sets the
   source file's own archive bit afterward (`mark_backed_up()`) so a
   later run can recognize it the same way -- nothing else in the
   codebase ever set that bit before this. Confirmed live on
   Copperline: an immediate second `SNAPSHOT` over an untouched tree
   reports every file unchanged; after a `modify.c` fixture rewrites
   exactly one file (both changing its bytes and clearing its archive
   bit, real AmigaDOS FFS behaviour), a third `SNAPSHOT` re-reads only
   that one file and `RESTORE` afterward reflects the change correctly
   while the untouched files' reused content is still exactly what was
   originally staged -- now a permanent regression in `run.sh` itself
   (three `SNAPSHOT`s, `(0 unchanged...)` / `(3 unchanged...)` /
   `(2 unchanged...)` asserted on each), not a one-off manual check.

   **Found and fixed a real O(n^2) performance bug in the same pass**:
   wiring this in made `run-perf.sh`'s own 10k-file "unchanged" gate
   measurement *worse* at first -- 109s (over the 60s budget) versus
   the no-fast-path baseline's 33.6s, the opposite of the intended
   effect. Root cause: `amisnap_index_lookup()`'s linear scan (already
   flagged in its own header comment as "a candidate to optimise... not
   assumed in advance") really did matter at exactly this scale --
   called once per scanned file against an index of the same size, 10k
   files means 10,000 x 10,000 = 100,000,000 comparisons. Fixed by
   sorting `amisnap_index_build()`'s entries by path (`qsort`) and
   making `amisnap_index_lookup()` a binary search -- no other API
   change, existing callers unaffected. Re-measured: 26.06s, stable
   across three consecutive runs, comfortably under the 60s gate and a
   real improvement over the original 33.6s no-fast-path baseline, not
   just a recovery back to it. `run-perf.sh`'s own `machine-perf.toml`
   also needed its fast RAM raised 4M -> 8M once the fast path started
   actually engaging -- confirmed empirically (a real `AMISNAP_ERR_NOMEM`
   building a 10k-entry index in 4M, not guessed) that `amisnap_index`'s
   current memory footprint (a doubling-growth entries array, each
   entry's content refs individually malloc'd, plus a full owned copy
   of the raw manifest bytes) is genuinely large at this scale --
   plausible on a real accelerated 68030 setup, but a real, documented
   memory-efficiency concern worth a future look if a much larger
   (50k+ file) target ever needs it, not silently absorbed into a
   bigger test-only RAM number and forgotten.

   **Also discovered and fixed while landing this**: `tests/
   test_crash_safety.c` (the previous item's SIGKILL proof) built and
   passed locally on macOS but failed CI's Linux container outright --
   `error: implicit declaration of function 'kill'` under `-std=c99`
   with `-Werror`. glibc gates `fork()`/`kill()`/`waitpid()`'s
   prototypes behind `_POSIX_C_SOURCE` under strict C99 in a way
   macOS's libc doesn't; macOS's own toolchain never surfaced this.
   Fixed with an explicit `#define _POSIX_C_SOURCE 200809L` before any
   system header, and reproduced/confirmed the exact CI failure and fix
   locally by running `make test-host` inside `ghcr.io/sidick/amiga-
   dev`'s own container (it has a real Linux host `cc` too, not just
   the m68k cross-compiler) rather than trusting a green local macOS
   build alone.

4. Paranoid verify mode ("xxHash re-check of unchanged files",
   `docs/proposal.md`: "Optional paranoid mode adds xxHash32
   verification of allegedly-unchanged files"). **Done (2026-08-12).**
   Two parts:
   - `repo.c`'s `amisnap_repo_writer_file()` now computes and stores
     E_XHASH (`amisnap_xxh32(data, len, 0)`) on every file, always --
     not just under paranoid mode. It's near-memory-speed
     (`docs/proposal.md`'s own CPU-budget case for using it freely),
     and without it recorded on *every* snapshot, a later paranoid run
     would have nothing from the previous one to compare against.
   - `ACTION=SNAPSHOT PARANOID` (a new `/S` switch): when a file would
     otherwise take the archive-bit fast path (metadata says
     unchanged), paranoid mode reads its bytes anyway and cross-checks
     `xxHash32` against what was stored last time before trusting the
     metadata match -- a previous entry with no `E_XHASH` at all
     (predates this item) can't be cross-checked and degrades honestly
     to a full re-hash+write rather than silently claiming "verified"
     it can't back up. A mismatch is reported distinctly
     (`files_paranoid_mismatch`, its own summary line), not folded
     silently into the ordinary "changed" count.

   Confirmed live on Copperline, including the actual failure mode
   this mode exists to catch, not just the happy path: a `lie.c`
   fixture (verification-only, since removed) rewrote `root.txt` with
   different bytes of the *same length*, then restored the exact same
   protection (archive bit included), comment, and datestamp stage.c
   had originally set -- metadata alone says "unchanged". Non-paranoid
   `SNAPSHOT` was fooled (3/3 unchanged, wrong). `PARANOID` caught it
   (1 mismatch reported, the file correctly re-read and re-hashed), and
   `RESTORE` afterward reflected the real (lied-about) content
   correctly. A following non-paranoid `SNAPSHOT` then correctly
   trusted the *new*, accurate state (3/3 unchanged again) -- proving
   this doesn't just detect a lie once, it correctly self-heals the
   index for every run after.

5. `tools/amisnap_reader.py` + the CI cross-implementation check.
   **Done (2026-08-12).** A stdlib-only Python 3 reader (`hashlib`
   has had BLAKE2s-256 since 3.6 -- no third-party dependency needed
   even for the integrity-critical hash), every tag value and field
   layout transcribed directly from `docs/format.md` and cross-checked
   against `tlv.c`/`meta.c`/`manifest.c`/`repo.c`'s own encode/decode,
   not assumed from the prose alone -- e.g. confirmed the double length
   -encoding on string fields (the outer TLV `length` plus a second,
   inner `u16` the string convention itself adds) directly against
   `amisnap_buf_field_string()`, since format.md's own wording alone
   left that genuinely ambiguous. Three subcommands: `list`, `verify
   [--full]`, `restore <dest> [--subtree]`.

   **The "+metadata" part of the gate has one honest caveat, not
   silently glossed over**: format.md's own reader guidance says
   "apply metadata as far as the target system allows, reporting what
   it couldn't apply" -- on a bare POSIX host, that's "almost none of
   it" (no `fib_Protection` concept, no per-file FileNote, no shared
   uid/gid namespace with the source Amiga), so `restore` reports every
   field's value for every entry rather than attempting a doomed
   mapping onto `chmod`/xattrs. Content restoration -- the disaster-
   recovery-critical half -- is complete and independently verified
   (BLAKE2s-256 re-checked against each object's own name, same as the
   C side, implemented from scratch rather than shared code).

   **A second, real, honest gap surfaced immediately** on the very
   first run: `amisnap.repo` (the repository header) is never actually
   written by `repo.c` at all yet (`repo.h`'s own header comment:
   repository-level state "is explicitly out of scope here... lands
   with encryption wiring, phase 4") -- so format.md's own reader
   guidance ("parse `amisnap.repo`, refuse unknown version/cipher") as
   a literal first step doesn't hold against any repository this
   version of AmiSnap can actually produce. The reader tolerates a
   missing `amisnap.repo` (assumes CIPHER=0, the only value the C side
   can produce right now) and says so on stderr, rather than either
   refusing every real repository or silently pretending the file
   exists.

   **CI cross-implementation check** (`make cross-check`, wired into
   `test-host`): `tests/cross/gen_sample_repo.c` (host-buildable, no
   Amiga dependency -- exercises `backend_dir.c`/`repo.c` directly, the
   same portable write path a real `SNAPSHOT` uses) writes one small,
   deterministic repository exercising every optional REC_ENTRY field
   at once (archive bit, comment, owner, a subdirectory, a zero-byte
   file with no E_CONTENT at all). `tests/cross/run.sh` then drives the
   Python reader against it as a real, independent subprocess (not an
   imported library call) and asserts `list`/`verify --full`/`restore`
   all agree with known-correct values -- then corrupts one real
   object byte on disk and confirms the reader's own from-scratch
   BLAKE2s-256 check independently catches it, proving the integrity
   check is real rather than a rubber stamp that would pass regardless.
   Confirmed passing inside `ghcr.io/sidick/amiga-dev` (CI's actual
   environment, not just macOS).

6. `.uaem` sidecars for metadata the Python reader can't apply, plus a
   companion Amiga-side `ACTION=APPLYUAEM` to apply them for real.
   **Done (2026-08-12)**, raised in discussion right after item 5's own
   "can't apply metadata on a bare POSIX host" caveat: `restore --uaem`
   now optionally writes a `<name>.uaem` sidecar next to each restored
   entry -- the same FS-UAE/Amiberry/Copperline host-directory-
   metadata convention item 8 already reverse-engineered and documented
   (protection flags, `YYYY-MM-DD HH:MM:SS.CC` datestamp, optional
   comment) -- so metadata a PC can't apply itself still survives the
   round trip, either for a later emulator mount or for this new tool.
   The exact HSPARWED bit-to-character mapping and centisecond math
   were re-derived from real `dos/dos.h` `FIBB_*` values and checked
   against three real captured Copperline `.uaem` lines from item 8
   (not assumed from the letter names alone) before writing either
   side.

   `src/amiga/applyuaem.c` (`ACTION=APPLYUAEM SOURCE=<path>`) is the
   from-scratch inverse on real AmigaDOS: walks a tree via classic
   `Examine()`/`ExNext()` (simpler than `ExAll()` -- this only needs
   filenames), finds every `.uaem` sidecar, and calls `SetComment()`/
   `SetFileDate()`/`SetProtection()` (protection last, restore_meta.c's
   own established ordering) on its sibling. The date parse needed real
   calendar arithmetic AmigaOS/libnix has no library for at all --
   Howard Hinnant's public-domain `days_from_civil` algorithm, the same
   one flagged as the right tool for daily/weekly/monthly retention
   (item 1) whenever that lands, used here for real for the first time.

   **A genuine, not-obvious testing pitfall found while proving this
   round trip**: an identical test run against Copperline's own HOSTFS
   mount reported "0 applied" yet still showed perfectly correct
   metadata -- not because `ApplyUAEM` did anything, but because
   HOSTFS's own driver already interprets `.uaem` sidecars natively (the
   same mechanism `run.sh`'s own `.uaem` inspection section already
   relies on) and had synthesized the metadata before `ApplyUAEM` ever
   ran, while also apparently not exposing the sidecar files themselves
   to `ExNext()` at all. Confirmed live on a **real FFS floppy** instead
   (no native `.uaem` awareness to confound the result): `ApplyUAEM`
   reports "4 applied, 0 failed" and an independent `Examine()` (a new
   `checkuaem` fixture) confirms every field -- protection, comment,
   datestamp -- matches the original values exactly. Now a permanent
   regression, `tests/copperline/run-uaem.sh` (wired into `test-target`):
   generates the same known sample repo `make cross-check` uses,
   restores it with `--uaem` via the Python reader, stages the result
   onto a real FFS floppy via `xdftool`, runs `ApplyUAEM`, and asserts
   the `Examine()` output exactly.

7. Fixed-size chunking for large files. **Done (2026-08-12).**
   `amisnap_repo_writer_file_chunked()` (`src/core/repo.c`/`repo.h`)
   streams a file through a caller-supplied `read_fn` pull callback,
   allocating exactly one chunk-size buffer regardless of the file's
   total size, hashing/deduping/writing each chunk as its own
   independently content-addressed object (format.md E_CONTENT: "several
   = fixed-size chunks", already designed for this since phase 1 -- the
   read side needed no format changes, only a memory-bounded producer).
   `E_XHASH` is computed via a new streaming XXH32 API
   (`xxhash32.[ch]`: `amisnap_xxh32_init/update/digest`), independently
   implemented (not layered on the one-shot function) and cross-checked
   against it at several `update()` split points. Wired into
   `cmd_snapshot` (`src/cli/main.c`): files over
   `AMISNAP_DEFAULT_CHUNK_SIZE` go through the chunked path via a
   `Read()`-backed callback; files at or under it keep using the
   existing whole-file `amisnap_repo_writer_file()`. PARANOID mode
   (item 4) is deliberately skipped for chunked files -- re-reading the
   whole file to paranoid-check it would defeat chunking's own purpose.

   **The documented 8 MiB default (format.md's original CHUNK_SIZE
   value) was wrong, found by real testing, not inspection**: an 8 MiB
   single-buffer allocation failed with `AMISNAP_ERR_NOMEM` even at
   Copperline's own Zorro II 8 MiB fast-RAM ceiling (the emulator
   itself refuses to configure more than that for a Zorro II board),
   once the OS, AmiSnap's own binary, and other buffers are accounted
   for -- confirmed live before being merely suspected. Corrected to
   256 KiB (`AMISNAP_DEFAULT_CHUNK_SIZE`, `repo.h`), matching explicit
   user feedback during this same work that 8 MiB is "a little extreme
   for a backup utility for resource constrained systems like the
   Amiga" -- the *default* has to work on a modest 68020/8 MiB machine;
   a well-equipped system with real 32-bit fast RAM can always be given
   a larger explicit chunk size later if that's ever exposed as an
   option. `docs/format.md`'s own CHUNK_SIZE documentation was updated
   to match (262144), keeping the format doc normative per the project's
   own stated policy.

   **A second, deeper gap surfaced once the write side worked**: with
   the corrected chunk size, `SNAPSHOT` and `VERIFY FULL` both
   succeeded on a real 8.7 MB test file (34 chunks), but `RESTORE`
   still failed with the identical `AMISNAP_ERR_NOMEM` -- `restore.c`'s
   `restore_file()` was accumulating every retrieved chunk into one
   growable buffer before a single final write, so chunking's memory
   bound was never actually extended to the read/restore path. Fixed by
   adding a genuine streaming write primitive to the backend
   abstraction itself (`backend.h`: `put_begin`/`put_append`/
   `put_finish`/`put_abort`, implemented for the directory backend in
   `backend_dir.c` via an open temp-file handle, finalized with the
   same rename-into-place atomicity `put()` already used) rather than a
   restore.c-local workaround -- WebDAV (phase 3) and S3 (phase 5) will
   need the same treatment when they land, so the vtable is the right
   place for it. `restore_file()` now streams each verified chunk
   straight through via `put_append()`, never holding more than one
   chunk's bytes at a time on either side of the copy.

   Host-tested (`tests/test_chunked.c`: cross-file dedup, short-read/
   early-EOF honesty, `read_fn`-failure propagation, full restore+verify
   round trip). Now a permanent regression,
   `tests/copperline/run-bigfile.sh` (wired into `test-target`): a
   dedicated `bigfile` fixture writes a real 8.7 MB file with
   deterministic per-block content at a constrained 2 MB fast-RAM
   Copperline config, then SNAPSHOT/VERIFY FULL/RESTORE run for real,
   with the restored file's content checked byte-for-byte (not just
   size/count) against the fixture's own generation pattern.

8. **Deferred design note: a backup exclude list.** Raised in
   discussion (2026-08-12), not scheduled to a phase yet: a plain-text
   file (per-source-directory, or one global list, TBD) naming files/
   directories the user never wants backed up, read by `scan.c` before
   walking so excluded entries never even get `Examine()`'d, matching
   `docs/proposal.md`'s own already-planned "include/exclude patterns"
   for `snapshot`. Natural to design alongside whichever item first
   needs `scan.c` to filter its own walk rather than emit everything.

**Deferred design note: media-spanning + parity (2026-08-12, not
scheduled to a phase yet).** Two related, separable features raised in
discussion, worth designing for but not building yet:

- **Snapshot spanning/splitting across fixed-capacity destinations**
  (CD/DVD/USB media smaller than the source volume). The repository
  format is already a natural fit -- many small content-addressed
  objects rather than one blob -- so a "span across N volumes, prompt
  for the next one" mode is a fairly natural extension of `repo.c`'s
  existing write path (greedily assign objects to the current volume by
  remaining capacity, roll to the next when full) rather than a new
  format. Without it today, a destination that's too small just fails
  mid-write with a raw backend I/O error -- honest, per principle 1, but
  poor UX for exactly the CD/USB case users will ask about.
- **Parity/redundancy for removable media** (PAR2-style recovery data
  generated after a spanned write). A genuinely separate, more optional
  feature from spanning itself -- most users backing up to CD/USB care
  more about "fits and restores" than bit-rot protection on the media,
  so this shouldn't block or gate spanning.

Recommended sequencing: after Phase 3 (WebDAV) and ideally Phase 5 (S3)
are far enough along that the design accounts for both *unbounded*
destinations (network/object storage, no spanning ever needed) and
*fixed-capacity* ones (local media) from the start, rather than bolting
capacity-awareness onto the backend abstraction retroactively. Revisit
scheduling this properly once Phase 3 lands.

**Phase 3 — WebDAV.** HTTP/1.1 client (PUT/GET/MKCOL/PROPFIND,
keep-alive, resumable) over `src/amiga/socket.c`; per-destination
`TLS=YES` via soft-loaded AmiSSL (absent library + TLS requested =
clear failure, plaintext destinations never touch it). Host CI runs the
protocol code against a local WebDAV container.

1. Portable HTTP/1.1 client protocol layer: request building and
   response parsing, with no socket dependency at all. **Done
   (2026-08-12).** `src/core/http.[ch]` -- follows the same "portable
   core, thin Amiga rind" split module map already used for
   `backend_dir.c`: `src/amiga/socket.c`/`tls.c` (still to come) are
   the only pieces that will ever touch bsdsocket/AmiSSL; this module
   is host-testable on its own, same as every other portable-core piece.

   `amisnap_http_build_request()` formats a request line + Host +
   optional Content-Length + caller-supplied headers (Authorization/
   Depth/Overwrite/Destination for WebDAV's own methods) + body, always
   sending `Connection: keep-alive` per proposal.md's "HTTP/1.1 client
   with keep-alive".

   `amisnap_http_response_feed()` is a streaming state machine, not a
   whole-buffer decoder -- a real socket `read()` returns whatever bytes
   happen to be available, which may be less than one header line or
   split a chunk boundary in half. Handles both `Content-Length` and
   `Transfer-Encoding: chunked` response framing (a real WebDAV server's
   PROPFIND/GET responses use either); a response with neither is
   correctly treated as a zero-length body rather than the HTTP/1.0
   "read until close" fallback, since this client never speaks anything
   but keep-alive. Host-tested (`tests/test_http.c`) with every response
   case fed both as one single `feed()` call and one byte at a time,
   confirming identical results either way, plus a battery of arbitrary
   split points landing mid-status-line/mid-header/mid-body -- the case
   a naive line-buffered parser gets wrong. Cross-build-verified under
   `m68k-amigaos-gcc -noixemul` (compiles clean; no bsdsocket/network
   code exists yet to exercise on-target).

2. `src/amiga/socket.c` -- bsdsocket.library glue (`socket`/`connect`/
   `send`/`recv`/`close`, `SocketBase` opened per proposal.md's own
   networking prerequisite). **Done (2026-08-12), cross-build-verified
   only.** A thin blocking TCP client: `amisnap_socket_lib_open()`
   (`OpenLibrary("bsdsocket.library", 4)`, since bsdsocket -- unlike
   dos.library -- isn't auto-opened by the C startup) /
   `amisnap_socket_connect()` (dotted-quad via `inet_aton()`, DNS name
   via `gethostbyname()` -- `inet_addr()` deliberately avoided, its
   return value is ambiguous for the legitimate address
   255.255.255.255) / `amisnap_socket_send()` (loops over `send()` --
   one call isn't guaranteed to accept the whole buffer) /
   `amisnap_socket_recv()` / `amisnap_socket_close()`.

   bsdsocket.library is Roadshow/AmiTCP's own de facto standard API,
   NOT part of the base NDK the rest of this codebase's Amiga-side
   modules verify against -- every function signature and struct layout
   here (`proto/bsdsocket.h`'s GCC inline-asm LVO stubs via a
   module-global `SocketBase`, `netdb.h`'s `struct hostent`,
   `netinet/in.h`'s `struct sockaddr_in`/`htons`) was instead checked
   against the real Roadshow SDK headers bundled in
   `ghcr.io/sidick/amiga-dev`, not assumed from memory -- house rule 6
   applies the same to a third-party library's headers as to
   Commodore/Hyperion's own.

   Verification status, honestly: compiles clean AND links clean into
   the full `AmiSnap` binary under `m68k-amigaos-gcc -noixemul` (a real
   check -- the inline LVO stubs still have to resolve at link time).
   Unlike this codebase's other Amiga-side modules, there is no
   cross-build-then-vamos-then-Copperline staged story here *yet*: vamos
   has no bsdsocket.library emulation at all (confirmed absent from its
   own skill reference material, unlike its partial dos.library
   coverage). Genuine on-target verification is deferred to item 3
   (something real to connect to), but **the path to it is now
   confirmed, not open**: sibling project amirfb already validated
   Copperline 0.15+'s `--hostsocket-net host` flag (confirmed locally
   installed: `copperline 0.15.0`) -- a "HostSocket bsdsocket.library
   board" that intercepts the guest's bsdsocket.library calls
   (connect/send/recv/bind/listen/accept) and passes them straight
   through to real host OS sockets, bypassing the emulated network
   stack entirely. No SANA-II driver, no AmiTCP/Miami stack, no
   bridge/NAT setup, no root privileges needed on the guest OR host
   side -- distinct from the separate `--a2065-net` flag (a real A2065
   Ethernet board emulation for guest SANA-II drivers, which none of
   this needs). It's a CLI flag, not a `machine.toml` field (`--help`
   shows no `[net]`/`[hostsocket]` config-file section) -- item 3's own
   Copperline harness will add `--hostsocket-net host` to the
   `copperline` invocation the same way `run-perf.sh` already adds
   `--cpu`/`--model` flags alongside its own toml, not by extending
   `machine.toml` itself.
3. `webdav.c` -- an `amisnap_backend_ops` implementation over
   items 1+2 (PUT/GET/MKCOL/PROPFIND mapped onto `backend.h`'s
   put/get/mkcol/exists/list/remove, plus the streaming
   put_begin/put_append/put_finish/put_abort trio chunking's own restore
   fix (Phase 2 item 7) added to the vtable). **Backend implementation
   done (2026-08-12); CLI wiring (a `DEST=` URL scheme dispatching to
   this backend vs. `backend_dir.c`) not done yet -- tracked as a
   remaining sub-item below, not silently assumed complete.**

   `src/core/webdav.c`/`webdav.h`, `src/core/transport.h`,
   `src/core/base64.[ch]`. `transport.h` is a new abstract
   connect/send/recv/close vtable (same shape as `backend.h`'s own),
   introduced specifically so `webdav.c` itself stays portable and
   host-testable (module map: listed under `src/core/`, deliberately
   not `src/amiga/`) -- it never calls bsdsocket.library or any host
   sockets API directly, only through this interface.
   `src/amiga/socket.c` (item 2) now also exposes
   `amisnap_bsdsocket_transport_ops`, the real target's implementation
   of it; a POSIX host implementation for item 5's own "run against a
   local WebDAV container" doesn't exist yet.

   A real bug this work found and fixed in item 1's own
   `amisnap_http_build_request()` (`http.c`): the trailing
   `"Connection: keep-alive\r\n\r\n"` was appended via a hand-counted
   literal length (27) that was wrong by one -- the true byte count is
   26, so every request built by this function was silently sending its
   own C string literal's NUL terminator as a stray extra byte
   immediately before the body. Never caught by `test_http.c` (which
   only exercises the *response* parser, never checks a *request*'s
   exact bytes against a body), only surfaced once `test_webdav.c`'s
   mock server checked a PUT's received body byte-for-byte and found
   `"hello"` arriving as `"\0hell"` -- confirmed via a raw hex dump of
   the mock's own accumulated request bytes, not guessed. Fixed by
   using `sizeof(tail) - 1` on a named literal instead of a hardcoded
   count (matching `test_http.c`'s own header-verification convention
   after the fact: no hand-counted string lengths anywhere in this
   codebase should exist uninspected again).

   `PROPFIND` (`list`/`exists`) is answered by a deliberately-scoped
   href scraper (`webdav_scrape_hrefs()`), not a real namespace-aware
   XML parser: it finds every `<...href>...</...>` occurrence
   (tolerating any/no `D:`/`d:`/`lp1:`-style namespace prefix, matching
   real servers' own variance -- Apache mod_dav vs. Nextcloud vs.
   others), percent-decodes it, and reports the final path component of
   everything except the request's own "self" entry. Scoped to the one
   shape every real WebDAV `PROPFIND` response actually takes, not a
   general SGML/XML document -- a documented limitation, not an
   oversight (same "honest, explicit gap, not silently wrong" pattern
   as restore.c's own soft-link handling).

   `put()`/`mkcol()` auto-create every missing parent collection first
   (`mkcol_parents()`/`webdav_mkcol_abspath()`, walking one path
   component at a time exactly like `backend_dir.c`'s own `mkdir_p()`,
   tolerating a `405`/`409` "already exists" response the same way
   `mkdir_one()` tolerates `EEXIST`) -- required by `backend.h`'s own
   `put()` contract ("creating any missing parent 'directories' as
   needed"), not an optional nicety.

   `put_begin`/`put_append`/`put_finish`/`put_abort` use real HTTP
   chunked *request* Transfer-Encoding (not Content-Length, since
   restore.c never knows the total size up front -- repo.h/restore.c's
   own doc comments), so a large chunked-entry restore stays
   memory-bounded end to end over WebDAV too, not just on the directory
   backend -- the exact gap Phase 2 item 7 closed for `backend_dir.c`
   would otherwise have silently reopened here.

   `amisnap_backend_webdav_open()`'s own base_path bootstrap MKCOLs
   every path component up front (mirroring
   `amisnap_backend_dir_open()`'s own `mkdir_p(root)`), and HTTP Basic
   auth (`username`/`password` -> a `base64.c`-encoded `Authorization`
   header) is supported since essentially every real self-hosted WebDAV
   target (Nextcloud, a NAS's WebDAV server) requires it -- not called
   out explicitly in proposal.md's own Tier 2 description but a real,
   unavoidable requirement in practice.

   Also implements real HTTP/1.1 keep-alive connection reuse
   (`webdav_exchange()`): one connection is kept open and reused across
   calls, with exactly one retry on a fresh connection if a *reused*
   connection's send/recv fails (the ordinary "server closed an idle
   keep-alive connection" case) -- a freshly-opened connection failing,
   or a malformed-response parse error, is never retried (retrying
   either would just repeat a real failure, not recover from staleness).

   Host-tested (`tests/test_webdav.c`) against a from-scratch in-memory
   mock `amisnap_transport` + minimal WebDAV server (PUT/GET/DELETE/
   MKCOL/PROPFIND, both Content-Length and chunked request bodies) --
   not just "doesn't crash": the mock enforces that a PUT/MKCOL's
   immediate parent must already exist as a known collection (else
   `409`), which forces `webdav.c`'s own auto-MKCOL-parents logic to
   really issue the right requests in the right order for these tests
   to pass at all. Covers put/get/exists/list/remove/mkcol round trips,
   the chunked streaming upload (including `put_abort` never becoming
   visible), 404-vs-real-error distinctions, and Basic auth actually
   being sent and enforced (including `amisnap_backend_webdav_open()`
   itself failing outright against a server that requires auth it
   wasn't given -- proving that failure isn't silently swallowed).
   Cross-build-verified clean under `m68k-amigaos-gcc -noixemul` (the
   whole point of `transport.h` existing) in addition to the host build.
   Real on-target execution (a live WebDAV server reachable from
   Copperline via `--hostsocket-net host`, item 2's own note) not done
   yet.

   **CLI wiring: done (2026-08-13).** `src/cli/main.c`'s new
   `open_backend()` dispatches `REPO=`/`DEST=` by scheme prefix
   (`http://`/`https://` -> `amisnap_backend_webdav_open()` with
   `src/amiga/socket.c`'s real `amisnap_bsdsocket_transport_ops`;
   anything else -> the existing `amisnap_backend_dir_open()`, unchanged
   -- confirmed live on Copperline via `run.sh`, same PASS as before
   this change). `amisnap_webdav_parse_url()` (`webdav.[ch]`) parses the
   `http://[user[:pass]@]host[:port][/path]` form (percent-decoded
   userinfo, default ports 80/443) -- host-tested
   (`tests/test_webdav.c`), not just wired blind. `bsdsocket.library` is
   opened *lazily*, only the first time a WebDAV destination is actually
   used in a given run -- a pure mounted-volume backup (SMB/NFS/local,
   the common case) must not require any TCP/IP stack installed at all.
   An `https://` destination fails with a clear, explicit message
   (`AMISNAP_ERR_IO`, "not implemented yet ... use an http://
   destination instead") rather than silently downgrading to plaintext
   -- proposal.md's own per-destination TLS opt-in policy, honored even
   though TLS itself (item 4) doesn't exist yet.

   **Real on-target exercise: done (2026-08-13),** and it found two real
   bugs neither the mock (`tests/test_webdav.c`) nor the host-CI check
   against a real server (item 5, over a POSIX transport) could have --
   both required an actual m68k guest talking to real
   `bsdsocket.library` LVOs. `tests/copperline/run-webdav.sh` boots
   Copperline with `--hostsocket-net host` and runs a real SNAPSHOT/
   LIST/VERIFY FULL/RESTORE cycle against `tests/webdav/mini_webdav_
   server.py` (the same independent server item 5 uses) over a real TCP
   loopback connection out of the guest -- confirmed stable across
   repeated runs, restored content checked byte-for-byte, and
   independently cross-checked against the object/snapshot files that
   actually landed on the server's own backing directory.

   Both bugs were found by bisecting with `amilog_err()` diagnostics
   inserted at each step (unbuffered logging was itself a necessary
   fix first -- see below) until the exact hanging call was isolated,
   not guessed at:

   - `src/amiga/socket.c`'s `amisnap_socket_connect()` used
     `inet_aton()` to parse a dotted-quad host before falling back to
     `gethostbyname()`. Confirmed by grepping Copperline's own guest
     ROM/dispatch (`guest/hostsocket/hostsocket_board.h`'s `CALL_*`
     list) that **no `CALL_INET_ATON` exists at all** -- only
     `CALL_INET_ADDR` -- so the LVO stub jumps into an unimplemented
     slot and the guest hangs forever, not a clean failure. Not an
     oversight: HostSocket's own guest-side wire protocol only covers
     the classic AmiTCP v3 API surface, and `inet_aton()` is a
     Roadshow-era addition on top of that -- the same reason it's a
     newer, non-universal function to lean on at all, not merely a
     Copperline-specific gap. Sibling project amipilot independently
     reached the identical conclusion for a *different* bsdsocket
     emulator (a real CPU trap there, not a hang) and hand-rolls its
     own dotted-quad parser for the same reason -- not a one-off
     Copperline quirk either way, a real "don't assume every
     bsdsocket.library implements every Roadshow-era extension" lesson.
     Fixed with a small hand-rolled `parse_dotted_quad()` (digit-by-
     digit, no `sscanf`), avoiding both this gap and `inet_addr()`'s
     own well-known `255.255.255.255` ambiguity.
   - `cmd_snapshot`'s `snapshot_source_repo_overlap()` guard (the
     self-backup check, `main.c`) called `Lock()` on `REPO=` unconditionally
     -- fine for a real AmigaDOS path, but for a WebDAV URL string
     (`"http://127.0.0.1:.../repo"`) `Lock()` doesn't fail cleanly the
     way an ordinary unmounted-device name would; it hangs indefinitely.
     Not investigated further (a real AmigaDOS/DOS-handler quirk parsing
     a string shaped nothing like `device:path`, not this codebase's own
     to fix) -- the check is skipped outright for a `http://`/`https://`
     `repo` instead, which is also the *correct* semantics: a URL can
     never alias a local AmigaDOS path in the first place (categorically
     different address space), so the check was meaningless there even
     before the hang.

   A real, permanent robustness fix landed alongside the diagnosis, not
   just removed afterward: `LOG=`'s output file is now opened
   unbuffered (`setvbuf(g_log, NULL, _IONBF, 0)`, `main.c`) -- stdio's
   default full-buffering-on-a-non-tty meant a run that hangs or
   crashes before its own `fclose()` left behind a *completely empty*
   log with zero diagnostic value, exactly the failure mode that made
   this bisection slower than it needed to be the first time through.
4. `src/amiga/tls.c` -- soft-loaded AmiSSL, per-destination `TLS=YES`
   (absent library + TLS requested = clear failure, never a silent
   plaintext fallback). **Core implementation, CLI wiring, and
   cross-build verification done (2026-08-13); real on-target
   execution not done yet.**

   `src/amiga/tls.c`/`tls.h`: a real `amisnap_transport_ops`
   implementation (same interface `src/amiga/socket.c`'s bsdsocket
   transport already implements) that opens a plain TCP connection via
   `amisnap_socket_connect()` and wraps it in a real TLS session via
   AmiSSL v5's `OpenAmiSSLTagList()` soft-load. Every AmiSSL/OpenSSL
   call signature was verified against the real AmiSSL 5.27 SDK
   (`scripts/fetch-amissl-sdk.sh`, same pinned/hashed release sibling
   AmiAuth already validated for its own dev-only PBKDF2-vs-AmiSSL
   benchmark, `tests/copperline/amisslbench.c` -- the soft-load
   sequence itself (`OpenLibrary("amisslmaster.library", 5)` then
   `OpenAmiSSLTags` with `AmiSSL_UsesOpenSSLStructs=FALSE` and an
   `AmiSSLBase`/`AmiSSLExtBase` pair) mirrors that proven pattern
   rather than being re-derived from scratch. `webdav.c` itself needed
   zero changes -- it was already built against `transport.h`'s
   abstract interface for exactly this reason (Phase 3 item 3's own
   design note).

   Real, not placeholder, certificate verification: `SSL_VERIFY_PEER` +
   `SSL_CTX_load_verify_locations` against `"AmiSSL:Certs"` (the
   standard OpenSSL `c_rehash`-format hashed CA directory AmiSSL's own
   installer sets up), plus per-connection hostname verification via
   `SSL_set1_host()` (chain trust alone is not enough -- confirmed this
   is a distinct check, not implied by chain verification, before
   relying on it). Fails closed if the cert store can't be loaded at
   `amisnap_tls_lib_open()` time, rather than silently connecting with
   no way to check who's on the other end -- "trust is everything".

   **A real build-system question this surfaced, not just an
   implementation detail**: `tls.c` needs AmiSSL's own headers to
   *compile* even though `amisslmaster.library` itself stays a
   soft, runtime-only dependency (proposal.md's own framing) -- a
   library's headers being a build-time need is a separate concern
   from the library being installed on the machine that later runs the
   binary, but `make m68k` had no path to those headers at all before
   this. Asked directly rather than assumed: fetch the real AmiSSL SDK
   automatically as part of `make m68k` (reusing
   `scripts/fetch-amissl-sdk.sh`'s already-pinned/hashed download, the
   same one `tests/copperline/`'s own future AmiSSL work will need) was
   the chosen approach over vendoring a header subset or making TLS
   support an opt-in build flag. `AMISSL_CACHE_DIR` is pinned to
   `.amissl-cache/` inside the repo checkout (git-ignored, survives
   `make clean`), not the fetch script's own `$HOME`-based default --
   found live that this project's own standard
   `docker run --user "$(id -u):$(id -g)"` cross-build invocation has
   no sane `$HOME` for that numeric UID, which silently produced an
   empty SDK path and a confusing "header not found" three lines later
   before this fix.

   `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)` trips semgrep's
   `openssl-disabled-cert-validation` rule on sight (it flags the
   `NULL` third argument without distinguishing the verify-callback
   parameter, which is genuinely optional and correctly `NULL` here,
   from the verify*mode*, which is `SSL_VERIFY_PEER` -- real
   verification, not `SSL_VERIFY_NONE`) -- a documented, reasoned
   `nosemgrep` suppression, not a silenced real finding.

   Cross-build-verified for real: compiles and links clean against the
   actual AmiSSL 5.27 SDK headers and `libamisslstubs.a`, and the full
   `make m68k` build (now automatically fetching the SDK) produces a
   working binary.

   **Retested (2026-08-13) whether AmiAuth's documented ramlib crash
   (`OpenAmiSSLTags()` on a from-scratch minimal boot lacking the
   `AmiSSL:` assign) still applies -- it doesn't, on this Copperline
   version.** Built two throwaway diagnostic fixtures (not committed,
   same "never shipped" convention as `stage.c`/the since-deleted
   `socktest.c`): one calling `amisnap_tls_lib_open()` directly, one
   duplicating its init sequence step-by-step with a log line after
   each call, both run under `copperline 0.15.0` on AmiSnap's own
   existing minimal HOSTFS boot volume (no `AmiSSL:` assign, just
   `amisslmaster.library` + `AmiSSL/68020-40/amissl_v362.library`
   copied into `LIBS:`). `OpenAmiSSLTags()` returns cleanly with a real
   non-zero error code (`2` -- undocumented in the SDK's own Autodocs,
   meaning unspecified) instead of crashing ramlib, both with and
   without the `AmiSSL:` assign additionally set up. No hang, no CPU
   exception, confirmed across multiple runs.

   This resolves the specific crash risk, but a **from-scratch minimal
   boot still doesn't get AmiSSL all the way to a working state** --
   `OpenAmiSSLTags()` fails with that same undocumented error 2 even
   with `AmiSSL:` assigned and `LIBS: AmiSSL:Libs ADD` set up by hand
   (matching the directory shape AmiSSL's own real installer produces).
   **Ruled out one specific hypothesis rather than leaving it open**:
   read AmiSSL's own real `Install-AmiSSL` installer script (Amiga
   Installer syntax, from the upstream release archive) to check
   whether the from-scratch boot was simply missing something the
   installer sets up beyond the two library files -- it also creates
   `AmiSSL:openssl.cnf`, `AmiSSL:UserCerts/`, and `AmiSSL:Private/`
   alongside `Certs/`. Retested with that complete structure in place
   (all four, via a real `AmiSSL:` assign) -- identical error 2, at the
   identical point (`OpenAmiSSLTags()` itself, before certificate
   loading is ever reached). Certificates/config files are not the
   blocker. Not chased further beyond that -- diminishing returns for
   what was actually asked (does the crash still happen), and getting a
   fully *working* from-scratch minimal AmiSSL boot is a distinct,
   deeper question from "does init fail safely" that the real
   on-target work (below) will need to resolve properly anyway, most
   likely by following AmiAuth's own `amissl-bench.sh` approach of
   cloning a real Workbench install with AmiSSL already installed via
   its own installer, rather than
   hand-assembling a minimal one.

   **Retested again (2026-08-13) against a real Workbench install with
   AmiSSL genuinely installed** -- sibling AmiAuth's own known-good WB
   3.2 clone (`AMIAUTH_WB_HDD`, cloned copy-on-write, never mutated;
   its `S:User-Startup` already has the real `Assign AmiSSL: "SYS:
   AmiSSL"` + `LIBS:` setup its own installer produced), mounted as an
   AmiSnap-style `[[filesys]]` with a real boot priority rather than
   `[ide]` (the directory-mount form documented in Copperline's own
   `copperline.example.toml`, not a raw `.hdf` image, so no reason to
   reach for the disk-image-specific mechanism). A throwaway diagnostic
   fixture (not committed) staged into `S:Startup-Sequence` right after
   `User-Startup`, before `LoadWB` (matching AmiAuth's own
   `amissl-bench.sh` placement).

   **`OpenAmiSSLTags()` now succeeds completely** (`rc=0`, real
   `AmiSSLBase`/`AmiSSLExtBase`), `SSL_CTX_new()` succeeds,
   `SSL_CTX_load_verify_locations("AmiSSL:Certs")` succeeds (`rc=1`),
   and a real `amisnap_socket_connect()` to `example.com:443` succeeds
   -- confirming `tls.c`'s own init sequence, exactly as written, is
   correct end to end once AmiSSL is actually installed properly. This
   fully resolves item 4's previously-open "does AmiSSL init even work
   on real hardware" question, not just "does it avoid crashing".

   **A real hang past that point, not a slow handshake -- and a known,
   independently-documented AmiSSL fragility, not a mystery.** First
   pass (see below) mis-attributed this to register/stack corruption
   from a truncated log line; that guess didn't survive a harder test
   and is retracted here rather than left uncorrected.

   Retested with real `timer.device` EClock timestamps bracketing
   `SSL_connect()` and a much longer `--benchmark-until 900` window
   (deterministic core, so this genuinely lets the guest run 900
   emulated seconds, not just a longer wall-clock budget): `SSL_connect()`
   was invoked at ~17 emulated seconds in, and by the full 900-second
   mark -- 883 more emulated seconds later -- nothing further had
   completed, not even a `ReadEClock()` + `fprintf()` of a plain integer
   immediately after the call returns (or doesn't).

   Asked directly whether this could just be slow, unaccelerated
   handshake math rather than a real stall (a fair challenge -- RSA/
   ECDHE bignum work on a 14MHz 68020 genuinely could be slow) --
   settled it empirically rather than by argument: reran the identical
   test at `--cpu-clock 200` (a 14x clock increase over the stock
   14MHz) with `--jit` (Copperline's batch/trace JIT, "not cycle-exact,
   accelerator-style timing", explicitly meant to approximate a real
   accelerator card's throughput). If the 900-second cutoff were purely
   compute-bound, a 14x faster clock plus JIT should have finished the
   same handshake in a small fraction of the emulated time. It didn't
   move at all -- identical truncation point, same 900-second run.
   Genuinely decisive: this rules out "just slow" conclusively, not
   merely by inference from wall-clock reasoning as the first pass did.

   Found the *why*, not just the *that*, by reading a second independent
   AmiSSL client on the same platform: `~/src/micropython/ports/amiga/
   modssl.c`'s own header comment (a real, shipped, working
   implementation) documents exactly this failure mode and why it was
   abandoned:

   > "An earlier revision had a second 'fd path' that handed AmiSSL the
   > raw descriptor via `SSL_set_fd` for blocking clients. It was
   > dropped: its ioctl couldn't report poll readiness (so it was
   > unusable from asyncio), and its single blocking `SSL_connect` was
   > the more fragile of the two -- **it intermittently broke the pipe
   > under the Amiga's slow handshakes**, where the BIO pump (with
   > proper EAGAIN handling) succeeds."

   `tls.c`'s current `tls_connect()` uses exactly the pattern that
   quote describes as fragile: `SSL_set_fd()` followed by one blocking
   `SSL_connect()` call, letting AmiSSL's own internal socket I/O drive
   the handshake. micropython's fix (their `modssl.c`, `make_ssl_socket`/
   `ssl_socket_pump`) is a real, proven, working alternative on this
   exact platform: `BIO_new_bio_pair()` + `SSL_set_bio()` to give
   OpenSSL a memory BIO instead of a raw fd, `SSL_set_connect_state()` +
   a manual `SSL_do_handshake()` loop checking `SSL_get_error()` for
   `SSL_ERROR_WANT_READ`/`SSL_ERROR_WANT_WRITE`, and hand-rolled ciphertext
   pumping between the BIO and the real socket (their own I/O, with real
   `EAGAIN` handling) instead of trusting AmiSSL's own blocking fd path
   to do it correctly. Also worth adopting regardless of the BIO-pair
   change: micropython's `amiga_ssl_open()` passes `AmiSSL_ErrNoPtr`,
   which `tls.c`'s own `amisnap_tls_lib_open()` currently omits (reasoned
   at the time as optional since nothing here reads `errno` directly) --
   `amissl.doc`'s own `InitAmiSSLA` entry warns "You should always
   specify this tag or errno error detection in your program will not
   work reliably", and AmiSSL's *own* internal socket calls (exactly the
   ones driving the now-confirmed-fragile blocking path) depend on it
   to interpret retry conditions correctly, independent of whether this
   codebase ever reads that pointer itself.

   **Net status**: `tls.c`'s own soft-load, cert-verification, and
   connection-setup logic is confirmed correct against a real AmiSSL
   install (item 4's original "does AmiSSL init even work on real
   hardware" question, fully resolved). The blocking `SSL_set_fd()` +
   `SSL_connect()` design is now a confirmed, understood, real design
   flaw -- not a hang of unknown origin -- with a concrete, working
   reference design (the BIO-pair pump) to build the real fix from.

   **`https://` is now deliberately disabled at the CLI level
   (2026-08-13), not just left reachable with a known bug**: a backup
   tool hanging indefinitely on a destination is a worse failure mode
   than a clear refusal, so `open_backend()` (`main.c`) now refuses
   every `https://` URL unconditionally, before ever touching
   `amisnap_tls_lib_open()` -- `plain http://` is completely unaffected
   (unchanged code path, still fully working). `tls.c`/`tls.h` and the
   `make m68k` AmiSSL-SDK auto-fetch both stay in the tree exactly as
   built and verified -- nothing here was reverted or deleted, only the
   CLI dispatch that could reach the known-hanging call. Revisit once
   `tls.c` is rebuilt around the non-blocking BIO-pair pump described
   above.
5. Host CI: protocol code (items 1-3) run against a local WebDAV
   container. **Done (2026-08-13)**, though "container" ended up meaning
   a real local server *process*, not a Docker container -- see below
   for why that's the more useful check, not a shortcut.

   `tests/webdav/posix_transport.[ch]` -- a real POSIX-sockets
   `amisnap_transport_ops` implementation, living under `tests/`, not
   `src/core/` (`CORE_SRCS` is a blanket wildcard shared by both the
   host test build and the m68k cross-build, and libnix `-noixemul` has
   no POSIX sockets at all -- confirmed while designing `transport.h`
   itself, which is exactly why this needed its own separate,
   non-wildcarded home).

   `tests/webdav/mini_webdav_server.py` -- a minimal, stdlib-only WebDAV
   server (PUT/GET/DELETE/MKCOL/PROPFIND, both Content-Length and
   chunked-Transfer-Encoding request bodies, decoded by hand since
   `BaseHTTPRequestHandler` doesn't do this itself) backed by a real
   directory. Deliberately a genuinely **independent** implementation,
   not this project's own in-memory mock (`tests/test_webdav.c`) run a
   second way -- a self-consistent mock can only ever confirm "my client
   agrees with my own assumptions about the wire format", never catch a
   real interop bug the way a separate implementation (a real server, a
   real HTTP/1.1 parser, on a real TCP loopback connection) can. This is
   *more* useful than pointing at an actual off-the-shelf WebDAV
   container image would have been for exactly the same reason curl's
   own successful chunked PUT against this same server (used mid-
   debugging, see below) was reassuring: this server has zero shared
   code or assumptions with AmiSnap's own.

   `tests/webdav/live_test.c` + `run.sh` drive the same operations
   `tests/test_webdav.c`'s mock-based tests already cover (put/get/
   exists/list/mkcol/remove, the chunked streaming upload including
   `put_abort`, 404-vs-real-error) against the real server instead,
   wired into `make webdav-check` (and `test-host`, so CI runs it on
   every push -- no Docker/container runtime needed, just `cc` and
   `python3`, both already required elsewhere in this repo's own
   tooling).

   **A real, genuine bug this found that the mock never could**: the
   very first run hung indefinitely on the first chunked upload.
   Root-caused by capturing the exact bytes on the wire (a small
   throwaway TCP-tee proxy, not guesswork) and confirming they were
   byte-for-byte correct chunked framing -- ruling out the client before
   suspecting the server. The bug was in `mini_webdav_server.py` itself:
   it used a plain single-threaded `socketserver.TCPServer`, but
   `webdav.c` legitimately holds one HTTP/1.1 keep-alive connection open
   across several requests (`webdav_exchange()`'s own connection reuse)
   while its streaming `put_begin`/`put_append`/`put_finish` trio opens
   a *second, concurrent* connection for the chunked upload -- exactly
   the real-world connection pattern a real multi-connection-capable
   WebDAV server has to support, which a single-threaded test server
   cannot: it was permanently blocked inside the first (still-open,
   idle) connection's next-request read, unable to ever accept the
   second. Fixed by switching to `socketserver.ThreadingMixIn`. A useful
   confirmation of `webdav_exchange()`'s own real-world connection
   pattern, not just a test-infra footnote -- it's exactly the kind of
   concurrent-connection behavior a real WebDAV server (Apache mod_dav,
   Nextcloud, ...) already has to handle as a matter of course.

**Phase 4 — Encryption.** Format already carries the encryption tags
from day one (designed in phase 1, unused until here;
docs/format.md "Encryption (CIPHER 1)" now specifies subkey
derivation, nonce discipline, and the WRAPPED_KEY layout precisely).

1. Vendor SHA-256/ChaCha20/HMAC-SHA256/PBKDF2-HMAC-SHA256 from AmiAuth
   v1.0. **Done (2026-08-13)** — `src/core/{sha256,chacha20,hmac_sha256,
   pbkdf2}.[ch]`. SHA-256 and ChaCha20 are straight renamed ports of
   AmiAuth's (RFC-verified there); HMAC is trimmed to the SHA-256
   variant only (AmiSnap has no use for AmiAuth's SHA-1/SHA-512 vault
   forms — carrying them would violate the CPU-budget "never
   mandatory" rule for code nobody calls on a 68020); PBKDF2 is
   adapted to HMAC-SHA256 per docs/format.md's `KDF` tag (AmiAuth's is
   HMAC-SHA1), with vectors independently computed via Python's
   `hashlib.pbkdf2_hmac` and cross-checked against `openssl kdf` since
   no RFC ships SHA-256 PBKDF2 vectors the way RFC 6070 does for
   SHA-1. ChaCha20 drops AmiAuth's asm-dispatch seam — AmiAuth itself
   measured a hand-written 68k asm block function slower than the C
   reference on real hardware, so there's nothing to dispatch to yet.
   `make test`: 673/673.
2. Vendor AmiAuth's HMAC-DRBG (`src/core/drbg.c`) and Amiga entropy
   pool (`src/amiga/random.c`/`entropy.h`, incl. `amisnap_read_passphrase()`
   and `amisnap_millis()` for PBKDF2 calibration below) — the repository
   key, its wrap nonce, and the KDF salt all need real randomness, not
   just the deterministic subkey derivation docs/format.md's Encryption
   section covers. **Done (2026-08-13)**. The DRBG itself is adapted to
   run over HMAC-SHA256 rather than AmiAuth's HMAC-SHA1 (same reasoning
   as item 1's HMAC trim: SHA-1 would otherwise be vendored solely for
   this one caller), verified against an independent Python
   HMAC-DRBG-over-SHA256 oracle in tests/test_drbg.c. `random.c`'s
   entropy-gathering, timer.device handling, and RAW-mode passphrase
   reading are otherwise unchanged from AmiAuth's, only its running
   accumulator hash moved from SHA-1 to the already-vendored SHA-256.
   Cross-build-verified only so far (`make m68k-docker` compiles and
   links clean); no host build exists for this file to run under vamos
   or Copperline (m68k-only, uses timer.device/RAW console mode with no
   vamos dos.library equivalent) — same on-target-only verification
   status AmiAuth's own random.c carries.
3. `init --passphrase`: generate the repository key and salt, calibrate
   PBKDF2 iterations with a short timing probe against `amiga_millis()`
   (target ~1-2s wall clock, same pattern as AmiAuth's own vault KDF
   calibration) rather than a fixed iteration count, wrap the key, and
   write `CIPHER`/`KDF`/`WRAPPED_KEY` into `REC_REPO`. A `re-key`
   path (new passphrase, same repository key) only touches
   `WRAPPED_KEY` — the point of keeping the repository key stable.
   **Crypto glue and header framing done (2026-08-13)**:
   `src/core/repo_crypto.c` (subkey derivation, deterministic object/
   manifest nonces, the encrypt/decrypt frame, key wrap/unwrap --
   vectors cross-checked against an independent from-spec Python
   reimplementation, not derived from this C code) and
   `src/core/repo_header.c` (amisnap.repo / REC_REPO TLV read/write,
   `repo.h`'s previously-out-of-scope repository-level state --
   round-trip and validation tests only so far, not yet wired into
   `amisnap_repo_writer_finish()` or any reader).
   **`INIT REPO=<path> PASSPHRASE` CLI command done (2026-08-13)**
   (`src/cli/main.c`'s `cmd_init()`): prompts twice for a passphrase
   (`amisnap_read_passphrase()`, RAW no-echo), generates the repository
   key/salt/WRAPPED_KEY nonce via `amisnap_random()`, calibrates PBKDF2
   iterations with a short timing probe against `amisnap_millis()`
   (target 1.5s, falling back to a fixed conservative iteration count
   if no timer is available), wraps the key, and writes
   `CIPHER`/`KDF`/`WRAPPED_KEY` into a fresh `amisnap.repo`. Refuses to
   run against a repository that already has one (a one-time setup
   step, not idempotent -- see `cmd_init()`'s own comment on why
   re-running it against an existing header is unsafe to allow blindly
   rather than merely unimplemented). Every other command
   (`SNAPSHOT`/`LIST`/`VERIFY`/`RESTORE`) now calls a shared
   `open_repo_key()` right after `open_backend()`: no `amisnap.repo` at
   all still means CIPHER 0 (unchanged, still the default -- `init` was
   never required for a plain repository and still isn't), `CIPHER=0`
   in the header is a no-op, `CIPHER=1` prompts for the passphrase and
   unwraps the key, failing closed (a real error, not silent plaintext
   fallback) on a wrong passphrase or corrupt header. Cross-build-
   verified (`make m68k-docker`: compiles and links clean; `vamos`:
   confirmed `ACTION=INIT`'s argument validation and the
   PASSPHRASE-required refusal message both work under emulation --
   the real entropy-gathering/passphrase-prompt path itself needs a
   real console and RTC, so it's on-target-only like the rest of
   `random.c`, per item 2 above). **Re-key done (2026-08-13)**:
   `ACTION=REKEY REPO=<path>` (`cmd_rekey()`) changes the passphrase
   without touching the repository key itself -- unwraps the existing
   `WRAPPED_KEY` under the CURRENT passphrase first (failing closed on
   a wrong one, same as `open_repo_key()`), prompts for and confirms a
   new one, recalibrates PBKDF2 (a repository's KDF cost should track
   the machine re-keying it, not stay frozen at init time), and
   rewrites `KDF`/`WRAPPED_KEY` in `amisnap.repo` -- `REPO_ID`/
   `CHUNK_SIZE`/`FORMAT_APP` and, critically, the repository key itself
   (so every already-written object/manifest stays readable) are
   carried over unchanged. `cmd_init()` and `cmd_rekey()` share two new
   helpers (`prompt_new_passphrase()`, `calibrate_and_wrap()`) rather
   than duplicating the "type it twice, calibrate, wrap" sequence.
   Cross-build-verified the same way as `INIT` (`make m68k-docker`
   clean; `vamos` confirms `REKEY`'s argument validation and its
   two distinct refusals -- no `amisnap.repo` at all, and a plain
   CIPHER=0 repository -- both work under emulation).
4. Wire `K`/`K_enc`/`K_mac` through `repo.c`'s object writer/reader and
   `manifest.c`'s manifest writer/reader for the nonce/ciphertext/mac
   framing docs/format.md specifies. `tools/amisnap_reader.py` (the
   host-side reference reader) gets the same logic in parallel —
   docs/format.md's own "New format structures need the host-side
   reference reader updated in the same change" rule — so
   `cross-check` keeps proving the two agree once CIPHER=1 repositories
   exist. **C side done (2026-08-13)**: `amisnap_repo_writer_init()`
   takes an optional `amisnap_repo_subkeys *` (NULL = CIPHER 0,
   unchanged behavior) and, when set, `write_object()` encrypts every
   new object and `amisnap_repo_writer_finish()` encrypts the manifest
   (flags bit 0 set), both using repo_crypto.c's deterministic nonce
   derivation. Two new shared read-side helpers —
   `amisnap_repo_fetch_object()` (fetch+decrypt+hash-verify one object
   in a single call) and `amisnap_repo_open_manifest()` (decrypt a
   fetched manifest file's body if its flags bit 0 is set, including a
   consistency check that the embedded nonce matches the deterministic
   derivation from its own snapid) — are now used by both
   `amisnap_verify_manifest()` and `amisnap_restore_manifest()` (both
   gained `subkeys`/`snapid` parameters), so a real end-to-end
   write→verify→restore cycle against a CIPHER=1 repository works
   today (`tests/test_repo_encrypted.c`: writes a snapshot with real
   subkeys, confirms the *raw backend bytes* are genuinely not
   plaintext — not just that the high-level round-trip succeeds — then
   verifies and restores it, plus negative cases for no key and the
   wrong key). `make test`: 741/741 (in the exact CI container, not
   just locally). **`tools/amisnap_reader.py` is NOT yet updated** —
   it still refuses any CIPHER != 0 repository outright; that, plus
   repository-header wiring (item 3's `init --passphrase`) and CLI
   passphrase handling (item 5), are what's left before an encrypted
   repository is usable end-to-end from the actual CLI.
5. CLI: passphrase prompt (`amiga_read_passphrase()`) for every
   command that opens an encrypted repository; a wrong passphrase must
   fail closed with a clear message (MAC check on `WRAPPED_KEY`),
   never silently produce garbage plaintext. **Done (2026-08-13)** as
   part of item 3's `cmd_init()`/`open_repo_key()` work above -- no
   separate key-file option ended up needed (the original one-line
   Phase 4 blurb's "key file with optional passphrase wrap" is exactly
   what `WRAPPED_KEY` inside `amisnap.repo` already *is*, once
   format.md's design was worked out in full -- there was never a
   second on-disk key file to design). **`PRUNE` wired too
   (2026-08-13)**: `prune.c`'s mark pass (decode every surviving
   manifest to collect referenced object hashes) now calls
   `amisnap_repo_open_manifest()` per snapshot, same as list/verify/
   restore; the sweep pass needed no change at all (object *names* are
   always the plaintext content hash regardless of CIPHER, so matching
   sweep candidates against the mark set never touched the key).
   `amisnap_prune_execute()` gained a `subkeys` parameter, threaded
   through from `cmd_prune()`'s own `open_repo_key()` call.
   `tests/test_repo_encrypted.c` covers it: two encrypted snapshots
   sharing one deduplicated object, pruning the older one with the
   wrong key (fails closed on the mark pass -- confirmed via
   `objects_deleted == 0`, i.e. the sweep that would touch real
   objects never ran, even though the target manifest itself was
   already gone by then per the documented manifest-first-no-partial-
   rollback contract) and then the real key (correctly sweeps the
   orphaned object, leaves the still-referenced shared one alone).
6. End-to-end test: snapshot/restore/verify cycle against a CIPHER=1
   repository (host `backend_dir`), plus the cross-check above.
   **Done (2026-08-13)**, including the Python side:
   `tests/test_repo_encrypted.c` (see item 4) for the core C round-trip,
   and `tools/amisnap_reader.py` now implements CIPHER=1 fully -- a
   stdlib-only pure-Python ChaCha20 (RFC 8439, deliberately *not*
   calling into `src/core/chacha20.c` or a third-party crypto package:
   the entire value of a reference reader is staying independent of the
   implementation it's meant to be checking), PBKDF2/keyed-BLAKE2s via
   `hashlib` (already stdlib), and a `getpass`-prompted passphrase. Its
   subkey/nonce/frame functions are verified against the exact same
   fixed vectors `tests/test_repo_crypto.c` uses (agreement with the C
   side, not just internal self-consistency) plus the standalone RFC
   8439 ChaCha20 vector directly. `tests/cross/gen_sample_repo.c` grew
   an optional third argument (a passphrase) that writes a CIPHER=1
   `amisnap.repo` (fixed, known-answer repo key -- this is a
   reproducible test fixture, not a real repository, so real entropy
   doesn't apply) and encrypts the same fixture snapshot;
   `tests/cross/run.sh` now drives list/verify/restore against it
   through the real Python reader (passphrase piped via stdin) and
   confirms a wrong passphrase fails closed. Verified against the exact
   CI container: `make test-host` 741/741, `cross-check` green
   including the new encrypted section, `make build` (m68k) clean.
   **Still open**: on real hardware, confirming `cmd_init()`'s PBKDF2
   calibration lands in the target range on at least one real
   (non-emulated) CPU speed -- `amisnap_millis()`/`amisnap_random()`
   are m68k-only and untestable on host or under vamos (no
   timer.device/RAW-console emulation), same status as `random.c`
   itself (item 2).

**Phase 5 — S3.** SigV4 with `UNSIGNED-PAYLOAD`, large objects, tested
against MinIO in CI and B2 manually. Builds on Phase 3's `http.c`
(transport-agnostic HTTP/1.1 request/response layer -- S3 needs a
different *auth* scheme and body shape than WebDAV, not a different
socket/TLS story) and Phase 4's vendored HMAC-SHA256/SHA-256 (SigV4's
signing chain is HMAC-SHA256 throughout, no new hash primitive
needed).

1. SigV4 signing primitive (`src/core/sigv4.c`): canonical request,
   string-to-sign, the four-step HMAC-SHA256 signing-key derivation
   (date -> region -> service -> `aws4_request`), and the final
   signature/`Authorization` header, per
   docs/proposal.md's "Tier 3" (`UNSIGNED-PAYLOAD` — S3 lets the
   payload hash be that literal string instead of a real SHA-256,
   avoiding a second body pass or buffering the whole object just to
   hash it first). Vectors: AWS's own published
   `aws-sig-v4-test-suite` (fetched live from
   `github.com/saibotsivad/aws-sig-v4-test-suite`, a mirror of the
   suite AWS's docs link to — canonical request, string-to-sign, *and*
   final signature for each case, not just intermediate values),
   never transcribed from memory. No new hash primitive: built
   entirely on the already-vendored `hmac_sha256.c`/`sha256.c`.
   **Done (2026-08-13)**: `src/core/sigv4.[ch]` -- canonical-request
   assembly (internal header lowercasing/sorting and value
   canonicalization: trim + collapse internal whitespace runs to one
   space, confirmed against the `get-header-value-trim` vector, which
   collapses whitespace even inside a quoted value), string-to-sign,
   the 4-step signing-key derivation, final signature, `Authorization`
   header assembly, and a standalone `UriEncode()` primitive
   (uppercase-hex, space as `%20`, `/` encoded only when the caller
   says to -- query strings vs. path components). `tests/test_sigv4.c`
   checks four real AWS vectors (`get-vanilla`,
   `get-vanilla-query-unreserved`, `get-header-value-trim`,
   `post-vanilla`) end to end -- canonical request text, string-to-
   sign, *and* final signature all matched AWS's published values
   on the first run. `make test`: 798/798 (exact CI container);
   `make build` (m68k) clean.
2. S3 protocol layer + backend, built on `http.c` exactly like
   `webdav.c` is, differing only in headers (SigV4 `Authorization` +
   `x-amz-date`/`x-amz-content-sha256` instead of WebDAV's Basic
   auth/`Depth`) and body handling (`UNSIGNED-PAYLOAD`, no XML request
   bodies needed for basic object CRUD). **Done (2026-08-13)**: one
   file, `src/core/s3.c` (+ `s3.h`) -- combining protocol and backend
   the same way `webdav.c` itself does (transport.h's own header
   comment already anticipated this exact split: "webdav.c, s3.c
   protocol clients over a socket abstraction"), so the originally-
   planned separate `backend_s3.c` never ended up needed.
   PUT/GET/HEAD(`exists`)/DELETE, `mkcol` as the documented no-op, and
   `ListObjectsV2` (a small hand-rolled XML scan, paginated via
   `NextContinuationToken`, bounded at 100000 pages against a broken/
   hostile server that never stops claiming `IsTruncated` -- same
   defensive-bound reasoning `prune.c`'s own snapid-collision loop
   uses) for `list()`. `remove()` does a `HEAD` before `DELETE` --
   real S3's own `DELETE` is unconditionally "successful" (204
   whether or not the key ever existed), which would otherwise
   silently break `backend.h`'s documented `AMISNAP_ERR_NOT_FOUND`
   contract that `prune.c` and other callers rely on for accurate
   counts; a real, deliberate extra request, not an oversight.
   `put_begin`/`append`/`finish`/`abort` buffer the whole chunk in
   memory and issue one ordinary signed PUT at `finish` (unlike
   WebDAV's real chunked-Transfer-Encoding stream) -- SigV4's
   `UNSIGNED-PAYLOAD` still needs a definite `Content-Length`, and S3
   doesn't accept arbitrary `Transfer-Encoding: chunked` request
   bodies the way a generic WebDAV server does; real S3 multipart
   upload is deliberately out of scope (item 4 below). SigV4 needs a
   real wall-clock UTC timestamp per request (`amisnap_s3_now()`,
   plain ISO C `time()`/`gmtime()` -- confirmed working under libnix
   `-noixemul` on the real m68k cross-build, not just assumed), the
   one non-deterministic seam in an otherwise fully portable,
   host-testable module.

   Tested against a mock `amisnap_transport` (`tests/test_s3.c`,
   smaller than `test_webdav.c`'s own mock since S3 needs no chunked-
   request decoding or MKCOL bootstrapping): PUT/GET/HEAD/DELETE
   round-trip, streaming upload + abort, `ListObjectsV2` including a
   real multi-page pagination scenario, and URL parsing. Building this
   mock surfaced (and fixed) three real bugs the unit-level SigV4 tests
   couldn't have caught, since they only exercise the signing math, not
   full request assembly: `amisnap_sigv4_canonical_request()`'s
   `signed_headers_out` and `amisnap_sigv4_authorization_header()`'s
   own output were never NUL-terminated, so using them as C strings
   (exactly what `amisnap_http_build_request()`'s own `%s` formatting
   needs) read past the end of their buffers; and `s3_list()`'s
   pagination loop could spin forever if a server's `NextContinuation
   Token` extraction ever came back empty while `IsTruncated` stayed
   true (now bounded, see above, independent of the specific bug that
   first surfaced it in the mock). `make test`: 884/884 (exact CI
   container). `make build` (m68k): clean.
3. CLI wiring: `s3://` URL dispatch in `open_backend()`
   (`src/cli/main.c`), same pattern as the existing `http://`/`https://`
   dispatch — access key/secret/region/bucket parsed from the URL and
   `S3_*`-style config, TLS following the same per-destination opt-in
   `tls.c` already provides (proposal: plaintext against a LAN MinIO,
   `TLS=YES` required for public providers). **Done (2026-08-13)**,
   TLS aside: `s3://<access_key>:<secret_key>@host[:port]/<bucket>
   [/prefix][?region=<region>]` dispatches to
   `amisnap_backend_s3_open()`, lazily opening bsdsocket.library the
   same way the WebDAV path already does (shared `g_bsdsocket_transport`/
   `g_socket_lib_open` state — no TCP/IP stack requirement for a pure
   directory-backend backup). There is no separate `s3s://`/TLS-enabled
   scheme yet — `s3://` is plaintext-only, same known AmiSSL blocking-
   handshake issue that disabled `https://` for WebDAV (item 4 in Phase
   3); revisit both together once `tls.c` is rebuilt around the
   non-blocking BIO-pair pump. Cross-build-verified (`make m68k-docker`
   clean; `vamos` confirms both the malformed-URL refusal and the
   no-TCP/IP-stack refusal work under emulation — reaching a real MinIO
   endpoint needs real hardware/network, item 6 below).

   **`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_REGION`/
   `AWS_DEFAULT_REGION` env-var fallback added (2026-08-17)**, so a
   `REPO=s3://host/bucket` URL doesn't have to carry credentials in
   plaintext in a Startup-Sequence script, shell history, or `ps`
   output -- same standard names/precedence the AWS CLI and SDKs use
   everywhere else. `amisnap_s3_parse_url()`'s userinfo is now optional
   (`amisnap_s3_url.has_credentials`/`has_region` report which parts
   the URL itself supplied); `open_backend()` calls `GetVar()` (no
   `GVF_GLOBAL_ONLY`/`GVF_LOCAL_ONLY`, so both a local `Set` and a
   global `SetEnv` are honoured, same as a Unix shell's plain
   assignment vs. `export`) only for whatever the URL left unspecified,
   and only errors ("no credentials for ...") if both the URL and the
   environment come up empty. Confirmed live under Copperline (the
   `run-s3.sh` on-target test's own second pass, `Set`-only since this
   minimal boot's `C:` has no `MakeDir`/`Assign`/`List` to build a real
   `ENV:`): a full SNAPSHOT/LIST cycle against the same independent S3
   server, `REPO=` carrying no credentials at all.

   One real bug surfaced and fixed before this could ship safely: an
   early version ran the `AWS_REGION`/`AWS_DEFAULT_REGION` lookup
   unconditionally whenever the URL's own `?region=` was absent (the
   common case) -- regardless of whether the URL already carried
   credentials. `GetVar()`'s global-variable fallback resolves through
   the `ENV:` logical device, and (the same class of quirk as this
   item's own `snapshot_source_repo_overlap()`/`Lock()`-on-a-URL
   finding below) confirmed live to hang on a real "Please insert
   volume ENV in any drive" requester rather than failing cleanly when
   `ENV:` isn't assigned -- rare on a normally-booted AmigaOS system
   (every stock Startup-Sequence assigns it) but a real risk for an
   unattended backup run on a minimal/embedded/scripted one, and it
   would have silently added that risk to every existing
   credentials-in-the-URL deployment, not just new env-var-only ones.
   Fixed by nesting the region lookup inside the "no URL credentials"
   branch, so it only runs once the caller has already opted into
   "configure entirely from the environment" -- a URL with embedded
   credentials but no `?region=` is exactly as safe as it was before
   this feature existed.
4. "Large objects to minimise request count": proposal's own stated
   S3 strategy is bigger chunks, not S3 multipart upload — repo.c's
   existing `amisnap_repo_writer_file_chunked()`/`AMISNAP_DEFAULT_CHUNK_SIZE`
   mechanism already does exactly this or needs a larger *default*
   chunk size for S3 destinations specifically (SigV4 signs one whole
   request at a time, so a chunk is one PUT either way); real S3
   multipart upload (`CreateMultipartUpload`/`UploadPart`/
   `CompleteMultipartUpload`) was originally scoped as out of scope for
   v1 unless a single PUT's practical size ceiling forced it.
   **Done anyway (2026-08-13)**, once a real ceiling turned out to
   already exist: `restore.c`'s `put_begin`/`append`/`finish` spans an
   ENTIRE reconstructed destination file (looping `put_append()` once
   per source `E_CONTENT` chunk), which can be arbitrarily large no
   matter how small `AMISNAP_DEFAULT_CHUNK_SIZE` itself is — the
   original whole-buffer-then-one-PUT streaming implementation (item 2)
   would have silently defeated chunked restore's own memory-bounded
   design for any S3 destination restoring a large file. `s3.c`'s
   streaming path now escalates to a real multipart upload once
   buffered data reaches `AMISNAP_S3_MIN_PART_SIZE` (5 MiB, S3's own
   real minimum part size for every part but the last), uploading each
   full part as it's reached rather than continuing to grow one
   unbounded buffer; an upload that never reaches the threshold still
   takes the original single-PUT path unchanged. `put_abort()`/a
   failed `put_finish()` both issue a real `AbortMultipartUpload` once
   a multipart upload was actually started.

   `tests/s3/mini_s3_server.py` grew a genuine implementation of all
   four multipart operations (not a shortcut) specifically so this
   proves `s3.c`'s multipart *client* code against something that
   actually implements the server side of the protocol, the same
   "independent implementation, not this project's own assumptions"
   reasoning as everything else in that file.
   `tests/s3/live_test.c` uploads a real 12 MiB object across three
   `put_append()` calls (crossing the 5 MiB threshold twice, so this
   is a genuine 3-part upload, not just a 1-part edge case) and
   confirms the round-tripped bytes match exactly — passed on the
   first real run. Verified against the exact CI container: `make
   test-host` 884/884 (including `s3-check`'s new multipart round
   trip) and `make build` (m68k) both clean.
5. Host CI: a real MinIO instance (container or process, same
   "independent implementation, not this project's own mock a second
   way" reasoning `tests/webdav/mini_webdav_server.py` documents —
   MinIO is a real, independent S3 implementation, so this is even
   stronger than the WebDAV case's own from-scratch Python server) --
   `tests/s3/` mirroring `tests/webdav/`'s shape (a host-only POSIX
   transport, a `*-check` Makefile target wired into `test-host`).
   **Done (2026-08-13)**, "MinIO instance" ended up meaning a
   from-scratch, stdlib-only Python S3 server (`tests/s3/
   mini_s3_server.py`) rather than a real MinIO binary or container --
   the same "ended up meaning a real local server process, not a
   Docker container" reasoning `webdav-check`'s own comment gives (no
   docker-in-docker in the CI runner), but pulling in a real ~100MB
   third-party binary download every CI run for this purpose was a
   worse trade than writing an independent implementation directly,
   especially since the actually-interesting thing to verify --
   **whether a genuinely separate SigV4 implementation accepts a
   signature `s3.c` produced** -- needed *some* real verification code
   regardless of whether the server wrapping it was MinIO or hand-
   written. `mini_s3_server.py` recomputes the canonical request/
   string-to-sign/signature from the actually-received request
   (headers, method, path, query string) and rejects a mismatch with
   403 -- independent Python `hmac`/`hashlib`, not a copy of
   `src/core/sigv4.c`. This is strictly stronger than AWS's own
   published test vectors (`tests/test_sigv4.c`): those prove the
   *signing* math is right in isolation; this proves a *live* request
   s3.c actually builds and sends is accepted by someone else's
   verification, over a real TCP loopback connection
   (`tests/webdav/posix_transport.c`, reused as-is -- no S3-specific
   logic in it to duplicate). `tests/s3/live_test.c` mirrors
   `tests/webdav/live_test.c`'s own checks (put/get, exists, streaming
   upload + abort, list, remove's `NOT_FOUND` contract) and passed on
   the first real run. Wired into `test-host` as `make s3-check`.
   Verified against the exact CI container: `test-host` (including
   `s3-check`) and `make build` (m68k) both clean.
6. On-target (Copperline) smoke test against the same independent S3
   server used by item 5's host-CI check. **Plaintext half done
   (2026-08-17)**: `tests/copperline/run-s3.sh`, mirroring
   `run-webdav.sh`'s own shape exactly (`--hostsocket-net host`,
   `mini_s3_server.py` reachable over real loopback TCP out of the
   guest) — a real SNAPSHOT/LIST/VERIFY/RESTORE cycle against a real,
   independent, signature-verifying S3 server, all under real 68020
   execution. The manual real-B2-bucket run with `TLS=YES` is still
   open, same AmiSSL blocker as item 3/Phase 3 item 4.

   This was the first real on-target exercise of *anything* linked
   against `libamisslstubs.a` (Phase 4 added the link, but no on-target
   Copperline test had been re-run since) and it surfaced three
   genuine, previously-undiscovered bugs no host-only testing could
   have caught:

   - **Every** on-target Copperline test, not just S3's, was silently
     broken since Phase 4: `libamisslstubs.a` carries an unresolved
     reference to `LocaleBase`, which libnix's linker resolves by
     pulling its own auto-open glue out of `libstubs.a` -- and that
     glue makes `__initlibraries()` hard-require `locale.library` at
     startup, aborting the whole program (RC 20, before `main()` runs)
     if it's absent, which it is on the minimal Copperline boot volume
     (`locale.library` is a Workbench-disk module, not a ROM
     component). Confirmed live: `AmiSnap failed returncode 20` /
     "locale.library failed to load" on a plain boot, no network
     involved. Fixed with `src/amiga/no_locale.c`, a single
     `struct Library *LocaleBase = NULL;` definition linked ahead of
     `libstubs.a` in the documented link order -- satisfies
     amisslstubs.a's reference directly, so ld never pulls in the
     auto-open glue, and `LocaleBase` simply stays NULL the same way a
     real "no locale.library installed" system would leave it (not a
     crash: nothing in this codebase's own call graph dereferences it).
   - `amisnap_s3_parse_url()` (`src/core/s3.c`) located the userinfo/
     host boundary by searching for the first '/' anywhere in the URL
     before ever looking for '@' -- broken for any real AWS-shaped
     secret key, which is base64-alphabet and routinely contains a
     literal '/' with no escaping required by this scheme's own
     documented syntax. Confirmed live against AWS's own published
     SigV4 test-vector secret key (which contains a '/'). Fixed by
     scanning for '@' unbounded instead (it can't legitimately appear
     in the host/bucket/prefix components that follow, so the first
     one in the whole remaining string is always the real boundary);
     regression test added to `tests/test_s3.c`'s own URL-parsing
     block using that exact secret key.
   - `snapshot_source_repo_overlap()` (`src/cli/main.c`)'s own
     documented Phase-3 finding -- calling `Lock()` on a URL string
     doesn't fail cleanly, it hangs the guest on a real "Please insert
     volume ... in any drive" requester -- was only ever guarded for
     `http://`/`https://`; Phase 5 added the `s3://` scheme but never
     extended this check's skip list, so every on-target S3 SNAPSHOT
     hung indefinitely at this exact spot. Fixed by adding `s3://` to
     the same skip condition.

   Also confirmed live, not a bug: a `REPO=` URL value containing a
   second, embedded `=` (e.g. a `?region=` query string) is genuinely
   unparseable by AmigaDOS `ReadArgs()` as a bare, unquoted keyword
   value -- `ReadItem()`'s own documented contract delimits *any*
   unquoted argument on the first space/tab/semicolon/equals-sign it
   meets, not just the one `ReadArgs` itself consumes for `KEY=`.
   Wrapping the value in double quotes does not help either: a quote
   immediately following that consumed `=` is not "at the start of the
   line or preceded by a blank/tab" (`ReadItem`'s own precise
   quote-recognition rule), so it isn't treated as opening a quoted
   string, and the resulting literal quote character breaks `s3.c`'s
   own `"s3://"` prefix check in `open_backend()` instead (confirmed
   live: falls through to the mounted-volume backend, reproducing the
   same "insert volume" hang as the bug above, from a different cause).
   `run-s3.sh` avoids the whole class of problem by never appending
   `?region=` at all -- `us-east-1` is already
   `amisnap_s3_parse_url()`'s own built-in default -- rather than
   fighting AmigaDOS quoting edge cases for it; real deployments
   targeting a non-default region need to be aware `REPO=` can't
   safely carry a second `=` unquoted on an AmigaDOS command line.

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

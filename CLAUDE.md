# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

AmiSnap is a snapshot-based backup tool for classic AmigaOS targeting
modern destinations (mounted volumes / SMB / NFS first, then WebDAV,
then S3-compatible object storage), with incremental snapshots,
retention pruning, verified restore, and bit-perfect round-trip of Amiga
filesystem metadata. **The design document of record is
`docs/proposal.md`** -- read it before making architectural decisions;
this file only covers building and navigating the code day to day.

**Current state:** scaffold only. The build system, CI wiring, test
harness, and the first core module (`src/core/xxhash32.c`, XXH32 with
reference-verified vectors) exist; no snapshot engine, no Amiga metadata
capture, no backends yet. Phase 1 (proposal "Phases") is the next work:
snapshot/index/manifest model, ExAll()-based metadata capture and
restore, BLAKE2s, and the mounted-filesystem backend.

## Layout

- `src/core/` -- portable C engine: hashing, snapshot model, index,
  manifest/repository format. Builds with any host compiler; no Amiga
  includes allowed here.
- `src/amiga/` -- Amiga-only code: ExAll()/Examine() metadata capture,
  SetOwner()/SetComment()/SetProtection() restore, DOS I/O backend,
  bsdsocket transports later. m68k build only.
- `src/cli/` -- the AmiSnap command front-end (ReadArgs templates, RC
  codes). Currently a version-printing stub that exits RC 5 (WARN) so
  scripts can't mistake it for a working tool.
- `tests/` -- host-side unit/vector tests (`tests/test.h` harness, same
  shape as sibling AmiAuth's: TEST_CHECK fails the run, TEST_PENDING
  doesn't). `tests/copperline/run.sh` is an honest skip until on-target
  work exists.
- `docs/proposal.md` -- the design document (copied from the
  project-ideas repo; this copy is the working reference).

## Build commands

```sh
make test          # host unit/vector tests (default target)
make m68k          # cross-build build/AmiSnap (m68k-amigaos-gcc on PATH)
make m68k-docker   # same, inside ghcr.io/sidick/amiga-dev
make dist          # build/dist/AmiSnap.lha + .readme for Aminet
make clean
```

CI verb contract (`sidick/amiga-workflows/build-test.yml`, invoked from
`.github/workflows/ci.yml`): `build` / `test-host` / `test-target` /
`lint` / `dist` -- CI depends on those exact Makefile target names, don't
rename them.

Target floor: **68020, AmigaOS 3.0 (V39)**, no FPU (`-m68020
-msoft-float -noixemul`). The audience for network backup skews
accelerated/emulated (proposal, "Toolchain and testing"); V39 gives
`SetOwner()` for restore. Check before using anything newer than V39.

## Design rules that bind the code

- **CPU budget is the design driver** (proposal, "CPU budget"): SHA-256
  must never be mandatory anywhere; xxHash32 free, BLAKE2s once per
  new/changed file, ChaCha20/TLS opt-in per destination.
- **Metadata is the product**: capture via `ExAll()`/`Examine()` only
  (no filesystem internals), sized for long names and `ED_OWNER` from
  the start. No 30-character filename assumption anywhere in the
  repository format. Restore degrades explicitly, never silently.
- **Trust is everything**: atomic snapshot commit (manifest last), a
  crashed run leaves the previous snapshot intact, `verify` is a
  first-class command. New format structures need the host-side
  reference reader updated in the same change.
- Crypto (ChaCha20/PBKDF2/HMAC) is vendored from sibling AmiAuth v1.0
  (RFC-verified, OpenSSL-differential-fuzzed there) when Phase 4 lands
  -- don't reimplement. BLAKE2s is new work here and needs the same
  vector + differential-fuzz regime.
- Test vectors get verified against a reference implementation before
  being recorded (see `tests/test_xxhash32.c`'s header for the
  pattern), never transcribed from memory.

## House conventions (this repo and its siblings)

- Version lives in `version.mk` (`VERSION`/`REVISION`, Amiga
  major.minor). The CLI's `$VER` cookie must match -- `make dist` greps
  for it.
- License is BSD 2-Clause; source files don't need a header (LICENSE
  covers the repo), but workflow/CI files carry an SPDX header.
- Releases are tag-driven: push a `v*` tag matching `version.mk` and
  `AmiSnap.readme`'s `Version:` (checked by
  `scripts/verify-version.sh`), then
  `sidick/amiga-workflows/aminet-release.yml` builds `make dist` and
  publishes behind the `aminet` environment's required reviewer. A
  release PR bumps the two version files first; the workflow verifies,
  it doesn't bump.
- Real functions, not guessed heuristics: when correct behavior isn't
  obvious, find the documented contract (autodocs, RKRM, RFC) and
  verify against a real fixture/emulator -- don't trust compilation
  alone.

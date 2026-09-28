# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

AmiSnap is a snapshot-based backup tool for classic AmigaOS targeting
modern destinations (mounted volumes / SMB / NFS first, then WebDAV,
then S3-compatible object storage), with incremental snapshots,
retention pruning, verified restore, and bit-perfect round-trip of Amiga
filesystem metadata. **The working plan of record is
`docs/implementation-plan.md`** (module map, work order, decisions made
since the proposal -- e.g. the archive-bit trust policy); the original
design rationale is `docs/proposal.md`, and where they disagree the
plan wins. Read the plan before making architectural decisions; this
file only covers building and navigating the code day to day.

**Current state:** feature-complete against the proposal's Phases 1-6
and not yet released. The engine (snapshot/index/manifest, metadata
capture and restore, xxHash32/BLAKE2s/SHA-256), prune, verify,
encryption (ChaCha20/PBKDF2/HMAC), and all three backend tiers
(directory/mounted volume, WebDAV, S3 with SigV4) are implemented and
tested; `src/cli/main.c` is a real front-end with ten actions
(`SNAPSHOT` `RESTORE` `LIST` `VERIFY` `PRUNE` `APPLYUAEM` `INIT`
`REKEY` `BENCHMARK` `HELP`), and `userdocs/` + `make guide` ship both
MkDocs and AmigaGuide documentation. **What remains for 1.0 is not
code:** the tag-driven Aminet release, and the gate of at least one
full backup rotation reported from real hardware. `version.mk` still
reads 0.1 and `userdocs/Changelog.md` honestly states no tagged release
exists.

Track outstanding work in GitHub issues, not in this file. Note that
`docs/implementation-plan.md` records completed items inline with
`**Done (date)**` markers -- read those before assuming something is
unbuilt.

## Layout

- `src/core/` -- portable C engine: hashing (xxhash32, blake2s, sha256),
  snapshot model, index, manifest/repository format, prune, restore,
  crypto (chacha20, pbkdf2, hmac, drbg), compression (lz4, miniz), and
  the backends (backend_dir, webdav, s3/sigv4 over `transport.h`).
  Builds with any host compiler; **no Amiga includes allowed here**.
- `src/amiga/` -- Amiga-only code: `ExAll()`/`Examine()` metadata
  capture (`scan.c`), `SetOwner()`/`SetComment()`/`SetProtection()`
  restore (`restore_meta.c`), path handling (`amipath.c`), bsdsocket
  transport (`socket.c`), AmiSSL TLS (`tls.c`), stack swapping
  (`stackswap.c`), `.uaem` sidecar application (`applyuaem.c`). m68k
  build only. See `src/amiga/README.md`.
- `src/cli/` -- the AmiSnap command front-end: ReadArgs templates, the
  action dispatch, and RC codes. The `TEMPLATE`/`ARG_*` definitions
  here are the normative source for `userdocs/CLI-Reference.md` --
  update both together.
- `tests/` -- host-side unit/vector tests (`tests/test.h` harness, same
  shape as sibling AmiAuth's: TEST_CHECK fails the run, TEST_PENDING
  doesn't), plus `tests/cross/` (C<->Python reference-reader
  cross-check), `tests/vamos/` (m68k binaries run under amitools vamos),
  `tests/webdav/` and `tests/s3/` (container-backed backend tests), and
  `tests/copperline/` (on-target emulator harness; skips honestly,
  exit 0, when the emulator isn't available locally).
- `tools/` -- `amisnap_reader.py`, the host-side reference reader that
  makes a repository recoverable without an Amiga, and `docs2guide.py`,
  the Markdown-to-AmigaGuide converter behind `make guide`.
- `userdocs/` -- MkDocs Material user documentation; also the source for
  the shipped `AmiSnap.guide`.
- `docs/format.md` -- the **normative** repository format spec. New
  format structures change this file, `tools/amisnap_reader.py`, and
  the C implementation in the same commit.
- `docs/proposal.md` -- the original design rationale.

## Build commands

```sh
make test          # host unit/vector tests (default target)
make test-host     # everything CI runs on the host: test + vamos +
                   #   cross-check + webdav-check + s3-check
make test-target   # on-target harness (Copperline) + fixtures
make m68k          # cross-build build/AmiSnap (m68k-amigaos-gcc on PATH)
make m68k-docker   # same, inside ghcr.io/sidick/amiga-dev
make guide         # build/AmiSnap.guide from userdocs/
make lint          # semgrep
make dist          # build/dist/AmiSnap.lha + .readme for Aminet
make clean
```

CI verb contract (`sidick/amiga-workflows/build-test.yml`, invoked from
`.github/workflows/ci.yml`): `build` / `test-host` / `test-target` /
`lint` / `dist` -- CI depends on those exact Makefile target names, don't
rename them.

Target floor: **68020, AmigaOS 2.04 (V37)**, no FPU (`-m68020
-msoft-float -noixemul`). The audience for network backup skews
accelerated/emulated (proposal, "Toolchain and testing"). Newer APIs
(e.g. V39's `SetOwner()`) are used opportunistically but **must** be
gated by an explicit runtime library-version check before every call
-- calling a function newer than what a library actually implements
hits whatever is past the end of its real jump table, not a clean
failure. See implementation-plan.md "OS floor is V37, not V39" for the
full policy and checklist before adding any such call.

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

## Prior art worth knowing about

**Amiga Guardian** (CopperByte Games, released 2026-09-27,
https://copperbytegames.itch.io/guardian) is a local snapshot-and-
rollback utility for OS 2.04+ on any 68000 -- snapshots into a Vault on
the user's own hard drive, compare-against-live, rollback of a file,
drawer, or whole drive. It is **complementary, not competing**, and
says so itself: "It is not a backup program. The copies live on your
own hardware." AmiSnap's differentiation is the off-machine
destinations and a format recoverable without an Amiga; Guardian's is
local undo, which AmiSnap has never claimed.

Several of its features are tracked as issues here (protected
snapshots, restore pre-flight plan, journaled restore, `COMPARE`,
exact-state restore, rescue volume). When positioning AmiSnap in docs,
say what it is not -- `docs/proposal.md`'s "nothing modern exists"
claim now holds only for the network/versioned case.

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

# AmiSnap

Versioned network/cloud backup for classic AmigaOS: incremental
snapshots, retention pruning, verified restore, optional compression
and encryption, and bit-perfect preservation of Amiga filesystem
metadata (full 32-bit protection mask, FileNotes, ticks-precision
datestamps, owner/group, long filenames) -- to a mounted volume,
WebDAV, or S3-compatible object storage.

**Documentation: <https://sidick.github.io/amisnap/>** -- installation,
CLI reference, destinations, encryption/compression, disaster recovery,
and more.

**Status: beta.** The engine (`SNAPSHOT`/`RESTORE`/`VERIFY`/`PRUNE`/
`LIST`), full Amiga metadata capture and restore, all three destination
tiers (mounted volume, WebDAV, S3), and optional per-repository
encryption and compression are implemented and tested -- host unit
tests, a from-scratch cross-implementation Python reader, and
on-target runs against real emulated AmigaOS (Copperline) with real
filesystems and real independent WebDAV/S3 server implementations.
There has not yet been a full release cycle on real, non-emulated
hardware -- run it alongside your existing backup method for now, not
as its sole replacement. The full design and phase plan live in
[docs/implementation-plan.md](docs/implementation-plan.md) (the
working plan of record) and [docs/proposal.md](docs/proposal.md) (the
original design rationale).

## Design in one paragraph

The design driver is a 68030's CPU budget: change detection is
metadata-first with the Amiga archive bit as a fast path, xxHash32 is
used freely, BLAKE2s integrity hashing happens once per new/changed
file, and compression (LZ4/deflate) and ChaCha20 encryption/TLS are
per-destination opt-ins that default to off -- so the common case
(trusted NAS on the LAN) runs at wire speed. The repository format is
documented ([docs/format.md](docs/format.md)) and versioned with a
host-side Python reference reader
([tools/amisnap_reader.py](tools/amisnap_reader.py)), so a snapshot is
recoverable on a PC even if the Amiga is dead.

## Building

The core engine is portable C; host tests build with any C compiler.

```sh
make test          # build + run host-side unit/vector tests
make m68k          # cross-build the Amiga binary (needs amiga-gcc on PATH)
make m68k-docker   # same, inside the ghcr.io/sidick/amiga-dev container
make dist          # package build/dist/AmiSnap.lha for Aminet
make guide         # build build/AmiSnap.guide (AmigaGuide docs, from userdocs/)
```

CI runs the shared five-verb contract (`build` / `test-host` /
`test-target` / `lint` / `dist`) via
[sidick/amiga-workflows](https://github.com/sidick/amiga-workflows).

## License

BSD 2-Clause -- see [LICENSE](LICENSE).

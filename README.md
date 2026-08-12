# AmiSnap

Versioned network/cloud backup for classic AmigaOS: incremental
snapshots, retention pruning, verified restore, and bit-perfect
preservation of Amiga filesystem metadata (full 32-bit protection mask,
FileNotes, ticks-precision datestamps, owner/group, long filenames) --
to a mounted volume today, WebDAV and S3-compatible storage later.

**Status: early scaffold.** Nothing works yet. The full design and phase
plan live in [docs/proposal.md](docs/proposal.md).

## Design in one paragraph

The design driver is a 68030's CPU budget: change detection is
metadata-first with the Amiga archive bit as a fast path, xxHash32 is
used freely, BLAKE2s integrity hashing happens once per new/changed
file, and ChaCha20 encryption and TLS are per-destination opt-ins that
default to off -- so the common case (trusted NAS on the LAN) runs at
wire speed. The repository format is documented and versioned with a
host-side Python reference reader, so a snapshot is recoverable on a PC
even if the Amiga is dead.

## Building

The core engine is portable C; host tests build with any C compiler.

```sh
make test          # build + run host-side unit/vector tests
make m68k          # cross-build the Amiga binary (needs amiga-gcc on PATH)
make m68k-docker   # same, inside the ghcr.io/sidick/amiga-dev container
make dist          # package build/dist/AmiSnap.lha for Aminet
```

CI runs the shared five-verb contract (`build` / `test-host` /
`test-target` / `lint` / `dist`) via
[sidick/amiga-workflows](https://github.com/sidick/amiga-workflows).

## License

BSD 2-Clause -- see [LICENSE](LICENSE).

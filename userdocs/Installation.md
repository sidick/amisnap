# Installation

## Requirements

- AmigaOS 2.04 (V37) or later, on a real 68020+ CPU or an accelerator
  card, or an emulator (Copperline, Amiberry, WinUAE, FS-UAE) configured
  for at least a 68020. AmiSnap is built `-m68020 -msoft-float`: it will
  not run on plain 68000/68010 hardware, and does not require or use an
  FPU.
- `bsdsocket.library` (any TCP/IP stack that provides it -- Roadshow,
  AmiTCP, Miami, ...) only if you use a `http://`/`https://` (WebDAV) or
  `s3://` destination. A plain mounted-volume destination (a local
  partition, or a DOS device from `smbfs`/`AmiNFS`/similar) needs no
  networking library at all.
- `AmiSSL` (v5, opened at runtime) only if a destination URL uses
  `https://` with `TLS=YES`, or you need TLS for another reason. AmiSnap
  runs fine without AmiSSL installed as long as no destination actually
  needs TLS.

## Getting the binary

AmiSnap has not yet had its first tagged Aminet release (see
[the index page](index.md)'s note on beta status) -- until one exists,
the way to get the binary is to build it yourself, either on a real
`m68k-amigaos-gcc` toolchain or via the project's Docker-based
cross-build. See [Building from Source](Building-from-Source.md) for
both paths (`make m68k` / `make m68k-docker`), and `make dist` for the
Aminet-shaped archive (`build/dist/AmiSnap.lha` +
`build/dist/AmiSnap.readme`) the release pipeline itself produces.

Once a release exists, it will be published via the project's tag-driven
Aminet pipeline (`docs/implementation-plan.md` "House conventions") and
this page will link straight to it. The archive shape either way is:

- `AmiSnap` -- the command-line tool itself. Copy it to `C:` (or
  anywhere on your `PATH`).
- `AmiSnap.readme` -- the short Aminet-style summary.
- `LICENSE` -- BSD 2-Clause.

There is no installer script and nothing to configure before first use
-- `AmiSnap` is a single self-contained binary.

## Checking it works

Run it with no arguments (or an invalid `ACTION`) from a Shell:

```
1.C:> AmiSnap
AmiSnap 0.1 (12.08.2026)
AmiSnap: bad arguments. Template: ACTION/A,SOURCE/K,REPO/K,DEST/K,...
```

Seeing the version banner confirms the binary runs on your system at
all (it prints before argument parsing, so it appears even on a usage
error). If it instead fails to start, double check the CPU/accelerator
requirement above -- a plain 68000 will refuse to run a `-m68020`
binary.

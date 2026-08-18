# Building from Source

```
$ git clone https://github.com/sidick/amisnap.git
$ cd amisnap
```

## Running the host-side tests

No Amiga toolchain needed -- the portable core (hashing, snapshot
model, repository format, most of the protocol layers) is plain C99 and
builds with any host compiler:

```
$ make test
```

This is the default target and what CI runs on every push.

## Cross-building the Amiga binary

Needs `m68k-amigaos-gcc` on `PATH` (from the
[amiga-gcc](https://github.com/bebbo/amiga-gcc) toolchain or similar):

```
$ make m68k
```

produces `build/AmiSnap`. No local cross-toolchain? Build inside the
same Docker image the project's own CI uses instead:

```
$ make m68k-docker
```

(needs `docker` on `PATH`; pulls `ghcr.io/sidick/amiga-dev` on first
use).

## Building the Aminet-shaped release archive

```
$ make dist
```

Builds the m68k binary, confirms it embeds the version currently in
`version.mk` (catching a stale `build/` directory before it ships), and
packages `build/dist/AmiSnap.lha` + `build/dist/AmiSnap.readme` -- the
exact pair the project's tag-driven Aminet release pipeline publishes.

## Building this documentation

The MkDocs site (this page included) lives in `userdocs/`:

```
$ pip install mkdocs-material mike
$ mkdocs serve
```

The on-Amiga AmigaGuide version is generated from the same `userdocs/`
source, not maintained separately:

```
$ make guide
```

produces `build/AmiSnap.guide`, readable in AmigaGuide/MultiView back to
OS 2.x. `make dist` includes it in the release archive automatically.

## Cleaning up

```
$ make clean
```

## Target floor

68020, AmigaOS 2.04 (V37), no FPU (`-m68020 -msoft-float -noixemul`).
Newer APIs (e.g. V39's `SetOwner()`) are used opportunistically but only
ever behind an explicit runtime library-version check -- see
`docs/implementation-plan.md`'s "OS floor is V37, not V39" section if
you're contributing code that touches a version-gated call.

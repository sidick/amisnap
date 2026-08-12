# nondistribution/

Local-only home for assets that can't be committed to this repo for
licensing reasons — Kickstart ROM images, Workbench install directories,
and anything else that falls under this rule. Everything under this
directory except this README is gitignored.

This is the reason a real on-target harness (Copperline/Amiberry,
implementation-plan.md Phase 1 item 8) stays local-only, never CI:
there's no committable base image to build a hosted harness from.

## Current contents

```
nondistribution/
  roms/
    a1200-kick31-40.68.rom   Kickstart 3.1, Rev 40.68, model A1200
                             (CRC32 D6BAE334) -- identified by checksum
                             via the amiberry MCP tools, not filename;
                             the source file this was copied from was
                             misleadingly named "amiga-os-310-a4000.rom"
                             despite actually being the A1200 ROM. A
                             same-named-but-different file in that same
                             collection ("amiga-os-310-a1200.rom")
                             identifies as Rev 40.63, model
                             A500/A600/A2000 -- NOT this ROM, despite
                             the more plausible-looking filename. If
                             sourcing Kickstart ROMs again, verify by
                             checksum, never by filename.
    a600-kick205-37.350.rom  Kickstart 2.05, Rev 37.350, model A600HD
                             (CRC32 43B0DF7B). Requested as "37.300"
                             originally -- the minimum revision with
                             hard drive support on the A600 -- but that
                             exact revision was not present in the
                             source ROM collection
                             (~/Documents/Amiberry/Kickstarts). 37.350
                             is a later revision in the same 2.05 line
                             and so still has HD support; used as a
                             substitute with the user's explicit
                             confirmation (2026-08-12).
```

Copied from `~/Documents/Amiberry/Kickstarts` via the `amiberry` MCP
tools' `list_roms`/`identify_rom` (checksum-based identification, since
filenames in that source collection are not reliable).

Suggested layout for anything added later (nothing here is enforced by
tooling — point your own `.toml`/`.uae` configs at wherever these
actually live):

```
nondistribution/
  roms/            # Kickstart ROM images
  workbench/        # Directory-backed Workbench install(s)
```

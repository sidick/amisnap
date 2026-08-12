# src/amiga

Amiga-only code (m68k build only, never the host tests): metadata
capture via `ExAll()`/`Examine()`, restore via `SetProtection()`/
`SetComment()`/`SetFileDate()`/`SetOwner()`, the DOS I/O (Tier 1)
backend, and later the bsdsocket-based WebDAV/S3 transports.

Empty at scaffold time -- Phase 1's capture/restore code lands here
first. Everything portable belongs in `src/core/` instead.

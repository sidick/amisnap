# Proposal: AmiSnap — Versioned Cloud & Network Backup for AmigaOS

**Status:** Candidate project
**Feasibility estimate:** Medium–High (~70–75%) — the design is solid but the correctness surface (backup must never lose data, four destination protocols) is large
**Dependencies:** Amiga filesystem metadata handling, SMB/NFS/WebDAV/S3 destinations, shared crypto core (from AmiAuth), AmiSSL (optional TLS)

## Summary

A snapshot-based backup tool for classic AmigaOS that backs up to modern destinations — a LAN NAS over SMB/NFS, WebDAV, or S3-compatible object storage — with incremental snapshots, retention pruning, verified restore, and full preservation of Amiga filesystem metadata. The design takes the platform's CPU constraints seriously: cryptography and content hashing are *opt-in per destination*, not baked into the pipeline, so the common case (trusted NAS on the LAN) runs at wire/disk speed while the untrusted-cloud case pays for client-side encryption only when the user asks for it.

## Why this project

- The classic backup tools (Quarterback, Diavolo, ABackup) predate networking as a destination and are abandonware; nothing modern exists that does *versioned* backup from an Amiga to a NAS or cloud. Current practice is ad-hoc: manual copies to an smbfs mount, or imaging the whole CF card on another machine.
- Generic approaches lose data. Copying files to a Samba share silently drops **protection bits** (the full HSPARWED set), **file comments** (FileNotes are real user data on Amiga — decades of them), original **datestamps** in edge cases, and **soft/hard links**. A native tool that round-trips all of it is the core value proposition, independent of the transport.
- Restic/borg-style tools cannot be sensibly ported: their content-defined chunking and mandatory SHA-256-everything pipeline is designed for CPUs four orders of magnitude faster. The interesting engineering here is designing a *backup model that respects a 68030*.

## CPU budget — the design driver

Rough orders of magnitude on a 68030/50 (the realistic mid-range target; a stock A1200 is worse, emulation/PiStorm far better):

| Operation | Approx. throughput | Implication |
|---|---|---|
| SMB/NFS copy, no processing | 500–1500 KB/s (NIC-bound) | baseline — this is what users will compare against |
| SHA-256 | low hundreds of KB/s | must never be mandatory |
| BLAKE2s | ~2–3× SHA-256 | preferred integrity hash where one is needed |
| xxHash32 | near-memory-speed | fine to use freely for change detection |
| ChaCha20 | high hundreds of KB/s | acceptable opt-in encryption cost |
| TLS bulk transfer (AmiSSL) | cipher-bound as above | LAN plaintext stays the fast path |

Consequences baked into the design:

1. **Change detection is metadata-first.** A file is considered changed if size, datestamp, or protection/comment metadata differ from the snapshot index — the same model every fast backup tool on every platform uses. The Amiga **archive bit** is honoured as an additional fast-path hint (set on write by the OS, cleared by AmiSnap after backup), giving near-instant "nothing changed" runs. Optional paranoid mode adds xxHash32 verification of allegedly-unchanged files.
2. **No content-defined chunking.** Whole-file granularity, with a fixed-size chunk split only for files above a threshold (default 8MB) so a giant file's tail change doesn't force a full re-upload. Dedup across identical files (by size + xxHash + BLAKE2s confirm) is cheap and catches the realistic duplication on Amiga volumes; rolling-hash dedup is not worth its CPU cost here.
3. **Integrity hashing (BLAKE2s) happens once per new/changed file**, stored in the index, reused for verify and restore checking. Never re-hashed on unchanged files in normal runs.
4. **Encryption (ChaCha20 + BLAKE2s MAC) and TLS are per-destination options, both defaulting to off.** Each network destination carries a `TLS=YES|NO` setting (default `NO`): a stock 68030 talking to a LAN NAS or LAN MinIO stays plaintext at full speed, while a PiStorm, Vampire, or emulated machine can turn TLS on and barely notice the cost. AmiSSL is loaded only when a destination requests it, so the tool has no hard AmiSSL dependency and fails gracefully with a clear message if TLS is requested but the library is absent.

## Destinations

Tiered by how much the Amiga has to do:

- **Tier 1 — Mounted filesystem (SMB via smbfs, NFS via a mounted handler, or any DOS volume).** AmiSnap just does DOS I/O to a path like `NAS:Backups/A1200`. Zero protocol code, works with whatever mount the user already has, and is the recommended default. This tier alone would make the tool worthwhile.
- **Tier 2 — WebDAV over HTTP(S).** Native client (PUT/GET/MKCOL/PROPFIND) via bsdsocket, plain HTTP by default with TLS as the per-destination opt-in. Plaintext covers the LAN self-hosted case (Nextcloud or a WebDAV-enabled NAS on your own network); TLS unlocks internet-facing endpoints like Hetzner Storage Box or rsync.net for machines with the CPU to spare.
- **Tier 3 — S3-compatible object storage.** AWS Signature v4 requires an HMAC-SHA256 signing chain per request; AmiSnap keeps this affordable by signing with `UNSIGNED-PAYLOAD` and using large objects to minimise request count. TLS follows the same per-destination opt-in: plaintext HTTP works against LAN targets like MinIO on a NAS (SigV4 never transmits the secret key, so plaintext leaks data in transit but not credentials, acceptable on a trusted LAN), while public providers (B2, Wasabi, R2, AWS) require HTTPS and are documented as needing `TLS=YES` and a correspondingly capable CPU. In-transit integrity comes from TLS where enabled and from AmiSnap's own BLAKE2s manifest hashes everywhere — `verify` catches any transit corruption regardless of transport.

All destinations sit behind one backend API (`open/put/get/list/delete/close`), so snapshots are destination-agnostic and a repository can be mirrored between tiers by a host-side companion or a later `copy` command.

## Repository format

- Content storage: files (or chunks of large files) stored under their BLAKE2s hash, optionally ChaCha20-encrypted; a small manifest per snapshot lists every path with its full Amiga metadata — protection bits, FileNote comment, datestamp (ticks precision), link information — plus the hash references.
- **Metadata captured as the full superset, not the lowest common denominator.** The manifest stores the complete 32-bit protection mask, not just the classic HSPARWED byte — so the group/other RWED bits used by MultiUser filesystems round-trip intact — and records **owner UID/GID** where the filesystem provides them (`ED_OWNER` via `ExAll()`). Filenames are stored with no length assumption anywhere in the format: long-name filesystems (long-name FFS in OS 3.1.4+/3.2, SFS, PFS3 variants) are handled from day one rather than retrofitted, since baking a 30-character assumption into a v1 repository format would be the classic mistake. Manifest metadata records are tag-based and extensible, so future filesystem attributes slot in without a format break.
- **Per-volume filesystem identification in every snapshot:** the source volume's DosType (e.g. `DOS\7` long-name FFS, `PFS\3`, `SFS\0`), volume name and creation date, and a detected capability set (max filename length, owner support). This serves two purposes: it's forensic context for disaster recovery ("what exactly was this machine running?"), and it drives restore-time compatibility handling — restoring onto a *different* filesystem than the source, AmiSnap knows in advance which names won't fit and whether ownership can be applied, instead of failing file-by-file.
- **Restore degrades explicitly, never silently:** names too long for the target filesystem follow a user-chosen policy (fail, skip, or truncate with a collision-proof suffix — each logged); owner/group applied via `SetOwner()` where the target supports it and reported as skipped where it doesn't; the summary states exactly what couldn't be represented.
- Manifests and indexes are plain, documented, versioned binary structures with a host-side reference reader in Python, so **a snapshot is recoverable on a PC even if the Amiga is dead** — an explicit design goal for a backup tool, and it makes the "restore my dead machine's data" story credible.
- Local snapshot index cached on the Amiga so incremental runs never need to read the remote index over a slow link; self-heals by re-fetching if missing or stale.
- Retention: `keep last N / daily D / weekly W / monthly M` pruning with a mark-and-sweep of unreferenced content objects.

## Operations (v1)

- `snapshot` (with include/exclude patterns; `.info` files are just files and round-trip perfectly), `restore` (full or subtree, to original or alternate path, restoring all metadata last so protection bits like `d` don't block the restore itself), `list`, `verify` (structural always; `verify FULL` re-hashes content), `prune`.
- CLI-first with proper AmigaDOS ReadArgs templates and RC codes for scripting; ARexx port and a ClassAct GUI (consistent with AmiMQTT/AmiAuth) in a later phase. Scheduling in v1 is delegated to cron-alikes or a simple `WAIT`-loop script; a commodity scheduler is a v2 candidate.
- Logging designed for unattended runs: summary line (files scanned/changed/uploaded, bytes, duration) plus optional verbose log to a file.

## Toolchain and testing

C via amiga-gcc, 68020+ target (68000 build possible but the audience for network backup skews accelerated/emulated). Core engine (snapshot model, index, repository format, hashing, ChaCha20) is portable C with a host build; CI runs the full snapshot/restore/prune/verify cycle against a directory backend and a MinIO container on the host, plus round-trip property tests on the metadata encoding. Amiberry smoke test drives the real binary against a Samba share and checks metadata round-trip (protection bits, comments, datestamps) bit-for-bit. Aminet release via aminet-release-action.

**Copperline (0.12+) as a second, deterministic emulator harness.** Its writable host-directory mounts persist Amiga protection bits, comments, and datestamps to `.uaem` sidecars with Latin-1 filename mapping and `ACTION_EXAMINE_ALL` support — so a CI job can snapshot inside the guest, then assert metadata fidelity by reading the `.uaem` files on the host, with the deterministic core and JSON-RPC control protocol (scripted sessions, input injection, screenshots) making runs byte-reproducible. The same sidecar convention being implemented independently by WinUAE, Amiberry, and now Copperline also validates `.uaem` as the right interchange target for the future `amisnap-tool` host client — three emulators, one metadata format. The deterministic guest clock (`rtc_time`) additionally makes snapshot datestamps reproducible across CI runs, which turns "byte-identical repository given identical input" into a testable property.

**Planned optimisation: 68k assembler for BLAKE2s and ChaCha20** once the C versions pass their vectors — these two sit on every hot path (integrity hashing, encrypted tier, paranoid verify) and share the same 16/12/8/7 rotation set, which maps unusually well onto 68k (`SWAP` for rot-16, immediate `ROL` for the rest, no multiplies anywhere). C reference implementations remain in the build with runtime dispatch from `AttnFlags`; register pressure (ChaCha20's 16-word state vs eight data registers) means scheduling may warrant separate 020/030 and 060 variants. Asm paths are CI-tested by running the vector binary under amitools' `vamos`, and the ChaCha20/PBKDF2/HMAC components are vendored from the shipped AmiAuth v1.0 codebase (RFC-verified and OpenSSL-differential-fuzzed there) so the effort is paid once.

**Crypto provider selection (`CRYPTO=BUILTIN|AMISSL|AUTO`, default `BUILTIN`).** The dispatch table that separates C from asm also admits a third provider backed by AmiSSL's EVP API — worthwhile because AmiSSL ships CPU-optimised builds whose primitives may outperform our C on some machines, and EVP's per-call overhead amortises away on exactly the bulk hashing/encryption paths where AmiSnap spends its time. Soft-loaded like the TLS path, so `BUILTIN` configurations still never touch AmiSSL. `AUTO` runs a millisecond-scale micro-benchmark per primitive at first run and caches the winner. The repository format is provider-agnostic (standardised algorithms), and CI asserts cross-provider round-trip: written with one provider, read with another, bit-identical.

## Phases

**Phase 1 — Engine + Tier 1 (3–4 weekends).** Snapshot/index/manifest model, metadata capture and restore, xxHash/BLAKE2s, filesystem backend. Deliverable: snapshot + restore + verify to any mounted volume — already a usable product against smbfs/NFS mounts.

**Phase 2 — Prune + hardening (2 weekends).** Retention pruning, interrupted-run recovery (resumable uploads, atomic manifest commit last), paranoid verify mode, host-side reference reader.

**Phase 3 — WebDAV (2–3 weekends).** HTTP/1.1 client with keep-alive and resumable transfers; per-destination `TLS=YES` support via runtime-loaded AmiSSL (soft dependency — plaintext destinations never touch it).

**Phase 4 — Encryption (1–2 weekends).** Per-destination ChaCha20 + MAC, key file with optional passphrase wrap (PBKDF2) — vendoring the crypto components shipped in AmiAuth v1.0, which are already RFC-vector-verified and differentially fuzzed against OpenSSL in CI. BLAKE2s is the one primitive *not* in AmiAuth and is new work here (built in Phase 1 for integrity hashing); it should join the same vector + differential-fuzz test regime.

**Phase 5 — S3 (2 weekends).** SigV4 with UNSIGNED-PAYLOAD, tested against MinIO and B2.

**Phase 6 — Release.** Docs including an honest performance guide per tier and a disaster-recovery walkthrough using the host-side reader.

## Future goals (post-1.0)

- **`amisnap-tool` — a Unix command-line companion (Linux/macOS).** Grows the Phase 2 Python reference reader into a full extractor for working with snapshots outside the Amiga, aimed squarely at emulation workflows:
  - **Extract to directory-based virtual drives with `.uaem` sidecar files**, so protection bits, FileNote comments, and ticks-precision datestamps survive into a directory that WinUAE/Amiberry mounts as a native volume — a restore path that needs no running Amiga at all. (The plain-directory extract without `.uaem` files doubles as "just get my data onto the PC".)
  - **HDF writing as a stretch goal beyond the above, not a v-next commitment.** Writing into filesystem images pulls in real complexity (amitools dependency, OFS/FFS write correctness, RDB handling, no PFS3/SFS story at all) for a workflow the `.uaem` directory extract already covers — modern emulator setups mount directory drives happily, and an HDF can always be produced by copying inside the emulator. Kept on the roadmap for the archival/image-based use case, but explicitly sequenced after the directory-drive extract and backup client are solid. HDF *reading* for one-shot ingest is a smaller lift and may land earlier.
  - **A full backup client for directory-based drives, not just one-shot ingest.** The host tool runs the same snapshot engine against a directory drive — parsing `.uaem` sidecars so Amiga metadata is captured faithfully — with proper incremental change detection, retention pruning, and verify against the same repository format. This is the natural way to back up an Amiberry setup: the host does the work at host speed (where TLS, S3, and hashing cost nothing), on the host's scheduler, without the emulated machine even running, and the resulting snapshots are fully interchangeable with ones taken on real hardware — one repository can hold the history of both.
  - Filesystem identity and capability data recorded per volume (DosType, name length, owner support) is what makes this tool honest: it can warn before writing long names or owner data into an HDF whose filesystem can't represent them, mirroring the Amiga-side restore policies.
  - Same repository code path as the CI reference reader, so the extractor is continuously tested rather than a bolt-on — and its existence strengthens the core disaster-recovery promise from "your data is recoverable on a PC" to "your data is recoverable into a directory drive an emulator boots from."
- Commodity-based scheduler for unattended timed backups.
- ClassAct GUI and ARexx port (shared stack with AmiMQTT/AmiAuth).
- Repository mirroring between destinations (`copy` command or host-side, e.g. NAS tier replicated to an encrypted cloud tier).

## Risks and mitigations

- **Trust is everything for backup software:** a data-losing bug is fatal to adoption. Mitigate with the host-side test matrix, `verify` as a first-class command, atomic snapshot commit (a crashed run leaves the previous snapshot fully intact), and a beta period framed as "run alongside your existing method."
- **Filesystem variance (OFS/FFS/PFS3/SFS, long-name variants, MultiUser, exotic handlers):** metadata capture goes through `ExAll()`/`Examine()` only, no filesystem internals, with buffer sizes and structures sized for long names and `ED_OWNER` from the start; capability detection is probed per volume rather than inferred from DosType alone (some handlers lie). Test matrix covers FFS, long-name FFS, and PFS3 at minimum, with muFS owner round-trip in the Amiberry smoke test.
- **Large-volume index memory:** index streamed and windowed rather than fully resident; target comfortable operation on a 4MB fast RAM machine for ~50k files.
- **RAM-hungry TLS + big transfer buffers together:** buffer sizes configurable; encrypted cloud tier documented as wanting 8MB+ fast RAM.

## Success criteria

- Metadata round-trip is bit-perfect: the full 32-bit protection mask, owner/group, comments, datestamps, and long filenames identical after snapshot → wipe → restore on a like-for-like filesystem, verified in CI; cross-filesystem restores report every degradation explicitly.
- Incremental run over 10,000 unchanged files completes in under a minute on a 68030 (archive-bit fast path).
- A snapshot taken to a NAS is fully restorable using only the Python reference reader on a PC.
- At least one full user backup rotation (snapshot, prune, restore test) reported from real hardware before 1.0.

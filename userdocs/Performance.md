# Performance

AmiSnap's design treats CPU budget as a first-class constraint (this
project targets a 68020 floor, not an accelerated machine) -- this page
states the real, measured numbers behind that design, not aspirational
ones, so you can plan a backup schedule that actually fits your
hardware.

## Incremental scans are metadata-first

After the first full snapshot, a later `SNAPSHOT` only re-reads a file
if its metadata (protection excluding the archive bit, datestamp,
comment, owner, size) differs from the previous snapshot's record, OR
its archive bit is currently clear. A file that passes all of those
checks is reused without a single byte being read or hashed. On a real
68020, a repeat `SNAPSHOT` of a 10,000-file tree with nothing changed
completed in about 26 seconds in the project's own benchmark harness --
comfortably under its own 60-second target, and faster than the
same scan with the fast path disabled entirely (33.6s), not merely a
recovery back to that baseline.

`PARANOID` mode (re-reading and re-hashing every "unchanged" file below
the chunk-size threshold to catch bytes that changed without any
metadata change) costs real I/O on every run -- use it periodically, not
as your everyday default, if you want that extra guarantee.

## Memory

The incremental index (the previous snapshot's manifest, loaded once per
`SNAPSHOT` to drive the fast path above) is a genuine, documented memory
cost at scale: a 10,000-file index needed roughly 8MB of free RAM in the
project's own testing, once every entry's own content references and a
full copy of the raw manifest bytes are accounted for. If `SNAPSHOT`
fails with an out-of-memory error on a very large tree, this index is
the most likely cause -- reducing the number of files under one
`SOURCE=`, or backing up in smaller pieces, are the practical
workarounds today. A much larger (50,000+ file) target would benefit
from a real memory-efficiency pass this index hasn't had yet.

## Large files: chunking

A file larger than 256KiB (the current default chunk size) is streamed
through in fixed-size pieces rather than read whole into memory --
neither `SNAPSHOT` nor `RESTORE` ever needs to hold more than one
chunk's worth of a large file in RAM at a time, regardless of the file's
total size. This threshold exists because AmiSnap's own testing found a
single-buffer whole-file read genuinely fails with an out-of-memory
error on a stock Zorro II 8MB fast-RAM Amiga once the OS and AmiSnap's
own working set are accounted for -- 256KiB was chosen specifically to
work on that modest, non-accelerated configuration, not the largest
buffer a well-equipped system could technically spare.

`PARANOID` mode is deliberately skipped for chunked (large) files: a
paranoid re-check requires re-reading the whole file, which would defeat
the entire memory-bounded point of chunking. Large files still get the
ordinary metadata-trust fast path even under `PARANOID`.

## Hashing

Two hashes are involved, at very different costs, matching this
project's stated CPU-budget policy:

- **xxHash32** -- computed on every file, every snapshot, regardless of
  whether it changed (needed so a later `PARANOID` run has something to
  compare against). It runs near memory speed and is never the
  bottleneck.
- **BLAKE2s-256** -- computed once per new or changed file (the content
  hash content-addressing and deduplication both depend on), never on
  an unchanged file reused via the fast path above. This is the
  meaningfully more expensive of the two, by design only paid when a
  file's bytes actually need re-reading anyway.

SHA-256 is never used on the hot path -- it's reserved for
encryption-related key derivation (`INIT`/`REKEY`'s PBKDF2), a one-time,
deliberately-slow operation, not something run per file.

## Compression: which algorithm?

There's no single right answer -- it depends on the ratio of this
machine's CPU speed to this destination's real throughput, and both
vary enormously across the Amiga install base. Run `AmiSnap
ACTION=BENCHMARK REPO=<path>` (optionally `SOURCE=<path>` to sample
real file content instead of synthetic data) to get a real answer for
your own setup rather than a guess -- see [CLI Reference](
CLI-Reference.md)'s `BENCHMARK` section for what it measures and how
to read the result.

## Destinations: pick the right tier for your hardware

- **Mounted volume (Tier 1)** -- a local partition, or a network share
  mounted as a real DOS device (`smbfs`, `AmiNFS`, or similar). No
  networking library or TLS overhead at all; this is the fastest tier
  and the project's primary recommendation for a traditional,
  stock-speed Amiga.
- **Plain `http://` WebDAV** on a trusted home LAN -- a practical second
  choice at stock speed, still with no TLS overhead.
- **`https://` WebDAV, TLS**, measured on real 68020/14MHz hardware
  under Copperline emulation (bulk-cipher throughput only, PSK ciphers
  isolating transfer speed from certificate/handshake cost):

  | Cipher | KB/s | Time for 100MB (extrapolated) |
  |---|---|---|
  | AES-128-CBC | 11 | ~2.6 hours |
  | ChaCha20-Poly1305 | 9 | ~3.2 hours |
  | AES-256-CBC | 9 | ~3.2 hours |
  | AES-128-GCM | 5 | ~5.7 hours |
  | AES-256-GCM | 5 | ~5.7 hours |

  At a stock 68020 floor, TLS's own bulk-transfer overhead dwarfs any
  difference between ciphers -- hours for a real 100MB backup either
  way. **This project does not recommend `https://` for a traditional,
  stock-speed Amiga.** TLS support is real and genuinely useful for a
  different audience: PiStorm-class accelerators and fast emulation,
  where this CPU budget stops being the binding constraint. If you are
  on accelerated hardware and want to tune cipher choice for it,
  `CIPHERS=<list>` (see [CLI Reference](CLI-Reference.md)) is exactly
  that lever -- counter-intuitively, plain AES-CBC measured faster here
  than either ChaCha20-Poly1305 or the AES-GCM modes, likely because
  GCM/Poly1305's carry-less-multiplication-heavy authentication has no
  hardware acceleration on this platform. (Caveat: this is a first real
  data point from bulk-transfer-only measurement, not a full
  handshake-plus-transfer benchmark against a real certificate.)

  The table above is one machine's data point, not a promise about
  yours -- if you want to compare `CIPHERS=` choices on your own
  hardware against your own destination, run `AmiSnap ACTION=BENCHMARK
  REPO=<path> CIPHERS=<candidate>` once per candidate and compare the
  "Destination write" line each time (see [CLI Reference](
  CLI-Reference.md)'s `BENCHMARK` section). `BENCHMARK` itself doesn't
  loop over ciphers automatically: AmiSSL has a documented history of
  handshake fragility on this platform (`docs/implementation-plan.md`'s
  TLS section), and reopening it repeatedly inside one run risks
  reintroducing exactly that.
- **`s3://`** -- no TLS support yet, so the same "don't expect wire
  speed over a WAN link on stock hardware" reasoning applies even more
  directly; S3 destinations are inherently remote.

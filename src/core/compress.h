/* compress.h -- the OBJCOMP=1 object frame (docs/format.md "Content
 * objects"): `alg:u8` + `usize:u64 BE` + payload, where alg 0 = stored,
 * 1 = LZ4 block format, 2 = zlib (RFC 1950). The frame is the object
 * *body* -- in an encrypted repository it is what gets encrypted
 * (compress-then-encrypt), and the object's content-address hash is
 * always of the uncompressed bytes, never of the frame.
 *
 * Compression backends are the vendored upstream implementations
 * (src/core/lz4.[ch], LZ4 v1.10.0; src/core/miniz.[ch], miniz 3.0.2
 * stripped to the compression core via MINIZ_DEFS in the Makefile) --
 * not reimplemented, per the vendor-don't-guess rule. Interop with
 * non-AmiSnap decoders is asserted in tests/test_compress.c against
 * reference streams produced by python-lz4 and Python's zlib.
 */
#ifndef AMISNAP_COMPRESS_H
#define AMISNAP_COMPRESS_H

#include <stddef.h>
#include <stdint.h>

#include "tlv.h"

#define AMISNAP_COMP_STORED 0u
#define AMISNAP_COMP_LZ4    1u
#define AMISNAP_COMP_ZLIB   2u

#define AMISNAP_FRAME_HDR_SIZE 9u /* alg:u8 + usize:u64 */

/* Frames `data`/`len` into `out` (caller amisnap_buf_free()s it),
 * compressing with `alg` where that shrinks the payload and falling
 * back to AMISNAP_COMP_STORED where it doesn't (format.md: a framed
 * repository is never larger than necessary; already-packed content
 * costs near zero CPU). alg is the writer's *preference*; the frame
 * that comes out names what was actually used. Returns AMISNAP_OK,
 * AMISNAP_ERR_NOMEM, AMISNAP_ERR_MALFORMED if `alg` isn't a value this
 * writer implements, or AMISNAP_ERR_TOO_LONG if `len` exceeds what the
 * chosen backend can represent (LZ4's input cap is ~2GB; objects are
 * CHUNK_SIZE-bounded in practice, so this is a guard, not a path). */
int amisnap_frame_encode(uint8_t alg, const uint8_t *data, size_t len,
                         amisnap_buf *out);

/* Decodes the frame `data`/`len` into `out` (caller amisnap_buf_free()s
 * it). `expected_usize` is the size the caller already knows from the
 * manifest's E_CONTENT ref -- format.md requires the frame's usize to
 * equal it, and requiring it here also stops a corrupt/hostile frame
 * from asking this reader to allocate an arbitrary amount of memory.
 * Returns AMISNAP_OK; AMISNAP_ERR_CRITICAL_TAG if the frame names an
 * alg this reader doesn't implement (same refuse-loudly class as an
 * unknown CIPHER); AMISNAP_ERR_MALFORMED on a truncated frame, a usize
 * that isn't expected_usize, or a payload that doesn't decompress to
 * exactly usize bytes; AMISNAP_ERR_NOMEM. */
int amisnap_frame_decode(const uint8_t *data, size_t len,
                         uint64_t expected_usize, amisnap_buf *out);

#endif /* AMISNAP_COMPRESS_H */

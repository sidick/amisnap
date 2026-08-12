/* xxhash32.h -- XXH32, the fast non-cryptographic hash AmiSnap uses for
 * change detection and dedup pre-filtering (docs/proposal.md "CPU budget"):
 * near-memory-speed on a 68030, so it can be used freely where BLAKE2s
 * cannot. NOT an integrity hash -- the repository format's content
 * addresses use BLAKE2s; xxHash only ever short-circuits work.
 *
 * The one-shot API stays exactly as it was (a hand-rolled direct
 * implementation, no state-struct copying overhead for the common
 * small-file case). amisnap_xxh32_init/update/digest below is the
 * "streaming context" this header's own comment once deferred --
 * needed now that large files are read (and E_XHASH computed) in
 * fixed-size chunks rather than whole into memory (repo.c's
 * amisnap_repo_writer_file_chunked()); format.md's E_XHASH is one
 * value for the whole logical file, not per chunk. Independently
 * implemented from the same published spec, not built on top of the
 * one-shot function -- tests/test_xxhash32.c cross-checks the two
 * agree at many different update() split points, rather than needing
 * a second set of external reference vectors for this path. */
#ifndef AMISNAP_XXHASH32_H
#define AMISNAP_XXHASH32_H

#include <stddef.h>
#include <stdint.h>

uint32_t amisnap_xxh32(const void *data, size_t len, uint32_t seed);

typedef struct {
    uint32_t acc1, acc2, acc3, acc4;
    uint32_t seed;
    uint64_t total_len;
    uint8_t buf[16];
    size_t buf_len; /* 0-15: bytes carried over between update() calls,
                      * not yet folded into acc1-4 */
} amisnap_xxh32_state;

void amisnap_xxh32_init(amisnap_xxh32_state *s, uint32_t seed);
void amisnap_xxh32_update(amisnap_xxh32_state *s, const void *data, size_t len);
uint32_t amisnap_xxh32_digest(const amisnap_xxh32_state *s);

#endif /* AMISNAP_XXHASH32_H */

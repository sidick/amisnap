/* xxhash32.h -- XXH32, the fast non-cryptographic hash AmiSnap uses for
 * change detection and dedup pre-filtering (docs/proposal.md "CPU budget"):
 * near-memory-speed on a 68030, so it can be used freely where BLAKE2s
 * cannot. NOT an integrity hash -- the repository format's content
 * addresses use BLAKE2s; xxHash only ever short-circuits work.
 *
 * One-shot API only for now; a streaming context comes with the snapshot
 * scanner if file-at-a-time buffering turns out not to fit the RAM budget.
 */
#ifndef AMISNAP_XXHASH32_H
#define AMISNAP_XXHASH32_H

#include <stddef.h>
#include <stdint.h>

uint32_t amisnap_xxh32(const void *data, size_t len, uint32_t seed);

#endif /* AMISNAP_XXHASH32_H */

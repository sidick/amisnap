/* chacha20.h -- ChaCha20 stream cipher (RFC 8439), vendored from sibling
 * AmiAuth v1.0 (src/core/chacha20.c there; RFC-verified). This is
 * docs/format.md's CIPHER 1 object/manifest cipher. AmiAuth found a
 * hand-written 68k asm block function measured *slower* than this C
 * reference on real hardware, so no dispatch seam is carried over here.
 */
#ifndef AMISNAP_CHACHA20_H
#define AMISNAP_CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#define AMISNAP_CHACHA20_KEY_SIZE   32
#define AMISNAP_CHACHA20_NONCE_SIZE 12

/* XOR `len` bytes of `in` with the ChaCha20 keystream into `out`
 * (in-place permitted; `in` may be NULL to emit the raw keystream).
 * `counter` is the initial 32-bit block counter. */
void amisnap_chacha20_xor(const uint8_t key[AMISNAP_CHACHA20_KEY_SIZE],
                           const uint8_t nonce[AMISNAP_CHACHA20_NONCE_SIZE],
                           uint32_t counter,
                           const uint8_t *in, uint8_t *out, size_t len);

#endif /* AMISNAP_CHACHA20_H */

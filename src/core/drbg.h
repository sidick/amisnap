/* drbg.h -- HMAC-DRBG (NIST SP 800-90A Sec 10.1.2), adapted from sibling
 * AmiAuth v1.0's src/core/drbg.c. AmiAuth's DRBG runs over HMAC-SHA1
 * (its vault's own primitive); this one runs over HMAC-SHA256 instead
 * so it needs no separate SHA-1 vendoring -- SP 800-90A's HMAC_DRBG is
 * defined generically over any approved hash, and AmiSnap already
 * carries HMAC-SHA256 for PBKDF2 (see pbkdf2.h). This is the
 * whitening/expansion stage only, used to generate the repository key,
 * KDF salt, and WRAPPED_KEY nonce (docs/format.md "Encryption"); the
 * *entropy* that seeds it is a platform concern -- see
 * src/amiga/random.c for the AmigaOS source.
 */
#ifndef AMISNAP_DRBG_H
#define AMISNAP_DRBG_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"                /* AMISNAP_SHA256_DIGEST_SIZE */

typedef struct {
    uint8_t K[AMISNAP_SHA256_DIGEST_SIZE];
    uint8_t V[AMISNAP_SHA256_DIGEST_SIZE];
} amisnap_drbg_state;

/* Instantiate from seed material (entropy || nonce || personalisation, in any
 * combination the caller has gathered). `seedlen == 0` is accepted by the
 * algorithm (it degenerates to the fixed SP 800-90A initial K/V with no
 * folded-in data) but is NOT a safe way to seed this generator -- the result
 * is then fully deterministic and public. Guaranteeing real entropy is the
 * caller's responsibility, not this primitive's (see src/amiga/random.c,
 * whose seed is always a full AMISNAP_SHA256_DIGEST_SIZE-byte digest, never
 * empty). */
void amisnap_drbg_init(amisnap_drbg_state *st, const uint8_t *seed, size_t seedlen);

/* Fold additional entropy into the running state (SP 800-90A reseed). Same
 * non-empty-input caveat as amisnap_drbg_init above. */
void amisnap_drbg_reseed(amisnap_drbg_state *st, const uint8_t *in, size_t inlen);

/* Emit n pseudo-random bytes and advance the state. */
void amisnap_drbg_generate(amisnap_drbg_state *st, uint8_t *out, size_t n);

#endif /* AMISNAP_DRBG_H */

/* pbkdf2.h -- PBKDF2-HMAC-SHA256 (RFC 2898), the repository KDF
 * (docs/format.md "Encryption": `KDF` tag kdfid=1). Adapted from sibling
 * AmiAuth v1.0's src/core/pbkdf2.c (same block algorithm, HMAC-SHA1
 * there vs HMAC-SHA256 here -- AmiSnap's format spec fixes SHA-256, not
 * AmiAuth's SHA-1, as the repository KDF hash). Vectors independently
 * verified against Python's hashlib.pbkdf2_hmac before being recorded
 * in tests/test_pbkdf2.c, per house rule.
 */
#ifndef AMISNAP_PBKDF2_H
#define AMISNAP_PBKDF2_H

#include <stddef.h>
#include <stdint.h>

/* Derive `outlen` bytes into `out` from the passphrase and salt.
 * `iterations` is calibrated at repository init (target ~1-2s on the
 * host CPU -- see docs/implementation-plan.md Phase 4) and stored in
 * the repository's KDF tag, so it travels with the repository rather
 * than being fixed at build time. */
void amisnap_pbkdf2_hmac_sha256(const uint8_t *pass, size_t passlen,
                                 const uint8_t *salt, size_t saltlen,
                                 uint32_t iterations,
                                 uint8_t *out, size_t outlen);

#endif /* AMISNAP_PBKDF2_H */

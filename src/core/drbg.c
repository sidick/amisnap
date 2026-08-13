/* drbg.c -- HMAC-DRBG over SHA-256 (NIST SP 800-90A Sec 10.1.2), adapted
 * from sibling AmiAuth v1.0's src/core/drbg.c (see drbg.h for why
 * SHA-256 here vs AmiAuth's SHA-1). additional_input and prediction
 * resistance are not used: the caller reseeds explicitly via
 * amisnap_drbg_reseed when it has fresh entropy. State is (K, V), each
 * one SHA-256 digest wide. Validated against an independent Python
 * HMAC-DRBG-over-SHA256 oracle (hmac/hashlib, mirroring SP 800-90A
 * 10.1.2) in tests/test_drbg.c.
 */
#include "drbg.h"

#include <string.h>

#include "hmac_sha256.h"

/* V = HMAC(K, V). */
static void hmac_kv(amisnap_drbg_state *st)
{
    uint8_t v[AMISNAP_SHA256_DIGEST_SIZE];
    amisnap_hmac_sha256(st->K, sizeof st->K, st->V, sizeof st->V, v);
    memcpy(st->V, v, sizeof st->V);
}

/* HMAC_DRBG_Update (SP 800-90A 10.1.2.2). With empty data this is the
 * post-generate state advance; with data it is instantiate/reseed. */
static void drbg_update(amisnap_drbg_state *st, const uint8_t *data, size_t len)
{
    amisnap_hmac_sha256_ctx h;
    uint8_t sep;

    /* K = HMAC(K, V || 0x00 || data);  V = HMAC(K, V) */
    amisnap_hmac_sha256_init(&h, st->K, sizeof st->K);
    amisnap_hmac_sha256_update(&h, st->V, sizeof st->V);
    sep = 0x00;
    amisnap_hmac_sha256_update(&h, &sep, 1);
    if (len) amisnap_hmac_sha256_update(&h, data, len);
    amisnap_hmac_sha256_final(&h, st->K);
    hmac_kv(st);

    if (len == 0) return;         /* no provided data -> stop after the first round */

    /* K = HMAC(K, V || 0x01 || data);  V = HMAC(K, V) */
    amisnap_hmac_sha256_init(&h, st->K, sizeof st->K);
    amisnap_hmac_sha256_update(&h, st->V, sizeof st->V);
    sep = 0x01;
    amisnap_hmac_sha256_update(&h, &sep, 1);
    amisnap_hmac_sha256_update(&h, data, len);
    amisnap_hmac_sha256_final(&h, st->K);
    hmac_kv(st);
}

void amisnap_drbg_init(amisnap_drbg_state *st, const uint8_t *seed, size_t seedlen)
{
    memset(st->K, 0x00, sizeof st->K);
    memset(st->V, 0x01, sizeof st->V);
    drbg_update(st, seed, seedlen);
}

void amisnap_drbg_reseed(amisnap_drbg_state *st, const uint8_t *in, size_t inlen)
{
    drbg_update(st, in, inlen);
}

void amisnap_drbg_generate(amisnap_drbg_state *st, uint8_t *out, size_t n)
{
    size_t got = 0;
    while (got < n) {
        size_t take = n - got;
        hmac_kv(st);
        if (take > sizeof st->V) take = sizeof st->V;
        memcpy(out + got, st->V, take);
        got += take;
    }
    drbg_update(st, NULL, 0);      /* advance state (additional_input empty) */
}

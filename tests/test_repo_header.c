/* test_repo_header.c -- amisnap.repo / REC_REPO round-trip and
 * validation, docs/format.md "Repository header". */
#include <string.h>

#include "test.h"
#include "repo_header.h"

static void fill_repo_id(uint8_t id[AMISNAP_REPO_ID_SIZE])
{
    int i;
    for (i = 0; i < AMISNAP_REPO_ID_SIZE; i++) id[i] = (uint8_t)(0xA0 + i);
}

void run_repo_header_tests(void)
{
    /* --- CIPHER 0: round-trip, no key material. --- */
    {
        amisnap_repo_header hdr, decoded;
        amisnap_buf out;

        memset(&hdr, 0, sizeof(hdr));
        fill_repo_id(hdr.repo_id);
        hdr.cipher = 0;
        hdr.has_chunk_size = 1;
        hdr.chunk_size = 262144;
        hdr.has_format_app = 1;
        hdr.format_app = (const uint8_t *)"AmiSnap";
        hdr.format_app_len = 7;

        TEST_CHECK(amisnap_repo_header_encode(&hdr, &out) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_header_decode(out.data, out.len, &decoded) == AMISNAP_OK);

        TEST_CHECK(memcmp(decoded.repo_id, hdr.repo_id, AMISNAP_REPO_ID_SIZE) == 0);
        TEST_CHECK(decoded.cipher == 0);
        TEST_CHECK(decoded.has_chunk_size && decoded.chunk_size == 262144);
        TEST_CHECK(decoded.has_format_app && decoded.format_app_len == 7 &&
                   memcmp(decoded.format_app, "AmiSnap", 7) == 0);
        TEST_CHECK(decoded.salt == NULL && decoded.wrapped_key == NULL);

        amisnap_buf_free(&out);
    }

    /* --- CIPHER 0 with key material set is rejected at encode time. --- */
    {
        amisnap_repo_header hdr;
        amisnap_buf out;
        uint8_t salt[8] = { 0 };
        uint8_t wrapped[AMISNAP_WRAPPED_KEY_SIZE] = { 0 };

        memset(&hdr, 0, sizeof(hdr));
        fill_repo_id(hdr.repo_id);
        hdr.cipher = 0;
        hdr.salt = salt;
        hdr.salt_len = sizeof(salt);
        hdr.wrapped_key = wrapped;

        TEST_CHECK(amisnap_repo_header_encode(&hdr, &out) == AMISNAP_ERR_MALFORMED);
    }

    /* --- CIPHER 1: round-trip with KDF + WRAPPED_KEY. --- */
    {
        amisnap_repo_header hdr, decoded;
        amisnap_buf out;
        uint8_t salt[16];
        uint8_t wrapped[AMISNAP_WRAPPED_KEY_SIZE];
        int i;

        for (i = 0; i < 16; i++) salt[i] = (uint8_t)(0x10 + i);
        for (i = 0; i < AMISNAP_WRAPPED_KEY_SIZE; i++) wrapped[i] = (uint8_t)(0x50 + i);

        memset(&hdr, 0, sizeof(hdr));
        fill_repo_id(hdr.repo_id);
        hdr.cipher = 1;
        hdr.kdf_id = AMISNAP_KDF_PBKDF2_HMAC_SHA256;
        hdr.kdf_iters = 200000;
        hdr.salt = salt;
        hdr.salt_len = sizeof(salt);
        hdr.wrapped_key = wrapped;

        TEST_CHECK(amisnap_repo_header_encode(&hdr, &out) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_header_decode(out.data, out.len, &decoded) == AMISNAP_OK);

        TEST_CHECK(decoded.cipher == 1);
        TEST_CHECK(decoded.kdf_id == AMISNAP_KDF_PBKDF2_HMAC_SHA256);
        TEST_CHECK(decoded.kdf_iters == 200000);
        TEST_CHECK(decoded.salt_len == sizeof(salt) &&
                   memcmp(decoded.salt, salt, sizeof(salt)) == 0);
        TEST_CHECK(decoded.wrapped_key != NULL &&
                   memcmp(decoded.wrapped_key, wrapped, AMISNAP_WRAPPED_KEY_SIZE) == 0);

        amisnap_buf_free(&out);
    }

    /* --- CIPHER 1 without KDF/WRAPPED_KEY is rejected at encode time. --- */
    {
        amisnap_repo_header hdr;
        amisnap_buf out;

        memset(&hdr, 0, sizeof(hdr));
        fill_repo_id(hdr.repo_id);
        hdr.cipher = 1;

        TEST_CHECK(amisnap_repo_header_encode(&hdr, &out) == AMISNAP_ERR_MALFORMED);
    }

    /* --- An unrecognised CIPHER value is refused on read (critical tag):
     * format.md "A reader that does not implement the stated CIPHER MUST
     * refuse the repository". The encoder itself only checks salt/
     * wrapped_key presence against cipher==0 vs !=0, so a future-cipher
     * value (2) with key material set encodes cleanly and this only
     * exercises the *decoder's* range check. --- */
    {
        amisnap_repo_header hdr, decoded;
        amisnap_buf out;
        uint8_t salt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
        uint8_t wrapped[AMISNAP_WRAPPED_KEY_SIZE] = { 0 };

        memset(&hdr, 0, sizeof(hdr));
        fill_repo_id(hdr.repo_id);
        hdr.cipher = 2;                 /* not yet a real cipher */
        hdr.kdf_id = AMISNAP_KDF_PBKDF2_HMAC_SHA256;
        hdr.kdf_iters = 1;
        hdr.salt = salt;
        hdr.salt_len = sizeof(salt);
        hdr.wrapped_key = wrapped;

        TEST_CHECK(amisnap_repo_header_encode(&hdr, &out) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_header_decode(out.data, out.len, &decoded)
                   == AMISNAP_ERR_CRITICAL_TAG);

        amisnap_buf_free(&out);
    }

    /* --- Trailing garbage after REC_REPO is rejected. --- */
    {
        amisnap_repo_header hdr, decoded;
        amisnap_buf out;
        uint8_t extra = 0xFF;

        memset(&hdr, 0, sizeof(hdr));
        fill_repo_id(hdr.repo_id);
        hdr.cipher = 0;

        TEST_CHECK(amisnap_repo_header_encode(&hdr, &out) == AMISNAP_OK);
        TEST_CHECK(amisnap_buf_bytes(&out, &extra, 1) == AMISNAP_OK);
        TEST_CHECK(amisnap_repo_header_decode(out.data, out.len, &decoded) != AMISNAP_OK);

        amisnap_buf_free(&out);
    }
}

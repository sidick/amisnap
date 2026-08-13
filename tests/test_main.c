/* test_main.c -- runner. Each module contributes a run_*_tests() entry point. */
#include "test.h"

test_ctx g_test = { 0, 0, 0 };

void run_xxhash32_tests(void);
void run_blake2s_tests(void);
void run_tlv_tests(void);
void run_meta_tests(void);
void run_manifest_tests(void);
void run_backend_dir_tests(void);
void run_repo_tests(void);
void run_index_tests(void);
void run_restore_tests(void);
void run_verify_tests(void);
void run_prune_tests(void);
void run_crash_safety_tests(void);
void run_chunked_tests(void);
void run_http_tests(void);
void run_base64_tests(void);
void run_webdav_tests(void);
void run_sha256_tests(void);
void run_chacha20_tests(void);
void run_hmac_sha256_tests(void);
void run_pbkdf2_tests(void);
void run_drbg_tests(void);
void run_repo_crypto_tests(void);
void run_repo_header_tests(void);

int main(void)
{
    run_xxhash32_tests();
    run_blake2s_tests();
    run_tlv_tests();
    run_meta_tests();
    run_manifest_tests();
    run_backend_dir_tests();
    run_repo_tests();
    run_index_tests();
    run_restore_tests();
    run_verify_tests();
    run_prune_tests();
    run_crash_safety_tests();
    run_chunked_tests();
    run_http_tests();
    run_base64_tests();
    run_webdav_tests();
    run_sha256_tests();
    run_chacha20_tests();
    run_hmac_sha256_tests();
    run_pbkdf2_tests();
    run_drbg_tests();
    run_repo_crypto_tests();
    run_repo_header_tests();

    fprintf(stderr, "passed=%d failed=%d pending=%d\n",
            g_test.passed, g_test.failed, g_test.pending);
    return g_test.failed ? 1 : 0;
}

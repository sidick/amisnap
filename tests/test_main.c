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

    fprintf(stderr, "passed=%d failed=%d pending=%d\n",
            g_test.passed, g_test.failed, g_test.pending);
    return g_test.failed ? 1 : 0;
}

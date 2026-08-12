/* test_main.c -- runner. Each module contributes a run_*_tests() entry point. */
#include "test.h"

test_ctx g_test = { 0, 0, 0 };

void run_xxhash32_tests(void);

int main(void)
{
    run_xxhash32_tests();

    fprintf(stderr, "passed=%d failed=%d pending=%d\n",
            g_test.passed, g_test.failed, g_test.pending);
    return g_test.failed ? 1 : 0;
}

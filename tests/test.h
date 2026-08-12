/* test.h -- tiny host-side test harness for the portable core (same shape
 * as sibling AmiAuth's tests/test.h).
 *
 * A test uses TEST_CHECK(cond) for real assertions and TEST_PENDING(msg)
 * to record an unimplemented case (a scaffolded stub). Pending cases are
 * reported but do NOT fail the run, so CI stays green while modules are
 * filled in. The runner exits non-zero only on a real failure. */
#ifndef AMISNAP_TEST_H
#define AMISNAP_TEST_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    int passed;
    int failed;
    int pending;
} test_ctx;

extern test_ctx g_test;

#define TEST_CHECK(cond)                                                    \
    do {                                                                    \
        if (cond) {                                                         \
            g_test.passed++;                                                \
        } else {                                                            \
            g_test.failed++;                                                \
            fprintf(stderr, "FAIL    %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                   \
    } while (0)

#define TEST_PENDING(msg)                                                   \
    do {                                                                    \
        g_test.pending++;                                                   \
        fprintf(stderr, "PENDING %s:%d: %s\n", __FILE__, __LINE__, (msg));  \
    } while (0)

#endif /* AMISNAP_TEST_H */

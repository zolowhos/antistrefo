// re_test.h - minimal assertion harness, no external dependency, CTest friendly.
// Module: test (C11).
// Owns: the check counter, the failure message and the process exit code.
// Depends: stdio only. Prints to stdout because it is a test binary, not antistrefo.
#pragma once

#include <stdio.h>
#include <string.h>

// Shared across the test translation units so a single main can report them all.
extern int re_test_count;
extern int re_test_fail;

// Failures flush immediately. A crash later in the suite must not discard the
// buffered output that would have explained it.
#define RE_CHECK(cond)                                             \
    do {                                                           \
        re_test_count++;                                           \
        if (!(cond)) {                                             \
            re_test_fail++;                                        \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
            fflush(stdout);                                        \
        }                                                          \
    } while (0)

// An unconditional failure. RE_CHECK(0) reads the same but is a constant condition,
// which MSVC /W4 reports (C4127) and /WX then refuses to build.
#define RE_FAIL(msg)                                         \
    do {                                                     \
        re_test_count++;                                     \
        re_test_fail++;                                      \
        printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, msg); \
        fflush(stdout);                                      \
    } while (0)

#define RE_CHECK_EQ_U(got, want)                                                            \
    do {                                                                                    \
        re_test_count++;                                                                    \
        unsigned long long g_ = (unsigned long long)(got);                                  \
        unsigned long long w_ = (unsigned long long)(want);                                 \
        if (g_ != w_) {                                                                     \
            re_test_fail++;                                                                 \
            printf("FAIL %s:%d  %s = %llu, want %llu\n", __FILE__, __LINE__, #got, g_, w_); \
            fflush(stdout);                                                                 \
        }                                                                                   \
    } while (0)

#define RE_CHECK_EQ_HEX(got, want)                                                          \
    do {                                                                                    \
        re_test_count++;                                                                    \
        unsigned long long g_ = (unsigned long long)(got);                                  \
        unsigned long long w_ = (unsigned long long)(want);                                 \
        if (g_ != w_) {                                                                     \
            re_test_fail++;                                                                 \
            printf("FAIL %s:%d  %s = %llx, want %llx\n", __FILE__, __LINE__, #got, g_, w_); \
            fflush(stdout);                                                                 \
        }                                                                                   \
    } while (0)

// A count cannot tell you the answer was the right one. Anything whose whole point is
// a particular string - a demangled name, a disassembled operand, an export kind -
// has to be compared as text, or a tool that returned the wrong name with the right
// number of lines passes.
#define RE_CHECK_EQ_STR(got, want)                                                     \
    do {                                                                               \
        re_test_count++;                                                               \
        const char *g_ = (got);                                                        \
        const char *w_ = (want);                                                       \
        if (!g_ || strcmp(g_, w_) != 0) {                                              \
            re_test_fail++;                                                            \
            printf("FAIL %s:%d  %s = \"%s\", want \"%s\"\n", __FILE__, __LINE__, #got, \
                   g_ ? g_ : "(null)", w_);                                            \
            fflush(stdout);                                                            \
        }                                                                              \
    } while (0)

// Index only when the vector is long enough, so a wrong count reports a
// failure instead of crashing and hiding everything after it.
#define RE_CHECK_FITS(vec, want) RE_CHECK_EQ_U(RE_VEC_LEN(&(vec)), (uint64_t)(want))

static inline int re_test_report(const char *suite) {
    printf("%s: %d checks, %d failures\n", suite, re_test_count, re_test_fail);
    return re_test_fail ? 1 : 0;
}

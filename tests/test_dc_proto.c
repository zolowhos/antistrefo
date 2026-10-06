// test_dc_proto.c - an import name prints with its argument count, not a guess.
// Module: test (C11).
// Owns: the IoCompleteRequest spelling and the unknown-call refusal.
// Depends: re_dc_proto. A name not in the table is not rewritten.
#include "re_test.h"

#include <string.h>

#include "features/dec/re_dc_proto.h"
#include "utils/text/re_str.h"

int re_test_count = 0;
int re_test_fail = 0;

static void check_complete(void) {
    char dst[96];
    RE_CHECK(re_dc_proto_format(re_str("IoCompleteRequest"), "rcx, rdx, r8", dst, sizeof(dst)));
    RE_CHECK(strcmp(dst, "IoCompleteRequest(rcx, rdx)") == 0);
    RE_CHECK(!strstr(dst, "r8"));
}

static void check_short_call(void) {
    char dst[96];
    RE_CHECK(re_dc_proto_format(re_str("CloseHandle"), "rcx", dst, sizeof(dst)));
    RE_CHECK(strcmp(dst, "CloseHandle(rcx)") == 0);
}

static void check_unknown(void) {
    char dst[96];
    dst[0] = 'x';
    RE_CHECK(!re_dc_proto_format(re_str("call_0x1400"), "rcx, rdx", dst, sizeof(dst)));
    RE_CHECK_EQ_U((unsigned)dst[0], (unsigned)'x');
}

int main(void) {
    check_complete();
    check_short_call();
    check_unknown();
    return re_test_report("dc_proto");
}

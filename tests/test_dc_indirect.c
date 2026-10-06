// test_dc_indirect.c - one reaching lea is a name, and a slot is not a guess.
// Module: test (C11).
// Owns: the lea case and the unresolved slot spelling.
// Depends: re_dc_indirect. A second definition must not become a target.
#include "re_test.h"

#include <string.h>

#include "features/indirect/re_dc_indirect.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "re_pe_fixture.h"
#include "utils/mem/re_arena.h"

int re_test_count = 0;
int re_test_fail = 0;

static void check_lea(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    char dst[96];
    static const uint8_t k[] = {
        0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, // lea rax, [rip+0]
        0xFF, 0xD0,                               // call rax
        0xFF, 0x51, 0x18,                         // call [rcx+0x18]
    };
    build_pe(img);
    memcpy(img + HDRS, k, sizeof(k));
    re_arena_init(&a, 65536);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    RE_CHECK(re_dc_indirect_format(&code, IMAGE_BASE + TEXT_RVA + 7, dst, sizeof(dst)));
    RE_CHECK(strstr(dst, "sub_") != NULL);
    RE_CHECK(re_dc_indirect_format(&code, IMAGE_BASE + TEXT_RVA + 9, dst, sizeof(dst)));
    RE_CHECK(strstr(dst, "slot_0x") != NULL);
    RE_CHECK(re_dc_indirect_slot(&code, IMAGE_BASE + TEXT_RVA + 9, "DriverEntry", dst, sizeof(dst)));
    RE_CHECK(strcmp(dst, "DriverEntry::slot3(rcx)") == 0);
    re_arena_free(&a);
}

int main(void) {
    check_lea();
    return re_test_report("dc_indirect");
}

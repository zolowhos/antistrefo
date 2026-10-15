// test_qa_contracts.c - synthetic pins for universal decompile/agent contracts.
// Module: test (C11).
// Owns: multi-format-agnostic checks on opaque PE fixtures (no titled binaries).
// Depends: re_core public headers and re_pe_fixture.
#include "re_test.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/code/re_xref.h"
#include "features/data/re_search.h"
#include "features/meta/re_disasm.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"
#include "re_pe_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

// Plant a pointer-table cell in .edata that names AlphaFunc's string VA.
static void plant_string_ptr(uint8_t *img) {
    uint8_t *ed = img + HDRS + sizeof(kCode);
    uint64_t str_va = IMAGE_BASE + EDATA_RVA + 0x6C; // AlphaFunc text
    put64(ed + 0x150, str_va);
}

static void test_ptr_table_xref(re_arena_t *a) {
    uint8_t img[IMG_BYTES];
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_xrefset_t xs;
    uint64_t str_va = IMAGE_BASE + EDATA_RVA + 0x6C;
    size_t n;
    const re_xref_t *r;
    const re_disasm_t *d = re_disasm_find("x86-64");
    build_pe(img);
    plant_string_ptr(img);
    RE_CHECK(re_pe_parse(re_span(img, IMG_BYTES), a, &pe) == RE_OK);
    RE_CHECK(re_code_init(&code, re_span(img, IMG_BYTES), &pe, d, a));
    re_func_scan(&code, a, &scan);
    re_xref_build(&code, &scan, &pe, a, &xs);
    n = re_xref_to_count(&xs, str_va);
    RE_CHECK(n >= 1);
    r = re_xref_to_at(&xs, str_va, 0);
    RE_CHECK(r != NULL);
    if (r) {
        RE_CHECK_EQ_U(r->kind, RE_XR_DATA);
        RE_CHECK((r->flags & RE_XRF_STRING) != 0);
        RE_CHECK_EQ_HEX(r->from, IMAGE_BASE + EDATA_RVA + 0x150);
    }
}

// Positive frame slot [rbp+0x10] must enter displacements via note_slot.
static void test_positive_slot(re_arena_t *a) {
    static const uint8_t kBody[] = {
        0x55,                   // push rbp
        0x48, 0x89, 0xe5,       // mov rbp, rsp
        0x48, 0x8b, 0x45, 0x10, // mov rax, [rbp+0x10]
        0x48, 0x89, 0x45, 0xf8, // mov [rbp-8], rax
        0xc3,                   // ret
    };
    uint8_t img[IMG_BYTES];
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_stack_t st;
    const re_func_t *fn;
    const re_disasm_t *d = re_disasm_find("x86-64");
    bool saw_p = false;
    bool saw_m = false;
    uint32_t i;
    build_pe(img);
    memcpy(img + HDRS, kBody, sizeof(kBody));
    RE_CHECK(re_pe_parse(re_span(img, IMG_BYTES), a, &pe) == RE_OK);
    RE_CHECK(re_code_init(&code, re_span(img, IMG_BYTES), &pe, d, a));
    re_func_scan(&code, a, &scan);
    fn = re_func_at(&scan, 0);
    RE_CHECK(fn != NULL);
    re_stack_analyze(&code, fn, a, &st);
    for (i = 0; i < st.n_slots; i++) {
        if (st.slots[i] == 0x10)
            saw_p = true;
        if (st.slots[i] == -8)
            saw_m = true;
    }
    RE_CHECK(saw_p);
    RE_CHECK(saw_m);
}

// Multi-width: value 0x148 is found as imm16/imm32, deduped by off.
static void test_imm_all_widths(re_arena_t *a) {
    uint8_t buf[24];
    re_search_t s;
    size_t i;
    bool found = false;
    memset(buf, 0, sizeof(buf));
    buf[4] = 0x48;
    buf[5] = 0x01;
    re_search_init(&s);
    re_search_immediate_all(re_span(buf, sizeof(buf)), 0x148u, 0, 0, a, &s);
    RE_CHECK(s.total >= 1);
    RE_CHECK_EQ_U(RE_VEC_LEN(&s.hits), s.total);
    for (i = 0; i < RE_VEC_LEN(&s.hits); i++) {
        if (RE_VEC_AT(&s.hits, re_search_hit_t, i).off == 4)
            found = true;
    }
    RE_CHECK(found);
}

int main(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    if (!re_disasm_find("x86-64")) {
        printf("FAIL no x86-64 backend\n");
        return 1;
    }
    test_ptr_table_xref(&a);
    test_positive_slot(&a);
    test_imm_all_widths(&a);
    re_arena_free(&a);
    printf("qa_contracts: %d checks, %d failures\n", re_test_count, re_test_fail);
    return re_test_fail ? 1 : 0;
}

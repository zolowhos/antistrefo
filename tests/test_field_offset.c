// test_field_offset.c - synthetic pins for imm snap, disasm len, xref window, disp.
// Module: test (C11).
// Owns: universal field-offset agent-surface contracts (no titled binaries).
// Depends: re_core public headers, re_decompile, re_search.
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
#include "features/dec/re_decompile.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_buf.h"
#include "utils/mem/re_vec.h"
#include "utils/text/re_strbuf.h"

int re_test_count = 0;
int re_test_fail = 0;

#define FO_BASE 0x180000000ull
#define FO_TEXT 0x1000u
#define FO_HDRS 0x200u
#define FO_OPT 0xF0u

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)v);
    put32(p + 4, (uint32_t)(v >> 32));
}

// Body: cmp [rax+0x1E78],1 ; mov rax,[rax+0x1E78] ; mov byte [rax+0x10],1 ; ret
// The disp bytes of the cmp are 78 1E 00 00, which alone decode as js.
static const uint8_t kFoCode[] = {
    0x83, 0xb8, 0x78, 0x1e, 0x00, 0x00, 0x01, // cmp dword [rax+0x1E78], 1
    0x48, 0x8b, 0x80, 0x78, 0x1e, 0x00, 0x00, // mov rax, [rax+0x1E78]
    0xc6, 0x40, 0x10, 0x01,                   // mov byte [rax+0x10], 1
    0xc3,                                     // ret
};

#define FO_BYTES (FO_HDRS + (uint32_t)sizeof(kFoCode))

static void build_fo(uint8_t *img) {
    uint8_t *coff;
    uint8_t *opt;
    uint8_t *sec;
    memset(img, 0, FO_BYTES);
    put16(img, 0x5A4D);
    put32(img + 0x3C, 0x40);
    put32(img + 0x40, 0x00004550u);
    coff = img + 0x44;
    put16(coff + 0, 0x8664);
    put16(coff + 2, 1);
    put16(coff + 16, FO_OPT);
    put16(coff + 18, 0x0022);
    opt = coff + 20;
    put16(opt, 0x20B);
    put32(opt + 16, FO_TEXT);
    put64(opt + 24, FO_BASE);
    put32(opt + 56, FO_TEXT * 2);
    put16(opt + 68, 1);
    put32(opt + 108, 16);
    sec = img + 0x148;
    memcpy(sec, ".text", 5);
    put32(sec + 8, (uint32_t)sizeof(kFoCode));
    put32(sec + 12, FO_TEXT);
    put32(sec + 16, (uint32_t)sizeof(kFoCode));
    put32(sec + 20, FO_HDRS);
    put32(sec + 36, 0x60000020u);
    memcpy(img + FO_HDRS, kFoCode, sizeof(kFoCode));
}

static bool open_fo(re_arena_t *a, uint8_t *img, re_pe_t *pe, re_code_t *code, re_fscan_t *scan) {
    const re_disasm_t *d = re_disasm_find("x86-64");
    build_fo(img);
    if (re_pe_parse(re_span(img, FO_BYTES), a, pe) != RE_OK || !pe->valid)
        return false;
    if (!re_code_init(code, re_span(img, FO_BYTES), pe, d, a))
        return false;
    re_func_scan(code, a, scan);
    return RE_VEC_LEN(&scan->funcs) > 0;
}

// Same contract as re_snap_insn_va: walk forward from fn_va until at is covered.
static bool snap_insn(re_code_t *code, uint64_t fn_va, uint64_t at, uint64_t *insn_va) {
    uint64_t va = fn_va;
    if (!insn_va || at < fn_va)
        return false;
    *insn_va = at;
    while (va <= at) {
        re_insn_t in;
        if (!re_code_insn(code, va, &in) || in.size == 0)
            return false;
        if (at < va + in.size) {
            *insn_va = va;
            return true;
        }
        va += in.size;
        if (va - fn_va > 65536u)
            return false;
    }
    return false;
}

// Mid-disp byte of cmp must snap to the cmp, not decode as js.
static void test_imm_snap(re_arena_t *a) {
    uint8_t img[FO_BYTES];
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_insn_t in;
    uint64_t fn = FO_BASE + FO_TEXT;
    uint64_t hit = fn + 2; // first byte of 0x1E78 LE inside the cmp
    uint64_t insn_va = 0;
    const re_func_t *f;
    RE_CHECK(open_fo(a, img, &pe, &code, &scan));
    f = re_func_at(&scan, 0);
    RE_CHECK(f != NULL);
    RE_CHECK(snap_insn(&code, f->va, hit, &insn_va));
    RE_CHECK_EQ_HEX(insn_va, fn);
    RE_CHECK(re_code_insn(&code, insn_va, &in));
    RE_CHECK_EQ_U((uint64_t)in.disp, 0x1E78u);
    RE_CHECK(re_code_insn(&code, hit, &in));
    RE_CHECK(RE_INSN_OPCODE(&in) == 0x78u); // alone, that byte is js
}

// Decompile must print reg+disp; byte store stays width 1 in the C text.
static void test_decompile_disp(re_arena_t *a) {
    uint8_t img[FO_BYTES];
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_stack_t st;
    re_decomp_t d;
    re_strbuf_t text;
    const re_func_t *fn;
    const char *src;
    RE_CHECK(open_fo(a, img, &pe, &code, &scan));
    fn = re_func_at(&scan, 0);
    RE_CHECK(fn != NULL);
    re_stack_analyze(&code, fn, a, &st);
    memset(&d, 0, sizeof(d));
    d.code = &code;
    d.arena = a;
    re_strbuf_init(&text, a);
    re_decompile_func(&d, fn, &st, &text);
    src = text.p ? text.p : "";
    RE_CHECK(strstr(src, "0x1e78") != NULL || strstr(src, "0x1E78") != NULL);
    RE_CHECK(strstr(src, "uint8_t") != NULL);
}

// Covering insn for a raw imm hit must carry the value as disp (not a js).
static void test_search_imm_filter(re_arena_t *a) {
    uint8_t img[FO_BYTES];
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_search_t s;
    re_insn_t in;
    size_t i;
    bool saw = false;
    RE_CHECK(open_fo(a, img, &pe, &code, &scan));
    re_search_init(&s);
    re_search_immediate_all(re_span(img, FO_BYTES), 0x1E78u, 0, 0, a, &s);
    RE_CHECK(s.total >= 1);
    for (i = 0; i < RE_VEC_LEN(&s.hits); i++) {
        re_search_hit_t h = RE_VEC_AT(&s.hits, re_search_hit_t, i);
        uint32_t rva = 0;
        uint64_t va;
        uint64_t insn_va = 0;
        long fi;
        if (!re_pe_off2rva(&pe, h.off, &rva))
            continue;
        va = pe.image_base + rva;
        if (!re_code_in_code(&code, va))
            continue;
        fi = re_func_index_of(&scan, va);
        RE_CHECK(fi >= 0);
        RE_CHECK(snap_insn(&code, re_func_at(&scan, (size_t)fi)->va, va, &insn_va));
        RE_CHECK(re_code_insn(&code, insn_va, &in));
        RE_CHECK((uint64_t)in.disp == 0x1E78u || (uint64_t)in.imm == 0x1E78u);
        RE_CHECK(RE_INSN_OPCODE(&in) != 0x78u);
        saw = true;
    }
    RE_CHECK(saw);
}

int main(void) {
    re_arena_t a;
    re_arena_init(&a, 0);
    if (!re_disasm_find("x86-64")) {
        printf("FAIL no x86-64 backend\n");
        return 1;
    }
    test_imm_snap(&a);
    test_decompile_disp(&a);
    test_search_imm_filter(&a);
    re_arena_free(&a);
    printf("field_offset: %d checks, %d failures\n", re_test_count, re_test_fail);
    return re_test_fail ? 1 : 0;
}

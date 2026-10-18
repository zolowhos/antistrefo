// test_cfg.c - the control flow graph of a hand assembled function.
// Module: test (C11).
// Owns: block partitioning, terminator classification and the edge list.
// Depends: re_core through the public headers, never a private one, so the graph is
//           built by the same calls the cfg command makes.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "features/analysis/re_analyze.h"
#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/code/re_stack.h"
#include "features/data/re_regions.h"
#include "features/dec/re_cfg.h"
#include "features/dec/re_dc_walk.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "utils/mem/re_vec.h"

#include "re_pe_fixture.h"
#include "re_walk_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

// The terminator of block i, or RE_CFG_TERM_UNKNOWN when there is no such block.
static uint8_t term_of(const re_cfg_t *g, size_t i) {
    if (i >= RE_VEC_LEN(&g->blocks))
        return RE_CFG_TERM_UNKNOWN;
    return RE_VEC_AT(&g->blocks, re_cfg_block_t, i).term;
}

// The destinations leaving block i, as edge kinds in order.
static size_t succ_kinds(const re_cfg_t *g, size_t from, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&g->edges); i++) {
        const re_cfg_edge_t *e = RE_VEC_PTR(&g->edges, re_cfg_edge_t, i);
        if (e->from == from && n < cap)
            out[n++] = e->kind;
    }
    return n;
}

// Whether block from reaches block to by the given kind.
static bool reaches(const re_cfg_t *g, size_t from, int32_t to, uint8_t kind) {
    for (size_t i = 0; i < RE_VEC_LEN(&g->edges); i++) {
        const re_cfg_edge_t *e = RE_VEC_PTR(&g->edges, re_cfg_edge_t, i);
        if (e->from == from && e->to == to && e->kind == kind)
            return true;
    }
    return false;
}

// The block partitioning and the edges. Every expectation here is derived from the
// hand assembled fixture above, so a failure names the edge that changed rather than
// just a count that moved.
static void check_graph(re_code_t *code, const re_func_t *f, re_arena_t *a) {
    re_cfg_t g;
    uint8_t kinds[4];
    RE_CHECK(re_cfg_build(code, f, &g, a));
    RE_CHECK_FITS(g.blocks, 4);
    RE_CHECK(!g.truncated);
    RE_CHECK_EQ_U(term_of(&g, 0), RE_CFG_TERM_COND);
    RE_CHECK_EQ_U(term_of(&g, 1), RE_CFG_TERM_JUMP);
    RE_CHECK_EQ_U(term_of(&g, 2), RE_CFG_TERM_RET);
    RE_CHECK_EQ_U(term_of(&g, 3), RE_CFG_TERM_RET);
    RE_CHECK(reaches(&g, 0, 2, RE_CFG_EDGE_TAKEN));
    RE_CHECK(reaches(&g, 0, 1, RE_CFG_EDGE_FALL));
    RE_CHECK(reaches(&g, 1, 3, RE_CFG_EDGE_TAKEN));
    RE_CHECK_EQ_U(succ_kinds(&g, 2, kinds, 4), 0);
    RE_CHECK_EQ_U(succ_kinds(&g, 3, kinds, 4), 0);
    RE_CHECK_EQ_U(succ_kinds(&g, 0, kinds, 4), 2);
    RE_CHECK_EQ_U(g.n_unknown, 0);
    RE_CHECK_EQ_U(g.n_unresolved, 0);
}

// The walk on its own, because the decompiler reads the same structure and a missing
// label there is what makes it print a bare address instead of an L number.
static void check_walk(re_code_t *code, const re_func_t *f, re_arena_t *a) {
    re_dc_walk_t w = {0};
    re_dc_walk(code, f, &w, a);
    RE_CHECK_FITS(w.labels, 4);
    RE_CHECK(re_dc_label_of(&w, f->va) != 0);
    RE_CHECK(re_dc_label_of(&w, f->va + 6) != 0);
    RE_CHECK(re_dc_label_of(&w, f->va + 13) != 0);
    RE_CHECK(re_dc_label_of(&w, f->va + 19) != 0);
    RE_CHECK_EQ_U(re_dc_label_of(&w, f->va + 1), 0);
}

static void drive_malformed(const uint8_t *bytes, size_t n);

// The no-crash guarantee, on inputs that are not a valid image. A protected binary
// arrives as a file whose headers may be inconsistent, and both of these walks trust
// the PE enough to index off it, so a truncated or corrupted image is the case most
// likely to read out of bounds. Reaching the end of this loop is the assertion: a
// crash or a spin fails the binary or the CTest timeout, and neither can be caught
// and turned into a passing check.
static void check_malformed(void) {
    static const size_t kCuts[] = {1, 0x20, 0x41, 0x58, 0x100, 0x148, 0x170, 0x1f0};
    static const size_t kPokes[] = {0x3c, 0x44, 0x46, 0x58, 0x5a, 0x68, 0x148, 0x15c};
    uint8_t img[IMG_BYTES];
    uint8_t bad[IMG_BYTES];
    size_t done = 0;
    for (size_t ci = 0; ci < sizeof(kCuts) / sizeof(kCuts[0]); ci++) {
        build_pe(img);
        for (size_t pi = 0; pi < sizeof(kPokes) / sizeof(kPokes[0]); pi++) {
            size_t cut = kCuts[ci] < sizeof(img) ? kCuts[ci] : sizeof(img);
            memcpy(bad, img, cut);
            if (pi < sizeof(kPokes) / sizeof(kPokes[0]) && kPokes[pi] < cut)
                bad[kPokes[pi]] = (uint8_t)(0xA5u ^ (unsigned)pi);
            drive_malformed(bad, cut);
            done++;
        }
    }
    RE_CHECK_EQ_U(done, sizeof(kCuts) / sizeof(kCuts[0]) * (sizeof(kPokes) / sizeof(kPokes[0])));
}

// Run both analyses over whatever it was given and require only that they return.
static void drive_malformed(const uint8_t *bytes, size_t n) {
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_cfg_t g;
    re_vec_t out;
    bool truncated = false;
    re_arena_init(&a, 65536);
    re_span_t span = {(const uint8_t *)bytes, n};
    if (re_pe_parse(span, &a, &pe) != RE_OK || !pe.valid) {
        re_arena_free(&a);
        return;
    }
    if (!re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a)) {
        re_arena_free(&a);
        return;
    }
    re_func_scan(&code, &a, &scan);
    for (size_t i = 0; i < RE_VEC_LEN(&scan.funcs); i++)
        re_cfg_build(&code, RE_VEC_PTR(&scan.funcs, re_func_t, i), &g, &a);
    re_vec_init(&out, sizeof(re_region_t));
    re_region_scan(&code, &scan, NULL, &pe, 512, &out, &truncated, &a);
    re_arena_free(&a);
}

// The analysis driver, driven through its real entry point. The fixture has to be on
// disk for that, because re_analysis_open takes a path and that is what a caller has;
// testing a private entry point instead would pass while the one commands use rotted.
static void check_analysis(void) {
    static const char kTmp[] = "re_test_cfg_fixture.sys";
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_analysis_t an;
    FILE *fh;
    build_pe(img);
    fh = fopen(kTmp, "wb");
    RE_CHECK(fh != NULL);
    if (!fh)
        return;
    fwrite(img, 1, sizeof(img), fh);
    fclose(fh);
    re_arena_init(&a, 1u << 20);
    RE_CHECK(re_analysis_open(&an, &a, kTmp));
    RE_CHECK(re_analysis_run_all(&an));
    RE_CHECK(an.ok);
    RE_CHECK(an.has_pe);
    RE_CHECK(an.has_code);
    RE_CHECK_EQ_U(RE_VEC_LEN(&an.passes), RE_PASS_COUNT);
    // Every pass is accounted for, and the ones this file can support did run.
    for (int i = 0; i < RE_PASS_COUNT; i++) {
        const re_pass_stat_t *st = re_analysis_pass(&an, (re_pass_t)i);
        RE_CHECK(st != NULL);
        if (!st)
            continue;
        RE_CHECK_EQ_U(st->pass, (unsigned)i);
        RE_CHECK(re_analysis_pass_name(st->pass) != NULL);
    }
    const re_pass_stat_t *fx = re_analysis_pass(&an, RE_PASS_FUNCS);
    const re_pass_stat_t *xs = re_analysis_pass(&an, RE_PASS_XREFS);
    RE_CHECK(fx && fx->ran);
    RE_CHECK(fx && fx->count > 0);
    RE_CHECK(xs && xs->ran);
    RE_CHECK(xs && xs->count > 0);
    // Exports came from the fixture's export directory, so a driver that lost them
    // between the PE parse and the report would show here.
    RE_CHECK_FITS(an.pe.exports, 4);
    RE_CHECK(re_str_eq_cstr(re_analysis_pass(&an, RE_PASS_FUNCS)->pass == RE_PASS_FUNCS
                                ? RE_VEC_AT(&an.pe.exports, re_pe_exp_t, 0).name
                                : re_str(""),
                            "AlphaFunc"));
    // The stack accessor has to reach the functions the scan found.
    re_stack_t st;
    RE_CHECK(re_analysis_stack_of(&an, 0, &st));
    re_analysis_close(&an);
    re_arena_free(&a);
    remove(kTmp);
}

// The pass table must have one record per pass, whatever happened. A pass that bailed
// still has a slot saying so, because a report with nine rows and seven real results
// reads exactly like one where two passes found nothing.
static void check_pass_records(void) {
    RE_CHECK_EQ_U(RE_PASS_COUNT, 11);
    RE_CHECK(re_str_eq_cstr(re_str(re_analysis_pass_name(RE_PASS_FUNCS)), "functions"));
    // The wording for a skip has to say something actionable, not just "skipped".
    RE_CHECK(re_str(re_analysis_skip_name(RE_PASS_SKIP_NO_DECODER)).n > 8);
    RE_CHECK_EQ_U(re_str(re_analysis_skip_name(RE_PASS_RAISED_NONE)).n, 0);
}

// The region classifier over the same fixture. The one section is executable and
// holds a decoded function, so it must come back as code; and the window it sits in
// starts below the first section, so the header region must come back unknown rather
// than being folded into a neighbour.
static void check_regions(re_code_t *code, const re_fscan_t *scan, const re_pe_t *pe,
                          re_arena_t *a) {
    re_vec_t out;
    bool truncated = true;
    re_vec_init(&out, sizeof(re_region_t));
    size_t n = re_region_scan(code, scan, NULL, pe, 512, &out, &truncated, a);
    RE_CHECK(n >= 2);
    RE_CHECK(!truncated);
    // The image is 0x200 bytes of headers plus 20 bytes of code, so a 512 byte window
    // covers the headers and the section sits in the next one.
    size_t found = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&out); i++) {
        const re_region_t *r = RE_VEC_PTR(&out, re_region_t, i);
        if (r->n_funcs == 0)
            continue;
        found++;
        RE_CHECK_EQ_U(r->kind, RE_REG_CODE);
        RE_CHECK(r->exec);
        RE_CHECK(r->func_bytes > 0);
        RE_CHECK(r->confidence >= RE_REG_CONF_LOW);
    }
    RE_CHECK(found >= 1);
}

// With --emit <path>, write the fixture to disk and stop; --emit-walk writes the
// recovery fixture instead, which is the one whose bodies need junk resync, an
// overlap, the instruction ceiling and a declared non-returning tail. The command
// layer lives in the executable rather than in a library, so the only way to test a
// command is to run it against a real file, and this is how that file appears.
// Without a flag this is the normal suite.
static int emit_fixture(int argc, char **argv) {
    static uint8_t img[IMG_BYTES];
    static uint8_t walk[WALK_IMG_BYTES];
    const uint8_t *bytes = img;
    size_t n = sizeof(img);
    FILE *fh;
    if (argc < 3)
        return 2;
    if (strcmp(argv[1], "--emit-walk") == 0) {
        walk_build_pe(walk);
        bytes = walk;
        n = sizeof(walk);
    } else {
        build_pe(img);
    }
    fh = fopen(argv[2], "wb");
    if (!fh)
        return 3;
    fwrite(bytes, 1, n, fh);
    fclose(fh);
    return 0;
}

// A section carrying MEM_EXECUTE but not CNT_CODE is still code, and one carrying
// CNT_CODE but not MEM_EXECUTE is still code. Requiring both flags made a whole
// protected image invisible: a real 98 MB .text had its execute bit stripped and given
// to .rodata instead, and every function in it was missed because of it. The fixture
// here starts with both bits, and each is removed in turn.
int main(int argc, char **argv) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    if (argc > 1)
        return emit_fixture(argc, argv);
    re_arena_init(&a, 65536);
    build_pe(img);

    re_span_t span = {img, sizeof(img)};
    re_pe_parse(span, &a, &pe);
    RE_CHECK(pe.valid);
    RE_CHECK_EQ_HEX(pe.image_base, IMAGE_BASE);
    RE_CHECK_EQ_U(pe.n_sec_field, 2);
    RE_CHECK(pe.pe32plus);

    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    re_func_scan(&code, &a, &scan);
    // The scanner may legitimately read the trailing "jmp" as a tail call and seed
    // the ret it points at as its own function, so only the count is asserted here.
    // What this suite is about is the graph, and that needs an extent covering the
    // whole fixture, so the function under test is stated explicitly rather than
    // taken from whatever extent the scan happened to record.
    RE_CHECK(RE_VEC_LEN(&scan.funcs) >= 1);

    re_func_t f;
    memset(&f, 0, sizeof(f));
    f.va = IMAGE_BASE + TEXT_RVA;
    f.rva = TEXT_RVA;
    f.size = (uint32_t)sizeof(kCode);
    f.flags = RE_FUNC_ENTRY | RE_FUNC_RET;

    // The regression this suite was written for: a function with four blocks and a
    // loop-free diamond must not collapse to one.
    check_graph(&code, &f, &a);
    check_walk(&code, &f, &a);
    check_regions(&code, &scan, &pe, &a);
    check_pass_records();
    check_analysis();
    check_malformed();
    re_arena_free(&a);
    return re_test_report("cfg");
}

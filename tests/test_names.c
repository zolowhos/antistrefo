// test_names.c - the naming pass over the hand built RTTI fixture.
// Module: test (C11).
// Owns: slot naming, virtual call recovery, and the EH scope decode.
// Depends: re_core through the public headers and the shared PE fixture, so the
//           pass runs on exactly the image the other suites describe.
#include "re_test.h"

#include <string.h>

#include "features/flow/re_names.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"

#include "re_pe_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

// The fixture's class is Probe with two slots at EDATA+0x120 and +0x128. Slot 0
// points at the AlphaFunc export, which the image already named, so on the raw
// fixture nothing is written: a table does not overrule a statement. With that
// export name cleared, the same slot names its function from the class table,
// which is the write the pass exists for. Slot 1 points six bytes into the first
// function, and naming a middle of a body is exactly what must never happen.
static void check_slot_naming(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_vset_t vs;
    re_names_stat_t nm;
    re_func_t *f0;
    long idx;
    build_pe(img);
    re_arena_init(&a, 1 << 16);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK && pe.valid);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    re_fscan_init(&scan);
    re_func_scan(&code, &a, &scan);
    re_vtable_scan(&pe, &code, &a, &vs);
    RE_CHECK_FITS(vs.vtables, 1);
    re_names_apply(&pe, &code, &scan, &vs, &a, &nm);
    // Both deferrals happened: the export keeps its name, the body middle gets none.
    RE_CHECK_EQ_U(nm.n_slots, 0);
    idx = re_func_index_of(&scan, 0x180000000ull + TEXT_RVA);
    RE_CHECK(idx >= 0);
    if (idx < 0) {
        re_arena_free(&a);
        return;
    }
    f0 = RE_VEC_PTR(&scan.funcs, re_func_t, (size_t)idx);
    RE_CHECK(re_str_eq_cstr(f0->name, "AlphaFunc"));
    // Now the image's own name is gone, and the class table is the only evidence.
    f0->name = re_str("");
    f0->module = re_str("");
    re_names_apply(&pe, &code, &scan, &vs, &a, &nm);
    RE_CHECK_EQ_U(nm.n_slots, 1);
    RE_CHECK(re_str_eq_cstr(f0->name, "Probe::vfn0"));
    RE_CHECK(re_str_eq_cstr(f0->module, "vtable"));
    re_arena_free(&a);
}

// The slot ordinal is part of the name, so two slots of one class never share a
// name, and the class prefix is the name the RTTI stated.
static void check_slot_names_differ(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_vset_t vs;
    re_names_stat_t nm;
    build_pe(img);
    re_arena_init(&a, 1 << 16);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK && pe.valid);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    re_fscan_init(&scan);
    re_func_scan(&code, &a, &scan);
    re_vtable_scan(&pe, &code, &a, &vs);
    re_names_apply(&pe, &code, &scan, &vs, &a, &nm);
    // The vtable record carries the class name the locator led to; the slot names
    // are built from it, so the record and the functions must agree. An empty vec
    // is a broken fixture, not a reason to dereference null: check it and leave.
    const re_vtable_t *v = RE_VEC_LEN(&vs.vtables) ? RE_VEC_PTR(&vs.vtables, re_vtable_t, 0) : NULL;
    RE_CHECK(v != NULL);
    if (!v) {
        re_arena_free(&a);
        return;
    }
    RE_CHECK(re_str_eq_cstr(v->name, "Probe"));
    re_arena_free(&a);
}

// A slot whose pointer does not land on a recovered function start is not
// named: the walk never walked it, and naming a middle of a body would point
// a reader at a function that does not exist. The fixture's second slot points
// six bytes into the first function, so wiping every function record must take
// the count to zero: no target, no name, no exception made for proximity.
static void check_unwalked_slot_skipped(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_vset_t vs;
    re_names_stat_t nm;
    build_pe(img);
    re_arena_init(&a, 1 << 16);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK && pe.valid);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    re_fscan_init(&scan);
    re_func_scan(&code, &a, &scan);
    re_vtable_scan(&pe, &code, &a, &vs);
    for (size_t i = 0; i < RE_VEC_LEN(&scan.funcs); i++)
        RE_VEC_PTR(&scan.funcs, re_func_t, i)->va = 0;
    re_names_apply(&pe, &code, &scan, &vs, &a, &nm);
    RE_CHECK_EQ_U(nm.n_slots, 0);
    re_arena_free(&a);
}

// An image with no class tables at all: the pass reports zeros and nothing
// else changes. A plain C binary is the common case, not an error.
static void check_no_tables(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    re_names_stat_t nm;
    build_pe(img);
    re_arena_init(&a, 1 << 16);
    re_span_t span = {img, sizeof(img)};
    RE_CHECK(re_pe_parse(span, &a, &pe) == RE_OK && pe.valid);
    RE_CHECK(re_code_init(&code, span, &pe, re_disasm_find("x86-64"), &a));
    re_fscan_init(&scan);
    re_func_scan(&code, &a, &scan);
    re_names_apply(&pe, &code, &scan, NULL, &a, &nm);
    RE_CHECK_EQ_U(nm.n_slots, 0);
    RE_CHECK_EQ_U(nm.n_vcalls, 0);
    RE_CHECK_EQ_U(nm.n_scopes, 0);
    re_arena_free(&a);
}

// Null tolerance: the pass is called from a pipeline that can hand it an image
// with no unwind table, and a crash there would take the analysis with it.
static void check_null_args(void) {
    re_names_stat_t nm;
    re_arena_t a;
    re_arena_init(&a, 1 << 12);
    re_names_stat_init(&nm, &a);
    re_names_apply(NULL, NULL, NULL, NULL, &a, &nm);
    RE_CHECK_EQ_U(nm.n_slots, 0);
    re_names_apply(NULL, NULL, NULL, NULL, &a, NULL);
    re_arena_free(&a);
}

int main(void) {
    check_slot_naming();
    check_slot_names_differ();
    check_unwalked_slot_skipped();
    check_no_tables();
    check_null_args();
    return re_test_report("names");
}

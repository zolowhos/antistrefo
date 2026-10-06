// test_pe.c - what a PE says about an address, and what an export actually is.
// Module: test (C11).
// Owns: the export directory's contents and the code/data decision behind it.
// Depends: re_pe through its public header, so the parser is exercised as a caller.
#include "re_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "features/code/re_code.h"
#include "features/code/re_func.h"
#include "features/data/re_vtable.h"
#include "features/lib/re_flirt.h"
#include "features/meta/re_disasm.h"
#include "features/pe/re_pe.h"
#include "utils/mem/re_arena.h"
#include "cli/screen/re_gui_model.h"

#include "re_pe_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

// The export table, asserted on its content rather than its size. Every earlier test
// in this project compared counts, which is why a parser that returned the opening
// bytes of a function as each export's name passed: the number of names parsed is the
// same either way, so only the text can catch it.
static void check_exports(const re_pe_t *pe) {
    static const char *const kWant[4] = {"AlphaFunc", "BetaFunc", "GammaFunc", "FwdFunc"};
    RE_CHECK_FITS(pe->exports, 4);
    for (size_t i = 0; i < RE_VEC_LEN(&pe->exports) && i < 4; i++) {
        const re_pe_exp_t *x = RE_VEC_PTR(&pe->exports, re_pe_exp_t, i);
        RE_CHECK(re_str_eq_cstr(x->name, kWant[i]));
        // Base is 1 in the fixture, so ordinal i is i+1.
        RE_CHECK_EQ_U(x->ordinal, i + 1u);
        static const uint32_t kRva[4] = {TEXT_RVA, TEXT_RVA + 6, TEXT_RVA + 19, EDATA_RVA + 0x94};
        RE_CHECK_EQ_HEX(x->rva, kRva[i]);
    }
}

// An export is not automatically a function. Real binaries contain exports that are
// not: a forwarder points at a string naming another module, and a driver's
// preference dword is a value a loader reads rather than an address to call. Both sit
// beside genuine code in the same table, so "has an export" cannot be what decides
// whether an address can be called. The three cases are pinned separately because
// conflating any two of them produces an answer that looks right.
static void check_export_kinds(const re_pe_t *pe) {
    const re_pe_section_t *text = re_pe_section_at_rva(pe, TEXT_RVA);
    const re_pe_section_t *edat = re_pe_section_at_rva(pe, EDATA_RVA);
    // A hit, a hit on data, and a miss. The space past the last section is in no
    // section at all, and NULL there is the answer rather than a failure.
    RE_CHECK(text != NULL);
    RE_CHECK(edat != NULL);
    RE_CHECK(re_pe_section_at_rva(pe, EDATA_RVA + EDATA_SIZE + 0x100) == NULL);
    RE_CHECK_EQ_STR(re_pe_region_kind(text), "code");
    RE_CHECK_EQ_STR(re_pe_region_kind(edat), "data");
    RE_CHECK_EQ_STR(re_pe_region_kind(NULL), "unmapped");
    RE_CHECK_EQ_STR(text->name, ".text");
    RE_CHECK_EQ_STR(edat->name, ".edata");
    // Only the last export is a forwarder, and only it names another module.
    RE_CHECK_FITS(pe->exports, 4);
    for (size_t i = 0; i < RE_VEC_LEN(&pe->exports) && i < 4; i++) {
        const re_pe_exp_t *x = RE_VEC_PTR(&pe->exports, re_pe_exp_t, i);
        re_str_t f = re_pe_export_forwarder(pe, x->rva);
        if (i == 3)
            RE_CHECK(re_str_eq_cstr(f, "KERNEL32.Sleep"));
        else
            RE_CHECK_EQ_U(f.n, 0);
    }
}

// A section carrying MEM_EXECUTE but not CNT_CODE is still code, and one carrying
// CNT_CODE but not MEM_EXECUTE is still code. Requiring both flags made a whole
// protected image invisible: a real 98 MB .text had its execute bit stripped and given
// to .rodata instead, and every function in it was missed because of it. Both variants
// start from .text's real characteristics and then lose one flag; starting the second
// from .edata's would clear nothing and pass by accident.
static void check_one_flag_is_enough(void) {
    uint8_t img[IMG_BYTES];
    static const uint32_t kTextChars = 0x60000020u;
    for (size_t variant = 0; variant < 2; variant++) {
        re_arena_t a;
        re_pe_t pe;
        re_arena_init(&a, 65536);
        build_pe(img);
        uint32_t base =
            kTextChars & (variant == 0 ? ~(uint32_t)RE_SEC_CODE : ~(uint32_t)RE_SEC_EXEC);
        put32(img + 0x148 + 36, base);
        re_pe_parse(re_span(img, sizeof(img)), &a, &pe);
        RE_CHECK(pe.valid);
        const re_pe_section_t *s = re_pe_section_at_rva(&pe, TEXT_RVA);
        RE_CHECK(s != NULL);
        RE_CHECK_EQ_STR(re_pe_region_kind(s), "code");
        re_arena_free(&a);
    }
}

// The exception directory is the compiler's own function list, so it is the one part
// of the PE that states where functions are rather than hinting. It was parsed with a
// NULL arena first, which crashed on every image including ones with no exception
// table at all, and no fixture exercised it. Now one is always present.
static void check_unwind(const re_pe_t *pe) {
    RE_CHECK_FITS(pe->unwind, 2);
    re_pe_unwind_t u;
    RE_CHECK(re_pe_unwind_covering(pe, TEXT_RVA, &u));
    RE_CHECK_EQ_HEX(u.begin, TEXT_RVA);
    RE_CHECK_EQ_HEX(u.end, CODE_FN1_END);
    RE_CHECK(re_pe_unwind_covering(pe, CODE_FN2_END - 1u, &u));
    RE_CHECK_EQ_HEX(u.begin, CODE_FN1_END);
    RE_CHECK_EQ_HEX(u.end, CODE_FN2_END);
    // The end is exclusive, so the last byte of a function is covered and the byte
    // after it is not. An off by one here would silently drop the final instruction.
    RE_CHECK(!re_pe_unwind_covering(pe, CODE_FN2_END, &u));
    RE_CHECK(!re_pe_unwind_covering(pe, EDATA_RVA, &u));
}

// A function that begins where the unwind table says so takes its end from there, so
// the reported size is the compiler's and not wherever the walk happened to stop.
static void check_unwind_bounds_function(re_code_t *code, const re_fscan_t *scan) {
    const re_func_t *f =
        re_func_index_of(scan, code->base + TEXT_RVA) >= 0
            ? re_func_at(scan, (size_t)re_func_index_of(scan, code->base + TEXT_RVA))
            : NULL;
    RE_CHECK(f != NULL);
    if (!f)
        return;
    RE_CHECK(f->flags & RE_FUNC_UNWIND);
    RE_CHECK_EQ_HEX(f->size, CODE_FN1_END - TEXT_RVA);
}

// The byte test that finds prologue shaped code cannot tell a "sub rsp, 0x20" at a
// real entry from one three bytes into a function body. The exception table can,
// because the compiler wrote down where the function actually ends. So the second
// fixture function must come back as exactly one function: if the interior stack
// adjustment ever starts a second one, a real function has been split in two.
static void check_no_split_inside_unwind(re_code_t *code, const re_fscan_t *scan) {
    size_t starts = 0;
    uint64_t interior = code->base + CODE_FN1_END + 1u; // the sub rsp itself
    uint64_t lo = code->base + CODE_FN1_END, hi = code->base + CODE_FN2_END;
    for (size_t i = 0; i < RE_VEC_LEN(&scan->funcs); i++) {
        uint64_t va = re_func_at(scan, i)->va;
        if (va == interior)
            starts++;
        else if (va >= lo && va < hi)
            starts++;
    }
    RE_CHECK_EQ_U(starts, 1);
}

// Slack is a claim about the pattern: the last n bytes are ones the signature makes
// no statement about. Parsing it is not the same as honouring it, and for a while the
// field was filled in and then never read by the matcher, so a signature written with
// slack was compared in full. That is the difference between a pattern covering a
// prologue with an unknown stack adjustment and a pattern that never matches.
static void check_slack_matching(re_code_t *code) {
    re_sig_t s;
    memset(&s, 0, sizeof(s));
    s.module = re_str("");
    s.name = re_str("exact");
    // The first three bytes of .text, which are 48 83 f8. The fourth is 01 here.
    s.pattern = re_str("4883f8");
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    // A signature that was never compiled claims nothing, so it cannot match. This is
    // the state a hand built signature is in until it is compiled, and treating it as
    // an empty pattern would make it match everything.
    s.n = 0;
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
    // Same pattern with the last byte wrong and one byte of slack: the wrong byte is
    // exactly the one slack excuses, so this must match.
    s.pattern = re_str("4883f8ff");
    s.slack = 1;
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(re_sig_match(code, code->base + TEXT_RVA, &s));
    // And without the slack the same pattern must not match, or slack means nothing.
    s.slack = 0;
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
    // A wrong byte that slack does not reach is still a miss.
    s.pattern = re_str("fffff8");
    s.slack = 1;
    RE_CHECK(re_sig_compile(&s));
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
    // Slack covering the whole pattern claims nothing at all, so the pattern is
    // refused at compile time rather than loaded as one that can never fire.
    s.pattern = re_str("4883f8");
    s.slack = 3;
    RE_CHECK(!re_sig_compile(&s));
    RE_CHECK(!re_sig_match(code, code->base + TEXT_RVA, &s));
}

// The C++ class tables, found structurally rather than by looking for names. A locator
// is only believed when its pSelf field repeats its own address, which is the one
// thing in a data section that cannot happen by accident, so a run of coincidental
// code pointers cannot turn into a class.
static bool line_has(const re_gui_listing_t *ls, const char *needle) {
    for (size_t i = 0; i < ls->n; i++) {
        if (ls->text[i] && strstr(ls->text[i], needle))
            return true;
    }
    return false;
}

// The right-hand pages, pinned on the text a reader would see. Counts are not enough:
// a row of the right length with the wrong bytes, or an export line that names the
// wrong function, would pass a length check and still be the wrong page.
static void check_view_pages(const re_pe_t *pe, re_code_t *code, re_arena_t *a) {
    re_gui_listing_t ls;
    re_vset_t empty;
    re_vset_t vs;
    memset(&ls, 0, sizeof(ls));
    memset(&empty, 0, sizeof(empty));
    re_gui_hex_fill(&ls, a, pe, TEXT_RVA, 20u, 0, 8);
    RE_CHECK(ls.n >= 1);
    RE_CHECK(ls.text[0] && strstr(ls.text[0], "48 83 f8 01"));
    re_gui_exports_fill(&ls, a, pe, 0, 8);
    RE_CHECK(ls.n >= 1);
    RE_CHECK(ls.text[0] && strstr(ls.text[0], "AlphaFunc"));
    RE_CHECK(line_has(&ls, "KERNEL32.Sleep"));
    re_gui_imports_fill(&ls, a, pe, 0, 8);
    RE_CHECK(ls.n == 1);
    RE_CHECK(ls.text[0] && strcmp(ls.text[0], "no imports") == 0);
    re_gui_structs_fill(&ls, a, &empty, 0, 8);
    RE_CHECK(ls.n == 1);
    RE_CHECK(ls.text[0] && strcmp(ls.text[0], "no class tables") == 0);
    re_vtable_scan(pe, code, a, &vs);
    re_gui_structs_fill(&ls, a, &vs, 0, 8);
    RE_CHECK(line_has(&ls, "Probe"));
}

static void check_vtables(const re_pe_t *pe, re_code_t *code, re_arena_t *a) {
    re_vset_t vs;
    re_vtable_scan(pe, code, a, &vs);
    RE_CHECK_FITS(vs.vtables, 1);
    if (!RE_VEC_LEN(&vs.vtables))
        return;
    const re_vtable_t *v = RE_VEC_PTR(&vs.vtables, re_vtable_t, 0);
    RE_CHECK_EQ_HEX(v->rva, EDATA_RVA + 0x120);
    RE_CHECK_EQ_HEX(v->col_rva, EDATA_RVA + 0xF0);
    RE_CHECK_EQ_HEX(v->td_rva, EDATA_RVA + 0xD0);
    RE_CHECK_EQ_U(v->n_entries, 2);
    RE_CHECK_EQ_U(vs.n_named, 1);
    RE_CHECK(v->name.n != 0);
    RE_CHECK(re_str_eq_cstr(v->name, "Probe"));
    RE_CHECK(v->demangled);
    RE_CHECK_EQ_U(v->n_bases, 1);
    // The entries have to be the two function addresses the fixture wrote, which is
    // what makes this a class table rather than a table of pointers to something.
    uint32_t e0 = 0, e1 = 0, e2 = 0;
    RE_CHECK(re_vtable_entry(pe, v, 0, &e0));
    RE_CHECK(re_vtable_entry(pe, v, 1, &e1));
    RE_CHECK_EQ_HEX(e0, TEXT_RVA);
    RE_CHECK_EQ_HEX(e1, TEXT_RVA + 6);
    RE_CHECK(!re_vtable_entry(pe, v, 2, &e2));
    // The locator check on its own, since the whole module rests on it. A locator
    // whose pSelf was wrong must be refused, and so must one that is not there.
    uint32_t td = 0, bcd = 0;
    RE_CHECK(re_vtable_col_at(pe, EDATA_RVA + 0xF0, &td, &bcd));
    RE_CHECK_EQ_HEX(td, EDATA_RVA + 0xD0);
    RE_CHECK_EQ_HEX(bcd, EDATA_RVA + 0x108);
    // The decoy: well formed in every field except pSelf, which names another address.
    // If the self check goes, this is accepted and a coincidence becomes a class.
    RE_CHECK(!re_vtable_col_at(pe, EDATA_RVA + 0x148, &td, &bcd));
    RE_CHECK(!re_vtable_col_at(pe, EDATA_RVA + 0xD0, &td, &bcd));
    RE_CHECK(!re_vtable_col_at(pe, 0xFFFFFFF0u, &td, &bcd));
}

static void check_func_pick(void) {
    re_gui_funcs_t l;
    memset(&l, 0, sizeof(l));
    l.n = 10;
    l.vis = 5;
    RE_CHECK_EQ_U(re_gui_funcs_index(0, &l, 0), 0);
    RE_CHECK_EQ_U(re_gui_funcs_index(0, &l, 2), 2);
    RE_CHECK_EQ_U(re_gui_funcs_row(0, &l), 0);
    RE_CHECK_EQ_U(re_gui_funcs_index(7, &l, 2), 7);
    RE_CHECK_EQ_U(re_gui_funcs_row(7, &l), 2);
    RE_CHECK_EQ_U(re_gui_funcs_index(9, &l, 4), 9);
    // The window stops at the end of the list rather than scrolling past it, so the
    // last function is on the last row and no row repeats the one above it.
    RE_CHECK_EQ_U(re_gui_funcs_row(9, &l), 4);
    RE_CHECK_EQ_U(re_gui_funcs_index(9, &l, 0), 5);
    // A pane the whole list fits in never scrolls: every row is its own function,
    // which is what showing however much fits means.
    l.vis = 10;
    RE_CHECK_EQ_U(re_gui_funcs_row(7, &l), 7);
    RE_CHECK_EQ_U(re_gui_funcs_index(7, &l, 7), 7);
    RE_CHECK_EQ_U(re_gui_funcs_index(9, &l, 0), 0);
    l.name[7] = "seven";
    const char *rows[10];
    re_gui_funcs_window(7, &l, rows, 10);
    RE_CHECK(rows[7] && re_str_eq_cstr(re_str(rows[7]), "seven"));
    // fit sizes the window to the pane, and never past the list it has or the bound
    // the caller's array was built for.
    re_gui_funcs_fit(&l, 4);
    RE_CHECK_EQ_U(l.vis, 4);
    re_gui_funcs_fit(&l, 1000);
    RE_CHECK_EQ_U(l.vis, 10);
    // A pane of 27 rows on a 40 function list, which is what a 30 row frame gives the
    // view: the window is the pane, in order from the top, and at the end it stops at
    // the last 27 functions rather than scrolling past them.
    l.n = 40;
    re_gui_funcs_fit(&l, 27);
    RE_CHECK_EQ_U(l.vis, 27);
    RE_CHECK_EQ_U(re_gui_funcs_index(0, &l, 26), 26);
    RE_CHECK_EQ_U(re_gui_funcs_index(30, &l, 0), 13);
    RE_CHECK_EQ_U(re_gui_funcs_row(30, &l), 17);
    RE_CHECK_EQ_U(re_gui_funcs_row(39, &l), 26);
    // An empty list is one row, and it says so rather than leaving the row unset.
    re_gui_funcs_t e;
    memset(&e, 0, sizeof(e));
    const char *empty[2] = {NULL, NULL};
    re_gui_funcs_window(0, &e, empty, 2);
    RE_CHECK(empty[0] && re_str_eq_cstr(re_str(empty[0]), "(no functions)"));
}

// Address translation must work when the build cannot decode the image. analyze's
// regions pass walks this context; a zeroed pe is the NULL re_pe_rva2off hit on x86.
static void check_code_binds_without_decoder(const uint8_t *img, const re_pe_t *pe) {
    re_arena_t a;
    re_code_t code;
    uint64_t off = 1;
    re_arena_init(&a, 4096);
    memset(&code, 0, sizeof(code));
    RE_CHECK(!re_code_init(&code, re_span(img, IMG_BYTES), pe, NULL, &a));
    RE_CHECK(code.pe == pe);
    RE_CHECK(code.dis == NULL);
    RE_CHECK_EQ_U(code.base, pe->image_base);
    RE_CHECK(code.img.p == img);
    RE_CHECK(re_code_offset(&code, pe->image_base + TEXT_RVA, &off));
    RE_CHECK_EQ_U(off, HDRS);
    off = 1;
    RE_CHECK(!re_pe_rva2off(NULL, TEXT_RVA, &off));
    RE_CHECK_EQ_U(off, 1); // a NULL parser is a refusal, not a write
    re_arena_free(&a);
}

int main(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_pe_t pe;
    re_arena_init(&a, 65536);
    build_pe(img);
    re_pe_parse(re_span(img, sizeof(img)), &a, &pe);
    RE_CHECK(pe.valid);
    RE_CHECK_EQ_U(pe.n_sec_field, 2);
    check_code_binds_without_decoder(img, &pe);
    check_func_pick();
    check_exports(&pe);
    check_export_kinds(&pe);
    check_one_flag_is_enough();
    check_unwind(&pe);
    {
        // The scanner must agree with the table, which means it needs the code layer.
        re_arena_t a2;
        re_code_t code;
        re_fscan_t scan;
        re_arena_init(&a2, 65536);
        if (re_code_init(&code, re_span(img, sizeof(img)), &pe, re_disasm_find("x86-64"), &a2)) {
            re_func_scan(&code, &a2, &scan);
            check_unwind_bounds_function(&code, &scan);
            check_no_split_inside_unwind(&code, &scan);
            check_slack_matching(&code);
            check_vtables(&pe, &code, &a2);
            check_view_pages(&pe, &code, &a2);
        }
        re_arena_free(&a2);
    }
    re_arena_free(&a);
    return re_test_report("pe");
}

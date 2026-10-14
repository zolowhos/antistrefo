// test_alt.c - .alt sidecar round-trip and rename apply onto the PE fixture.
// Module: test (C11).
// Owns: load/save format pins and that applied names reach the function table.
// Depends: re_alt, re_analyze, the shared PE fixture.
#include "re_test.h"

#include <stdio.h>
#include <string.h>

#include "features/analysis/re_alt.h"
#include "features/analysis/re_analyze.h"
#include "features/code/re_func.h"

#include "re_pe_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

static const char kBin[] = "re_test_alt_fixture.sys";
static const char kAlt[] = "re_test_alt_fixture.sys.alt";

static void write_fixture(void) {
    uint8_t img[IMG_BYTES];
    FILE *fh;
    build_pe(img);
    fh = fopen(kBin, "wb");
    RE_CHECK(fh != NULL);
    if (!fh)
        return;
    RE_CHECK(fwrite(img, 1, sizeof(img), fh) == sizeof(img));
    fclose(fh);
}

static void check_round_trip(void) {
    re_arena_t a;
    re_alt_t m;
    const re_alt_ent_t *e;
    FILE *fh;
    char buf[128];
    re_arena_init(&a, 1 << 16);
    re_alt_init(&m, &a);
    RE_CHECK(re_alt_set(&m, TEXT_RVA, re_str("user_entry")));
    RE_CHECK(re_alt_set(&m, TEXT_RVA + 6u, re_str("user_beta")));
    RE_CHECK(re_alt_save(&m, kBin));
    fh = fopen(kAlt, "rb");
    RE_CHECK(fh != NULL);
    if (fh) {
        size_t n = fread(buf, 1, sizeof(buf) - 1u, fh);
        buf[n] = '\0';
        fclose(fh);
        RE_CHECK(strstr(buf, "0x1000=user_entry") != NULL);
        RE_CHECK(strstr(buf, "0x1006=user_beta") != NULL);
    }
    re_alt_init(&m, &a);
    RE_CHECK(re_alt_load(&m, kBin));
    RE_CHECK_EQ_U(RE_VEC_LEN(&m.ents), 2);
    e = re_alt_find(&m, TEXT_RVA);
    RE_CHECK(e && re_str_eq_cstr(e->name, "user_entry"));
    e = re_alt_find(&m, TEXT_RVA + 6u);
    RE_CHECK(e && re_str_eq_cstr(e->name, "user_beta"));
    re_arena_free(&a);
}

static void check_apply_and_output(void) {
    re_arena_t a;
    re_analysis_t an;
    const re_func_t *f;
    long idx;
    re_arena_init(&a, 1 << 20);
    RE_CHECK(re_analysis_open(&an, &a, kBin));
    idx = re_func_index_of(&an.scan, IMAGE_BASE + TEXT_RVA);
    RE_CHECK(idx >= 0);
    f = re_func_at(&an.scan, (size_t)idx);
    RE_CHECK(f && re_str_eq_cstr(f->name, "user_entry"));
    RE_CHECK(re_str_eq_cstr(f->module, "alt"));
    re_analysis_close(&an);
    re_arena_free(&a);
}

static void check_resolve_by_name(void) {
    re_arena_t a;
    re_analysis_t an;
    uint32_t rva = 0;
    re_arena_init(&a, 1 << 20);
    RE_CHECK(re_analysis_open(&an, &a, kBin));
    RE_CHECK(re_alt_resolve(&an.scan, &an.pe, re_str("user_entry"), &rva));
    RE_CHECK_EQ_U(rva, TEXT_RVA);
    RE_CHECK(re_alt_resolve(&an.scan, &an.pe, re_str("0x1000"), &rva));
    RE_CHECK_EQ_U(rva, TEXT_RVA);
    re_analysis_close(&an);
    re_arena_free(&a);
}

int main(void) {
    write_fixture();
    check_round_trip();
    check_apply_and_output();
    check_resolve_by_name();
    remove(kAlt);
    remove(kBin);
    return re_test_report("alt");
}

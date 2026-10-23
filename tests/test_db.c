// test_db.c - the .asdb sidecar: round trip, determinism, stale and malformed.
// Module: test (C11).
// Owns: the pins that a database load matches a deep run, and that a bad file is refused.
// Depends: re_deep, re_db, the shared PE fixture. Each refusal is a check a dropped test
//           would let a torn or stale file through.
#include "re_test.h"

#include <stdio.h>
#include <string.h>

#include "features/analysis/re_deep.h"
#include "features/db/re_db.h"
#include "features/dec/re_decompile.h"
#include "re_pe_fixture.h"

int re_test_count = 0;
int re_test_fail = 0;

static const char kBin[] = "re_test_db_fixture.sys";
static const char kTwin[] = "re_test_db_fixture_t.sys";
static const char kCopy[] = "re_test_db_fixture_b.sys";

static void write_bin(const char *path, const uint8_t *img) {
    FILE *fh = fopen(path, "wb");
    RE_CHECK(fh != NULL);
    if (!fh)
        return;
    RE_CHECK(fwrite(img, 1, IMG_BYTES, fh) == IMG_BYTES);
    fclose(fh);
}

static bool copy_file(const char *from, const char *to) {
    FILE *in = fopen(from, "rb");
    FILE *out = fopen(to, "wb");
    uint8_t buf[4096];
    size_t n;
    if (!in || !out) {
        if (in)
            fclose(in);
        if (out)
            fclose(out);
        return false;
    }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return false;
        }
        if (n < sizeof(buf))
            break;
    }
    fclose(in);
    fclose(out);
    return true;
}

static bool files_equal(const char *a, const char *b) {
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    uint8_t xa[4096];
    uint8_t xb[4096];
    bool same = fa && fb;
    while (same) {
        size_t na = fread(xa, 1, sizeof(xa), fa);
        size_t nb = fread(xb, 1, sizeof(xb), fb);
        if (na != nb || memcmp(xa, xb, na) != 0)
            same = false;
        if (na < sizeof(xa))
            break;
    }
    if (fa)
        fclose(fa);
    if (fb)
        fclose(fb);
    return same;
}

static void check_funcs(const re_analysis_t *live, const re_analysis_t *loaded) {
    size_t n = RE_VEC_LEN(&live->scan.funcs);
    RE_CHECK(loaded->db != NULL);
    RE_CHECK(loaded->deep);
    RE_CHECK_EQ_U(RE_VEC_LEN(&loaded->scan.funcs), n);
    RE_CHECK_EQ_U(RE_VEC_LEN(&loaded->scan.edges), RE_VEC_LEN(&live->scan.edges));
    RE_CHECK_EQ_U(RE_VEC_LEN(&loaded->xs.fwd), RE_VEC_LEN(&live->xs.fwd));
    for (size_t i = 0; i < n; i++) {
        const re_func_t *a = RE_VEC_PTR(&live->scan.funcs, re_func_t, i);
        const re_func_t *b = RE_VEC_PTR(&loaded->scan.funcs, re_func_t, i);
        RE_CHECK_EQ_HEX(b->va, a->va);
        RE_CHECK_EQ_U(b->size, a->size);
        RE_CHECK_EQ_U(b->flags, a->flags);
        RE_CHECK_EQ_U(b->n_insns, a->n_insns);
        RE_CHECK(re_str_eq(a->name, b->name));
    }
}

static void check_decomp(re_analysis_t *live) {
    re_arena_t a;
    re_decomp_t d;
    re_stack_t st;
    re_strbuf_t sb;
    re_str_t pre;
    const re_func_t *f;
    bool pre_ok = false;
    bool ok;
    if (!RE_VEC_LEN(&live->scan.funcs) || !live->db)
        return;
    f = RE_VEC_PTR(&live->scan.funcs, re_func_t, 0);
    re_arena_init(&a, 1 << 20);
    memset(&d, 0, sizeof(d));
    d.code = &live->code;
    d.xrefs = &live->xs;
    d.jtables = &live->jtables;
    d.arena = &a;
    d.scan = &live->scan;
    re_strbuf_init(&sb, &a);
    re_stack_analyze(d.code, f, &a, &st);
    ok = re_decompile_ok(&d, f);
    if (ok)
        re_decompile_func(&d, f, &st, &sb);
    RE_CHECK(re_db_decomp(live->db, 0, &pre, &pre_ok));
    RE_CHECK(pre_ok == ok);
    RE_CHECK(pre.n == sb.len);
    RE_CHECK(pre.n == 0 || memcmp(pre.p, sb.p, pre.n) == 0);
    re_arena_free(&a);
}

static void check_user(const char *bin) {
    re_arena_t a;
    re_db_t db;
    re_alt_t m;
    re_err_t err;
    re_file_t src;
    bool bad = true;
    char *side;
    re_arena_init(&a, 1 << 20);
    side = re_db_path(&a, bin);
    re_alt_init(&m, &a);
    RE_CHECK(re_alt_set(&m, TEXT_RVA, re_str("from_db")));
    RE_CHECK(re_db_user_save(side, &m, &a));
    RE_CHECK(re_file_open(bin, &a, &src) == RE_OK);
    memset(&err, 0, sizeof(err));
    RE_CHECK(re_db_open(&db, side, src.whole, &a, &err));
    re_alt_init(&m, &a);
    RE_CHECK(re_db_user_load(&db, &m, &bad));
    RE_CHECK(!bad);
    RE_CHECK(re_alt_find(&m, TEXT_RVA) &&
             re_str_eq_cstr(re_alt_find(&m, TEXT_RVA)->name, "from_db"));
    re_db_close(&db);
    re_file_close(&src);
    re_arena_free(&a);
}

static void check_stale_and_torn(const uint8_t *img) {
    re_arena_t a;
    re_analysis_t an;
    re_db_t db;
    re_err_t err;
    uint8_t flipped[IMG_BYTES];
    char *side;
    FILE *fh;
    memcpy(flipped, img, IMG_BYTES);
    flipped[IMG_BYTES - 1u] ^= 0xFFu;
    write_bin(kCopy, flipped);
    side = NULL;
    re_arena_init(&a, 1 << 20);
    RE_CHECK(copy_file(re_db_path(&a, kBin), re_db_path(&a, kCopy)));
    RE_CHECK(re_analysis_open(&an, &a, kCopy));
    RE_CHECK(an.db == NULL); // the hash no longer matches, so the entry tier runs
    re_analysis_close(&an);
    side = re_db_path(&a, kCopy);
    fh = fopen(side, "wb");
    RE_CHECK(fh != NULL);
    if (fh) {
        fwrite("ASDB", 1, 4, fh); // a header with nothing after it
        fclose(fh);
    }
    memset(&err, 0, sizeof(err));
    RE_CHECK(!re_db_open(&db, side, re_span(flipped, IMG_BYTES), &a, &err));
    RE_CHECK(err.code == RE_E_MALFORMED || err.code == RE_E_UNSUPPORTED);
    re_arena_free(&a);
}

static void check_entry(const uint8_t *img) {
    re_arena_t a;
    re_pe_t pe;
    re_code_t code;
    re_fscan_t scan;
    const re_func_t *f;
    long idx;
    re_arena_init(&a, 1 << 20);
    RE_CHECK(re_pe_parse(re_span(img, IMG_BYTES), &a, &pe) == RE_OK);
    RE_CHECK(re_code_init(&code, re_span(img, IMG_BYTES), &pe, re_disasm_find("x86-64"), &a));
    RE_CHECK(!code.lim.deep);
    RE_CHECK_EQ_U(code.lim.edges, 2000000u);
    RE_CHECK_EQ_U(code.lim.insns, 4096u);
    re_func_scan(&code, &a, &scan);
    idx = re_func_index_of(&scan, IMAGE_BASE + TEXT_RVA);
    f = idx >= 0 ? re_func_at(&scan, (size_t)idx) : NULL;
    RE_CHECK(f != NULL);
    RE_CHECK_EQ_HEX(f->size, CODE_FN1_END - TEXT_RVA);
    re_arena_free(&a);
}

int main(void) {
    uint8_t img[IMG_BYTES];
    re_arena_t a;
    re_arena_t b;
    re_analysis_t live;
    re_analysis_t loaded;
    build_pe(img);
    write_bin(kBin, img);
    write_bin(kTwin, img);
    re_arena_init(&a, 1 << 22);
    re_arena_init(&b, 1 << 22);
    RE_CHECK(re_analysis_open(&live, &a, kBin));
    RE_CHECK(re_deep_run(&live, NULL));
    RE_CHECK(live.scan.funcs.len > 0);
    RE_CHECK(re_analysis_open(&loaded, &b, kBin));
    check_funcs(&live, &loaded);
    check_decomp(&loaded);
    re_analysis_close(&live);
    re_analysis_close(&loaded);
    RE_CHECK(re_analysis_open(&live, &a, kTwin));
    RE_CHECK(re_deep_run(&live, NULL));
    RE_CHECK(files_equal(re_db_path(&a, kBin), re_db_path(&a, kTwin)));
    re_analysis_close(&live);
    check_user(kBin);
    check_stale_and_torn(img);
    check_entry(img);
    remove(kBin);
    remove(re_db_path(&a, kBin));
    remove(kTwin);
    remove(re_db_path(&a, kTwin));
    remove(kCopy);
    remove(re_db_path(&a, kCopy));
    re_arena_free(&a);
    re_arena_free(&b);
    if (re_test_fail)
        printf("%d of %d checks failed\n", re_test_fail, re_test_count);
    return re_test_fail ? 1 : 0;
}

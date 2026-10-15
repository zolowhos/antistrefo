// test_nameref.c - ordered name references, including a shared address and a hole.
// Module: test (C11).
// Owns: the sequence, the shared-address split, and both gap fills.
// Depends: re_nameref. A synthetic image, not a shipped binary.
#include "re_test.h"

#include <string.h>

#include "features/resolve/re_nameref.h"
#include "utils/mem/re_arena.h"

int re_test_count = 0;
int re_test_fail = 0;

enum { kImg = 0x400, kTextRaw = 0x200, kDataRaw = 0x300 };
static const uint64_t kBase = 0x140000000ull;

static void blank(re_pe_t *pe, uint8_t *img) {
    memset(img, 0, kImg);
    memset(pe, 0, sizeof(*pe));
    pe->valid = true;
    pe->image_base = kBase;
    pe->img = re_span(img, kImg);
    pe->n_sec = 2;
    memcpy(pe->sec[0].name, ".text", 5);
    pe->sec[0].vaddr = 0x1000;
    pe->sec[0].vsize = 0x100;
    pe->sec[0].rsize = 0x100;
    pe->sec[0].rptr = kTextRaw;
    pe->sec[0].chars = RE_SEC_CODE | RE_SEC_EXEC;
    memcpy(pe->sec[1].name, ".rdata", 6);
    pe->sec[1].vaddr = 0x2000;
    pe->sec[1].vsize = 0x100;
    pe->sec[1].rsize = 0x100;
    pe->sec[1].rptr = kDataRaw;
    pe->sec[1].chars = 0x40000040u;
}

static void put_rip(uint8_t *img, uint32_t off, int rex, int mov, uint64_t target) {
    uint8_t *p = img + kTextRaw + off;
    size_t n = rex ? 7u : 6u;
    uint64_t at = kBase + 0x1000u + off;
    int32_t disp = (int32_t)(target - (at + n));
    size_t o = 0;
    if (rex)
        p[o++] = 0x48;
    p[o++] = (uint8_t)(mov ? 0x8B : 0x8D);
    p[o++] = 0x05;
    memcpy(p + o, &disp, 4);
}

static uint64_t put_str(uint8_t *img, uint32_t *cursor, const char *s) {
    uint32_t off = *cursor;
    size_t n = 0;
    while (s[n])
        n++;
    memcpy(img + kDataRaw + off, s, n);
    img[kDataRaw + off + n] = 0;
    *cursor = off + (uint32_t)n + 1;
    return kBase + 0x2000u + off;
}

static re_nameref_in_t nin(const char *s, uint32_t rva) {
    re_nameref_in_t in;
    in.name = re_str(s);
    in.rva = rva;
    in.has_rva = true;
    return in;
}

static void assert_clean(const re_nameref_t *nr, uint64_t alpha, uint64_t gamma, uint64_t delta) {
    const re_nameref_hit_t *h;
    const re_nameref_miss_t *m;
    const re_nameref_gap_t *g;
    RE_CHECK_FITS(nr->hits, 3);
    RE_CHECK_FITS(nr->unreferenced, 1);
    RE_CHECK_FITS(nr->absent, 1);
    h = RE_VEC_PTR(&nr->hits, re_nameref_hit_t, 0);
    RE_CHECK(re_str_eq_cstr(h->name, "alpha"));
    RE_CHECK_EQ_U(h->index, 0);
    RE_CHECK_EQ_HEX(h->from, kBase + 0x1000);
    RE_CHECK_EQ_HEX(h->to, alpha);
    RE_CHECK_EQ_U(h->order_index, 0);
    h = RE_VEC_PTR(&nr->hits, re_nameref_hit_t, 1);
    RE_CHECK(re_str_eq_cstr(h->name, "gamma"));
    RE_CHECK_EQ_HEX(h->from, kBase + 0x1007);
    RE_CHECK_EQ_HEX(h->to, gamma);
    RE_CHECK_EQ_U(h->order_index, 2);
    h = RE_VEC_PTR(&nr->hits, re_nameref_hit_t, 2);
    RE_CHECK(re_str_eq_cstr(h->name, "delta"));
    RE_CHECK_EQ_HEX(h->from, kBase + 0x100E);
    RE_CHECK_EQ_HEX(h->to, delta);
    RE_CHECK_EQ_U(h->order_index, 3);
    m = RE_VEC_PTR(&nr->unreferenced, re_nameref_miss_t, 0);
    RE_CHECK(re_str_eq_cstr(m->name, "beta"));
    RE_CHECK_EQ_HEX(m->rva, 0x2000);
    RE_CHECK_EQ_U(m->order_index, 1);
    RE_CHECK(re_str_eq_cstr(m->order_name, "beta"));
    g = RE_VEC_PTR(&nr->absent, re_nameref_gap_t, 0);
    RE_CHECK(re_str_eq_cstr(g->name, "beta"));
    RE_CHECK(re_str_eq_cstr(g->order_name, "beta"));
}

// gamma and delta share an export rva. Both still load, and the one skipped
// name fills the single hole in the order list.
static void check_clean(void) {
    uint8_t img[kImg];
    re_pe_t pe;
    re_arena_t a;
    re_nameref_t nr;
    re_nameref_in_t in[4];
    re_str_t order[4];
    uint32_t cursor = 0;
    uint64_t alpha, gamma, delta;
    blank(&pe, img);
    alpha = put_str(img, &cursor, "alpha");
    put_str(img, &cursor, "beta");
    gamma = put_str(img, &cursor, "gamma");
    delta = put_str(img, &cursor, "delta");
    put_rip(img, 0, 1, 0, alpha);
    put_rip(img, 7, 1, 1, gamma);
    put_rip(img, 14, 1, 0, delta);
    put_rip(img, 21, 1, 0, kBase + 0x20F0);
    in[0] = nin("alpha", 0x1000);
    in[1] = nin("beta", 0x2000);
    in[2] = nin("gamma", 0x3000);
    in[3] = nin("delta", 0x3000);
    order[0] = re_str("alpha");
    order[1] = re_str("beta");
    order[2] = re_str("gamma");
    order[3] = re_str("delta");
    re_arena_init(&a, 1 << 16);
    RE_CHECK(re_nameref_scan(&pe, in, 4, order, 4, &a, &nr));
    assert_clean(&nr, alpha, gamma, delta);
    re_arena_free(&a);
}

// Two holes, so the one export the code never loads stays unnamed.
static void check_split(void) {
    uint8_t img[kImg];
    re_pe_t pe;
    re_arena_t a;
    re_nameref_t nr;
    re_nameref_in_t in[3];
    re_str_t order[4];
    uint32_t cursor = 0;
    uint64_t aa, cc;
    const re_nameref_hit_t *h;
    const re_nameref_miss_t *m;
    const re_nameref_gap_t *g;
    blank(&pe, img);
    aa = put_str(img, &cursor, "aa");
    put_str(img, &cursor, "bb");
    cc = put_str(img, &cursor, "cc");
    put_rip(img, 0, 1, 0, aa);
    put_rip(img, 7, 1, 0, cc);
    in[0] = nin("aa", 0x1000);
    in[1] = nin("bb", 0x2000);
    in[2] = nin("cc", 0x3000);
    order[0] = re_str("aa");
    order[1] = re_str("xx");
    order[2] = re_str("cc");
    order[3] = re_str("yy");
    re_arena_init(&a, 1 << 16);
    RE_CHECK(re_nameref_scan(&pe, in, 3, order, 4, &a, &nr));
    RE_CHECK_FITS(nr.hits, 2);
    RE_CHECK_FITS(nr.unreferenced, 1);
    RE_CHECK_FITS(nr.absent, 2);
    h = RE_VEC_PTR(&nr.hits, re_nameref_hit_t, 0);
    RE_CHECK(re_str_eq_cstr(h->name, "aa"));
    RE_CHECK_EQ_HEX(h->to, aa);
    RE_CHECK_EQ_U(h->order_index, 0);
    RE_CHECK(re_str_eq_cstr(h->order_name, "aa"));
    h = RE_VEC_PTR(&nr.hits, re_nameref_hit_t, 1);
    RE_CHECK(re_str_eq_cstr(h->name, "cc"));
    RE_CHECK_EQ_HEX(h->to, cc);
    RE_CHECK_EQ_U(h->order_index, 2);
    m = RE_VEC_PTR(&nr.unreferenced, re_nameref_miss_t, 0);
    RE_CHECK(re_str_eq_cstr(m->name, "bb"));
    RE_CHECK(m->order_index < 0);
    RE_CHECK_EQ_U(m->order_name.n, 0);
    g = RE_VEC_PTR(&nr.absent, re_nameref_gap_t, 0);
    RE_CHECK(re_str_eq_cstr(g->order_name, "xx"));
    RE_CHECK_EQ_U(g->name.n, 0);
    g = RE_VEC_PTR(&nr.absent, re_nameref_gap_t, 1);
    RE_CHECK(re_str_eq_cstr(g->order_name, "yy"));
    RE_CHECK_EQ_U(g->name.n, 0);
    re_arena_free(&a);
}

// Two loads of one string, one of them without a REX prefix, stay two hits.
static void check_repeat(void) {
    uint8_t img[kImg];
    re_pe_t pe;
    re_arena_t a;
    re_nameref_t nr;
    re_nameref_in_t in;
    uint32_t cursor = 0;
    uint64_t alpha;
    const re_nameref_hit_t *a0;
    const re_nameref_hit_t *a1;
    blank(&pe, img);
    alpha = put_str(img, &cursor, "alpha");
    put_rip(img, 0, 1, 0, alpha);
    put_rip(img, 7, 0, 0, alpha);
    in = nin("alpha", 0x1000);
    re_arena_init(&a, 1 << 16);
    RE_CHECK(re_nameref_scan(&pe, &in, 1, NULL, 0, &a, &nr));
    RE_CHECK_FITS(nr.hits, 2);
    RE_CHECK_FITS(nr.unreferenced, 0);
    a0 = RE_VEC_PTR(&nr.hits, re_nameref_hit_t, 0);
    a1 = RE_VEC_PTR(&nr.hits, re_nameref_hit_t, 1);
    RE_CHECK_EQ_HEX(a0->to, alpha);
    RE_CHECK_EQ_HEX(a1->to, alpha);
    RE_CHECK(a0->from != a1->from);
    RE_CHECK_EQ_U(a0->index, 0);
    RE_CHECK_EQ_U(a1->index, 1);
    re_arena_free(&a);
}

// "alp" is a prefix of "alpha" and must not steal the reference.
static void check_prefix(void) {
    uint8_t img[kImg];
    re_pe_t pe;
    re_arena_t a;
    re_nameref_t nr;
    re_nameref_in_t in[2];
    uint32_t cursor = 0;
    uint64_t alpha;
    const re_nameref_hit_t *h;
    const re_nameref_miss_t *m;
    blank(&pe, img);
    alpha = put_str(img, &cursor, "alpha");
    put_rip(img, 0, 1, 0, alpha);
    in[0] = nin("alp", 0x1000);
    in[1] = nin("alpha", 0x2000);
    re_arena_init(&a, 1 << 16);
    RE_CHECK(re_nameref_scan(&pe, in, 2, NULL, 0, &a, &nr));
    RE_CHECK_FITS(nr.hits, 1);
    RE_CHECK_FITS(nr.unreferenced, 1);
    h = RE_VEC_PTR(&nr.hits, re_nameref_hit_t, 0);
    RE_CHECK(re_str_eq_cstr(h->name, "alpha"));
    m = RE_VEC_PTR(&nr.unreferenced, re_nameref_miss_t, 0);
    RE_CHECK(re_str_eq_cstr(m->name, "alp"));
    re_arena_free(&a);
}

int main(void) {
    check_clean();
    check_split();
    check_repeat();
    check_prefix();
    return re_test_report("nameref");
}

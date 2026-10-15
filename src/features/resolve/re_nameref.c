// re_nameref.c - find RIP-relative loads of exact names, in instruction order.
// Module: feature (C11).
// Owns: the section walk, the name sites, and the one-gap fill.
// Depends: re_nameref.h. Reads the image through re_pe sections only.
#include "features/resolve/re_nameref.h"

#include <string.h>

typedef struct {
    re_str_t name;
    uint32_t rva;
    uint32_t ord;
    bool has_rva;
    bool hit;
} nm_t;

typedef struct {
    uint64_t va;
    uint32_t name_i;
} site_t;

static bool section_bytes(const re_pe_t *pe, const re_pe_section_t *s, const uint8_t **p,
                          size_t *n) {
    uint64_t end;
    if (!pe->img.p || s->rsize == 0)
        return false;
    end = (uint64_t)s->rptr + s->rsize;
    if (end > pe->img.n)
        return false;
    *p = pe->img.p + s->rptr;
    *n = s->rsize;
    return true;
}

// name followed by NUL, so a shorter prefix of a longer string is not a hit.
static bool find_cstr(const uint8_t *p, size_t n, re_str_t name, size_t from, size_t *at) {
    size_t last;
    if (name.n == 0 || n < name.n + 1 || from >= n)
        return false;
    last = n - name.n;
    for (size_t i = from; i < last; i++) {
        if (p[i + name.n] != 0)
            continue;
        if (memcmp(p + i, name.p, name.n) == 0) {
            *at = i;
            return true;
        }
    }
    return false;
}

static bool sites_in(const re_pe_t *pe, const re_pe_section_t *s, const nm_t *names, size_t nnames,
                     re_arena_t *a, re_vec_t *sites) {
    const uint8_t *p;
    size_t n;
    if (!section_bytes(pe, s, &p, &n))
        return true;
    for (size_t k = 0; k < nnames; k++) {
        size_t from = 0;
        size_t at = 0;
        while (find_cstr(p, n, names[k].name, from, &at)) {
            site_t site;
            site.va = pe->image_base + s->vaddr + (uint32_t)at;
            site.name_i = (uint32_t)k;
            if (!RE_VEC_PUSH(sites, a, site))
                return false;
            from = at + 1;
        }
    }
    return true;
}

static bool gather(const re_pe_t *pe, const nm_t *names, size_t nnames, re_arena_t *a,
                   re_vec_t *sites) {
    uint16_t n = pe->n_sec > RE_PE_MAX_SECTIONS ? RE_PE_MAX_SECTIONS : pe->n_sec;
    for (uint16_t s = 0; s < n; s++) {
        if (!sites_in(pe, &pe->sec[s], names, nnames, a, sites))
            return false;
    }
    return true;
}

// REX optional, opcode LEA (8D) or MOV r, r/m (8B), ModRM rip+disp32.
static bool rip_disp(const uint8_t *p, size_t n, size_t i, size_t *len, int32_t *disp) {
    size_t op = i;
    if (i < n && p[i] >= 0x40 && p[i] <= 0x4F)
        op = i + 1;
    if (op + 6 > n)
        return false;
    if (p[op] != 0x8D && p[op] != 0x8B)
        return false;
    if ((p[op + 1] & 0xC7) != 0x05)
        return false;
    memcpy(disp, p + op + 2, 4);
    *len = op + 6 - i;
    return true;
}

static bool note_target(re_vec_t *sites, nm_t *names, uint64_t from, uint64_t to, re_arena_t *a,
                        re_vec_t *hits) {
    for (size_t i = 0; i < sites->len; i++) {
        site_t *s = RE_VEC_PTR(sites, site_t, i);
        re_nameref_hit_t h;
        if (s->va != to)
            continue;
        h.from = from;
        h.to = to;
        h.index = (uint32_t)hits->len;
        h.name = names[s->name_i].name;
        h.order_index = -1;
        h.order_name = re_str("");
        names[s->name_i].hit = true;
        if (!RE_VEC_PUSH(hits, a, h))
            return false;
    }
    return true;
}

static bool walk_exec(const re_pe_t *pe, const re_pe_section_t *s, re_vec_t *sites, nm_t *names,
                      re_arena_t *a, re_vec_t *hits) {
    const uint8_t *p;
    size_t n;
    size_t i = 0;
    if ((s->chars & (RE_SEC_CODE | RE_SEC_EXEC)) == 0)
        return true;
    if (!section_bytes(pe, s, &p, &n))
        return true;
    while (i < n) {
        size_t len = 0;
        int32_t disp = 0;
        uint64_t from;
        uint64_t target;
        if (!rip_disp(p, n, i, &len, &disp)) {
            i++;
            continue;
        }
        from = pe->image_base + s->vaddr + i;
        target = from + len + (uint64_t)(int64_t)disp;
        if (!note_target(sites, names, from, target, a, hits))
            return false;
        i += len ? len : 1;
    }
    return true;
}

static bool walk_all(const re_pe_t *pe, re_vec_t *sites, nm_t *names, re_arena_t *a,
                     re_vec_t *hits) {
    uint16_t n = pe->n_sec > RE_PE_MAX_SECTIONS ? RE_PE_MAX_SECTIONS : pe->n_sec;
    for (uint16_t s = 0; s < n; s++) {
        if (!walk_exec(pe, &pe->sec[s], sites, names, a, hits))
            return false;
    }
    return true;
}

static int cmp_miss(const void *a, const void *b, void *ctx) {
    const re_nameref_miss_t *x = a;
    const re_nameref_miss_t *y = b;
    (void)ctx;
    if (x->rva != y->rva)
        return x->rva < y->rva ? -1 : 1;
    if (x->ord != y->ord)
        return x->ord < y->ord ? -1 : 1;
    return 0;
}

static bool collect_miss(const nm_t *names, size_t n, re_arena_t *a, re_vec_t *miss) {
    for (size_t i = 0; i < n; i++) {
        re_nameref_miss_t m;
        if (names[i].hit)
            continue;
        m.name = names[i].name;
        m.rva = names[i].rva;
        m.ord = names[i].ord;
        m.has_rva = names[i].has_rva;
        m.order_index = -1;
        m.order_name = re_str("");
        if (!RE_VEC_PUSH(miss, a, m))
            return false;
    }
    re_vec_sort(miss, cmp_miss, NULL);
    return true;
}

static bool push_absent(re_vec_t *absent, re_arena_t *a, re_str_t name, int32_t index) {
    re_nameref_gap_t g;
    g.name = re_str("");
    g.order_name = name;
    g.order_index = index;
    g.rva = 0;
    g.has_rva = false;
    return RE_VEC_PUSH(absent, a, g);
}

// Hits consume the order list in order. Entries skipped to reach the next hit,
// and whatever remains after the last hit, are the holes.
static bool align_hits(re_vec_t *hits, const re_str_t *order, size_t norder, re_arena_t *a,
                       re_vec_t *absent) {
    size_t oi = 0;
    for (size_t h = 0; h < hits->len; h++) {
        re_nameref_hit_t *hit = RE_VEC_PTR(hits, re_nameref_hit_t, h);
        bool found = false;
        while (oi < norder && !found) {
            if (re_str_eq(order[oi], hit->name)) {
                hit->order_index = (int32_t)oi;
                hit->order_name = order[oi];
                oi++;
                found = true;
            } else if (!push_absent(absent, a, order[oi], (int32_t)oi)) {
                return false;
            } else {
                oi++;
            }
        }
    }
    while (oi < norder) {
        if (!push_absent(absent, a, order[oi], (int32_t)oi))
            return false;
        oi++;
    }
    return true;
}

static bool gap_is_one(const re_vec_t *absent) {
    int32_t base;
    if (absent->len == 0)
        return false;
    base = RE_VEC_AT(absent, re_nameref_gap_t, 0).order_index;
    for (size_t i = 1; i < absent->len; i++) {
        int32_t want = base + (int32_t)i;
        if (RE_VEC_AT(absent, re_nameref_gap_t, i).order_index != want)
            return false;
    }
    return true;
}

static void fill_gap(re_vec_t *absent, re_vec_t *miss) {
    if (!gap_is_one(absent) || absent->len != miss->len)
        return;
    for (size_t i = 0; i < miss->len; i++) {
        re_nameref_miss_t *m = RE_VEC_PTR(miss, re_nameref_miss_t, i);
        re_nameref_gap_t *g = RE_VEC_PTR(absent, re_nameref_gap_t, i);
        m->order_index = g->order_index;
        m->order_name = g->order_name;
        g->name = m->name;
        g->rva = m->rva;
        g->has_rva = m->has_rva;
    }
}

bool re_nameref_scan(const re_pe_t *pe, const re_nameref_in_t *names, size_t nnames,
                     const re_str_t *order, size_t norder, re_arena_t *a, re_nameref_t *out) {
    nm_t *nm;
    re_vec_t sites;
    if (!out)
        return false;
    re_vec_init(&out->hits, sizeof(re_nameref_hit_t));
    re_vec_init(&out->unreferenced, sizeof(re_nameref_miss_t));
    re_vec_init(&out->absent, sizeof(re_nameref_gap_t));
    if (!pe || !a || nnames == 0)
        return true;
    nm = (nm_t *)re_arena_alloc(a, nnames * sizeof(nm_t));
    if (!nm)
        return false;
    for (size_t i = 0; i < nnames; i++) {
        nm[i].name = names[i].name;
        nm[i].rva = names[i].rva;
        nm[i].ord = (uint32_t)i;
        nm[i].has_rva = names[i].has_rva;
        nm[i].hit = false;
    }
    re_vec_init(&sites, sizeof(site_t));
    if (!gather(pe, nm, nnames, a, &sites))
        return false;
    if (!walk_all(pe, &sites, nm, a, &out->hits))
        return false;
    if (!collect_miss(nm, nnames, a, &out->unreferenced))
        return false;
    if (norder && order && !align_hits(&out->hits, order, norder, a, &out->absent))
        return false;
    fill_gap(&out->absent, &out->unreferenced);
    return true;
}

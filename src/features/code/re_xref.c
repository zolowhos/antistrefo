// re_xref.c - cross reference indexes with every target named where possible.
// Module: feature (C11).
// Owns: the import, export and string lookups, classification, both indexes.
// Depends: re_xref.h. A target is looked up, never guessed: an unnamed one is
//           reported as unnamed rather than given a plausible label.
#include "features/code/re_xref.h"

#include "utils/algo/re_sort.h"

#define RE_XREF_STRINGS_MAX 20000u

// A name bound to an address. One shape serves imports, exports and strings, so
// there is exactly one lookup routine in this file.
typedef struct {
    uint64_t va;
    re_str_t name;
} named_t;

static int cmp_va(const void *a, const void *b, void *ctx) {
    const named_t *x = (const named_t *)a;
    const named_t *y = (const named_t *)b;
    (void)ctx;
    if (x->va < y->va)
        return -1;
    return x->va > y->va ? 1 : 0;
}

static const named_t *find_named(const re_vec_t *v, uint64_t va) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(v);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const named_t *e = RE_VEC_PTR(v, named_t, mid);
        if (va < e->va)
            hi = mid;
        else if (va > e->va)
            lo = mid + 1;
        else
            return e;
    }
    return NULL;
}

static void add_named(re_arena_t *a, re_vec_t *v, uint64_t va, re_str_t name) {
    if (!va || name.n == 0)
        return;
    named_t e;
    e.va = va;
    e.name = name;
    RE_VEC_PUSH(v, a, e);
}

// One entry per IAT slot, because code reaches an import by loading the slot's
// address, never by naming the symbol.
static void build_imports(const re_pe_t *pe, re_arena_t *a, re_vec_t *out) {
    size_t step = pe->pe32plus ? 8u : 4u;
    for (size_t m = 0; m < RE_VEC_LEN(&pe->imports); m++) {
        const re_pe_imp_t *imp = RE_VEC_PTR(&pe->imports, re_pe_imp_t, m);
        if (!imp->first_thunk)
            continue;
        for (uint32_t i = 0; i < imp->n_syms; i++) {
            if (imp->first_sym + i >= RE_VEC_LEN(&pe->syms))
                break;
            re_str_t sym = RE_VEC_AT(&pe->syms, re_str_t, imp->first_sym + i);
            add_named(a, out, pe->image_base + imp->first_thunk + i * step, sym);
        }
    }
    re_vec_sort(out, cmp_va, NULL);
}

static void build_exports(const re_pe_t *pe, re_arena_t *a, re_vec_t *out) {
    for (size_t i = 0; i < RE_VEC_LEN(&pe->exports); i++) {
        const re_pe_exp_t *e = RE_VEC_PTR(&pe->exports, re_pe_exp_t, i);
        add_named(a, out, pe->image_base + e->rva, e->name);
    }
    re_vec_sort(out, cmp_va, NULL);
}

// Strings are found at file offsets, so each one is translated to a virtual
// address. A string in a section with no raw data has no address and is dropped.
static void build_strings(const re_pe_t *pe, re_span_t img, re_arena_t *a, re_vec_t *out) {
    re_strings_t st;
    re_strings_init(&st);
    re_strings_scan(img, 4, RE_XREF_STRINGS_MAX, a, &st);
    for (size_t i = 0; i < RE_VEC_LEN(&st.hits); i++) {
        const re_str_hit_t *h = RE_VEC_PTR(&st.hits, re_str_hit_t, i);
        uint32_t rva = 0;
        if (!re_pe_off2rva(pe, h->off, &rva))
            continue;
        add_named(a, out, pe->image_base + rva, h->text);
    }
    re_vec_sort(out, cmp_va, NULL);
}

// True when the address falls in a mapped, non executable section, which is what
// a reference into .rdata or .data looks like.
static bool in_data(const re_pe_t *pe, uint64_t va) {
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        uint64_t bytes = s->vsize > s->rsize ? s->vsize : s->rsize;
        if (va >= pe->image_base + s->vaddr && va - (pe->image_base + s->vaddr) < bytes)
            return (s->chars & RE_SEC_EXEC) == 0;
    }
    return false;
}

static bool sec_is_bss(const re_pe_section_t *s) {
    if (s->chars & RE_SEC_BSS)
        return true;
    return (s->chars & RE_SEC_WRITE) != 0 && (s->chars & RE_SEC_EXEC) == 0 && s->rsize == 0;
}

static bool in_bss(const re_pe_t *pe, uint64_t va) {
    for (uint16_t i = 0; i < pe->n_sec; i++) {
        const re_pe_section_t *s = &pe->sec[i];
        uint64_t bytes = s->vsize > s->rsize ? s->vsize : s->rsize;
        if (va >= pe->image_base + s->vaddr && va - (pe->image_base + s->vaddr) < bytes)
            return sec_is_bss(s);
    }
    return false;
}

static bool read_ptr_at(const re_pe_t *pe, re_span_t img, uint64_t va, uint64_t *out) {
    uint32_t rva;
    uint64_t off = 0;
    size_t step = pe->pe32plus ? 8u : 4u;
    uint64_t v = 0;
    size_t i;
    if (va < pe->image_base)
        return false;
    rva = (uint32_t)(va - pe->image_base);
    if (!re_pe_rva2off(pe, rva, &off) || off + step > img.n)
        return false;
    for (i = 0; i < step; i++)
        v |= (uint64_t)img.p[off + i] << (i * 8);
    *out = v;
    return true;
}

// Everything classification needs, gathered once so the per edge work is a
// handful of binary searches and nothing else.
typedef struct {
    re_code_t *code;
    const re_pe_t *pe;
    const re_fscan_t *scan;
    re_vec_t imports; // named_t
    re_vec_t exports; // named_t
    re_vec_t strings; // named_t
} xr_ctx_t;

// Every flag that applies to a target. A target can be several things at once:
// an import slot also lives in .rdata, and reporting only one would understate
// what the reference is. A target nothing is known about is OUTSIDE, which is the
// honest answer and is not the same as saying it is uninteresting.
static void classify(const xr_ctx_t *x, re_xref_t *r) {
    const named_t *n;
    bool is_import;
    r->name = re_str("");
    r->rva = (uint32_t)(r->to - x->code->base);
    r->flags = 0;
    n = find_named(&x->imports, r->to);
    is_import = n != NULL;
    if (!n)
        n = find_named(&x->exports, r->to);
    if (n) {
        r->name = n->name;
        r->flags |= is_import ? RE_XRF_IMPORT : RE_XRF_EXPORT;
    } else if ((n = find_named(&x->strings, r->to)) != NULL) {
        r->name = n->name;
        r->flags |= RE_XRF_STRING;
    }
    if (re_func_index_of(x->scan, r->to) >= 0)
        r->flags |= RE_XRF_CODE;
    if (in_data(x->pe, r->to))
        r->flags |= RE_XRF_DATA;
    if (r->flags == 0)
        r->flags |= RE_XRF_OUTSIDE;
}

// Readable non-exec sections: pointer-sized cells equal to a known string VA.
static void scan_ptr_tables(xr_ctx_t *x, re_arena_t *a, re_xrefset_t *out) {
    size_t step = x->pe->pe32plus ? 8u : 4u;
    uint16_t si;
    for (si = 0; si < x->pe->n_sec; si++) {
        const re_pe_section_t *s = &x->pe->sec[si];
        uint64_t base, end, va;
        if ((s->chars & RE_SEC_EXEC) || !(s->chars & RE_SEC_READ) || s->rsize < step)
            continue;
        base = x->pe->image_base + s->vaddr;
        end = base + (s->rsize < s->vsize ? s->rsize : s->vsize);
        for (va = base; va + step <= end; va += step) {
            uint64_t ptr = 0;
            const named_t *n;
            re_xref_t r;
            if (!read_ptr_at(x->pe, x->code->img, va, &ptr))
                continue;
            n = find_named(&x->strings, ptr);
            if (!n)
                continue;
            r.from = va;
            r.to = ptr;
            r.kind = RE_XR_DATA;
            classify(x, &r);
            r.flags |= RE_XRF_STRING | RE_XRF_DATA;
            r.name = n->name;
            if (in_bss(x->pe, ptr))
                r.flags |= RE_XRF_GLOBAL_SLOT;
            RE_VEC_PUSH(&out->fwd, a, r);
        }
    }
}

static uint8_t kind_of(uint8_t edge_kind) {
    switch (edge_kind) {
        case RE_EDGE_CALL:
            return RE_XR_CALL;
        case RE_EDGE_JUMP:
            return RE_XR_JUMP;
        case RE_EDGE_COND:
            return RE_XR_COND;
        default:
            return RE_XR_DATA;
    }
}

static int cmp_fwd(const void *a, const void *b, void *ctx) {
    const re_xref_t *x = (const re_xref_t *)a;
    const re_xref_t *y = (const re_xref_t *)b;
    (void)ctx;
    if (x->from < y->from)
        return -1;
    return x->from > y->from ? 1 : 0;
}

// The reverse index holds indices into fwd, sorted by the target they point at,
// so both directions are a binary search and neither needs a hash.
static int cmp_rev(const void *a, const void *b, void *ctx) {
    const re_xrefset_t *s = (const re_xrefset_t *)ctx;
    uint32_t ia = *(const uint32_t *)a;
    uint32_t ib = *(const uint32_t *)b;
    uint64_t ta = RE_VEC_AT(&s->fwd, re_xref_t, ia).to;
    uint64_t tb = RE_VEC_AT(&s->fwd, re_xref_t, ib).to;
    if (ta < tb)
        return -1;
    return ta > tb ? 1 : 0;
}

void re_xref_build(re_code_t *c, const re_fscan_t *scan, const re_pe_t *pe, re_arena_t *a,
                   re_xrefset_t *out) {
    xr_ctx_t x;
    x.code = c;
    x.pe = pe;
    x.scan = scan;
    re_vec_init(&out->fwd, sizeof(re_xref_t));
    re_vec_init(&out->rev, sizeof(uint32_t));
    out->n_indirect = 0;
    // Every one of these has to be initialised. A vector built on uninitialised
    // memory silently accepts nothing, which looks exactly like an image with no
    // imports rather than like a bug.
    re_vec_init(&x.imports, sizeof(named_t));
    re_vec_init(&x.exports, sizeof(named_t));
    re_vec_init(&x.strings, sizeof(named_t));
    build_imports(pe, a, &x.imports);
    build_exports(pe, a, &x.exports);
    build_strings(pe, c->img, a, &x.strings);
    for (size_t i = 0; i < RE_VEC_LEN(&scan->edges); i++) {
        const re_edge_t *e = RE_VEC_PTR(&scan->edges, re_edge_t, i);
        re_xref_t r;
        if (!e->has_to) {
            out->n_indirect++;
            continue;
        }
        r.from = e->from;
        r.to = e->to;
        r.kind = kind_of(e->kind);
        classify(&x, &r);
        RE_VEC_PUSH(&out->fwd, a, r);
    }
    scan_ptr_tables(&x, a, out);
    re_vec_sort(&out->fwd, cmp_fwd, NULL);
    for (size_t i = 0; i < RE_VEC_LEN(&out->fwd); i++) {
        uint32_t idx = (uint32_t)i;
        RE_VEC_PUSH(&out->rev, a, idx);
    }
    re_vec_sort(&out->rev, cmp_rev, out);
}

// The first index whose key is at or past va, in either direction.
static size_t lower_fwd(const re_xrefset_t *s, uint64_t va) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&s->fwd);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (RE_VEC_AT(&s->fwd, re_xref_t, mid).from < va)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static size_t lower_rev(const re_xrefset_t *s, uint64_t va) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&s->rev);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (RE_VEC_AT(&s->fwd, re_xref_t, RE_VEC_AT(&s->rev, uint32_t, mid)).to < va)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

size_t re_xref_from_count(const re_xrefset_t *s, uint64_t va) {
    size_t i = lower_fwd(s, va);
    size_t n = 0;
    while (i + n < RE_VEC_LEN(&s->fwd) && RE_VEC_AT(&s->fwd, re_xref_t, i + n).from == va)
        n++;
    return n;
}

const re_xref_t *re_xref_from_at(const re_xrefset_t *s, uint64_t va, size_t i) {
    size_t k = lower_fwd(s, va) + i;
    if (k >= RE_VEC_LEN(&s->fwd) || RE_VEC_AT(&s->fwd, re_xref_t, k).from != va)
        return NULL;
    return RE_VEC_PTR(&s->fwd, re_xref_t, k);
}

size_t re_xref_to_count(const re_xrefset_t *s, uint64_t va) {
    size_t i = lower_rev(s, va);
    size_t n = 0;
    while (i + n < RE_VEC_LEN(&s->rev) &&
           RE_VEC_AT(&s->fwd, re_xref_t, RE_VEC_AT(&s->rev, uint32_t, i + n)).to == va)
        n++;
    return n;
}

const re_xref_t *re_xref_to_at(const re_xrefset_t *s, uint64_t va, size_t i) {
    size_t k = lower_rev(s, va) + i;
    if (k >= RE_VEC_LEN(&s->rev))
        return NULL;
    uint32_t idx = RE_VEC_AT(&s->rev, uint32_t, k);
    if (RE_VEC_AT(&s->fwd, re_xref_t, idx).to != va)
        return NULL;
    return RE_VEC_PTR(&s->fwd, re_xref_t, idx);
}

// Every distinct string a function touches. Deduplicated by address, because one
// long string referenced from four places is one thing the function touches.
size_t re_xref_func_strings(const re_xrefset_t *s, const re_func_t *f, re_arena_t *a,
                            re_vec_t *out) {
    uint64_t last = 0;
    re_vec_clear(out);
    // Same range query as the two below, so it starts where the function starts and
    // stops at its end. Scanning every reference in the binary once per function made
    // emitting a large file quadratic: 200 functions took 9 seconds, and the largest
    // file in the corpus would have taken twenty minutes.
    size_t i = lower_fwd(s, f->va);
    for (; i < RE_VEC_LEN(&s->fwd); i++) {
        const re_xref_t *r = RE_VEC_PTR(&s->fwd, re_xref_t, i);
        if (r->from >= f->va + f->size)
            break;
        if (!(r->flags & RE_XRF_STRING) || r->to == last)
            continue;
        last = r->to;
        RE_VEC_PUSH(out, a, i);
    }
    return RE_VEC_LEN(out);
}

// Both range queries walk the sorted forward index and stop at the first
// reference past the end, so a range query costs one scan rather than one per
// member. fwd is sorted by from, which is what makes the forward query a scan.
size_t re_xref_out_of(const re_xrefset_t *s, re_arena_t *a, uint64_t va, uint64_t size, size_t max,
                      re_vec_t *out) {
    size_t i = lower_fwd(s, va);
    size_t n = 0;
    re_vec_clear(out);
    while (i < RE_VEC_LEN(&s->fwd)) {
        const re_xref_t *r = RE_VEC_PTR(&s->fwd, re_xref_t, i);
        if (r->from >= va + size)
            break;
        if (max && n >= max)
            break;
        uint32_t idx = (uint32_t)i;
        RE_VEC_PUSH(out, a, idx);
        i++;
        n++;
    }
    return n;
}

size_t re_xref_into_count(const re_xrefset_t *s, uint64_t va, uint64_t size, size_t max) {
    size_t i = lower_rev(s, va);
    size_t n = 0;
    while (i < RE_VEC_LEN(&s->rev)) {
        uint32_t idx = RE_VEC_AT(&s->rev, uint32_t, i);
        if (RE_VEC_AT(&s->fwd, re_xref_t, idx).to >= va + size)
            break;
        if (max && n >= max)
            break;
        i++;
        n++;
    }
    return n;
}

// rev is sorted by target, so this is the same shape against the other index.
size_t re_xref_into(const re_xrefset_t *s, re_arena_t *a, uint64_t va, uint64_t size, size_t max,
                    re_vec_t *out) {
    size_t i = lower_rev(s, va);
    size_t n = 0;
    re_vec_clear(out);
    while (i < RE_VEC_LEN(&s->rev)) {
        uint32_t idx = RE_VEC_AT(&s->rev, uint32_t, i);
        if (RE_VEC_AT(&s->fwd, re_xref_t, idx).to >= va + size)
            break;
        if (max && n >= max)
            break;
        RE_VEC_PUSH(out, a, idx);
        i++;
        n++;
    }
    return n;
}

size_t re_xref_func_calls(const re_xrefset_t *s, const re_func_t *f) {
    size_t n = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&s->fwd); i++) {
        const re_xref_t *r = RE_VEC_PTR(&s->fwd, re_xref_t, i);
        if (r->from >= f->va && r->from < f->va + f->size && r->kind == RE_XR_CALL)
            n++;
    }
    return n;
}

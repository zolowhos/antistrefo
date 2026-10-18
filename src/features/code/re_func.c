// re_func.c - what a walk of the whole image consists of: seeds and passes.
// Module: feature (C11).
// Owns: the seeds, the unwind and sweep passes, naming, and the edge counts.
// Depends: re_func_priv.h, which holds the walk itself and the state it shares
//           with the seeds. A function is reported only if it was walked.
#include "features/code/re_func.h"

#include "features/code/re_func_priv.h"
#include "features/code/re_seeds.h"
#include "features/pe/re_pe.h"

#include <string.h>

// Declared here because the scan sorts its table and then applies the names the image
// states; the body sits below the walk it serves, next to the sort it depends on.
static void name_exports(const re_pe_t *pe, re_fscan_t *out);

void re_fscan_init(re_fscan_t *s) {
    re_vec_init(&s->funcs, sizeof(re_func_t));
    re_vec_init(&s->edges, sizeof(re_edge_t));
    s->truncated = false;
}

// Push one recovered function. No count cap: every walked start is kept. Only an
// arena failure stops the scan, and that is reported as truncated (OOM).
static bool push_func(walk_t *w, re_func_t *f) {
    re_func_t copy;
    if (w->truncated)
        return false;
    copy = *f;
    if (!RE_VEC_PUSH(w->out, w->a, copy)) {
        w->truncated = true;
        return false;
    }
    return true;
}

static int cmp_va(const void *a, const void *b, void *ctx) {
    const re_func_t *x = (const re_func_t *)a;
    const re_func_t *y = (const re_func_t *)b;
    (void)ctx;
    if (x->va < y->va)
        return -1;
    return x->va > y->va ? 1 : 0;
}

// The unwind table is the compiler's own list of where its functions begin and end.
// Where it is present it beats any inference from bytes: it gives a function that no
// call points at, such as one reached only through SEH or a runtime callback, and it
// gives the exact end rather than the end the walk happened to reach. It is not
// complete, because a leaf function needing no frame has no entry, so this runs
// alongside the sweep rather than instead of it.
static void unwind_pass(walk_t *w) {
    const re_pe_t *pe = w->code->pe;
    for (size_t i = 0; i < RE_VEC_LEN(&pe->unwind) && !w->truncated; i++) {
        const re_pe_unwind_t *u = RE_VEC_PTR(&pe->unwind, re_pe_unwind_t, i);
        uint64_t start = w->code->base + u->begin;
        if (!re_code_in_code(w->code, start) || re_code_covered(w->code, start, 1))
            continue;
        re_func_t f;
        re_walk_func(w, start, &f);
        if (f.n_insns == 0)
            continue;
        f.flags |= RE_FUNC_UNWIND;
        // The compiler knows where the function stops even when the walk stopped
        // early, so the declared end wins over the walked one.
        if (u->end > u->begin && f.rva + f.size < u->end)
            f.size = u->end - u->begin;
        push_func(w, &f);
    }
}

// The prologue sweep. Functions reached only through a vtable or a driver
// dispatch table are not pointed at by any call, so without this pass they are
// invisible. It is a byte test, not a decode, and it only starts a walk on
// unmarked bytes, so the cost is one comparison per byte of code.
static void sweep(walk_t *w) {
    uint64_t va = 0;
    uint64_t len = 0;
    for (uint16_t r = 0; re_code_range(w->code, r, &va, &len) && !w->truncated; r++) {
        uint64_t end = va + len;
        for (uint64_t at = va; at < end && !w->truncated; at++) {
            re_func_t f;
            if (re_code_covered(w->code, at, 1))
                continue;
            // A byte test says "sub rsp, 0x28" looks like a prologue. Inside a
            // function the compiler already described, that is a stack adjustment
            // mid body, and starting one there is how one real function became two.
            re_pe_unwind_t u;
            if (re_pe_unwind_covering(w->code->pe, (uint32_t)(at - w->code->base), &u) &&
                w->code->base + u.begin != at)
                continue;
            if (!re_walk_looks_like_start(w->code, at))
                continue;
            re_walk_func(w, at, &f);
            if (f.n_insns == 0)
                continue;
            f.flags |= RE_FUNC_PROLOGUE;
            if (!push_func(w, &f))
                return;
            at += f.size ? f.size - 1 : 0;
        }
    }
}

// A function that begins where the compiler put an unwind entry takes its end from
// there too, whichever pass happened to discover it first. Most of the table is
// already reached by a call, so without this the declared end is available but
// unused, and a function the walk stopped short of keeps the short size.
static void adopt_unwind(const re_pe_t *pe, re_vec_t *funcs) {
    for (size_t i = 0; i < RE_VEC_LEN(funcs); i++) {
        re_func_t *f = RE_VEC_PTR(funcs, re_func_t, i);
        re_pe_unwind_t u;
        if (!re_pe_unwind_covering(pe, f->rva, &u) || u.begin != f->rva)
            continue;
        f->flags |= RE_FUNC_UNWIND;
        if (u.end > u.begin)
            f->size = u.end - u.begin;
    }
}

// How many transfers leave each function. One pass over the edges, with the owning
// function found by binary search, because the caller needs this for every function
// and asking the edge list per function made emitting a large file quadratic.
// Two records that share bytes. The walk of an earlier function sometimes runs
// past its real end into the next one, and then the next function's opening is
// already claimed and every branch into it looks like a target in the middle of an
// instruction. The later function is the one whose bytes were taken, so the flag
// goes there; the sizes have already been reconciled against the unwind table by
// this point, which is what makes the test exact rather than an inference.
static void mark_record_overlaps(re_fscan_t *s) {
    for (size_t i = 1; i < RE_VEC_LEN(&s->funcs); i++) {
        const re_func_t *prev = RE_VEC_PTR(&s->funcs, re_func_t, i - 1);
        re_func_t *f = RE_VEC_PTR(&s->funcs, re_func_t, i);
        uint64_t end = prev->va + prev->size;
        // A record with no size at all says nothing, so it is not an overlap.
        if (prev->size > 0 && end > f->va)
            f->flags |= RE_FUNC_OVERLAP;
    }
}

static void count_edges(re_fscan_t *s) {
    // Zeroed here as well, so the count is this pass's answer no matter what the
    // record was created with. An increment over an unset field is not a count.
    for (size_t i = 0; i < RE_VEC_LEN(&s->funcs); i++)
        RE_VEC_PTR(&s->funcs, re_func_t, i)->out_edges = 0;
    for (size_t i = 0; i < RE_VEC_LEN(&s->edges); i++) {
        const re_edge_t *e = RE_VEC_PTR(&s->edges, re_edge_t, i);
        long f = re_func_index_of(s, e->from);
        if (f >= 0)
            RE_VEC_PTR(&s->funcs, re_func_t, (size_t)f)->out_edges++;
    }
}

// Name the functions the image's own structures point at, without a transfer. An
// export name and a name a structure states are not the same claim: an export entry
// is a statement about an entry point, while a dispatch slot is a statement that the
// compiler put this address in this field. So this runs after the exports and never
// replaces a name that is already there, and a seed with no name - a bare code
// pointer - has nothing to apply.
static void name_seeds(const re_vec_t *seeds, re_fscan_t *out) {
    for (size_t i = 0; i < RE_VEC_LEN(seeds); i++) {
        const re_seed_t *s = RE_VEC_PTR(seeds, re_seed_t, i);
        long idx;
        re_func_t *f;
        if (s->name.n == 0)
            continue;
        idx = re_func_index_of(out, s->va);
        if (idx < 0)
            continue;
        f = RE_VEC_PTR(&out->funcs, re_func_t, (size_t)idx);
        if (f->va != s->va || f->name.n != 0)
            continue;
        f->name = s->name;
        f->module = s->module;
    }
}

void re_func_scan(re_code_t *c, re_arena_t *a, re_fscan_t *out) {
    re_vec_t queue;
    re_vec_t seeds;
    re_vec_t irp;
    walk_t w;
    size_t cursor = 0;
    re_fscan_init(out);
    re_vec_init(&queue, sizeof(uint64_t));
    re_vec_init(&seeds, sizeof(re_seed_t));
    re_vec_init(&irp, sizeof(re_seed_t));
    memset(&w, 0, sizeof(w));
    w.code = c;
    w.a = a;
    w.edges = &out->edges;
    w.queue = &queue;
    w.out = &out->funcs;
    re_vec_init(&w.blocks, sizeof(uint64_t));
    if (c->pe->entry_rva)
        re_walk_push(a, &queue, c->base + c->pe->entry_rva);
    for (size_t i = 0; i < RE_VEC_LEN(&c->pe->exports); i++) {
        const re_pe_exp_t *e = RE_VEC_PTR(&c->pe->exports, re_pe_exp_t, i);
        if (e->rva)
            re_walk_push(a, &queue, c->base + e->rva);
    }
    // The starts nothing branches to, queued after the ones a reader would expect, so
    // a seed that lands inside a function found the ordinary way is skipped as covered.
    re_seed_collect(c->pe, c, a, &seeds);
    for (size_t i = 0; i < RE_VEC_LEN(&seeds); i++)
        re_walk_push(a, &queue, RE_VEC_AT(&seeds, re_seed_t, i).va);
    while (cursor < RE_VEC_LEN(&queue) && !w.truncated) {
        uint64_t start = *(const uint64_t *)RE_VEC_PTR(&queue, uint64_t, cursor);
        re_func_t f;
        cursor++;
        if (!re_code_in_code(c, start) || re_code_covered(c, start, 1))
            continue;
        re_walk_func(&w, start, &f);
        if (f.n_insns == 0)
            continue;
        if (c->pe->entry_rva && f.rva == c->pe->entry_rva)
            f.flags |= RE_FUNC_ENTRY;
        push_func(&w, &f);
    }
    unwind_pass(&w);
    sweep(&w);
    out->truncated = w.truncated;
    adopt_unwind(c->pe, &out->funcs);
    re_vec_sort(&out->funcs, cmp_va, NULL);
    mark_record_overlaps(out);
    name_exports(c->pe, out);
    name_seeds(&seeds, out);
    // The dispatch slots a driver fills in. This is asked for after the walk only
    // because the names are applied to the functions the walk found: the scan itself
    // is over the image's bytes, since a driver's entry point is usually a short stub
    // and the table is filled in by the function it calls.
    re_seed_irp(c->pe, c, a, &irp);
    name_seeds(&irp, out);
    count_edges(out);
    re_vec_truncate(&seeds, 0);
    re_vec_truncate(&irp, 0);
}

// The image states its own export names, which makes them the strongest name a
// function can have: everything else - a signature pattern, a recovered Go symbol
// table, a reader's own note - is an inference. Applied after the sort so each export
// is one binary search, and a function that exactly starts at the export takes the
// name; a function merely containing that address is left alone, because an export
// entry names an entry point.
static void name_exports(const re_pe_t *pe, re_fscan_t *out) {
    if (!pe)
        return;
    for (size_t i = 0; i < RE_VEC_LEN(&pe->exports); i++) {
        const re_pe_exp_t *e = RE_VEC_PTR(&pe->exports, re_pe_exp_t, i);
        long idx = re_func_index_of(out, pe->image_base + e->rva);
        re_func_t *f;
        if (idx < 0)
            continue;
        f = RE_VEC_PTR(&out->funcs, re_func_t, (size_t)idx);
        if (f->va != pe->image_base + e->rva || e->name.n == 0)
            continue;
        f->name = e->name;
        f->flags |= RE_FUNC_EXPORT;
    }
}

const re_func_t *re_func_at(const re_fscan_t *s, size_t index) {
    if (index >= RE_VEC_LEN(&s->funcs))
        return NULL;
    return RE_VEC_PTR(&s->funcs, re_func_t, index);
}

long re_func_index_of(const re_fscan_t *s, uint64_t va) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&s->funcs);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const re_func_t *f = RE_VEC_PTR(&s->funcs, re_func_t, mid);
        if (va < f->va) {
            hi = mid;
        } else if (va >= f->va + f->size) {
            lo = mid + 1;
        } else {
            return (long)mid;
        }
    }
    return -1;
}

// How many transfers leave this function. The count was taken when the scan
// finished, because a caller wants one per function and scanning the whole edge list
// per function made emitting a large file quadratic. The lookup is by address rather
// than by pointer, because callers hold a copy of the record, not the stored one.
size_t re_func_edge_count(const re_fscan_t *s, const re_func_t *f) {
    long i = re_func_index_of(s, f->va);
    if (i < 0)
        return 0;
    return re_func_at(s, (size_t)i)->out_edges;
}

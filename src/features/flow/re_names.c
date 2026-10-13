// re_names.c - names and call targets recovered from the image's own tables.
// Module: feature (C11).
// Owns: vtable slot naming, the two x64 virtual call forms, and the EH scopes.
// Depends: re_names.h, re_demangle. Sits in flow because a recovered call target
//           is flow recovery. Every name here was stated by the image or derived
//           from one of its own tables, never guessed from a pattern.
#include "features/flow/re_names.h"

#include "features/lib/re_demangle.h"

#include <stdio.h>
#include <string.h>

// One indexed vtable slot: where the slot lives, which function its pointer
// reaches, and the name the class table gives that function. Sorted by the slot
// address, because that is the key a call site knows.
typedef struct {
    uint64_t slot_va;
    uint64_t fn_va;
    re_str_t name;
} slot_named_t;

// The pass's working state: the sorted slot index every recovery consults, and
// the output record the counts land in. Kept in one struct so the three phases
// read like a table of contents rather than a tangle of parameters.
typedef struct {
    re_vec_t slots; // slot_named_t, sorted by slot_va
    re_names_stat_t *st;
    re_arena_t *a;
} names_ctx_t;

// A slot's name is the class the RTTI states and the ordinal the slot holds:
// a type descriptor names a class, never a method, so inventing a method name
// would be a guess. "Class::vfn3" says exactly what was proven and no more.
static re_str_t slot_name(re_arena_t *a, const re_vtable_t *v, uint32_t ordinal) {
    char buf[RE_NAMES_NAME_MAX + 32];
    int k = snprintf(buf, sizeof(buf), "%.*s::vfn%u", (int)v->name.n, v->name.p, ordinal);
    if (k <= 0 || (size_t)k >= sizeof(buf))
        return re_str("");
    return re_strn(re_arena_strndup(a, buf, (size_t)k), (uint32_t)k);
}
// One slot: read the function pointer, name the function it lands on, and index
// the slot address so a virtual call recovery can ask about it later.
static void slot_pass(names_ctx_t *x, const re_pe_t *pe, re_fscan_t *scan, const re_vtable_t *v) {
    if (!v->name.n)
        return;
    for (uint32_t i = 0; i < v->n_entries; i++) {
        uint32_t rva = 0;
        uint64_t slot_va = pe->image_base + v->rva + (uint64_t)i * 8u;
        uint64_t va;
        long idx;
        re_str_t nm;
        slot_named_t e;
        if (!re_vtable_entry(pe, v, i, &rva))
            break;
        va = pe->image_base + rva;
        idx = re_func_index_of(scan, va);
        if (idx < 0 || re_func_at(scan, (size_t)idx)->va != va)
            continue;
        nm = slot_name(x->a, v, i);
        if (nm.n == 0)
            continue;
        e.slot_va = slot_va;
        e.fn_va = va;
        e.name = nm;
        RE_VEC_PUSH(&x->slots, x->a, e);
        re_func_t *f = RE_VEC_PTR(&scan->funcs, re_func_t, (size_t)idx);
        if (!f->name.n) {
            f->name = nm;
            f->module = re_str("vtable");
            x->st->n_slots++;
        }
    }
}

static int cmp_slot(const void *pa, const void *pb, void *ctx) {
    const slot_named_t *a = (const slot_named_t *)pa;
    const slot_named_t *b = (const slot_named_t *)pb;
    (void)ctx;
    if (a->slot_va != b->slot_va)
        return a->slot_va < b->slot_va ? -1 : 1;
    return 0;
}

static int cmp_scope(const void *pa, const void *pb, void *ctx) {
    const re_eh_scope_t *a = (const re_eh_scope_t *)pa;
    const re_eh_scope_t *b = (const re_eh_scope_t *)pb;
    (void)ctx;
    if (a->begin != b->begin)
        return a->begin < b->begin ? -1 : 1;
    if (a->end != b->end)
        return a->end < b->end ? -1 : 1;
    return 0;
}

static const slot_named_t *slot_find(const names_ctx_t *x, uint64_t slot_va) {
    size_t lo = 0;
    size_t hi = RE_VEC_LEN(&x->slots);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const slot_named_t *e = RE_VEC_PTR(&x->slots, slot_named_t, mid);
        if (slot_va < e->slot_va)
            hi = mid;
        else if (slot_va > e->slot_va)
            lo = mid + 1;
        else
            return e;
    }
    return NULL;
}

static void count_vcall(names_ctx_t *x, uint64_t at, const slot_named_t *e) {
    re_vcall_t v;
    v.at = at;
    v.method = e->name;
    RE_VEC_PUSH(&x->st->vcalls, x->a, v);
    x->st->n_vcalls++;
}

// The two indirect call forms x64 compilers emit for obj->vf(). Both end in a
// call through something other than a stated address, so the search is a short
// linear window over each function rather than a dataflow pass: farther back
// than the last transfer, and the load belongs to some other value.
static void vcall_scan(names_ctx_t *x, re_code_t *code, const re_fscan_t *scan) {
    for (size_t fi = 0; fi < RE_VEC_LEN(&scan->funcs); fi++) {
        const re_func_t *f = re_func_at(scan, fi);
        uint64_t va = f->va;
        uint64_t end = f->va + f->size;
        uint64_t ld_slot = 0;
        uint32_t taken = 0;
        while (va < end && taken < RE_FUNC_MAX_INSNS) {
            re_insn_t in;
            if (!re_code_insn(code, va, &in) || in.size == 0)
                break;
            taken++;
            if (in.is_call && !in.has_target && in.is_mem && in.rip_rel) {
                // Form one: call [rip+slot]. The slot is stated in the call.
                const slot_named_t *e = slot_find(x, in.mem);
                if (e)
                    count_vcall(x, va, e);
            } else if (RE_INSN_MAP(&in) == 0 && RE_INSN_OPCODE(&in) == 0x8B && in.rip_rel &&
                       in.is_mem) {
                // mov r, [rip+slot]: the register now holds the slot's address.
                ld_slot = in.mem;
            } else if (in.is_call && !in.has_target) {
                // Form two: call through the register that was filled above.
                const slot_named_t *e = ld_slot ? slot_find(x, ld_slot) : NULL;
                if (e)
                    count_vcall(x, va, e);
                ld_slot = 0;
            } else if (in.is_branch || in.is_return || (in.is_call && in.has_target)) {
                // A transfer breaks the linear window, so the register's origin
                // is no longer the instruction immediately before the next call.
                ld_slot = 0;
            }
            va += in.size;
        }
    }
}

// One scope table entry, read from the mapped image. The low two bits of the
// begin field carry the entry kind, and only the plain try form has both ends
// free of them; a filter or a finally is left for a later pass.
static bool eh_entry(const re_pe_t *pe, const re_pe_unwind_t *u, uint64_t at, re_eh_scope_t *s) {
    uint32_t w[4];
    uint32_t begin_rel, end_rel;
    if (at + 16 > pe->img.n)
        return false;
    for (int i = 0; i < 4; i++) {
        uint64_t p = at + (uint64_t)i * 4u;
        w[i] = (uint32_t)pe->img.p[p] | ((uint32_t)pe->img.p[p + 1] << 8) |
               ((uint32_t)pe->img.p[p + 2] << 16) | ((uint32_t)pe->img.p[p + 3] << 24);
    }
    if (!w[0] && !w[1] && !w[2] && !w[3])
        return false; // the terminator the table ends on
    if ((w[0] & 3u) != 0 || (w[2] & 3u) != 0)
        return false;
    begin_rel = w[0] & ~3u;
    end_rel = w[2] & ~3u;
    if (end_rel <= begin_rel || end_rel > (u->end - u->begin))
        return false;
    s->begin = pe->image_base + u->begin + begin_rel;
    s->end = pe->image_base + u->begin + end_rel;
    return true;
}

// The C++ EH scope table, decoded from the unwind metadata. The header: byte 0
// carries the version and the three flags, so a handler is declared by a non
// zero flag nibble; the count of unwind codes is the 16 bit word at +2; a
// handler rva sits after the code array when a flag is set, and the classic
// scope table follows it, padded to four. The modern format compresses its
// tables and is recognised here but not expanded: a function with EH is counted
// either way, and a scope range is reported only when the classic table's first
// entry validates, which is what keeps compressed bytes from being read as one.
static void eh_scan(names_ctx_t *x, const re_pe_t *pe) {
    for (size_t i = 0; i < RE_VEC_LEN(&pe->unwind) && x->st->n_scopes < RE_EH_MAX_SCOPES; i++) {
        const re_pe_unwind_t *u = RE_VEC_PTR(&pe->unwind, re_pe_unwind_t, i);
        uint64_t off = 0;
        uint32_t flags, ncodes;
        uint64_t table;
        re_eh_scope_t probe;
        if (!re_pe_rva2off(pe, u->unwind, &off) || off + 8 > pe->img.n)
            continue;
        flags = (uint32_t)pe->img.p[off] & 0xF8u;
        ncodes = (uint32_t)pe->img.p[off + 2] | ((uint32_t)pe->img.p[off + 3] << 8);
        if (!flags || !ncodes || ncodes > 255)
            continue;
        x->st->n_funcs++;
        table = off + 4u + (uint64_t)ncodes * 2u + ((ncodes & 1u) ? 2u : 0u) + 4u;
        // The first entry is the format test: the classic table starts with a
        // plain try range inside the function, so an entry that fails that shape
        // means the compressed form, and the whole table is left alone.
        if (!eh_entry(pe, u, table, &probe))
            continue;
        for (uint32_t k = 0; k < 256 && x->st->n_scopes < RE_EH_MAX_SCOPES; k++) {
            re_eh_scope_t s;
            if (!eh_entry(pe, u, table + (uint64_t)k * 16u, &s))
                break;
            RE_VEC_PUSH(&x->st->scopes, x->a, s);
            x->st->n_scopes++;
        }
    }
    if (RE_VEC_LEN(&x->st->scopes))
        re_vec_sort(&x->st->scopes, cmp_scope, NULL);
}

void re_names_stat_init(re_names_stat_t *st, re_arena_t *a) {
    memset(st, 0, sizeof(*st));
    re_vec_init(&st->vcalls, sizeof(re_vcall_t));
    re_vec_init(&st->scopes, sizeof(re_eh_scope_t));
    (void)a;
}

void re_names_apply(const re_pe_t *pe, re_code_t *code, re_fscan_t *scan, const re_vset_t *vs,
                    re_arena_t *a, re_names_stat_t *out) {
    names_ctx_t x = {0};
    size_t nv = vs ? RE_VEC_LEN(&vs->vtables) : 0;
    if (!out)
        return;
    re_names_stat_init(out, a);
    if (!pe || !code || !scan || !a)
        return;
    x.st = out;
    x.a = a;
    re_vec_init(&x.slots, sizeof(slot_named_t));
    for (size_t i = 0; i < nv && out->n_slots < RE_NAMES_MAX_SLOTS; i++)
        slot_pass(&x, pe, scan, RE_VEC_PTR(&vs->vtables, re_vtable_t, i));
    if (RE_VEC_LEN(&x.slots))
        re_vec_sort(&x.slots, cmp_slot, NULL);
    vcall_scan(&x, code, scan);
    eh_scan(&x, pe);
}

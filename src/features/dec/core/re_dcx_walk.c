// re_dcx_walk.c - decodes one function's reachable instructions for the decompiler.
// Module: feature (C11).
// Owns: the traversal, jump table targets, noreturn calls, and the block start set.
// Depends: re_dcx.h, re_code, re_jtable. Each byte is decoded at most once, and a
//           call that never returns ends its block, so no padding or next function is
//           read as code that follows it.
#include "features/dec/core/re_dcx.h"

#include <string.h>

// Calls that do not come back, by import or symbol name. A walk that continued past
// one of these decoded whatever followed, which is padding or another function.
static const char *const kNoReturn[] = {
    "ExitProcess",
    "ExitThread",
    "FreeLibraryAndExitThread",
    "RtlExitUserProcess",
    "RtlExitUserThread",
    "TerminateProcess_noreturn",
    "abort",
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "_invalid_parameter_noinfo_noreturn",
    "_invoke_watson",
    "_CxxThrowException",
    "__std_terminate",
    "terminate",
    "__report_gsfailure",
    "__report_rangecheckfailure",
    "__fastfail",
    "KeBugCheck",
    "KeBugCheckEx",
    "RtlRaiseStatus",
    "longjmp",
};

static bool name_noreturn(re_str_t n) {
    for (size_t i = 0; i < sizeof(kNoReturn) / sizeof(kNoReturn[0]); i++)
        if (re_str_eq_cstr(n, kNoReturn[i]))
            return true;
    return false;
}

// True when the call at in never returns: a known import, a function the scanner
// proved has no return path, or a call the compiler followed with an int3, which is
// how MSVC marks the end of a path that a noreturn call has ended.
static bool call_noreturn(const dx_fn_t *x, const re_insn_t *in) {
    const re_xref_t *xr;
    re_insn_t nx;
    if (!in->is_call)
        return false;
    if (re_code_insn(x->code, in->addr + in->size, &nx) && RE_INSN_MAP(&nx) == 0 &&
        RE_INSN_OPCODE(&nx) == 0xCC)
        return true;
    xr = x->d->xrefs ? re_xref_from_at(x->d->xrefs, in->addr, 0) : NULL;
    if (xr && xr->name.n && name_noreturn(xr->name))
        return true;
    if (in->has_target) {
        const dx_sum_t *sm = dx_summary(x, in->target);
        if (sm && sm->noret)
            return true;
    }
    if (in->has_target && x->d->scan) {
        long i = re_func_index_of(x->d->scan, in->target);
        const re_func_t *g = i >= 0 ? re_func_at(x->d->scan, (size_t)i) : NULL;
        if (g && g->va == in->target && (g->flags & RE_FUNC_NORETURN))
            return true;
        if (g && g->va == in->target && g->name.n && name_noreturn(g->name))
            return true;
    }
    return false;
}

// int3, ud2, hlt and int 0x29 (__fastfail) stop the processor's flow outright.
static bool halts(const re_insn_t *in) {
    unsigned map = RE_INSN_MAP(in), op = RE_INSN_OPCODE(in);
    if (map == 0 && (op == 0xCC || op == 0xF4))
        return true;
    if (map == 0 && op == 0xCD && in->imm == 0x29)
        return true;
    return map == 1 && (op == 0x0B || op == 0xFF || op == 0xB9);
}

bool dx_ends_block(const dx_fn_t *x, const re_insn_t *in) {
    if (in->is_return || (in->is_branch && !in->is_call))
        return true;
    return halts(in) || call_noreturn(x, in);
}

const re_jtable_t *dx_table_at(const dx_fn_t *x, uint64_t va) {
    const re_vec_t *t = x->d->jtables;
    for (size_t i = 0; t && i < RE_VEC_LEN(t); i++) {
        const re_jtable_t *j = RE_VEC_PTR(t, re_jtable_t, i);
        if (j->at == va)
            return j;
    }
    return NULL;
}

typedef struct {
    uint64_t lo, hi;
    uint8_t *seen; // one byte per byte of the range: 1 decoded, 2 block start
    re_vec_t work; // uint64_t
} wk_t;

static void want(wk_t *k, re_arena_t *a, uint64_t va) {
    if (va < k->lo || va >= k->hi)
        return;
    k->seen[va - k->lo] |= 2u;
    RE_VEC_PUSH(&k->work, a, va);
}

// Every successor of one instruction that is a new block: a branch target, the
// fallthrough of a conditional, and each entry of a jump table.
static void follow(dx_fn_t *x, wk_t *k, const re_insn_t *in) {
    uint64_t next = in->addr + in->size;
    if (in->is_branch && in->has_target)
        want(k, x->a, in->target);
    if (in->is_conditional)
        want(k, x->a, next);
    if (in->is_branch && !in->has_target && !in->is_call) {
        const re_jtable_t *t = dx_table_at(x, in->addr);
        for (uint32_t i = 0; t && i < t->count; i++)
            want(k, x->a, re_jtable_target(x->code, t, i));
    }
}

static void walk_from(dx_fn_t *x, wk_t *k, uint64_t va) {
    while (va >= k->lo && va < k->hi) {
        re_insn_t in;
        if (k->seen[va - k->lo] & 1u) {
            // Running into code another path already decoded makes this address a
            // join, so it starts a block even though nothing branched to it.
            k->seen[va - k->lo] |= 2u;
            return;
        }
        if (!re_code_insn(x->code, va, &in) || !in.size || va + in.size > k->hi)
            return;
        for (uint32_t i = 0; i < in.size; i++)
            k->seen[va - k->lo + i] |= 1u;
        RE_VEC_PUSH(&x->insns, x->a, in);
        if (RE_VEC_LEN(&x->insns) >= DX_MAX_INSNS)
            return;
        follow(x, k, &in);
        if (dx_ends_block(x, &in)) {
            // the next instruction, if anything reaches it, starts a block
            if (va + in.size < k->hi)
                k->seen[va + in.size - k->lo] |= 2u;
            return;
        }
        va += in.size;
    }
}

// Keys ascending by their high halves, which are unique. A short run is an insertion
// sort; a longer one is a byte at a time from the lowest, for only as many bytes as the
// largest offset has, through tmp, so a function's order costs a few passes over it.
static void sort_keys(uint64_t *key, uint64_t *tmp, size_t n, uint64_t top) {
    if (n < 64) {
        for (size_t i = 1; i < n; i++) {
            uint64_t v = key[i];
            size_t j = i;
            for (; j > 0 && key[j - 1] > v; j--)
                key[j] = key[j - 1];
            key[j] = v;
        }
        return;
    }
    for (unsigned sh = 32; sh < 64 && (top >> (sh - 32)) != 0; sh += 8) {
        size_t at[257] = {0};
        for (size_t i = 0; i < n; i++)
            at[((key[i] >> sh) & 0xFFu) + 1]++;
        for (unsigned d = 0; d < 256; d++)
            at[d + 1] += at[d];
        for (size_t i = 0; i < n; i++)
            tmp[at[(key[i] >> sh) & 0xFFu]++] = key[i];
        memcpy(key, tmp, n * sizeof(uint64_t));
    }
}

// Address order. No two instructions share a start, since a decoded byte is never
// decoded again, so sorting the starts alone decides the order: the key is the offset
// (a function is under 4 GB) above the index. Each record then moves once along the
// cycles of the permutation, where sorting the records swapped them over and over.
static bool order_insns(dx_fn_t *x, uint64_t lo) {
    size_t n = RE_VEC_LEN(&x->insns);
    re_insn_t *in = (re_insn_t *)x->insns.base;
    uint64_t top = 0;
    if (n < 2)
        return true;
    uint64_t *key = (uint64_t *)re_arena_alloc(x->a, 2 * n * sizeof(uint64_t));
    if (!key)
        return false;
    for (size_t i = 0; i < n; i++) {
        key[i] = ((in[i].addr - lo) << 32) | (uint64_t)i;
        top = in[i].addr - lo > top ? in[i].addr - lo : top;
    }
    sort_keys(key, key + n, n, top);
    for (size_t i = 0; i < n; i++) {
        if ((size_t)(uint32_t)key[i] == i)
            continue;
        re_insn_t tmp = in[i];
        size_t j = i;
        for (;;) {
            size_t from = (size_t)(uint32_t)key[j];
            key[j] = (uint64_t)j; // placed
            if (from == i)
                break;
            in[j] = in[from];
            j = from;
        }
        in[j] = tmp;
    }
    return true;
}

// Decode everything reachable from the entry inside the function's extent. Returns the
// block start map, one byte per byte, for the graph builder to cut blocks with.
uint8_t *dx_walk(dx_fn_t *x, uint64_t *lo) {
    wk_t k;
    k.lo = x->f->va;
    k.hi = x->f->va + (x->f->size ? x->f->size : 1);
    k.seen = (uint8_t *)re_arena_calloc(x->a, (size_t)(k.hi - k.lo), 1);
    re_vec_init(&k.work, sizeof(uint64_t));
    re_vec_init(&x->insns, sizeof(re_insn_t));
    if (!k.seen)
        return NULL;
    want(&k, x->a, k.lo);
    for (size_t i = 0; i < RE_VEC_LEN(&k.work) && RE_VEC_LEN(&x->insns) < DX_MAX_INSNS; i++)
        walk_from(x, &k, RE_VEC_AT(&k.work, uint64_t, i));
    if (!order_insns(x, k.lo))
        return NULL;
    *lo = k.lo;
    return k.seen;
}

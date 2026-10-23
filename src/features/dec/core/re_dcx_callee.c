// re_dcx_callee.c - what a called function's own body says about it.
// Module: feature (C11).
// Owns: the callee summaries: parameter count, return value, and whether it returns.
// Depends: re_dcx.h. A summary is the decompiler's own graph and liveness run on the
//           callee without printing, cached per decompilation and depth limited, so a
//           call takes the arguments its target reads rather than a count guessed from
//           which registers happened to be written before it.
#include "features/dec/core/re_dcx.h"

#include <string.h>

#define DX_SUM_DEPTH 2u      // summaries of summaries, and no further
#define DX_SUM_BUDGET 60000u // instructions summarised per decompilation

static dx_sum_t *find(dx_cache_t *c, uint64_t va) {
    for (size_t i = 0; i < RE_VEC_LEN(&c->sums); i++) {
        dx_sum_t *s = RE_VEC_PTR(&c->sums, dx_sum_t, i);
        if (s->va == va)
            return s;
    }
    return NULL;
}

// Whether a block that leaves the function does so by a path that comes back to the
// caller: a tail call or an indirect jump does, a halt or a noreturn call does not.
static bool exit_returns(const dx_fn_t *y, const dx_block_t *b) {
    if (b->i1 <= b->i0)
        return true; // a virtual exit: a conditional jump out, assumed to come back
    const re_insn_t *last = RE_VEC_PTR(&y->insns, re_insn_t, b->i1 - 1);
    if (last->is_branch && !last->is_call)
        return true;
    return !dx_ends_block(y, last); // the walk was cut short: nothing proves no return
}

static void summarise(dx_fn_t *y, dx_sum_t *out) {
    bool returns = false;
    for (uint32_t i = 0; i < y->norder && !returns; i++) {
        const dx_block_t *b = &y->b[y->order[i]];
        returns = b->term == DX_T_RET || (b->term == DX_T_EXIT && exit_returns(y, b));
    }
    out->noret = !returns;
    out->has_ret = y->has_ret;
    out->ret_w = y->has_ret ? y->ret_w : 0;
    out->nparams = y->nparams;
    out->nstk = y->nstk;
}

const dx_sum_t *dx_summary(const dx_fn_t *x, uint64_t target) {
    dx_cache_t *c = x->cache;
    const re_fscan_t *scan = x->d->scan;
    long i = scan ? re_func_index_of(scan, target) : -1;
    const re_func_t *g = i >= 0 ? re_func_at(scan, (size_t)i) : NULL;
    if (!c || !g || g->va != target)
        return NULL;
    dx_sum_t *s = find(c, target);
    if (s)
        return s->state == 2 ? s : NULL;
    if (c->depth >= DX_SUM_DEPTH || c->spent >= DX_SUM_BUDGET)
        return NULL;
    dx_sum_t ns;
    memset(&ns, 0, sizeof(ns));
    ns.va = target;
    ns.state = 1; // in progress: a recursive call sees no summary rather than a guess
    RE_VEC_PUSH(&c->sums, x->a, ns);
    dx_fn_t y;
    memset(&y, 0, sizeof(y));
    y.d = x->d, y.f = g, y.code = x->code, y.a = x->a, y.cc = x->cc, y.cache = c;
    re_vec_init(&y.vars, sizeof(dx_var_t));
    c->depth++;
    bool ok = dx_build(&y);
    if (ok) {
        dx_consts(&y);
        dx_frame_pass(&y);
        dx_facts(&y);
        summarise(&y, &ns);
        c->spent += (uint32_t)RE_VEC_LEN(&y.insns);
    }
    c->depth--;
    s = find(c, target);
    *s = ns;
    s->state = ok ? 2 : 3;
    return ok ? s : NULL;
}
